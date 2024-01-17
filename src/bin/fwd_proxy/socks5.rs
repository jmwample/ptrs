use anyhow::{anyhow, Context, Result};
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use futures::task::SpawnExt;
use futures::FutureExt;
use safelog::sensitive;
use std::io::Result as IoResult;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::str::FromStr;
use tracing::{debug, warn};

use tor_rtcompat::Runtime;
use tor_socksproto::{SocksAuth, SocksCmd};

/// Given a just-received TCP connection `S` on a SOCKS port, handle the
/// SOCKS handshake and relay the connection over the Tor network.
///
/// Uses `isolation_info` to decide which circuits this connection
/// may use.  Requires that `isolation_info` is a pair listing the listener
/// id and the source address for the socks request.
pub(crate) async fn handle_socks_conn<R, S>(runtime: R, socks_stream: S) -> Result<()>
where
    R: Runtime,
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    // Part 1: Perform the SOCKS handshake, to learn where we are
    // being asked to connect, and what we're being asked to do once
    // we connect there.
    //
    // The SOCKS handshake can require multiple round trips (SOCKS5
    // always does) so we we need to run this part of the process in a
    // loop.
    let mut handshake = tor_socksproto::SocksProxyHandshake::new();

    let (mut socks_r, mut socks_w) = socks_stream.split();
    let mut inbuf = [0_u8; 1024];
    let mut n_read = 0;
    let request = loop {
        if n_read == inbuf.len() {
            // We would like to read more of this SOCKS request, but there is no
            // more space in the buffer.  If we try to keep reading into an
            // empty buffer, we'll just read nothing, try to parse it, and learn
            // that we still wish we had more to read.
            //
            // In theory we might want to resize the buffer.  Right now, though,
            // we just reject handshakes that don't fit into 1k.
            return Err(anyhow!("Socks handshake did not fit in 1KiB buffer"));
        }
        // Read some more stuff.
        n_read += socks_r
            .read(&mut inbuf[n_read..])
            .await
            .context("Error while reading SOCKS handshake")?;

        // try to advance the handshake to the next state.
        let action = match handshake.handshake(&inbuf[..n_read]) {
            Err(_) => continue, // Message truncated.
            Ok(Err(e)) => {
                if let tor_socksproto::Error::BadProtocol(version) = e {
                    // check for HTTP methods: CONNECT, DELETE, GET, HEAD, OPTION, PUT, POST, PATCH and
                    // TRACE.
                    // To do so, check the first byte of the connection, which happen to be placed
                    // where SOCKs version field is.
                    if [b'C', b'D', b'G', b'H', b'O', b'P', b'T'].contains(&version) {
                        write_all_and_close(&mut socks_w, WRONG_PROTOCOL_PAYLOAD).await?;
                    }
                }
                // if there is an handshake error, don't reply with a Socks error, remote does not
                // seems to speak Socks.
                return Err(e.into());
            }
            Ok(Ok(action)) => action,
        };

        // reply if needed.
        if action.drain > 0 {
            inbuf.copy_within(action.drain..action.drain + n_read, 0);
            n_read -= action.drain;
        }
        if !action.reply.is_empty() {
            write_all_and_flush(&mut socks_w, &action.reply).await?;
        }
        if action.finished {
            break handshake.into_request();
        }
    };
    let request = match request {
        Some(r) => r,
        None => {
            warn!("SOCKS handshake succeeded, but couldn't convert into a request.");
            return Ok(());
        }
    };

    // Unpack the socks request and find out where we're connecting to.
    let addr = request.addr().to_string();
    let port = request.port();
    debug!(
        "Got a socks request: {} {}:{}",
        request.command(),
        sensitive(&addr),
        port
    );

    match request.command() {
        SocksCmd::CONNECT => {
            let sock_addr = SocketAddr::new(IpAddr::from_str(addr.as_str()).unwrap(), port);
            let covert_stream = runtime.connect(&sock_addr).await?;
            // Okay, great! We have a connection over the Tor network.
            debug!("Got a stream for {}:{}", sensitive(&addr), port);

            // Send back a SOCKS response, telling the client that it
            // successfully connected.
            let reply = request
                .reply(tor_socksproto::SocksStatus::SUCCEEDED, None)
                .context("Encoding socks reply")?;
            write_all_and_flush(&mut socks_w, &reply[..]).await?;

            let (tor_r, tor_w) = covert_stream.split();

            // Finally, spawn two background tasks to relay traffic between
            // the socks stream and the tor stream.
            runtime.spawn(copy_interactive(socks_r, tor_w).map(|_| ()))?;
            runtime.spawn(copy_interactive(tor_r, socks_w).map(|_| ()))?;
        }
        _ => {
            // We don't support this SOCKS command.
            warn!("Dropping request; {:?} is unsupported", request.command());
            let reply = request
                .reply(tor_socksproto::SocksStatus::COMMAND_NOT_SUPPORTED, None)
                .context("Encoding socks reply")?;
            write_all_and_close(&mut socks_w, &reply[..]).await?;
        }
    };

    Ok(())
}

/// write_all the data to the writer & flush the writer if write_all is successful.
async fn write_all_and_flush<W>(writer: &mut W, buf: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer
        .write_all(buf)
        .await
        .context("Error while writing SOCKS reply")?;
    writer
        .flush()
        .await
        .context("Error while flushing SOCKS stream")
}

/// write_all the data to the writer & close the writer if write_all is successful.
async fn write_all_and_close<W>(writer: &mut W, buf: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer
        .write_all(buf)
        .await
        .context("Error while writing SOCKS reply")?;
    writer
        .close()
        .await
        .context("Error while closing SOCKS stream")
}

/// Copy all the data from `reader` into `writer` until we encounter an EOF or
/// an error.
///
/// Unlike as futures::io::copy(), this function is meant for use with
/// interactive readers and writers, where the reader might pause for
/// a while, but where we want to send data on the writer as soon as
/// it is available.
///
/// This function assumes that the writer might need to be flushed for
/// any buffered data to be sent.  It tries to minimize the number of
/// flushes, however, by only flushing the writer when the reader has no data.
async fn copy_interactive<R, W>(mut reader: R, mut writer: W) -> IoResult<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    use futures::{poll, task::Poll};

    let mut buf = [0_u8; 1024];

    // At this point we could just loop, calling read().await,
    // write_all().await, and flush().await.  But we want to be more
    // clever than that: we only want to flush when the reader is
    // stalled.  That way we can pack our data into as few cells as
    // possible, but flush it immediately whenever there's no more
    // data coming.
    let loop_result: IoResult<()> = loop {
        let mut read_future = reader.read(&mut buf[..]);
        match poll!(&mut read_future) {
            Poll::Ready(Err(e)) => break Err(e),
            Poll::Ready(Ok(0)) => break Ok(()), // EOF
            Poll::Ready(Ok(n)) => {
                writer.write_all(&buf[..n]).await?;
                continue;
            }
            Poll::Pending => writer.flush().await?,
        }

        // The read future is pending, so we should wait on it.
        match read_future.await {
            Err(e) => break Err(e),
            Ok(0) => break Ok(()),
            Ok(n) => writer.write_all(&buf[..n]).await?,
        }
    };

    // Make sure that we flush any lingering data if we can.
    //
    // If there is a difference between closing and dropping, then we
    // only want to do a "proper" close if the reader closed cleanly.
    let flush_result = if loop_result.is_ok() {
        writer.close().await
    } else {
        writer.flush().await
    };

    loop_result.or(flush_result)
}

/// Type alias for the isolation information associated with a given SOCKS
/// connection _before_ SOCKS is negotiated.
///
/// Currently this is an index for which listener accepted the connection, plus
/// the address of the client that connected to the Socks port.
type ConnIsolation = (usize, IpAddr);

/// A Key used to isolate connections.
///
/// Composed of an usize (representing which listener socket accepted
/// the connection, the source IpAddr of the client, and the
/// authentication string provided by the client).
#[derive(Debug, Clone, PartialEq, Eq)]
struct SocksIsolationKey(ConnIsolation, SocksAuth);

impl arti_client::isolation::IsolationHelper for SocksIsolationKey {
    fn compatible_same_type(&self, other: &Self) -> bool {
        self == other
    }

    fn join_same_type(&self, other: &Self) -> Option<Self> {
        if self == other {
            Some(self.clone())
        } else {
            None
        }
    }
}

/// Payload to return when an HTTP connection arrive on a Socks port
const WRONG_PROTOCOL_PAYLOAD: &[u8] = br#"HTTP/1.0 501 Tor is not an HTTP Proxy
Content-Type: text/html; charset=utf-8

<!DOCTYPE html>
<html>
<head>
<title>This is a SOCKS Proxy, Not An HTTP Proxy</title>
</head>
<body>
<h1>This is a SOCKs proxy, not an HTTP proxy.</h1>
<p>
It appears you have configured your web browser to use this Tor port as
an HTTP proxy.
</p><p>
This is not correct: This port is configured as a SOCKS proxy, not
an HTTP proxy. If you need an HTTP proxy tunnel, wait for Arti to
add support for it in place of, or in addition to, socks_port.
Please configure your client accordingly.
</p>
<p>
See <a href="https://gitlab.torproject.org/tpo/core/arti/#todo-need-to-change-when-arti-get-a-user-documentation">https://gitlab.torproject.org/tpo/core/arti</a> for more information.
</p>
</body>
</html>"#;
