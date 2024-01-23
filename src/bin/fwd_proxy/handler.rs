#![allow(dead_code)]
use crate::socks5;
use obfs::{Error, Result};
use tor_rtcompat::PreferredRuntime;

use async_compat::CompatExt;
use std::str::FromStr;

use tokio::{
    self,
    io::{copy, split, AsyncRead, AsyncWrite},
};
use tokio_util::sync::CancellationToken;
use tracing::trace;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Handler {
    Socks5,
    Echo(EchoHandler),
}

impl Handler {
    pub async fn handle<'s, RW>(self, stream: RW, close_c: CancellationToken) -> Result<()>
    where
        RW: AsyncRead + AsyncWrite + Unpin + Send + Sync + 's,
    {
        match self {
            Handler::Socks5 => Socks5Handler::handle(stream.compat(), close_c).await,
            Handler::Echo(h) => h.handle(stream, close_c).await,
        }
    }
}

impl FromStr for Handler {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "socks5" => Ok(Handler::Socks5),
            "echo" => Ok(Handler::Echo(EchoHandler)),
            _ => Err(Error::Other("unknown handler".into())),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Socks5Handler;

impl Socks5Handler {
    pub async fn handle<'s, RW>(stream: RW, close_c: CancellationToken) -> Result<()>
    where
        RW: futures::AsyncRead + futures::AsyncWrite + Unpin + Send + Sync + 's,
    {
        let rt = PreferredRuntime::current()?;
        tokio::select! {
            r = socks5::handle_socks_conn(rt, stream) => {
                if let Err(e) = r {
                    tracing::error!("socks connection errored: {}", e);
                }
                trace!("socks connection completed")
            }
            _ = close_c.cancelled() => {}
        }
        Ok(())
    }
}

/// `EchoHandler` is a simple handler that echoes any data it receives back to the sender.
///
/// It implements an asynchronous `handle` method that takes a stream and a cancellation token. The
/// `handle` method reads data from the stream and echoes it back to the stream. It continues to do
/// this until either an error occurs, an eof is received, or the cancellation token is cancelled.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct EchoHandler;

impl EchoHandler {
    /// Handle a stream by echoing any data received back to the sender.
    ///
    /// This method takes a stream and a cancellation token. It reads data from the stream
    /// and writes it back to the stream. It continues to do this until either an error occurs
    /// or the cancellation token is cancelled.
    ///
    /// # Arguments
    ///
    /// * `stream` - The stream to handle.
    /// * `close_c` - The cancellation token.
    async fn handle<'a, RW>(&self, stream: RW, close_c: CancellationToken) -> Result<()>
    where
        RW: AsyncRead + AsyncWrite + Unpin + Send + 'a,
    {
        let (mut reader, mut writer) = split(stream);
        tokio::select! {
            r = copy(&mut reader, &mut writer) => {
                if let Err(e) = r {
                    tracing::error!("echo errored: {}", e);
                }
                trace!("echo finished")
            }
            _ = close_c.cancelled() => {}
        }
        Ok(())
    }
}
