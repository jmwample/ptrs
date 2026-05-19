//! TLS + HTTP Upgrade handshake for webtunnel.
//!
//! Confirmed from the Go reference implementation (pkg.go.dev and GitHub
//! mirror at blackyblack/webtunnel):
//!
//! - **ALPN**: Go client does NOT set ALPN (`NextProtos` is nil).
//!   We leave ALPN empty for maximum camouflage.
//!
//! - **Sec-WebSocket-Accept**: server does NOT return it — only sends
//!   `Connection: upgrade` + `Upgrade: websocket`. Parser is lenient.
//!
//! - **Sec-WebSocket-Key**: server does NOT validate it. We generate a
//!   proper one (16 random bytes, base64-encoded) for camouflage.

use std::sync::Arc;

use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::{Error, WebTunnelConfig, WebTunnelStream, PrefixStream};

/// Generate a Sec-WebSocket-Key (16 random bytes, base64-encoded).
pub(crate) fn generate_websocket_key() -> String {
    let mut buf = [0u8; 16];
    // getrandom only fails when the system RNG is unavailable — fatal
    // for a transport that depends on randomness.
    getrandom::getrandom(&mut buf)
        .expect("system RNG unavailable — cannot generate Sec-WebSocket-Key");
    base64::engine::general_purpose::STANDARD.encode(buf)
}

/// Build the HTTP/1.1 Upgrade request bytes.
pub(crate) fn build_upgrade_request(config: &WebTunnelConfig) -> String {
    let parsed = url::Url::parse(&config.url).expect("url already validated");
    let path = if parsed.path().is_empty() {
        "/"
    } else {
        parsed.path()
    };

    let host = config.tls_sni().expect("tls_sni already validated");
    let key = generate_websocket_key();

    format!(
        "GET {path} HTTP/1.1\r\n\
Host: {host}\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Key: {key}\r\n\
Sec-WebSocket-Version: 13\r\n\
\r\n"
    )
}

/// Parse a complete HTTP response from a byte slice.
///
/// Returns `Ok((status_code, leftover_bytes))` on 101, or an error for
/// any other status / parse failure. Lenient: only checks the status code.
#[cfg(test)]
pub(crate) fn parse_response(buf: &[u8]) -> Result<(u16, &[u8]), Error> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut resp = httparse::Response::new(&mut headers);

    let body_offset = match resp.parse(buf) {
        Ok(httparse::Status::Complete(n)) => n,
        Ok(httparse::Status::Partial) => {
            return Err(Error::HttpParse("incomplete HTTP response".into()))
        }
        Err(e) => return Err(Error::HttpParse(e.to_string())),
    };

    let code = resp
        .code
        .ok_or_else(|| Error::HttpParse("no status code".into()))?;

    if code != 101 {
        let reason = resp.reason.unwrap_or("(no reason)");
        return Err(Error::Non101(format!("{code} {reason}")));
    }

    Ok((code, &buf[body_offset..]))
}

/// Perform the full webtunnel handshake: TCP → (optional TLS) → HTTP Upgrade.
pub(crate) async fn connect(config: &WebTunnelConfig) -> Result<PrefixStream<WebTunnelStream>, Error> {
    let target = config.connect_host_port()?;
    let tcp = TcpStream::connect(&target).await?;

    if config.use_tls() {
        let tls_stream = tls_connect(config, tcp).await?;
        upgrade_and_return(tls_stream, config).await
    } else {
        upgrade_and_return(tcp, config).await
    }
}

async fn tls_connect(
    config: &WebTunnelConfig,
    tcp: TcpStream,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, Error> {
    let sni = config.tls_sni()?;
    let server_name = rustls::pki_types::ServerName::try_from(sni)
        .map_err(|e| Error::Tls(format!("invalid SNI: {e}")))?;

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // No ALPN set — matches the Go client which leaves NextProtos empty.
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let tls = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| Error::Tls(e.to_string()))?;

    Ok(tls)
}

/// Send the HTTP Upgrade request, read the 101 response, return the stream
/// in raw-byte mode. `S` is either `TlsStream<TcpStream>` or `TcpStream`.
async fn upgrade_and_return<S>(mut stream: S, config: &WebTunnelConfig) -> Result<PrefixStream<WebTunnelStream>, Error>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin + StreamWrapper + 'static,
{
    let request = build_upgrade_request(config);
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| Error::Handshake(format!("write upgrade request: {e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| Error::Handshake(format!("flush: {e}")))?;

    // Read the 101 response. The response is small (a few headers), so
    // a 4096-byte buffer is generous. We loop until httparse reports
    // Status::Complete.
    let mut buf = vec![0u8; 4096];
    let mut total = 0usize;
    loop {
        if total >= buf.len() {
            return Err(Error::Handshake("response headers too large".into()));
        }
        let n = stream
            .read(&mut buf[total..])
            .await
            .map_err(|e| Error::Handshake(format!("read response: {e}")))?;
        if n == 0 {
            return Err(Error::Handshake("connection closed before 101".into()));
        }
        total += n;

        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut resp = httparse::Response::new(&mut headers);

        match resp.parse(&buf[..total]) {
            Ok(httparse::Status::Complete(body_offset)) => {
                let code = resp
                    .code
                    .ok_or_else(|| Error::HttpParse("no status code".into()))?;
                if code != 101 {
                    let reason = resp.reason.unwrap_or("(no reason)");
                    return Err(Error::Non101(format!("{code} {reason}")));
                }

                let leftover: Vec<u8> = buf[body_offset..total].to_vec();
                if !leftover.is_empty() {
                    crate::warn!(
                        "webtunnel: {} trailing bytes after 101 — preserving in stream prefix",
                        leftover.len()
                    );
                }

                let inner = StreamWrapper::wrap(stream)?;
                return Ok(PrefixStream::new(inner, leftover));
            }
            Ok(httparse::Status::Partial) => continue,
            Err(e) => return Err(Error::HttpParse(e.to_string())),
        }
    }
}

/// Trait to convert the inner stream into a `WebTunnelStream`.
/// Implemented separately for `TlsStream<TcpStream>` and `TcpStream`.
trait StreamWrapper: Sized {
    fn wrap(self) -> Result<WebTunnelStream, Error>;
}

impl StreamWrapper for tokio_rustls::client::TlsStream<TcpStream> {
    fn wrap(self) -> Result<WebTunnelStream, Error> {
        Ok(WebTunnelStream::Tls(Box::new(self)))
    }
}

impl StreamWrapper for TcpStream {
    fn wrap(self) -> Result<WebTunnelStream, Error> {
        Ok(WebTunnelStream::Plain(self))
    }
}
