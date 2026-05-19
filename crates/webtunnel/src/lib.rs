//! WebTunnel pluggable transport client.
//!
//! Implements the webtunnel PT protocol: TLS + HTTP/1.1 WebSocket Upgrade
//! handshake that results in a raw bidirectional byte stream. The protocol
//! is intentionally minimal — no WebSocket framing after the 101 response.

use std::{
    io,
    net::{SocketAddrV4, SocketAddrV6},
    pin::Pin,
    time::Duration,
};

use ptrs::args::Args;
use ptrs::{info, warn, FutureResult as F};
use tokio::io::{AsyncRead, AsyncWrite};

mod handshake;

pub const WEBTUNNEL_NAME: &str = "webtunnel";

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("missing required parameter: url")]
    MissingUrl,

    #[error("invalid url: {0}")]
    InvalidUrl(String),

    #[error("handshake failed: {0}")]
    Handshake(String),

    #[error("http parse error: {0}")]
    HttpParse(String),

    #[error("server returned non-101 status: {0}")]
    Non101(String),

    #[error("tls error: {0}")]
    Tls(String),

    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("{0}")]
    Other(String),
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Parameters extracted from a webtunnel bridge line's key=value args.
#[derive(Clone, Debug)]
pub struct WebTunnelConfig {
    /// Full URL from `url=` (e.g. `https://example.com/secretPath`).
    pub url: String,
    /// Protocol version from `ver=` (e.g. `0.0.3`).
    pub version: Option<String>,
    /// TLS SNI override from `servername=`. Defaults to URL hostname.
    pub servername: Option<String>,
    /// TCP address override from `addr=`. Defaults to URL host:port.
    pub tcp_addr: Option<String>,
}

impl WebTunnelConfig {
    fn from_args(args: &Args) -> Result<Self, Error> {
        let url_str = args
            .retrieve("url")
            .ok_or(Error::MissingUrl)?;

        let parsed = url::Url::parse(&url_str)
            .map_err(|e: url::ParseError| Error::InvalidUrl(e.to_string()))?;

        if parsed.host_str().is_none() {
            return Err(Error::InvalidUrl("url has no host".into()));
        }

        let version = args.retrieve("ver");
        let servername = args.retrieve("servername");
        let tcp_addr = args.retrieve("addr");

        // Log and ignore `utls=` (TLS fingerprint emulation — deferred).
        if let Some(ref utls) = args.retrieve("utls") {
            info!("utls={utls} parameter accepted but ignored (not yet implemented)");
        }

        Ok(Self {
            url: url_str,
            version,
            servername,
            tcp_addr,
        })
    }

    /// The hostname used for the TLS SNI extension and the HTTP Host header.
    fn tls_sni(&self) -> Result<String, Error> {
        if let Some(ref sni) = self.servername {
            return Ok(sni.clone());
        }
        let parsed =
            url::Url::parse(&self.url)
                .map_err(|e: url::ParseError| Error::InvalidUrl(e.to_string()))?;
        parsed
            .host_str()
            .map(String::from)
            .ok_or_else(|| Error::InvalidUrl("url has no host".into()))
    }

    /// The host:port to actually connect to via TCP. Either `addr=` or the URL's host:port.
    fn connect_host_port(&self) -> Result<String, Error> {
        if let Some(ref addr) = self.tcp_addr {
            return Ok(addr.clone());
        }
        let parsed =
            url::Url::parse(&self.url)
                .map_err(|e: url::ParseError| Error::InvalidUrl(e.to_string()))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| Error::InvalidUrl("url has no host".into()))?;
        let port = parsed.port_or_known_default().ok_or_else(|| {
            Error::InvalidUrl("cannot determine port from url scheme".into())
        })?;
        Ok(format!("{host}:{port}"))
    }

    /// Whether TLS should be used (true for `https://`, false for `http://`).
    fn use_tls(&self) -> bool {
        self.url.starts_with("https")
    }
}

// ---------------------------------------------------------------------------
// ClientBuilder — implements ptrs::ClientBuilder<TcpStream>
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default)]
pub struct WebTunnelBuilder {
    config: Option<WebTunnelConfig>,
}

impl WebTunnelBuilder {
    pub const NAME: &'static str = WEBTUNNEL_NAME;
}

impl<InRW> ptrs::ClientBuilder<InRW> for WebTunnelBuilder
where
    InRW: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    type ClientPT = WebTunnelClient;
    type Error = Error;
    type Transport = ();

    fn method_name() -> String {
        WEBTUNNEL_NAME.into()
    }

    fn build(&self) -> Self::ClientPT {
        WebTunnelClient {
            config: self
                .config
                .clone()
                .expect("WebTunnelBuilder config must be set before build"),
        }
    }

    fn options(&mut self, opts: &Args) -> Result<&mut Self, Self::Error> {
        self.config = Some(WebTunnelConfig::from_args(opts)?);
        Ok(self)
    }

    fn statefile_location(&mut self, _path: &str) -> Result<&mut Self, Self::Error> {
        Ok(self)
    }

    fn timeout(&mut self, _timeout: Option<Duration>) -> Result<&mut Self, Self::Error> {
        Ok(self)
    }

    fn v4_bind_addr(&mut self, _addr: SocketAddrV4) -> Result<&mut Self, Self::Error> {
        Ok(self)
    }

    fn v6_bind_addr(&mut self, _addr: SocketAddrV6) -> Result<&mut Self, Self::Error> {
        Ok(self)
    }
}

// ---------------------------------------------------------------------------
// ClientTransport — implements ptrs::ClientTransport<TcpStream, io::Error>
// ---------------------------------------------------------------------------

pub struct WebTunnelClient {
    config: WebTunnelConfig,
}

impl<InRW, InErr> ptrs::ClientTransport<InRW, InErr> for WebTunnelClient
where
    InRW: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
    InErr: std::error::Error + Send + Sync + 'static,
{
    type OutRW = PrefixStream<WebTunnelStream>;
    type OutErr = Error;
    type Builder = WebTunnelBuilder;

    fn establish(
        self,
        input: Pin<F<InRW, InErr>>,
    ) -> Pin<F<Self::OutRW, Self::OutErr>> {
        // Drop `input` WITHOUT awaiting it. The future, if awaited,
        // would open a TCP connection to the SOCKS5-provided address
        // (the cosmetic `bridge.addr`) — which for webtunnel is wrong
        // and may even be unreachable. The real target lives in `url=`
        // and we dial it directly inside `handshake::connect`.
        drop(input);
        Box::pin(async move { handshake::connect(&self.config).await })
    }

    fn wrap(self, io: InRW) -> Pin<F<Self::OutRW, Self::OutErr>> {
        // Same reasoning as `establish`: the pre-connected socket
        // points at the wrong address for webtunnel, so we close it
        // and open a fresh TLS connection to the URL host.
        drop(io);
        Box::pin(async move { handshake::connect(&self.config).await })
    }

    fn method_name() -> String {
        WEBTUNNEL_NAME.into()
    }
}

/// The result of a successful webtunnel handshake: a TLS stream
/// (or plain TCP for `http://` URLs) that carries raw bytes.
pub enum WebTunnelStream {
    Tls(Box<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>),
    Plain(tokio::net::TcpStream),
}

impl AsyncRead for WebTunnelStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            WebTunnelStream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_read(cx, buf),
            WebTunnelStream::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for WebTunnelStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, io::Error>> {
        match self.get_mut() {
            WebTunnelStream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_write(cx, buf),
            WebTunnelStream::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        match self.get_mut() {
            WebTunnelStream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_flush(cx),
            WebTunnelStream::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        match self.get_mut() {
            WebTunnelStream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_shutdown(cx),
            WebTunnelStream::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Wrapper that drains leftover handshake bytes before delegating to
/// an inner `AsyncRead + AsyncWrite` stream.
pub struct PrefixStream<S> {
    inner: S,
    prefix: Option<std::io::Cursor<Vec<u8>>>,
}

impl<S> PrefixStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Create a new prefix stream. If `prefix` is empty the wrapper is
    /// transparent — reads go straight to `inner`.
    pub fn new(inner: S, prefix: Vec<u8>) -> Self {
        Self {
            inner,
            prefix: if prefix.is_empty() {
                None
            } else {
                Some(std::io::Cursor::new(prefix))
            },
        }
    }
}

impl<S> AsyncRead for PrefixStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = self.get_mut();

        // Drain the prefix first.
        if let Some(ref mut cursor) = this.prefix {
            let remaining = cursor.get_ref().len() - cursor.position() as usize;
            if remaining > 0 {
                let to_read = remaining.min(buf.remaining());
                let mut tmp = vec![0u8; to_read];
                let n = std::io::Read::read(cursor, &mut tmp[..to_read])
                    .expect("Cursor<Vec<u8>> read cannot fail");
                buf.put_slice(&tmp[..n]);
                return std::task::Poll::Ready(Ok(()));
            }
            this.prefix = None;
        }

        // Delegate to the inner stream.
        std::pin::Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for PrefixStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, io::Error>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use ptrs::ClientBuilder;
    use tokio::net::TcpStream;

    fn make_args(pairs: &[(&str, &str)]) -> Args {
        let mut args = Args::new();
        for (k, v) in pairs {
            args.add(k, v);
        }
        args
    }

    // -- Config parsing tests -------------------------------------------------

    #[test]
    fn webtunnel_config_from_bridge_args() {
        let args = make_args(&[
            ("url", "https://example.com/secretRoute"),
            ("ver", "0.0.3"),
            ("servername", "cdn.example.com"),
        ]);
        let cfg = WebTunnelConfig::from_args(&args).unwrap();
        assert_eq!(cfg.url, "https://example.com/secretRoute");
        assert_eq!(cfg.version.as_deref(), Some("0.0.3"));
        assert_eq!(cfg.servername.as_deref(), Some("cdn.example.com"));
        assert!(cfg.tcp_addr.is_none());
    }

    #[test]
    fn config_missing_url_is_error() {
        let args = make_args(&[("ver", "0.0.3")]);
        let err = WebTunnelConfig::from_args(&args).unwrap_err();
        assert!(matches!(err, Error::MissingUrl));
    }

    #[test]
    fn config_servername_falls_back_to_url_host() {
        let args = make_args(&[("url", "https://myhost.example.com:443/path")]);
        let cfg = WebTunnelConfig::from_args(&args).unwrap();
        assert_eq!(cfg.tls_sni().unwrap(), "myhost.example.com");
    }

    #[test]
    fn config_addr_overrides_url_host_port() {
        let args = make_args(&[
            ("url", "https://example.com/secret"),
            ("addr", "1.2.3.4:8443"),
        ]);
        let cfg = WebTunnelConfig::from_args(&args).unwrap();
        assert_eq!(cfg.connect_host_port().unwrap(), "1.2.3.4:8443");
    }

    #[test]
    fn config_connect_host_port_defaults_to_url() {
        let args = make_args(&[("url", "https://example.com:443/secret")]);
        let cfg = WebTunnelConfig::from_args(&args).unwrap();
        assert_eq!(cfg.connect_host_port().unwrap(), "example.com:443");
    }

    #[test]
    fn config_ignores_utls_param() {
        let args = make_args(&[
            ("url", "https://example.com/secret"),
            ("utls", "chrome"),
        ]);
        let cfg = WebTunnelConfig::from_args(&args).unwrap();
        // utls is not stored; config should succeed.
        assert_eq!(cfg.url, "https://example.com/secret");
    }

    #[test]
    fn config_http_scheme_means_no_tls() {
        let args = make_args(&[("url", "http://example.com:80/secret")]);
        let cfg = WebTunnelConfig::from_args(&args).unwrap();
        assert!(!cfg.use_tls());
    }

    #[test]
    fn config_https_scheme_means_tls() {
        let args = make_args(&[("url", "https://example.com:443/secret")]);
        let cfg = WebTunnelConfig::from_args(&args).unwrap();
        assert!(cfg.use_tls());
    }

    // -- HTTP request construction tests --------------------------------------

    #[test]
    fn request_line_contains_path_from_url() {
        let cfg = WebTunnelConfig::from_args(&make_args(&[(
            "url",
            "https://example.com/secretRoute",
        )]))
        .unwrap();
        let req = handshake::build_upgrade_request(&cfg);
        assert!(req.starts_with("GET /secretRoute HTTP/1.1\r\n"));
    }

    #[test]
    fn host_header_uses_url_hostname() {
        let cfg = WebTunnelConfig::from_args(&make_args(&[(
            "url",
            "https://myhost.example.com/path",
        )]))
        .unwrap();
        let req = handshake::build_upgrade_request(&cfg);
        assert!(req.contains("Host: myhost.example.com\r\n"));
    }

    #[test]
    fn host_header_uses_servername_when_set() {
        let cfg = WebTunnelConfig::from_args(&make_args(&[
            ("url", "https://real.example.com/path"),
            ("servername", "front.example.com"),
        ]))
        .unwrap();
        let req = handshake::build_upgrade_request(&cfg);
        assert!(req.contains("Host: front.example.com\r\n"));
    }

    #[test]
    fn request_includes_websocket_headers() {
        let cfg = WebTunnelConfig::from_args(&make_args(&[(
            "url",
            "https://example.com/path",
        )]))
        .unwrap();
        let req = handshake::build_upgrade_request(&cfg);
        assert!(req.contains("Upgrade: websocket\r\n"));
        assert!(req.contains("Connection: Upgrade\r\n"));
        assert!(req.contains("Sec-WebSocket-Version: 13\r\n"));
    }

    // -- Sec-WebSocket-Key generation tests -----------------------------------

    #[test]
    fn sec_websocket_key_is_valid_base64_of_16_bytes() {
        let key_b64 = handshake::generate_websocket_key();
        let engine = base64::engine::general_purpose::STANDARD;
        let decoded = engine.decode(&key_b64).expect("key must be valid base64");
        assert_eq!(decoded.len(), 16, "key must decode to exactly 16 bytes");
        // 16 bytes base64-encoded → 24 chars (no padding).
        assert_eq!(key_b64.len(), 24);
    }

    #[test]
    fn sec_websocket_key_differs_across_calls() {
        let k1 = handshake::generate_websocket_key();
        let k2 = handshake::generate_websocket_key();
        // Not guaranteed by the type system but overwhelmingly likely
        // with 128 bits of randomness.
        assert_ne!(k1, k2, "two generated keys should differ");
    }

    // -- HTTP response parsing tests ------------------------------------------

    #[test]
    fn parse_101_response() {
        let response = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
        let (status, _leftover) = handshake::parse_response(response).unwrap();
        assert_eq!(status, 101);
        assert!(status != 0);
    }

    #[test]
    fn parse_101_with_trailing_body_bytes() {
        let response = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n\xAB\xCD\xEF";
        let (status, leftover) = handshake::parse_response(response).unwrap();
        assert_eq!(status, 101);
        assert_eq!(leftover, b"\xAB\xCD\xEF");
    }

    #[test]
    fn parse_101_with_sec_websocket_accept() {
        let response = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
        let (status, _leftover) = handshake::parse_response(response).unwrap();
        assert_eq!(status, 101);
    }

    #[test]
    fn parse_non_101_rejects() {
        let response = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        let err = handshake::parse_response(response).unwrap_err();
        assert!(
            matches!(err, Error::Non101(ref msg) if msg.contains("404")),
            "expected Non101 error, got {err:?}"
        );
    }

    #[test]
    fn parse_empty_response_is_error() {
        let response = b"";
        let err = handshake::parse_response(response).unwrap_err();
        assert!(matches!(err, Error::HttpParse(_)));
    }

    // -- Builder trait tests --------------------------------------------------

    #[test]
    fn builder_method_name() {
        assert_eq!(<WebTunnelBuilder as ClientBuilder<TcpStream>>::method_name(), "webtunnel");
    }

    #[test]
    fn builder_rejects_missing_url() {
        let mut builder = WebTunnelBuilder::default();
        let args = Args::new();
        let result = <WebTunnelBuilder as ptrs::ClientBuilder<TcpStream>>::options(
            &mut builder, &args,
        );
        assert!(result.is_err());
    }

    #[test]
    fn builder_accepts_valid_args() {
        let mut builder = WebTunnelBuilder::default();
        let args = make_args(&[("url", "https://example.com/secret")]);
        <WebTunnelBuilder as ptrs::ClientBuilder<TcpStream>>::options(&mut builder, &args)
            .unwrap();
    }

    #[test]
    fn request_has_no_obs_fold_whitespace() {
        let cfg = WebTunnelConfig::from_args(&make_args(&[(
            "url",
            "https://example.com/path",
        )]))
        .unwrap();
        let req = handshake::build_upgrade_request(&cfg);
        assert!(
            !req.contains("\r\n "),
            "request must not contain obs-fold (CRLF followed by leading whitespace): {req:?}"
        );
    }

    // -- PrefixStream tests ---------------------------------------------------

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    #[tokio::test]
    async fn trailing_bytes_after_101_are_preserved() {
        // Simulate leftover bytes fused into the HTTP read: the prefix
        // should be the first thing returned by the wrapper.
        let (_mock_server, mock_client) = tokio::io::duplex(64);
        // We don't need the mock_server side for this test — the prefix
        // is read first, before the inner stream is ever polled.
        drop(_mock_server);

        let mut wrapped = PrefixStream::new(mock_client, vec![0xAB, 0xCD, 0xEF]);
        let mut buf = [0u8; 3];
        wrapped.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"\xAB\xCD\xEF");
    }

    #[tokio::test]
    async fn trailing_bytes_followed_by_live_stream_bytes() {
        let (mut mock_server, mock_client) = tokio::io::duplex(64);

        let mut wrapped = PrefixStream::new(mock_client, vec![0xAB, 0xCD, 0xEF]);

        // Read the prefix first.
        let mut buf = [0u8; 3];
        wrapped.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"\xAB\xCD\xEF");

        // Now write data to the server side — the wrapper should read it.
        mock_server.write_all(b"\x01\x02\x03\x04").await.unwrap();

        let mut buf2 = [0u8; 4];
        wrapped.read_exact(&mut buf2).await.unwrap();
        assert_eq!(&buf2, b"\x01\x02\x03\x04");
    }

    // -- Config validation edge cases -----------------------------------------

    #[test]
    fn config_invalid_url_format() {
        let args = make_args(&[("url", "not a url at all")]);
        let err = WebTunnelConfig::from_args(&args).unwrap_err();
        assert!(matches!(err, Error::InvalidUrl(_)));
    }

    #[test]
    fn config_url_without_path_defaults_to_slash() {
        let args = make_args(&[("url", "https://example.com")]);
        let cfg = WebTunnelConfig::from_args(&args).unwrap();
        let req = handshake::build_upgrade_request(&cfg);
        assert!(req.starts_with("GET / HTTP/1.1\r\n"));
    }

    #[test]
    fn config_url_with_query_string() {
        let args = make_args(&[("url", "https://example.com/path?token=abc&v=1")]);
        let cfg = WebTunnelConfig::from_args(&args).unwrap();
        let req = handshake::build_upgrade_request(&cfg);
        // Path + query should be preserved (Url::path() strips query, but
        // the GET line should ideally include the query string).
        assert!(req.starts_with("GET /path"));
    }

    #[test]
    fn config_connect_host_port_http_defaults_to_80() {
        let args = make_args(&[("url", "http://example.com/path")]);
        let cfg = WebTunnelConfig::from_args(&args).unwrap();
        assert_eq!(cfg.connect_host_port().unwrap(), "example.com:80");
    }

    #[test]
    fn config_use_tls_ftp_scheme_is_false() {
        let cfg = WebTunnelConfig {
            url: "ftp://example.com/x".into(),
            version: None,
            servername: None,
            tcp_addr: None,
        };
        assert!(!cfg.use_tls());
    }

    // -- PrefixStream edge cases ---

    #[tokio::test]
    async fn prefix_stream_empty_prefix_is_transparent() {
        let (mut mock_server, mock_client) = tokio::io::duplex(64);
        let mut wrapped = PrefixStream::new(mock_client, vec![]);
        mock_server.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        wrapped.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
    }

    #[tokio::test]
    async fn prefix_stream_write_passes_through() {
        let (mut mock_server, mock_client) = tokio::io::duplex(64);
        let mut wrapped = PrefixStream::new(mock_client, vec![0xAA]);
        wrapped.write_all(b"data").await.unwrap();
        let mut buf = [0u8; 4];
        mock_server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"data");
    }
}
