use anyhow::Result;
use futures::Future;
use ptrs::{info, warn};
use safelog::sensitive;
use tokio::io::{copy_bidirectional, AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use std::net::SocketAddr;
use std::ops::Deref;
use std::pin::Pin;
use std::sync::Arc;

pub(crate) trait Backend {
    /// The provided In must be usable as a connection in an async context.
    fn handle<In>(
        &self,
        conn: In,
        client_addr: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + Sync + '_>>
    // ) -> impl Future<Output = Result<()>> + Send + Sync
    where
        In: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static;
}

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, clap::Subcommand)]
pub(crate) enum Backends {
    #[default]
    #[command(
        about = "For each (successful) connection echo client traffic back over the tunnel.\n\t$ fwd [OPTIONS] [LADDR] server echo\n"
    )]
    Echo,

    #[command(
        about = "For each (successful) connection transparently proxy traffic to the provided host.\n\t$ fwd [OPTIONS] [LADDR] server fwd \"127.0.0.1:8080\"\n"
    )]
    Fwd {
        /// Destination address for forwarded traffic.
        dst: String,
    },

    #[command(
        about = "Run a socks5 server to handle all (successful) incoming connections.\n\t$ fwd [OPTIONS] [LADDR] server socks --auth \"user:example\"\n"
    )]
    Socks {
        /// Optional authentication (username:password) for the socks endpoint
        auth: Option<String>,
    },
}

impl Backends {
    pub(crate) fn arc(self) -> BackendArc {
        BackendArc(Arc::new(self))
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct BackendArc(Arc<Backends>);

impl BackendArc {
    async fn handle_internal<In>(&self, conn: In, client_addr: SocketAddr) -> Result<()>
    where
        In: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
    {
        match self.0.as_ref() {
            Backends::Echo => server_echo_connection(conn, client_addr).await?,
            Backends::Fwd { dst } => server_fwd_connection(conn, dst.parse()?, client_addr).await?,
            Backends::Socks { auth: _ } => todo!("not yet implemented"),
        }

        Ok(())
    }
}

impl Deref for BackendArc {
    type Target = Backends;
    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl Backend for BackendArc {
    fn handle<In>(
        &self,
        conn: In,
        client_addr: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + Sync + '_>>
    where
        In: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
    {
        Box::pin(self.handle_internal(conn, client_addr))
    }
}

async fn server_fwd_connection<In>(
    mut conn: In,
    remote_addr: SocketAddr,
    client_addr: SocketAddr,
) -> Result<()>
where
    // the provided In must be usable as a connection in an async context
    In: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
    // The provided S must be usable as a Pluggable Transport Server.
{
    let mut remote_conn = TcpStream::connect(remote_addr).await?;

    match copy_bidirectional(&mut conn, &mut remote_conn).await {
        Err(e) => {
            warn!(
                address = sensitive(client_addr).to_string(),
                "tunnel closed with error: {e}"
            );
        }
        Ok((up, down)) => {
            info!(
                address = sensitive(client_addr).to_string(),
                "tunnel closed {up} {down}"
            );
        }
    }

    Ok(())
}

async fn server_echo_connection<In>(conn: In, client_addr: SocketAddr) -> Result<()>
where
    // the provided In must be usable as a connection in an async context
    In: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    let (mut r, mut w) = tokio::io::split(conn);
    match tokio::io::copy(&mut r, &mut w).await {
        Err(e) => {
            warn!(
                address = sensitive(client_addr).to_string(),
                "tunnel closed with error: {e}"
            );
        }
        Ok(b) => {
            info!(
                address = sensitive(client_addr).to_string(),
                "tunnel closed {b} {b}"
            );
        }
    }

    Ok(())
}

async fn server_socks_handle<In>(conn: In, client_addr: SocketAddr) -> Result<()>
where
    // the provided In must be usable as a connection in an async context
    In: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    let (mut r, mut w) = tokio::io::split(conn);
    match tokio::io::copy(&mut r, &mut w).await {
        Err(e) => {
            warn!(
                address = sensitive(client_addr).to_string(),
                "tunnel closed with error: {e}"
            );
        }
        Ok(b) => {
            info!(
                address = sensitive(client_addr).to_string(),
                "tunnel closed {b} {b}"
            );
        }
    }

    Ok(())
}
