use anyhow::{Context, Result};
use clap::Parser;
use futures::Future;
use safelog::sensitive;
use tokio::io::{copy_bidirectional, AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tracing::{info, warn};

use std::net::SocketAddr;
use std::ops::Deref;
use std::sync::Arc;

pub(crate) trait Backend {
    /// The provided In must be usable as a connection in an async context.
    fn handle<In>(
        &self,
        conn: In,
        client_addr: SocketAddr,
    ) -> impl Future<Output = Result<()>> + Send + Sync
    where
        In: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static;
}

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, clap::Subcommand)]
pub(crate) enum Backends {
    /// For each (successful) connection echo client traffic back over the tunnel.
    #[default]
    Echo,

    /// Run a socks5 server to handle all (successful) incoming connections.
    Socks {
        /// Optional authentication (username:password) for the socks endpoint
        auth: Option<String>
    },

    /// For each (successful) connection transparently proxy traffic to the provided host.
    Fwd {
        /// Destination address for forwarded traffic.
        dst: String,
    },
}

impl Backends {
    pub(crate) fn arc(self) -> BackendArc {
        BackendArc(Arc::new(self))
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct BackendArc(Arc<Backends>);

impl Deref for BackendArc {
    type Target = Backends;
    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl Backend for BackendArc {
    async fn handle<In>(&self, conn: In, client_addr: SocketAddr) -> Result<()>
    where
        In: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
    {
        match self.0.as_ref() {
            Backends::Echo => server_echo_connection(conn, client_addr).await?,
            Backends::Fwd { dst } => server_fwd_connection(conn, dst.parse()?, client_addr).await?,
            Backends::Socks { auth } => todo!("not yet implemented"),
        }

        Ok(())
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

async fn server_echo_connection<In>(
    mut conn: In,
    client_addr: SocketAddr,
) -> Result<()>
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

async fn server_socks_handle<In>(mut conn: In, client_addr: SocketAddr) -> Result<()>
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
