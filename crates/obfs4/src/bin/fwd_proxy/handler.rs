#![allow(dead_code)]
use crate::socks5;
use futures::Future;
use obfs::Result;

use tokio::io::{copy, split, AsyncRead, AsyncWrite};
use tokio_util::sync::CancellationToken;
use tracing::trace;

pub trait Handler {
    fn handle<RW>(
        stream: RW,
        close_c: CancellationToken,
    ) -> impl Future<Output = Result<()>> + Send + Sync
    where
        RW: AsyncRead + AsyncWrite + Unpin + Send + Sync;
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Handlers {
    Socks5,
    Echo,
}

impl Handlers {
    pub async fn handle<'s, RW>(&self, stream: RW, close_c: CancellationToken) -> Result<()>
    where
        RW: AsyncRead + AsyncWrite + Unpin + Send + Sync,
    {
        match self {
            Handlers::Socks5 => Socks5Handler::handle(stream, close_c).await,
            Handlers::Echo => EchoHandler::handle(stream, close_c).await,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Socks5Handler;

impl Handler for Socks5Handler {
    async fn handle<RW>(stream: RW, close_c: CancellationToken) -> Result<()>
    where
        RW: AsyncRead + AsyncWrite + Unpin + Send + Sync,
    {
        tokio::select! {
            r = socks5::handle_socks_conn(stream) => {
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

impl Handler for EchoHandler {
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
    async fn handle<RW>(stream: RW, close_c: CancellationToken) -> Result<()>
    where
        RW: AsyncRead + AsyncWrite + Unpin + Send,
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
