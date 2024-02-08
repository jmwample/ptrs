use crate::Result;

use pin_project::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

#[pin_project]
pub struct AsyncSkipReader<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    #[pin]
    inner: S,
    skip: usize,
}

impl<S> AsyncSkipReader<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn skip_n(reader: S, n: usize) -> Self {
        Self {
            inner: reader,
            skip: 0,
        }
    }

    pub async fn discard_and_close_after_delay(_reader: S, _d: Duration) -> Result<()> {
        Ok(())
    }
}

pub type AsyncDiscard<S> = AsyncSkipReader<S>;

impl<S> AsyncRead for AsyncDiscard<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.project();
        this.inner.poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for AsyncDiscard<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::result::Result<usize, std::io::Error>> {
        let this = self.project();
        this.inner.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::result::Result<(), std::io::Error>> {
        let this = self.project();
        this.inner.poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), std::io::Error>> {
        let this = self.project();
        this.inner.poll_shutdown(cx)
    }
}
