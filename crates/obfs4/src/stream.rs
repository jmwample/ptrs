use futures::Future;
use pin_project::pin_project;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::Result;

/// Porvides an abstraction over ['AsyncRead'] and ['AsyncWrite'] while being
/// safe to send between threads
pub trait Stream<'a>: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'a {}

impl<'a, RW> Stream<'a> for RW where RW: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'a {}

///
pub trait StreamFut<'a> = Future<Output = Result<Box<dyn Stream<'a>>>>;

/// Abstraction over I/O interfaces requiring only that the object implements
/// [AsyncRead] and is safe to send between threads.
///
/// Generally used in context with a `split*` or [`combine`] operation.
pub trait ReadHalf: AsyncRead + Unpin + Send + Sync {}
impl<T> ReadHalf for T where T: AsyncRead + Unpin + Send + Sync {}

/// Abstraction over I/O interfaces requiring only that the object implements
/// [AsyncWrite] and is safe to send between threads.
///
/// Generally used in context with a `split*` or [`combine`] operation.
pub trait WriteHalf: AsyncWrite + Unpin + Send + Sync {}
impl<T> WriteHalf for T where T: AsyncWrite + Unpin + Send + Sync {}

#[pin_project]
struct Combined<R, W> {
    #[pin]
    r: R,
    #[pin]
    w: W,
}

/// Combine one read half and one write half into a single duplex [`Stream`].
pub fn combine<'a, R, W>(r: R, w: W) -> impl Stream<'a>
where
    R: AsyncRead + Unpin + Send + Sync + 'a,
    W: AsyncWrite + Unpin + Send + Sync + 'a,
{
    Combined { r, w }
}

impl<R: AsyncRead, W> AsyncRead for Combined<R, W> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.project();
        this.r.poll_read(cx, buf)
    }
}

impl<R, W: AsyncWrite> AsyncWrite for Combined<R, W> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.as_mut().project();
        this.w.poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.as_mut().project();
        this.w.poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.as_mut().project();
        this.w.poll_shutdown(cx)
    }
}

#[cfg(test)]
mod abstract_test {
    use super::*;
    use futures::executor::block_on;

    #[test]
    fn generic_handling() -> Result<()> {
        let d = block_on(connect())?;

        let _dd = block_on(wrap(d))?;

        Ok(())
    }

    trait D {}
    trait E<'a> = Future<Output = Result<Box<dyn D + 'a>>>;

    #[derive(Default)]
    struct F {}
    impl D for F {}

    impl F {
        fn into_d(self) -> Box<dyn D> {
            Box::new(self)
        }
    }

    fn wrap<'a>(d: Box<dyn D>) -> impl E<'a> {
        async move { Ok(d) }
    }

    fn connect<'a>() -> impl E<'a> {
        async move {
            let f = F::default();
            Ok(f.into_d())
        }
    }
}
