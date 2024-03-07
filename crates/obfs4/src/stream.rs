use futures::task::{noop_waker, Context};
use futures::Future;
use pin_project::pin_project;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::pin;

use std::io::Result as IoResult;

/// Porvides an abstraction over ['AsyncRead'] and ['AsyncWrite'] while being
/// safe to send between threads
pub trait Stream<'a>: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'a {}

impl<'a, RW> Stream<'a> for RW where RW: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'a {}

// /// Future returning a network stream that implements AsyncRead and AsyncWrite
// pub trait StreamFut<'a> = Future<Output = Result<Box<dyn Stream<'a>>>>;

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
pub async fn copy_interactive<'s, R, W>(mut reader: R, mut writer: W) -> IoResult<()>
where
    R: AsyncRead + Unpin + 's,
    W: AsyncWrite + Unpin + 's,
{
    use futures::task::Poll;

    let mut buf = [0_u8; 1024];

    // At this point we could just loop, calling read().await,
    // write_all().await, and flush().await.  But we want to be more
    // clever than that: we only want to flush when the reader is
    // stalled.  That way we can pack our data into as few cells as
    // possible, but flush it immediately whenever there's no more
    // data coming.
    let loop_result: IoResult<()> = loop {
        let read_future = reader.read(&mut buf[..]);
        pin!(read_future);
        match read_future.poll(&mut Context::from_waker(&noop_waker())) {
            Poll::Ready(Err(e)) => break Err(e),
            Poll::Ready(Ok(0)) => break Ok(()), // EOF
            Poll::Ready(Ok(n)) => {
                writer.write_all(&buf[..n]).await?;
                continue;
            }
            Poll::Pending => writer.flush().await?,
        }

        // The read future is pending, so we should wait on it.
        match reader.read(&mut buf[..]).await {
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
        writer.shutdown().await
    } else {
        writer.flush().await
    };

    loop_result.or(flush_result)
}

/*
#[cfg(test)]
mod abstract_test {
    use crate::Result;
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
*/
