//! Structured Proxy tunnel management and tracking.
//!

use std::fmt::{Error, Formatter};

mod metrics;
pub use metrics::Metrics;

/// All methods should be implemented using locks or as otherwise atomic operations
/// otherwise printed metrics may miss-count the number of events happening around
/// epoch transitions.
pub trait Metric {
    // Required methods

    /// Print formatted metric data.
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), Error>;

    /// Reset any reset-able counters usually used at the end of an epoch.
    fn reset(&self);

    /// Atomic operation that does both a formatted write of the stored metrics
    /// and resets any reset-able counters.
    fn print_and_reset(&self, f: &mut Formatter<'_>) -> std::result::Result<(), Error>;
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

// pub trait ManageTunnels {
//     type TransportBuilder;
//     type StreamHandler;
//
//     // fn run() -> impl Future::<Output=<Result<()>>>;
// }
//
// /// All tasks must return the same type `R`.
// pub struct TunnelManager<R, M: Metric> {
//     pub sessions: Arc<Mutex<JoinSet<R>>>,
//     pub metrics: Option<M>,
//     pub server: Box<dyn Wrap>,
// }
//
//
// impl<M:Metric, S:Wrap> TunnelManager<Result<()>, M> {
//     fn new(t: impl Builder) -> Result<Self> {
//         Ok(Self{
//             sessions: Arc::new(Mutex::new(JoinSet::new())),
//             metrics: None,
//             server: Box::new(t.build(&Role::Receiver)?),
//         })
//     }
//
//     async fn run() -> Result<()> {
//
//         Ok(())
//     }
// }

// #[cfg(test)]
// mod test {
//
//     #[test]
//     fn test_tunnel_manager() {
//         panic!("not implemented")
//     }
// }
