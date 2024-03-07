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
