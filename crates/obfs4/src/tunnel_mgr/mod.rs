//! Structured Proxy tunnel management and tracking.
//!

use tokio::task::JoinSet;

use std::fmt::{Error, Formatter};
use std::sync::{Arc, Mutex};

mod metrics;
pub use metrics::Metrics;

use crate::common::ntor_arti::ServerHandshake;

/// All methods should be implemented using locks or as otherwise atomic operations
/// otherwise printed metrics may miss-count the number of events happening around
/// epoch transitions.
pub trait Metric {
    // Required methods

    /// Print formatted metric data.
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error>;

    /// Reset any reset-able counters usually used at the end of an epoch.
    fn reset(&self);

    /// Atomic operation that does both a formatted write of the stored metrics
    /// and resets any reset-able counters.
    fn print_and_reset(&self, f: &mut Formatter<'_>) -> Result<(), Error>;
}

/// All tasks must return the same type `T`.
pub struct TunnelManager<R, M: Metric, S: ServerHandshake> {
    pub sessions: Arc<Mutex<JoinSet<R>>>,
    pub metrics: M,
    pub server: S,
}
