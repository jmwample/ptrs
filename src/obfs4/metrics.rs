

use std::sync::{Arc, Mutex};

pub struct ServerMetrics;

pub type Metrics = Arc<Mutex<ServerMetrics>>;
