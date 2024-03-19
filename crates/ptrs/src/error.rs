//! Errors that can occur during Pluggable Transport establishment.

use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    // #[error("No proxy requested in TOR_PT_PROXY")]
    // NoProxyRequested,
    #[error("PROXY-ERROR {0}")]
    ProxyError(String),
    #[error("data store disconnected")]
    Disconnect(#[from] io::Error),
    #[error("the data for key `{0}` is not available")]
    Redaction(String),
    #[error("invalid header (expected {expected:?}, found {found:?})")]
    InvalidHeader { expected: String, found: String },
    #[error("error parsing client params: {0}")]
    ParseError(String),
    #[error("unknown data store error")]
    Unknown,
}
