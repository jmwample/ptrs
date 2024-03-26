//! Errors that can occur during Pluggable Transport establishment.

use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum Error {
    // #[error("No proxy requested in TOR_PT_PROXY")]
    // NoProxyRequested,
    #[error("PROXY-ERROR {0}")]
    ProxyError(String),
    #[error("error parsing client params: {0}")]
    ParseError(String),
    #[error("unknown data store error")]
    Unknown,
}
