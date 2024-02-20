//! # obfs4 - The obfourscator

use crate::{traits::*, Result};

pub mod client;
pub mod server;

pub mod framing;
pub mod proto;
pub use client::{Client, ClientBuilder};
pub use server::{Server, ServerBuilder};

pub(crate) mod constants;
pub(crate) mod handshake;
pub(crate) mod metrics;
pub(crate) mod sessions;

const NAME: &str = "obfs4";

#[allow(non_camel_case_types)]
pub enum Builder {
    client(ClientBuilder),
    server(ServerBuilder),
}

impl Builder {
    pub fn from_statefile(location: &str, is_client: bool) -> Result<Self> {
        if is_client {
            Ok(Builder::client(
                 ClientBuilder::from_statefile(location)?,
            ))
        } else {
            Ok(Builder::server(
                 ServerBuilder::from_statefile(location)?,
            ))
        }
    }

    pub fn from_params(param_strs: Vec<impl AsRef<[u8]>>, is_client: bool) -> Result<Self> {
        if is_client {
            Ok(Builder::client(
                ClientBuilder::from_params(param_strs)?,
            ))
        } else {
            Ok(Builder::server(
                ServerBuilder::from_params(param_strs)?,
            ))
        }
    }
}

impl Named for Builder {
    fn name(&self) -> String {
        NAME.to_string()
    }
}

#[cfg(test)]
mod testing;
