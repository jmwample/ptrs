#![doc = include_str!("../../../doc/crate.md")]

// #![feature(trait_alias)]

// #![allow(dead_code)]
// #![allow(warnings)]

pub mod obfs4;

pub mod common;
pub mod stream;
pub mod traits;
pub mod tunnel_mgr;

mod error;
pub use error::{Error, Result};

#[cfg(test)]
pub(crate) mod test_utils;

#[derive(Debug)]
pub struct Transport {}

impl Transport {
    pub fn new() -> Self {
        Self {}
    }
}

impl<T> ptrs::PluggableTransport<T> for Transport {
    type ClientBuilder = obfs4::ClientBuilder;
    type ServerBuilder = obfs4::ServerBuilder;

    fn name() -> String {
        "obfs4".into()
    }
}
