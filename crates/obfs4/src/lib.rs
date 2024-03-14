#![doc = include_str!("../../../doc/crate.md")]

// #![feature(trait_alias)]

// #![allow(dead_code)]
// #![allow(warnings)]

pub mod obfs4;

pub mod common;
pub mod stream;
pub mod traits;
pub mod tunnel_mgr;

mod pt;
pub use pt::Transport;

mod error;
pub use error::{Error, Result};

#[cfg(test)]
pub(crate) mod test_utils;
