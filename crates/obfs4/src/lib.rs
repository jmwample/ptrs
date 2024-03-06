#![doc = include_str!("../../../doc/crate.md")]
#![feature(trait_alias)]
#![feature(slice_flatten)]
// #![feature(stdarch_x86_avx512)]

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
