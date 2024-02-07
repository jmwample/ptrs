#![doc = include_str!("../doc/crate.md")]
#![feature(trait_alias)]
#![feature(slice_flatten)]
// #![feature(stdarch_x86_avx512)]

// #![allow(dead_code)]
// #![allow(warnings)]

pub mod ident;
pub mod o5;
// pub mod o7;
pub mod obfs4;

pub mod common;
pub mod stream;
pub mod traits;

mod error;
pub use error::{Error, Result};

#[cfg(test)]
pub(crate) mod test_utils;
