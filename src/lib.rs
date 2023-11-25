#![doc = include_str!("../doc/crate.md")]
#![feature(trait_alias)]
#![allow(dead_code)]

pub mod ident;
// pub mod o5;
// pub mod o7;
pub mod obfs4;

pub(crate) mod common;
pub mod stream;
pub mod traits;

mod error;
pub use error::{Error, Result};


#[cfg(test)]
pub(crate) mod test_utils;
