use crate::Result;

use hmac::{digest::Reset, Hmac, Mac};
use sha2::{Sha256, Sha256VarCore};

mod skip;
pub use skip::AsyncDiscard;
// pub use skip::{AsyncDiscard, AsyncSkipReader, Discard, SkipReader};

pub mod elligator2;

pub mod drbg;
pub mod ntor;
pub mod probdist;
pub mod replay_filter;

pub trait ArgParse {
    type Output;

    fn parse_args() -> Result<Self::Output>;
}

pub(crate) type HmacSha256 = Hmac<Sha256>;
