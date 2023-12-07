use crate::{Error, Result};

mod c_impl;
mod dalek;

use std::fmt;
use std::str::FromStr;

use hex::FromHex;
use x25519_dalek::PublicKey;

pub use c_impl::{decode, encode};

/// The length of an Elligator representative.
pub const REPRESENTATIVE_LENGTH: usize = 32;

/// The length of an Elligator point public key.
const PUBLIC_KEY_LENGTH: usize = 32;

/// Elligator Representative of a public key value
#[derive(Debug, Clone, PartialEq)]
pub struct Representative {
    bytes: [u8; 32],
}

impl Representative {
    // Computes a curve25519 public key from a private key and also
    // a uniform representative for that public key. Note that this function will
    // fail and return None for about half of private keys.
    //
    // See http://elligator.cr.yp.to/elligator-20130828.pdf.
    pub fn new(pubkey: PublicKey) -> Option<Self> {
        Some(Self {
            bytes: c_impl::encode(pubkey.to_bytes())?,
        })
    }

    pub fn zero() -> Self {
        Self {
            bytes: [0_u8; REPRESENTATIVE_LENGTH],
        }
    }

    pub fn try_from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
        Self::try_from(bytes.as_ref())
    }

    /// Converts a uniform representative value for a curve25519 public key, as
    /// produced by [`to_public`] / [`Keypair::new`], to a curve25519 public key.
    #[allow(non_snake_case)]
    pub fn to_public(&self) -> Result<PublicKey> {
        Ok(PublicKey::from(c_impl::decode(self.bytes)?))
    }

    pub fn to_bytes(&self) -> [u8; REPRESENTATIVE_LENGTH] {
        self.bytes.clone()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl TryFrom<&Representative> for PublicKey {
    type Error = Error;
    fn try_from(representative: &Representative) -> Result<PublicKey> {
        representative.to_public()
    }
}

impl FromHex for Representative {
    type Error = Error;

    fn from_hex<T: AsRef<[u8]>>(msg: T) -> Result<Self> {
        let buffer = <[u8; REPRESENTATIVE_LENGTH]>::from_hex(msg)?;
        Ok(Representative { bytes: buffer })
    }
}

impl TryFrom<String> for Representative {
    type Error = Error;

    fn try_from(msg: String) -> Result<Self> {
        let buffer = <[u8; REPRESENTATIVE_LENGTH]>::from_hex(msg)?;
        Ok(Representative { bytes: buffer })
    }
}

impl TryFrom<&String> for Representative {
    type Error = Error;

    fn try_from(msg: &String) -> Result<Self> {
        let buffer = <[u8; REPRESENTATIVE_LENGTH]>::from_hex(msg)?;
        Ok(Representative { bytes: buffer })
    }
}

impl TryFrom<&str> for Representative {
    type Error = Error;

    fn try_from(msg: &str) -> Result<Self> {
        let buffer = <[u8; REPRESENTATIVE_LENGTH]>::from_hex(msg)?;
        Ok(Representative { bytes: buffer })
    }
}

impl FromStr for Representative {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Representative::from_hex(s)
    }
}

impl TryFrom<&[u8]> for Representative {
    type Error = Error;

    fn try_from(arr: &[u8]) -> Result<Self> {
        if arr.len() != REPRESENTATIVE_LENGTH {
            let e = format!(
                "incorrect drbg seed length {}!={REPRESENTATIVE_LENGTH}",
                arr.len()
            );
            return Err(Error::Other(e.into()));
        }

        Ok(Representative {
            bytes: (&arr[..])
                .try_into()
                .map_err(|e| Error::Other(format!("{e}").into()))?,
        })
    }
}

impl TryFrom<[u8; REPRESENTATIVE_LENGTH]> for Representative {
    type Error = Error;

    fn try_from(arr: [u8; REPRESENTATIVE_LENGTH]) -> Result<Self> {
        Ok(Representative { bytes: arr })
    }
}

impl TryFrom<Vec<u8>> for Representative {
    type Error = Error;

    fn try_from(arr: Vec<u8>) -> Result<Self> {
        Representative::try_from(arr.as_slice())
    }
}

impl fmt::Display for Representative {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.bytes[..]))
    }
}
