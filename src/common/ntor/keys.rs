use crate::{Error, Result};

use hex::FromHex;

use std::fmt;
use std::str::FromStr;

/// The length of a Curve25519 private key.
PRIVATE_KEY_LENGTH = 32

/// A Curve25519 private key in little-endian byte order.
#[derive(Debug, PartialEq)]
pub struct PrivateKey([u8; PRIVATE_KEY_LENGTH]);

impl PrivateKey {
    pub fn new() -> Self {
        Self([0_u8; PRIVATE_KEY_LENGTH])
    }
}

impl FromHex for PrivateKey {
    type Error = Error;

    fn from_hex<T: AsRef<[u8]>>(msg: T) -> Result<Self> {
        let buffer = <[u8; PRIVATE_KEY_LENGTH]>::from_hex(msg)?;
        Ok(PrivateKey(buffer))
    }
}

impl TryFrom<String> for PrivateKey {
    type Error = Error;

    fn try_from(msg: String) -> Result<Self> {
        let buffer = <[u8; PRIVATE_KEY_LENGTH]>::from_hex(msg)?;
        Ok(PrivateKey(buffer))
    }
}

impl TryFrom<&String> for PrivateKey {
    type Error = Error;

    fn try_from(msg: &String) -> Result<Self> {
        let buffer = <[u8; PRIVATE_KEY_LENGTH]>::from_hex(msg)?;
        Ok(PrivateKey(buffer))
    }
}

impl TryFrom<&str> for PrivateKey {
    type Error = Error;

    fn try_from(msg: &str) -> Result<Self> {
        let buffer = <[u8; PRIVATE_KEY_LENGTH]>::from_hex(msg)?;
        Ok(PrivateKey(buffer))
    }
}

impl FromStr for PrivateKey {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        PrivateKey::from_hex(s)
    }
}

impl TryFrom<&[u8]> for PrivateKey {
    type Error = Error;

    fn try_from(arr: &[u8]) -> Result<Self> {
        let mut seed = PrivateKey::new();
        if arr.len() != PRIVATE_KEY_LENGTH {
            let e = format!(
                "incorrect drbg seed length {}!={PRIVATE_KEY_LENGTH}",
                arr.len()
            );
            return Err(Error::Other(e.into()));
        }

        seed.0 = (&arr[..])
            .try_into()
            .map_err(|e| Error::Other(format!("{e}").into()))?;

        Ok(seed)
    }
}

impl TryFrom<[u8; PRIVATE_KEY_LENGTH]> for PrivateKey {
    type Error = Error;

    fn try_from(arr: [u8; PRIVATE_KEY_LENGTH]) -> Result<Self> {
        Ok(PrivateKey(arr))
    }
}

impl TryFrom<Vec<u8>> for PrivateKey {
    type Error = Error;

    fn try_from(arr: Vec<u8>) -> Result<Self> {
        PrivateKey::try_from(arr.as_slice())
    }
}

impl fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0[..]))
    }
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn privkey_from_() -> Result<()> {
        let expected = PrivateKey([0_u8; PRIVATE_KEY_LENGTH]);

        let input = "000000000000000000000000000000000000000000000000";
        assert_eq!(PrivateKey::try_from(input).unwrap(), expected);
        assert_eq!(PrivateKey::from_hex(input).unwrap(), expected);
        assert_eq!(PrivateKey::from_str(input).unwrap(), expected);

        let input: String = input.into();
        assert_eq!(PrivateKey::try_from(input.clone()).unwrap(), expected);
        assert_eq!(PrivateKey::from_hex(input.clone()).unwrap(), expected);
        assert_eq!(PrivateKey::try_from(&input.clone()).unwrap(), expected);
        assert_eq!(PrivateKey::from_hex(&input.clone()).unwrap(), expected);
        assert_eq!(PrivateKey::from_str(&input.clone()).unwrap(), expected);

        let input = [0_u8; PRIVATE_KEY_LENGTH];
        assert_eq!(PrivateKey::try_from(input.clone()).unwrap(), expected);
        assert_eq!(PrivateKey::try_from(&input.clone()[..]).unwrap(), expected);

        let input = vec![0_u8; PRIVATE_KEY_LENGTH];
        assert_eq!(PrivateKey::try_from(input.clone()).unwrap(), expected);
        assert_eq!(PrivateKey::try_from(&input.clone()[..]).unwrap(), expected);

        Ok(())
    }
}
