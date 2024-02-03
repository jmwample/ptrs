use crate::{Error, Result};

use hex::FromHex;
use rand_core::RngCore;
use std::fmt;
use std::str::FromStr;

/// The length of a ntor node identifier.
pub const NODE_ID_LENGTH: usize = 20;

/// Identifier for the specific node runnig this obfs4 server.
#[derive(Debug, PartialEq, Clone)]
pub struct ID([u8; NODE_ID_LENGTH]);

impl Default for ID {
    fn default() -> Self {
        Self::new()
    }
}

impl ID {
    pub fn new() -> Self {
        let mut id = [0_u8; NODE_ID_LENGTH];
        rand::thread_rng().fill_bytes(&mut id);
        ID(id)
    }

    pub fn to_bytes(&self) -> [u8; NODE_ID_LENGTH] {
        self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl FromHex for ID {
    type Error = Error;

    fn from_hex<T: AsRef<[u8]>>(msg: T) -> Result<Self> {
        let buffer = <[u8; NODE_ID_LENGTH]>::from_hex(msg)?;
        Ok(ID(buffer))
    }
}

impl TryFrom<String> for ID {
    type Error = Error;

    fn try_from(msg: String) -> Result<Self> {
        let buffer = <[u8; NODE_ID_LENGTH]>::from_hex(msg)?;
        Ok(ID(buffer))
    }
}

impl TryFrom<&String> for ID {
    type Error = Error;

    fn try_from(msg: &String) -> Result<Self> {
        let buffer = <[u8; NODE_ID_LENGTH]>::from_hex(msg)?;
        Ok(ID(buffer))
    }
}

impl TryFrom<&str> for ID {
    type Error = Error;

    fn try_from(msg: &str) -> Result<Self> {
        let buffer = <[u8; NODE_ID_LENGTH]>::from_hex(msg)?;
        Ok(ID(buffer))
    }
}

impl FromStr for ID {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        ID::from_hex(s)
    }
}

impl TryFrom<&[u8]> for ID {
    type Error = Error;

    fn try_from(arr: &[u8]) -> Result<Self> {
        let mut seed = ID::new();
        if arr.len() != NODE_ID_LENGTH {
            let e = format!("incorrect drbg seed length {}!={NODE_ID_LENGTH}", arr.len());
            return Err(Error::Other(e.into()));
        }

        seed.0 = arr
            .try_into()
            .map_err(|e| Error::Other(format!("{e}").into()))?;

        Ok(seed)
    }
}

impl From<[u8; NODE_ID_LENGTH]> for ID {

    fn from(arr: [u8; NODE_ID_LENGTH]) -> Self {
        ID(arr)
    }
}

impl TryFrom<Vec<u8>> for ID {
    type Error = Error;

    fn try_from(arr: Vec<u8>) -> Result<Self> {
        ID::try_from(arr.as_slice())
    }
}

impl fmt::Display for ID {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0[..]))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn from_() -> Result<()> {
        let expected = ID([0_u8; NODE_ID_LENGTH]);

        let input = "0000000000000000000000000000000000000000";
        assert_eq!(ID::try_from(input).unwrap(), expected);
        assert_eq!(ID::from_hex(input).unwrap(), expected);
        assert_eq!(ID::from_str(input).unwrap(), expected);

        let input: String = input.into();
        assert_eq!(ID::try_from(input.clone()).unwrap(), expected);
        assert_eq!(ID::from_hex(input.clone()).unwrap(), expected);
        assert_eq!(ID::try_from(&input.clone()).unwrap(), expected);
        assert_eq!(ID::from_hex(input.clone()).unwrap(), expected);
        assert_eq!(ID::from_str(&input.clone()).unwrap(), expected);

        let input = [0_u8; NODE_ID_LENGTH];
        assert_eq!(ID::try_from(input).unwrap(), expected);
        assert_eq!(ID::try_from(&input[..]).unwrap(), expected);

        let input = vec![0_u8; NODE_ID_LENGTH];
        assert_eq!(ID::try_from(input.clone()).unwrap(), expected);
        assert_eq!(ID::try_from(&input.clone()[..]).unwrap(), expected);

        Ok(())
    }
}
