#![allow(unused)]

use crate::{
    common::{
        colorize,
        ntor::{self, HandShakeResult, Representative, AUTH_LENGTH, REPRESENTATIVE_LENGTH, NODE_ID_LENGTH},
        HmacSha256,
    },
    obfs4::{
        framing::{FrameError, Marshall, Obfs4Codec, TryParse, KEY_LENGTH, KEY_MATERIAL_LENGTH},
        constants::*,
        proto::{IAT, Obfs4Stream, sessions},
    },
    stream::Stream,
    Error, Result,
};


use bytes::{Buf, BufMut, BytesMut};
use hmac::{Hmac, Mac};
use rand::prelude::*;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{debug, info};

use std::{io::{Error as IoError, ErrorKind as IoErrorKind}, fmt};
use std::sync::{Arc, Mutex};

pub struct ClientBuilder {
    pub iat_mode: IAT,
    pub node_id: ntor::ID,
    pub station_pubkey: ntor::PublicKey,
    pub statefile_location: Option<String>,
}

impl ClientBuilder {
    pub fn from_statefile(location: &str) -> Result<Self> {
        // TODO: implement client builder from statefile
        Ok(Self {
            iat_mode: IAT::Off,
            node_id: ntor::ID::from([0u8; NODE_ID_LENGTH]),
            station_pubkey: ntor::PublicKey::from([0_u8; KEY_LENGTH]),
            statefile_location: Some(location.into()),
        })

    }

    pub fn from_params(param_strs: Vec<impl AsRef<[u8]>>) -> Result<Self> {
        Ok(Self {
            iat_mode: IAT::Off,
            node_id: ntor::ID::from([0u8; NODE_ID_LENGTH]),
            station_pubkey: ntor::PublicKey::from([0_u8; KEY_LENGTH]),
            statefile_location: None,
        })
    }

    pub fn node_pubkey(mut self, pubkey: [u8; KEY_LENGTH]) -> Self {
        self.station_pubkey = ntor::PublicKey::from(pubkey);
        self
    }

    pub fn statefile_location(mut self, path: &str) -> Self {
        self.statefile_location = Some(path.into());
        self
    }

    pub fn node_id(mut self, id: [u8;NODE_ID_LENGTH]) -> Self {
        self.node_id = ntor::ID::from(id);
        self
    }

    pub fn iat_mode(mut self, iat: IAT) -> Self {
        self.iat_mode = iat;
        self
    }

    pub fn build(self) -> Client {
        Client {
            iat_mode: self.iat_mode,
            station_pubkey: self.station_pubkey,
            id: self.node_id,
        }
    }

    pub fn as_opts(&self) -> String {
        //TODO: String self as command line options
        "".into()
    }
}

impl fmt::Display for ClientBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        //TODO: string self
        write!(f, "")
    }

}


pub struct Client {
    pub iat_mode: IAT,
    pub station_pubkey: ntor::PublicKey,
    pub id: ntor::ID,
}

impl Client {
    pub fn set_args(&mut self, _args: &dyn std::any::Any) -> Result<&Self> {
        Ok(self)
    }

    pub async fn wrap<'a, T>(&self, mut stream: T) -> Result<Obfs4Stream<'a, T>>
    where
        T: AsyncRead + AsyncWrite + Unpin + 'a,
    {
        let session =
            sessions::new_client_session(self.id.clone(), self.station_pubkey, self.iat_mode);

        tokio::select! {
            r = session.handshake(stream) => r,
            e = tokio::time::sleep(CLIENT_HANDSHAKE_TIMEOUT) => Err(Error::HandshakeTimeout),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Result;


    #[test]
    fn parse_params() -> Result<()> {
        let test_args = [
            ["", "", ""],
        ];

        for (i, test_case) in test_args.iter().enumerate() {
            let cb = ClientBuilder::from_params(test_case.to_vec())?;
        }
        Ok(())
    }
}
