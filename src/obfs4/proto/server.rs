#![allow(unused)]

use crate::{
    common::{
        colorize, drbg,
        ntor::{self, Representative, AUTH_LENGTH, REPRESENTATIVE_LENGTH, NODE_ID_LENGTH},
        replay_filter::{self, ReplayFilter},
        HmacSha256,
    },
    obfs4::{
        constants::*,
        framing::{FrameError, Marshall, Obfs4Codec, TryParse, KEY_LENGTH},
        proto::{client::ClientBuilder, handshake_server, sessions::Session},
    },
    stream::Stream,
    Error, Result,
};

use super::*;

use bytes::{Buf, BufMut, Bytes};
use hmac::{Hmac, Mac};
use rand::prelude::*;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::codec::Encoder;
use tracing::{debug, info};

use std::time::Instant;

pub struct Server {
    identity_keys: ntor::IdentityKeyPair,
    node_id: ntor::ID,
    iat_mode: IAT,
    replay_filter: ReplayFilter,
}



pub struct ServerBuilder {
    pub iat_mode: IAT,
    pub node_id: ntor::ID,
    pub identity_keys: ntor::IdentityKeyPair,
    pub statefile_location: Option<String>,
}

impl ServerBuilder {
    pub fn from_statefile(location: &str) -> Result<Self> {
        // TODO: Implement server from statefile
        Ok(Self {
            iat_mode: IAT::Off,
            node_id: ntor::ID::from([0u8; NODE_ID_LENGTH]),
            identity_keys: ntor::IdentityKeyPair::from([0_u8; KEY_LENGTH*2]),
            statefile_location: Some(location.into()),
        })

    }

    pub fn from_params(param_strs: Vec<impl AsRef<[u8]>>) -> Result<Self> {
        Ok(Self {
            iat_mode: IAT::Off,
            node_id: ntor::ID::from([0u8; NODE_ID_LENGTH]),
            identity_keys: ntor::IdentityKeyPair::from([0_u8; KEY_LENGTH*2]),
            statefile_location: None,
        })
    }

    pub fn node_pubkey(mut self, privkey: [u8; KEY_LENGTH]) -> Self {
        self.identity_keys = ntor::IdentityKeyPair::from_privkey(privkey);
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

    pub fn build(self) -> Server {
        Server {
            identity_keys: self.identity_keys,
            node_id: self.node_id,
            replay_filter: ReplayFilter::new(REPLAY_TTL),
            iat_mode: self.iat_mode,
        }
    }
}


impl Server {
    pub fn new_from_random() -> Self {
        Self {
            identity_keys: ntor::IdentityKeyPair::new(),
            node_id: ntor::ID::new(),
            iat_mode: IAT::Off,
            replay_filter: ReplayFilter::new(REPLAY_TTL),
        }
    }

    pub async fn wrap<'a, T>(&'a mut self, stream: T) -> Result<Obfs4Stream<'a, T>>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let session = sessions::new_server_session(
            &self.identity_keys,
            self.node_id.clone(),
            self.iat_mode,
            &mut self.replay_filter,
        )?;
        tokio::select! {
            r = session.handshake(stream) => r,
            e = tokio::time::sleep(SERVER_HANDSHAKE_TIMEOUT) => Err(Error::HandshakeTimeout),
        }
    }

    pub fn set_args(&mut self, args: &dyn std::any::Any) -> Result<&Self> {
        Ok(self)
    }

    pub fn new_from_statefile() -> Result<Self> {
        Err(Error::NotImplemented)
    }

    pub fn write_statefile(f: std::fs::File) -> Result<()> {
        Err(Error::NotImplemented)
    }

    pub fn client_params(&self) -> ClientBuilder {
        ClientBuilder {
            station_pubkey: self.identity_keys.public,
            node_id: self.node_id.clone(),
            iat_mode: self.iat_mode,
            statefile_location: None,
        }
    }
}
