#![allow(unused)]

use crate::{
    common::{
        colorize, drbg,
        ntor::{self, AUTH_LENGTH, Representative, REPRESENTATIVE_LENGTH},
        replay_filter::{self, ReplayFilter},
        HmacSha256,
    },
    obfs4::{
        constants::*,
        framing::{FrameError, Marshall, Obfs4Codec, TryParse, KEY_MATERIAL_LENGTH},
        proto::{
            sessions::Session,
            client::ClientParams,
            handshake_client::ClientHandshakeMessage,
        },
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
        let session = self.new_session();
        tokio::select! {
            r = ServerHandshake::new(session).complete(stream) => r,
            e = tokio::time::sleep(CLIENT_HANDSHAKE_TIMEOUT) => Err(Error::HandshakeTimeout),
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

    pub fn client_params(&self) -> ClientParams {
        ClientParams {
            station_pubkey: self.identity_keys.public,
            node_id: self.node_id.clone(),
            iat_mode: self.iat_mode.clone(),
        }
    }

    pub fn new_session(&mut self) -> ServerSession {
        let session_keys = ntor::SessionKeyPair::new(true);

        ServerSession {
            session_id: session_keys.public.to_bytes()[..SESSION_ID_LEN]
                .try_into()
                .unwrap(),

            session_keys,
            identity_keys: &self.identity_keys,

            iat_mode: self.iat_mode.clone(),
            node_id: self.node_id.clone(),
            len_seed: drbg::Seed::new().unwrap(),
            iat_seed: drbg::Seed::new().unwrap(),
            replay_filter: &mut self.replay_filter,
        }
    }
}



