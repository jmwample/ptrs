#![allow(unused)]

use crate::{
    common::{
        colorize,
        ntor::{self, HandShakeResult, AUTH_LENGTH, Representative, REPRESENTATIVE_LENGTH},
        HmacSha256,
    },
    obfs4::{
        framing::{FrameError, Marshall, Obfs4Codec, TryParse, KEY_LENGTH, KEY_MATERIAL_LENGTH},
        proto::server::ServerHandshakeMessage,
    },
    stream::Stream,
    Error, Result,
};

use super::*;

use bytes::{Buf, BufMut, BytesMut};
use hmac::{Hmac, Mac};
use rand::prelude::*;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info};

use std::io::{Error as IoError, ErrorKind as IoErrorKind};
use std::sync::{Arc, Mutex};

pub struct ClientParams {
    pub iat_mode: IAT,
    pub node_id: ntor::ID,
    pub station_pubkey: ntor::PublicKey,
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

    pub async fn wrap<'a, T>(&self, mut stream: &'a mut T) -> Result<Obfs4Stream<'a, &'a mut T>>
    where
        T: AsyncRead + AsyncWrite + Unpin + 'a,
    {

        let session = sessions::new_client_session(self.id.clone(), self.station_pubkey.clone(), self.iat_mode);

        tokio::select! {
            r = session.handshake(&mut stream) => r,
            // r = ClientHandshake::new(&self.id, &self.station_pubkey, self.iat_mode).complete(stream) => r,
            e = tokio::time::sleep(CLIENT_HANDSHAKE_TIMEOUT) => Err(Error::HandshakeTimeout),
        }
    }

    pub fn from_params(params: ClientParams) -> Self {
        Self {
            iat_mode: params.iat_mode,
            station_pubkey: params.station_pubkey,
            id: params.node_id,
        }
    }
}

pub struct ClientSession {
    node_id: ntor::ID,
    node_pubkey: ntor::PublicKey,
    session_keys: ntor::SessionKeyPair,
    session_id: [u8; SESSION_ID_LEN],
    iat_mode: IAT, // TODO: add IAT normal / paranoid writing modes
    epoch_hour: String,
    pad_len: usize,

    len_seed: drbg::Seed, // TODO: initialize the distributions using the seed
}

impl std::fmt::Debug for ClientSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[ id:{}, ident_pk:{}, sess_key:{:?}, iat:{:?}, epoch_hr:{}, pad_len:{} ]",
            hex::encode(self.node_id.as_bytes()),
            hex::encode(self.node_pubkey.as_bytes()),
            self.session_keys,
            self.iat_mode,
            self.epoch_hour,
            self.pad_len,
        )
    }
}

impl ClientSession {
    pub fn new(station_id: ntor::ID, station_pubkey: ntor::PublicKey, iat_mode: IAT) -> Self {
        let session_keys = ntor::SessionKeyPair::new(true);
        let session_id = session_keys.get_public().to_bytes()[..SESSION_ID_LEN]
            .try_into()
            .unwrap();
        Self {
            session_keys,
            node_id: station_id,
            node_pubkey: station_pubkey,
            session_id,
            iat_mode,
            epoch_hour: "".into(),
            pad_len: rand::thread_rng().gen_range(CLIENT_MIN_PAD_LENGTH..CLIENT_MAX_PAD_LENGTH),

            len_seed: drbg::Seed::new().unwrap(),
        }
    }

    pub fn session_id(&self) -> String {
        String::from("c-") + &colorize(&self.session_id)
    }

    pub(crate) fn set_session_id(&mut self, id: [u8; SESSION_ID_LEN]) {
        debug!(
            "{} -> {} client updating session id",
            colorize(&self.session_id),
            colorize(&id)
        );
        self.session_id = id;
    }

    pub(crate) fn set_len_seed(&mut self, seed: drbg::Seed) {
        debug!(
            "{} setting length seed {}",
            self.session_id(),
            hex::encode(seed.as_bytes())
        );
        self.len_seed = seed;
    }
}

