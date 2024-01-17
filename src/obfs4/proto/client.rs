#![allow(unused)]

use crate::{
    common::{
        colorize,
        ntor::{self, HandShakeResult, Representative, AUTH_LENGTH, REPRESENTATIVE_LENGTH},
        HmacSha256,
    },
    obfs4::framing::{FrameError, Marshall, Obfs4Codec, TryParse, KEY_LENGTH, KEY_MATERIAL_LENGTH},
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

    pub fn from_params(params: ClientParams) -> Self {
        Self {
            iat_mode: params.iat_mode,
            station_pubkey: params.station_pubkey,
            id: params.node_id,
        }
    }
}
