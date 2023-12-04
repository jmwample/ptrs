#![allow(unused)]

use crate::{
    common::ntor,
    obfs4::{
        framing::{Obfs4Codec, KEY_LENGTH, KEY_MATERIAL_LENGTH},
        packet::{self, Packet, ServerHandshakeMessage},
    },
    stream::Stream,
    Error, Result,
};

use super::{
    O4Stream, Obfs4Stream, ServerHandshake, Session, IAT, MAX_HANDSHAKE_LENGTH, SEED_LENGTH,
    SESSION_ID_LEN,
};

use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use std::sync::{Arc, Mutex};

pub struct Client {
    pub iat_mode: IAT,
    pub station_pubkey: ntor::PublicKey,
    pub id: ntor::ID,
}

impl Client {
    pub fn set_args(&mut self, _args: &dyn std::any::Any) -> Result<&Self> {
        Ok(self)
    }

    pub async fn wrap<'a>(&self, stream: &'a mut impl Stream<'a>) -> Result<Obfs4Stream<'a>> {
        ClientHandshake::new(&self.id, &self.station_pubkey, self.iat_mode)
            .complete(stream)
            .await
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
    iat_mode: IAT,
}

impl ClientSession {
    pub fn new(station_id: ntor::ID, station_pubkey: ntor::PublicKey, iat_mode: IAT) -> Self {
        Self {
            node_id: station_id,
            node_pubkey: station_pubkey,
            session_keys: ntor::SessionKeyPair::new(true),
            // TODO: generate session id
            session_id: [0_u8; SESSION_ID_LEN],
            iat_mode,
        }
    }

    pub fn session_id(&self) -> String {
        return hex::encode(self.session_id);
    }
}

pub struct ClientHandshake {
    session: ClientSession,
}

impl ClientHandshake {
    pub fn new(id: &ntor::ID, station_pubkey: &ntor::PublicKey, iat_mode: IAT) -> Self {
        Self {
            session: ClientSession::new(id.clone(), *station_pubkey, iat_mode),
        }
    }

    pub fn for_session(session: ClientSession) -> Result<Self> {
        Ok(Self { session })
    }

    pub async fn complete<'a>(self, stream: &'a mut dyn Stream<'a>) -> Result<Obfs4Stream> {
        // build client handshake message
        let mut ch_msg = packet::ClientHandshakeMessage {};
        let mut buf = BytesMut::with_capacity(MAX_HANDSHAKE_LENGTH);
        ch_msg.marshall(&mut buf)?;

        // send client Handshake
        stream.write_all(&buf).await?;

        // Wait for and attempt to consume server handshake
        let mut buf = [0_u8; MAX_HANDSHAKE_LENGTH];
        let mut seed: [u8; SEED_LENGTH];
        loop {
            let n = stream.read(&mut buf).await?;

            // validate sever
            seed = match ServerHandshakeMessage::try_parse(&mut buf) {
                Ok(shs) => shs.get_seed()?.to_bytes(),
                Err(EAgain) => continue,
                Err(e) => return Err(e)?,
            };
            break;
        }

        // use the derived seed value to bootstrap Read / Write crypto codec.
        let okm = ntor::kdf(seed, KEY_MATERIAL_LENGTH * 2);
        let ekm: [u8; KEY_MATERIAL_LENGTH] = okm[..KEY_MATERIAL_LENGTH].try_into().unwrap();
        let dkm: [u8; KEY_MATERIAL_LENGTH] = okm[KEY_MATERIAL_LENGTH..].try_into().unwrap();

        let codec = Obfs4Codec::new(ekm, dkm);
        Ok(Obfs4Stream::from_o4(O4Stream::new(
            stream,
            codec,
            Session::Client(self.session),
        )))
    }
}

pub struct ClientParams {
    pub iat_mode: IAT,
    pub node_id: ntor::ID,
    pub station_pubkey: ntor::PublicKey,
}
