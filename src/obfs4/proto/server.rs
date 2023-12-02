#![allow(unused)]

use crate::{
    common::{drbg, ntor, replay_filter::ReplayFilter},
    obfs4::{
        framing::{Obfs4Codec, KEY_MATERIAL_LENGTH},
        packet::ClientHandshakeMessage,
    },
    stream::Stream,
    Error, Result,
};

use super::*;

use bytes::BufMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct Server {
    identity_keys: ntor::IdentityKeyPair,
    node_id: ntor::ID,
    iat_mode: IAT,
    replay_filter: ReplayFilter,
}

impl Server {
    pub async fn wrap<'a>(&mut self, stream: &'a mut dyn Stream<'a>) -> Result<Obfs4Stream<'a>> {
        ServerHandshake::new(&self.node_id, &self.identity_keys, self.iat_mode)
            .complete(stream)
            .await
    }

    pub fn set_args(&mut self, args: &dyn std::any::Any) -> Result<&Self> {
        Ok(self)
    }
}

pub(crate) struct ServerSession<'a> {
    // fixed by server
    iat_mode: IAT,
    node_id: ntor::ID,
    identity_keys: &'a ntor::IdentityKeyPair,
    replay_filter: &'a ReplayFilter,

    // generated per session
    session_keys: ntor::SessionKeyPair,
    session_id: [u8; SESSION_ID_LEN],
    len_seed: drbg::Seed,
    iat_seed: drbg::Seed,
}

impl<'a> ServerSession<'a> {
    pub fn new(node_id: ntor::ID, identity_keys: &ntor::IdentityKeyPair, iat_mode: IAT) -> Self {
        Self {
            // TODO: generate session id
            session_id: [0_u8; SESSION_ID_LEN],

            session_keys: ntor::SessionKeyPair::new(true),
            identity_keys,

            iat_mode,
            node_id,
            len_seed: drbg::Seed::new().unwrap(),
            iat_seed: drbg::Seed::new().unwrap(),
            replay_filter: ReplayFilter::new(REPLAY_TTL),
        }
    }

    pub fn session_id(&self) -> String {
        return hex::encode(self.session_id)
    }
}

pub struct ServerHandshake<'a> {
    session: ServerSession<'a>,
}

impl<'b> ServerHandshake<'b> {
    pub fn new(id: &ntor::ID, station_keypair: &ntor::IdentityKeyPair, iat_mode: IAT) -> Self {
        Self {
            session: ServerSession::new(id.clone(), station_keypair, iat_mode),
        }
    }

    pub async fn complete<'a>(&self, stream: &'a mut dyn Stream<'a>) -> Result<Obfs4Stream<'a>> {
        // wait for and attempt to consume the client hello message
        let mut buf = [0_u8; MAX_HANDSHAKE_LENGTH];
        let mut seed: [u8; SEED_LENGTH];
        loop {
            tokio::select!(
                _ = stream.read(&mut buf) => trace!("successfully read for {}", self.session.session_id()),
                _ = tokio::time::sleep(SERVER_HANDSHAKE_TIMEOUT) => Err(Error::HandshakeTimeout)?,
            );

            seed = match ClientHandshakeMessage::try_parse(&mut buf) {
                Ok(chs) => chs.get_seed()?.to_bytes(),
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
        let o4 = O4Stream::new(&mut stream, codec, Session::Server(self.session));
        Ok(Obfs4Stream::from_o4(o4))
    }
}
