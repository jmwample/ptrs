#![allow(unused)]

use crate::{
    common::{drbg, ntor, replay_filter::ReplayFilter},
    obfs4::{
        framing::{Obfs4Codec, KEY_MATERIAL_LENGTH},
        packet::ClientHandshakeMessage,
        proto::client::ClientParams,
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
    pub fn new_from_random() -> Self {
        Self {
            identity_keys: ntor::IdentityKeyPair::new(),
            node_id: ntor::ID::new(),
            iat_mode: IAT::Off,
            replay_filter: ReplayFilter::new(REPLAY_TTL),
        }
    }

    pub async fn wrap<'a>(&'a self, stream: &'a mut dyn Stream<'a>) -> Result<Obfs4Stream<'a>> {
        let session = self.new_session();
        ServerHandshake::new(session).complete(stream).await
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

    pub fn new_session(&self) -> ServerSession {
        ServerSession {
            // TODO: generate session id
            session_id: [0_u8; SESSION_ID_LEN],

            session_keys: ntor::SessionKeyPair::new(true),
            identity_keys: &self.identity_keys,

            iat_mode: self.iat_mode.clone(),
            node_id: self.node_id.clone(),
            len_seed: drbg::Seed::new().unwrap(),
            iat_seed: drbg::Seed::new().unwrap(),
            replay_filter: &self.replay_filter,
        }
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
    pub fn session_id(&self) -> String {
        return hex::encode(self.session_id);
    }
}

pub struct ServerHandshake<'a> {
    session: ServerSession<'a>,
}

impl<'b> ServerHandshake<'b> {
    pub fn new(session: ServerSession<'b>) -> Self {
        Self { session }
    }

    pub async fn complete<'a>(self, mut stream: &'a mut dyn Stream<'a>) -> Result<Obfs4Stream<'a>>
    where
        'b: 'a,
    {
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
        let o4 = O4Stream::new(stream, codec, Session::Server(self.session));
        Ok(Obfs4Stream::from_o4(o4))
    }
}
