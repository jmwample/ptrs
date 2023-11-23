#![allow(unused)]

use crate::{
    common::{drbg, ntor},
    stream::Stream,
    Result,
};

use super::{Obfs4Stream, Session, IAT};

pub struct Server {
    identity_keys: ntor::IdentityKeyPair,
}

impl Default for Server {
    fn default() -> Self {
        Server {
            identity_keys: ntor::IdentityKeyPair::new(),
        }
    }
}

impl Server {
    pub fn wrap<'a>(&mut self, stream: &'a mut dyn Stream) -> Result<Obfs4Stream<'a>> {
        let session = ServerSession::new()?;

        let o4_stream = session.wrap(stream)?;

        Ok(o4_stream)
    }

    pub fn set_args(&mut self, args: &dyn std::any::Any) -> Result<&Self> {
        Ok(self)
    }
}

pub struct ServerSession {
    session_id: Vec<u8>,

    iat_mode: IAT,
    node_id: ntor::ID,
    identity_keys: ntor::IdentityKeyPair,
    len_seed: drbg::Seed,
    iat_seed: drbg::Seed,
    // replay_filter: replayfilter.ReplayFilter,
}

impl ServerSession {
    fn new() -> Result<Self> {
        Ok(Self {
            session_id: vec![0_u8; 16],

            iat_mode: IAT::Off,
            node_id: ntor::ID::new(),
            identity_keys: ntor::IdentityKeyPair::new(),
            len_seed: drbg::Seed::new()?,
            iat_seed: drbg::Seed::new()?,
        })
    }

    fn wrap<'a>(self, stream: &'a mut dyn Stream) -> Result<Obfs4Stream<'a>> {
        let stream = Obfs4Stream {
            inner: stream,
            session: Session::Server(self),
            session_id: vec![0_u8; 16],
        };

        Ok(stream)
    }

    async fn handshake(&mut self) -> Result<()> {
        todo!()
    }
}
