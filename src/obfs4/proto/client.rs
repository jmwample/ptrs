#![allow(unused)]

use crate::{common::ntor, stream::Stream, Error, Result};

use super::{Obfs4Stream, Session, IAT};

#[derive(Default)]
pub struct Client {
    session: Option<ClientSession>,
}

impl Client {
    pub fn set_args(&mut self, _args: &dyn std::any::Any) -> Result<&Self> {
        Ok(self)
    }

    pub fn wrap<'a>(&self, stream: &mut dyn Stream) -> Result<Obfs4Stream<'a>> {
        Err(Error::NotImplemented)
    }
}

pub struct ClientSession {
    node_id: ntor::ID,
    session_keys: ntor::SessionKeyPair,
    iat_mode: IAT,
}

impl Default for ClientSession {
    fn default() -> Self {
        Self {
            node_id: ntor::ID::new(),
            session_keys: ntor::SessionKeyPair::new(true),
            iat_mode: IAT::Off,
        }
    }
}

impl ClientSession {
    async fn handshake(&mut self) -> Result<()> {
        todo!()
    }
}
