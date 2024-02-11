#![allow(unused)]

use crate::{
    common::{
        colorize,
        ntor::{
            self, HandShakeResult, Representative, AUTH_LENGTH, NODE_ID_LENGTH,
            REPRESENTATIVE_LENGTH,
        },
        HmacSha256,
    },
    obfs4::{
        constants::*,
        framing::{FrameError, Marshall, Obfs4Codec, TryParse, KEY_LENGTH, KEY_MATERIAL_LENGTH},
        proto::{sessions, Obfs4Stream, IAT, MaybeTimeout},
    },
    stream::Stream,
    Error, Result,
};

use bytes::{Buf, BufMut, BytesMut};
use hmac::{Hmac, Mac};
use rand::prelude::*;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{Duration, Instant};
use tracing::{debug, info, trace, warn};

use std::{
    fmt,
    io::{Error as IoError, ErrorKind as IoErrorKind},
    sync::{Arc, Mutex},
};

pub struct ClientBuilder {
    pub iat_mode: IAT,
    pub node_id: ntor::ID,
    pub station_pubkey: ntor::PublicKey,
    pub statefile_location: Option<String>,
    pub(crate) handshake_timeout: MaybeTimeout,
}

impl ClientBuilder {
    /// TODO: implement client builder from statefile
    pub fn from_statefile(location: &str) -> Result<Self> {
        Ok(Self {
            iat_mode: IAT::Off,
            node_id: ntor::ID::from([0u8; NODE_ID_LENGTH]),
            station_pubkey: ntor::PublicKey::from([0_u8; KEY_LENGTH]),
            statefile_location: Some(location.into()),
            handshake_timeout: MaybeTimeout::Default_,
        })
    }

    /// TODO: implement client builder from string args
    pub fn from_params(param_strs: Vec<impl AsRef<[u8]>>) -> Result<Self> {
        Ok(Self {
            iat_mode: IAT::Off,
            node_id: ntor::ID::from([0u8; NODE_ID_LENGTH]),
            station_pubkey: ntor::PublicKey::from([0_u8; KEY_LENGTH]),
            statefile_location: None,
            handshake_timeout: MaybeTimeout::Default_,
        })
    }

    pub fn with_node_pubkey(mut self, pubkey: [u8; KEY_LENGTH]) -> Self {
        self.station_pubkey = ntor::PublicKey::from(pubkey);
        self
    }

    pub fn with_statefile_location(mut self, path: &str) -> Self {
        self.statefile_location = Some(path.into());
        self
    }

    pub fn with_node_id(mut self, id: [u8; NODE_ID_LENGTH]) -> Self {
        self.node_id = ntor::ID::from(id);
        self
    }

    pub fn with_iat_mode(mut self, iat: IAT) -> Self {
        self.iat_mode = iat;
        self
    }

    pub fn with_handshake_timeout(mut self, d: Duration) -> Self {
        self.handshake_timeout = MaybeTimeout::Length(d);
        self
    }

    pub fn with_handshake_deadline(mut self, deadline: Instant) -> Self {
        self.handshake_timeout = MaybeTimeout::Fixed(deadline);
        self
    }

    pub fn fail_fast(mut self) -> Self {
        self.handshake_timeout = MaybeTimeout::Unset;
        self
    }

    pub fn build(self) -> Client {
        Client {
            iat_mode: self.iat_mode,
            station_pubkey: self.station_pubkey,
            id: self.node_id,
            handshake_timeout: self.handshake_timeout.duration(),
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

/// Client implementing the obfs4 protocol.
pub struct Client {
    iat_mode: IAT,
    station_pubkey: ntor::PublicKey,
    id: ntor::ID,
    handshake_timeout: Option<tokio::time::Duration>,
}

impl Client {
    /// TODO: extract args to create new builder
    pub fn get_args(&mut self, _args: &dyn std::any::Any) {}

    /// On a failed handshake the client will read for the remainder of the
    /// handshake timeout and then close the connection.
    pub async fn wrap<'a, T>(&self, mut stream: T) -> Result<Obfs4Stream<'a, T>>
    where
        T: AsyncRead + AsyncWrite + Unpin + 'a,
    {
        let session =
            sessions::new_client_session(self.id.clone(), self.station_pubkey, self.iat_mode);

        let deadline = self.handshake_timeout.map(|d| Instant::now() + d);

        session.handshake(stream, deadline).await
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Result;

    #[test]
    fn parse_params() -> Result<()> {
        let test_args = [["", "", ""]];

        for (i, test_case) in test_args.iter().enumerate() {
            let cb = ClientBuilder::from_params(test_case.to_vec())?;
        }
        Ok(())
    }
}
