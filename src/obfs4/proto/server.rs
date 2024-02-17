#![allow(unused)]

use crate::{
    common::{
        colorize, drbg,
        replay_filter::{self, ReplayFilter},
        HmacSha256,
        curve25519::StaticSecret,
    },
    obfs4::{
        constants::*, framing::{FrameError, Marshall, Obfs4Codec, TryParse, KEY_LENGTH}, handshake::{Obfs4NtorPublicKey, Obfs4NtorSecretKey}, proto::{client::ClientBuilder, sessions::Session, MaybeTimeout}
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
use tokio::time::{Duration, Instant};
use tokio_util::codec::Encoder;
use tracing::{debug, info};




pub struct ServerBuilder {
    pub iat_mode: IAT,
    pub identity_keys: Obfs4NtorSecretKey,
    pub statefile_location: Option<String>,
    pub(crate) handshake_timeout: MaybeTimeout,
}

impl ServerBuilder {
    /// TODO: Implement server from statefile
    pub fn from_statefile(location: &str) -> Result<Self> {
        let identity_keys = Obfs4NtorSecretKey{
            sk: [0_u8; KEY_LENGTH].into(),
            pk: Obfs4NtorPublicKey {
                    pk: [0_u8; KEY_LENGTH].into(),
                    id: [0_u8; NODE_ID_LENGTH].into(),
            },
        };
        Ok(Self {
            iat_mode: IAT::Off,
            identity_keys,
            statefile_location: Some(location.into()),
            handshake_timeout: MaybeTimeout::Default_,
        })

    }

    /// TODO: parse server params form str vec
    pub fn from_params(param_strs: Vec<impl AsRef<[u8]>>) -> Result<Self> {
        let identity_keys = Obfs4NtorSecretKey{
            sk: [0_u8; KEY_LENGTH].into(),
            pk: Obfs4NtorPublicKey {
                    pk: [0_u8; KEY_LENGTH].into(),
                    id: [0_u8; NODE_ID_LENGTH].into(),
            },
        };
        Ok(Self {
            iat_mode: IAT::Off,
            identity_keys,
            statefile_location: None,
            handshake_timeout: MaybeTimeout::Default_,
        })
    }

    pub fn node_pubkey(mut self, privkey: [u8; KEY_LENGTH]) -> Self {
        self.identity_keys.sk = privkey.into();
        self.identity_keys.pk.pk = (&self.identity_keys.sk).into();
        self
    }

    pub fn statefile_location(mut self, path: &str) -> Self {
        self.statefile_location = Some(path.into());
        self
    }

    pub fn node_id(mut self, id: [u8;NODE_ID_LENGTH]) -> Self {
        self.identity_keys.pk.id = id.into();
        self
    }

    pub fn iat_mode(mut self, iat: IAT) -> Self {
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
    pub fn build(self) -> Server {
        Server {
            identity_keys: self.identity_keys,
            replay_filter: ReplayFilter::new(REPLAY_TTL),
            iat_mode: self.iat_mode,
            handshake_timeout: self.handshake_timeout.duration(),
        }
    }
}


pub struct Server {
    identity_keys: Obfs4NtorSecretKey,
    iat_mode: IAT,
    replay_filter: ReplayFilter,
    handshake_timeout: Option<tokio::time::Duration>,
}


impl Server {
    pub fn new_from_random<R:RngCore+CryptoRng>(mut rng: R) -> Self {
        let mut id = [0_u8; 20];
        // Random bytes will work for testing, but aren't necessarily actually a valid id.
        rng.fill_bytes(&mut id);

        let sk = StaticSecret::random_from_rng(rng);

        let pk = Obfs4NtorPublicKey {
            pk: (&sk).into(),
            id: id.into(),
        };

        let identity_keys = Obfs4NtorSecretKey{ pk, sk };

        Self {
            identity_keys,
            iat_mode: IAT::Off,
            replay_filter: ReplayFilter::new(REPLAY_TTL),
            handshake_timeout: Some(SERVER_HANDSHAKE_TIMEOUT),
        }
    }

    pub fn getrandom() -> Self {
        let identity_keys = Obfs4NtorSecretKey::getrandom();
        Self {
            identity_keys,
            iat_mode: IAT::Off,
            replay_filter: ReplayFilter::new(REPLAY_TTL),
            handshake_timeout: Some(SERVER_HANDSHAKE_TIMEOUT),
        }
    }

    pub async fn wrap<'a, T>(&'a mut self, stream: T) -> Result<Obfs4Stream<'a, T>>
    where
        T: AsyncRead + AsyncWrite + Unpin + 'a,
    {
        let session = sessions::new_server_session(
            &self.identity_keys,
            self.iat_mode,
            &mut self.replay_filter,
        )?;

        let deadline = self.handshake_timeout.map(|d| Instant::now() + d);

        session.handshake(stream, deadline).await
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
            station_pubkey: self.identity_keys.pk,
            iat_mode: self.iat_mode,
            statefile_location: None,
            handshake_timeout: MaybeTimeout::Default_,
        }
    }
}
