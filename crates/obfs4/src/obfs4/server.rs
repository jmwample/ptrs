#![allow(unused)]

use super::*;
use crate::{
    common::{
        colorize,
        curve25519::PublicKey,
        curve25519::StaticSecret,
        drbg,
        replay_filter::{self, ReplayFilter},
        HmacSha256,
    },
    obfs4::{
        client::ClientBuilder,
        constants::*,
        framing::{FrameError, Marshall, Obfs4Codec, TryParse, KEY_LENGTH},
        handshake::{Obfs4NtorPublicKey, Obfs4NtorSecretKey},
        proto::{MaybeTimeout, Obfs4Stream, IAT},
        sessions::Session,
    },
    stream::Stream,
    Error, Result,
};

use std::{borrow::BorrowMut, ops::Deref, sync::Arc};

use bytes::{Buf, BufMut, Bytes};
use hmac::{Hmac, Mac};
use rand::prelude::*;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{Duration, Instant};
use tokio_util::codec::Encoder;
use tracing::{debug, info};

pub struct ServerBuilder {
    pub iat_mode: IAT,
    pub statefile_path: Option<String>,
    pub(crate) identity_keys: Obfs4NtorSecretKey,
    pub(crate) handshake_timeout: MaybeTimeout,
}

impl Default for ServerBuilder {
    fn default() -> Self {
        let identity_keys = Obfs4NtorSecretKey::getrandom();
        Self {
            iat_mode: IAT::Off,
            statefile_path: None,
            identity_keys,
            handshake_timeout: MaybeTimeout::Default_,
        }
    }
}

impl ServerBuilder {
    /// TODO: Implement server from statefile
    pub fn from_statefile(location: &str) -> Result<Self> {
        let identity_keys = Obfs4NtorSecretKey {
            sk: [0_u8; KEY_LENGTH].into(),
            pk: Obfs4NtorPublicKey {
                pk: [0_u8; KEY_LENGTH].into(),
                id: [0_u8; NODE_ID_LENGTH].into(),
            },
        };
        Ok(Self {
            iat_mode: IAT::Off,
            identity_keys,
            statefile_path: Some(location.into()),
            handshake_timeout: MaybeTimeout::Default_,
        })
    }

    /// TODO: parse server params form str vec
    pub fn from_params(param_strs: Vec<impl AsRef<[u8]>>) -> Result<Self> {
        let identity_keys = Obfs4NtorSecretKey {
            sk: [0_u8; KEY_LENGTH].into(),
            pk: Obfs4NtorPublicKey {
                pk: [0_u8; KEY_LENGTH].into(),
                id: [0_u8; NODE_ID_LENGTH].into(),
            },
        };
        Ok(Self {
            iat_mode: IAT::Off,
            identity_keys,
            statefile_path: None,
            handshake_timeout: MaybeTimeout::Default_,
        })
    }

    /// 64 byte combined representation of an x25519 public key, private key
    /// combination.
    pub fn node_keys(mut self, keys: [u8; KEY_LENGTH * 2]) -> Self {
        let sk: [u8; KEY_LENGTH] = keys[..KEY_LENGTH].try_into().unwrap();
        let pk: [u8; KEY_LENGTH] = keys[KEY_LENGTH..].try_into().unwrap();
        self.identity_keys.sk = sk.into();
        self.identity_keys.pk.pk = (&self.identity_keys.sk).into();
        self
    }

    pub fn statefile_path(mut self, path: &str) -> Self {
        self.statefile_path = Some(path.into());
        self
    }

    pub fn node_id(mut self, id: [u8; NODE_ID_LENGTH]) -> Self {
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
    pub fn build(&self) -> Server {
        Server(Arc::new(ServerInner {
            identity_keys: self.identity_keys.clone(),
            iat_mode: self.iat_mode,
            biased: false,
            handshake_timeout: self.handshake_timeout.duration(),

            // metrics: Arc::new(std::sync::Mutex::new(ServerMetrics {})),
            replay_filter: ReplayFilter::new(REPLAY_TTL),
        }))
    }
}

#[derive(Clone)]
pub struct Server(Arc<ServerInner>);

pub struct ServerInner {
    pub(crate) handshake_timeout: Option<tokio::time::Duration>,
    pub(crate) iat_mode: IAT,
    pub(crate) biased: bool,
    pub(crate) identity_keys: Obfs4NtorSecretKey,

    pub(crate) replay_filter: ReplayFilter,
    // pub(crate) metrics: Metrics,
}

impl Deref for Server {
    type Target = ServerInner;
    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl Server {
    pub fn new(sec: [u8; KEY_LENGTH], id: [u8; NODE_ID_LENGTH]) -> Self {
        let sk = StaticSecret::from(sec);
        let pk = Obfs4NtorPublicKey {
            pk: PublicKey::from(&sk),
            id: id.into(),
        };

        let identity_keys = Obfs4NtorSecretKey { pk, sk };

        Self::new_from_key(identity_keys)
    }

    pub(crate) fn new_from_key(identity_keys: Obfs4NtorSecretKey) -> Self {
        Self(Arc::new(ServerInner {
            handshake_timeout: Some(SERVER_HANDSHAKE_TIMEOUT),
            identity_keys,
            iat_mode: IAT::Off,
            biased: false,

            // metrics: Arc::new(std::sync::Mutex::new(ServerMetrics {})),
            replay_filter: ReplayFilter::new(REPLAY_TTL),
        }))
    }

    pub fn new_from_random<R: RngCore + CryptoRng>(mut rng: R) -> Self {
        let mut id = [0_u8; 20];
        // Random bytes will work for testing, but aren't necessarily actually a valid id.
        rng.fill_bytes(&mut id);

        // Generated identity secret key does not need to be elligator2 representable
        // so we can use the regular dalek_x25519 key generation.
        let sk = StaticSecret::random_from_rng(rng);

        let pk = Obfs4NtorPublicKey {
            pk: PublicKey::from(&sk),
            id: id.into(),
        };

        let identity_keys = Obfs4NtorSecretKey { pk, sk };

        Self::new_from_key(identity_keys)
    }

    pub fn getrandom() -> Self {
        let identity_keys = Obfs4NtorSecretKey::getrandom();
        Self::new_from_key(identity_keys)
    }

    pub async fn wrap<T>(self, stream: T) -> Result<Obfs4Stream<T>>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let session = self.new_server_session()?;
        let deadline = self.handshake_timeout.map(|d| Instant::now() + d);

        session.handshake(&self, stream, deadline).await
    }

    // pub fn set_iat_mode(&mut self, mode: IAT) -> &Self {
    //     self.iat_mode = mode;
    //     self
    // }

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
            station_pubkey: *self.identity_keys.pk.pk.as_bytes(),
            station_id: self.identity_keys.pk.id.as_bytes().try_into().unwrap(),
            iat_mode: self.iat_mode,
            statefile_path: None,
            handshake_timeout: MaybeTimeout::Default_,
        }
    }

    pub(crate) fn new_server_session(
        &self,
    ) -> Result<sessions::ServerSession<sessions::Initialized>> {
        let mut session_id = [0u8; SESSION_ID_LEN];
        rand::thread_rng().fill_bytes(&mut session_id);
        Ok(sessions::ServerSession {
            // fixed by server
            identity_keys: self.identity_keys.clone(),
            biased: self.biased,

            // generated per session
            session_id,
            len_seed: drbg::Seed::new().unwrap(),
            iat_seed: drbg::Seed::new().unwrap(),

            _state: sessions::Initialized {},
        })
    }
}
