//
//

use super::{CLIENT_MAX_PAD_LENGTH, CLIENT_MIN_PAD_LENGTH, IAT, SESSION_ID_LEN};
/// Session state management as a way to organize session establishment.

use crate::{
    common::{
        colorize, drbg, ntor,
        replay_filter::ReplayFilter,
        ntor::{HandShakeResult, AUTH_LENGTH, Representative, REPRESENTATIVE_LENGTH},
        HmacSha256,
    },
    obfs4::{
        framing::{self, FrameError, Marshall, Obfs4Codec, TryParse, KEY_LENGTH, KEY_MATERIAL_LENGTH},
        proto::{server::ServerHandshakeMessage, handshake_client, O4Stream, Obfs4Stream},
    },
    stream::Stream,
    Error, Result,
};


use bytes::{Buf, BufMut, BytesMut};
use hmac::{Hmac, Mac};
use rand::prelude::*;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::{
    codec::{Decoder, Encoder, Framed},
    io::{SinkWriter, StreamReader},
};
use tracing::{debug, info};

use std::io::{Error as IoError, ErrorKind as IoErrorKind};
use std::sync::{Arc, Mutex};
use std::marker::PhantomData;


/// Initial state for a Session, created with any params.
struct Initialized;

/// A session has completed the handshake and made it to steady state transfer.
struct Established;

/// The session broke due to something like a timeout, reset, lost connection, etc.
trait Fault {}


pub enum Session<'a> {
    Client(ClientSession<Established>),
    Server(ServerSession<'a, Established>),
}

impl<'a> Session<'a> {
    pub fn id(&self) -> String {
        match self {
            Session::Client(cs) => format!("c{}", cs.session_id()),
            Session::Server(ss) => format!("s{}", ss.session_id()),
        }
    }
}

// ================================================================ //
//                       Client States                              //
// ================================================================ //

struct ClientSession<S: ClientSessionState> {
    node_id: ntor::ID,
    node_pubkey: ntor::PublicKey,
    session_keys: ntor::SessionKeyPair,
    session_id: [u8; SESSION_ID_LEN],
    iat_mode: IAT, // TODO: add IAT normal / paranoid writing modes
    epoch_hour: String,

    len_seed: drbg::Seed, // TODO: initialize the distributions using the seed

    _state: PhantomData<S>,
}

struct ClientHandshakeFailed {
    details: String,
}

struct ClientHandshaking {}

trait ClientSessionState {}
impl ClientSessionState for Initialized {}
impl ClientSessionState for ClientHandshaking {}
impl ClientSessionState for Established {}

impl ClientSessionState for ClientHandshakeFailed {}
impl Fault for ClientHandshakeFailed {}

impl<S: ClientSessionState> ClientSession<S> {
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

    // Helper function to perform state transitions.
    fn transition<T: ClientSessionState>(mut self) -> ClientSession<T> {
        ClientSession {
            session_keys: self.session_keys,
            node_id: self.node_id,
            node_pubkey: self.node_pubkey,
            session_id: self.session_id,
            iat_mode: self.iat_mode,
            epoch_hour: self.epoch_hour,

            len_seed: self.len_seed,
            _state: PhantomData,
        }
    }

    // Helper function to perform state transitions.
    fn fault<F: Fault + ClientSessionState>(mut self) -> ClientSession<F> {
        ClientSession {
            session_keys: self.session_keys,
            node_id: self.node_id,
            node_pubkey: self.node_pubkey,
            session_id: self.session_id,
            iat_mode: self.iat_mode,
            epoch_hour: self.epoch_hour,

            len_seed: self.len_seed,
            _state: PhantomData,
        }
    }
}

pub fn new_client_session(
    station_id: ntor::ID,
    station_pubkey: ntor::PublicKey,
    iat_mode: IAT,
) -> ClientSession<Initialized> {
    let session_keys = ntor::SessionKeyPair::new(true);
    let session_id = session_keys.get_public().to_bytes()[..SESSION_ID_LEN]
        .try_into()
        .unwrap();
    ClientSession {
        session_keys,
        node_id: station_id,
        node_pubkey: station_pubkey,
        session_id,
        iat_mode,
        epoch_hour: "".into(),

        len_seed: drbg::Seed::new().unwrap(),
        _state: PhantomData,
    }
}

impl ClientSession<Initialized> {
    pub async fn handshake<'a, T>(mut self, mut stream: T) -> Result<Obfs4Stream<'a, T>>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {

        let session: ClientSession<ClientHandshaking> = self.transition();

        let materials = handshake_client::HandshakeMaterials {
            node_id: session.node_id,
            session_keys: session.session_keys,
            node_pubkey: session.node_pubkey,
            session_id: session.session_id,
            pad_len: rand::thread_rng().gen_range(CLIENT_MIN_PAD_LENGTH..CLIENT_MAX_PAD_LENGTH),
        };

        let handshake = handshake_client::start(stream, materials).await?;

        let handshake = handshake.retrieve_server_response(stream).await?;

        let codec = session.handle_server_response()?;

        let handshake = handshake.complete().await?;

        let params = handshake.to_inner();
        let session_state: ClientSession<Established> = self.transition();

        info!("{} handshake complete", self.session_id());

        codec.handshake_complete();
        let mut o4 = O4Stream::new(stream, codec, Session::Client(session_state));

        Ok(Obfs4Stream::from_o4(o4))
    }
}

impl ClientSession<ClientHandshaking> {
    pub(crate) fn handle_server_response(&mut self, server_hs: ServerHandshakeMessage, remainder: BytesMut) -> Result<Obfs4Codec> {
        let ntor_hs_result: HandShakeResult = match ntor::HandShakeResult::client_handshake(
            &self.session_keys,
            &server_hs.server_pubkey(),
            &self.node_pubkey,
            &self.node_id,
        )
        .into()
        {
            Some(r) => r,
            None => {
                self.fault();
                Err(Error::NtorError(ntor::NtorError::HSFailure(
                "failed to derive sharedsecret".into(),
            )))?
            }
        };

        // use the derived seed value to bootstrap Read / Write crypto codec.
        let okm = ntor::kdf(
            ntor_hs_result.key_seed,
            KEY_MATERIAL_LENGTH * 2 + SESSION_ID_LEN,
        );
        let ekm: [u8; KEY_MATERIAL_LENGTH] = okm[..KEY_MATERIAL_LENGTH].try_into().unwrap();
        let dkm: [u8; KEY_MATERIAL_LENGTH] = okm[KEY_MATERIAL_LENGTH..KEY_MATERIAL_LENGTH * 2]
            .try_into()
            .unwrap();
        self.set_session_id(okm[KEY_MATERIAL_LENGTH * 2..].try_into().unwrap());

        let mut codec = Obfs4Codec::new(ekm, dkm);
        let res = codec.decode(&mut remainder);
        if let Ok(Some(framing::Message::PrngSeed(seed))) = res {
            // try to parse the remainder of the server hello packet as a
            // PrngSeed since it should be there.
            session_state.set_len_seed(params.len_seed);
        } else {
            debug!("NOPE {res:?}");
        }
        Ok(codec)
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

impl<S: ClientSessionState> std::fmt::Debug for ClientSession<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[ id:{}, ident_pk:{}, sess_key:{:?}, iat:{:?}, epoch_hr:{} ]",
            hex::encode(self.node_id.as_bytes()),
            hex::encode(self.node_pubkey.as_bytes()),
            self.session_keys,
            self.iat_mode,
            self.epoch_hour,
        )
    }
}

// ================================================================ //
//                          Server States                           //
// ================================================================ //

struct ServerSession<'a, S: ServerSessionState> {
    // fixed by server
    iat_mode: IAT,
    node_id: ntor::ID,
    identity_keys: &'a ntor::IdentityKeyPair,
    replay_filter: &'a mut ReplayFilter,

    // generated per session
    session_keys: ntor::SessionKeyPair,
    session_id: [u8; SESSION_ID_LEN],
    len_seed: drbg::Seed,
    iat_seed: drbg::Seed,

    _state: PhantomData<S>,
}

struct ServerHandshakeSent;

struct ClientHandshakeReceived;

struct ServerHandshakeFailed {
    details: String,
}

trait ServerSessionState {}
impl ServerSessionState for Initialized {}
impl ServerSessionState for ServerHandshakeSent {}
impl ServerSessionState for ClientHandshakeReceived {}
impl ServerSessionState for Established {}

impl Fault for ServerHandshakeFailed {}

impl<'a, S: ServerSessionState> ServerSession<'a, S> {
    pub fn session_id(&self) -> String {
        String::from("c-") + &colorize(&self.session_id)
    }
}
