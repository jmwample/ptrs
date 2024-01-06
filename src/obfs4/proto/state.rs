//
//

use super::{CLIENT_MAX_PAD_LENGTH, CLIENT_MIN_PAD_LENGTH, IAT, SESSION_ID_LEN};
/// Session state management as a way to organize session establishment.

use crate::{
    Result,
    common::{colorize, drbg, ntor}
};

use std::marker::PhantomData;

use rand::prelude::*;
use tracing::debug;

/// Initial state for a Session, created with any params.
struct Initialized;

/// A session has completed the handshake and made it to steady state transfer.
struct Established;

/// The session broke due to something like a timeout, reset, lost connection, etc.
trait Fault {}

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
    pad_len: usize,

    len_seed: drbg::Seed, // TODO: initialize the distributions using the seed

    _state: PhantomData<S>,
}

struct ClientHandshaking;
struct ClientHandshakeFailed {
    details: String,
}

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
    fn transition<T:ClientSessionState>(mut self) -> ClientSession<T> {
        ClientSession {
            session_keys:  self.session_keys,
            node_id: self.node_id,
            node_pubkey: self.node_pubkey,
            session_id: self.session_id,
            iat_mode: self.iat_mode,
            epoch_hour: self.epoch_hour,
            pad_len: self.pad_len,

            len_seed: self.len_seed,
            _state:PhantomData,
        }
    }

    // Helper function to perform state transitions.
    fn fault<F:Fault+ClientSessionState>(mut self) -> ClientSession<F> {
        ClientSession {
            session_keys:  self.session_keys,
            node_id: self.node_id,
            node_pubkey: self.node_pubkey,
            session_id: self.session_id,
            iat_mode: self.iat_mode,
            epoch_hour: self.epoch_hour,
            pad_len: self.pad_len,

            len_seed: self.len_seed,
            _state:PhantomData,
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
        pad_len: rand::thread_rng().gen_range(CLIENT_MIN_PAD_LENGTH..CLIENT_MAX_PAD_LENGTH),

        len_seed: drbg::Seed::new().unwrap(),
        _state: PhantomData,
    }
}

impl ClientSession<Initialized> {
    pub fn handshake(mut self) -> Result<ClientSession<ClientHandshaking>>{
        Ok(self.transition())
    }
}

impl ClientSession<Established> {
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
            "[ id:{}, ident_pk:{}, sess_key:{:?}, iat:{:?}, epoch_hr:{}, pad_len:{} ]",
            hex::encode(self.node_id.as_bytes()),
            hex::encode(self.node_pubkey.as_bytes()),
            self.session_keys,
            self.iat_mode,
            self.epoch_hour,
            self.pad_len,
        )
    }
}


// ================================================================ //
//                          Server States                           //
// ================================================================ //

struct ServerSession<S: ServerSessionState> {
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

impl<S: ServerSessionState> ServerSession<S> {
    fn session_id() -> String {
        String::from("")
    }
}
