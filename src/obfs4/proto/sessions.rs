//
//

use super::{CLIENT_MAX_PAD_LENGTH, CLIENT_MIN_PAD_LENGTH, IAT, SESSION_ID_LEN};
/// Session state management as a way to organize session establishment.
use crate::{
    common::{
        colorize, drbg, ntor,
        ntor::{HandShakeResult, Representative, AUTH_LENGTH, REPRESENTATIVE_LENGTH},
        replay_filter::ReplayFilter,
        HmacSha256,
    },
    obfs4::{
        constants::SEED_LENGTH,
        framing::{
            self, FrameError, Marshall, Obfs4Codec, TryParse, KEY_LENGTH, KEY_MATERIAL_LENGTH,
        },
        proto::{
            handshake_client::{self, ClientHandshake, ClientHandshakeState, HandshakeMaterials},
            handshake_server::ServerHandshakeMessage,
            O4Stream, Obfs4Stream, Server,
        },
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
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};

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

    _state: S,
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
    fn transition<T: ClientSessionState>(mut self, t: T) -> ClientSession<T> {
        ClientSession {
            session_keys: self.session_keys,
            node_id: self.node_id,
            node_pubkey: self.node_pubkey,
            session_id: self.session_id,
            iat_mode: self.iat_mode,
            epoch_hour: self.epoch_hour,

            len_seed: self.len_seed,
            _state: t,
        }
    }

    // Helper function to perform state transitions.
    fn fault<F: Fault + ClientSessionState>(mut self, f: F) -> ClientSession<F> {
        ClientSession {
            session_keys: self.session_keys,
            node_id: self.node_id,
            node_pubkey: self.node_pubkey,
            session_id: self.session_id,
            iat_mode: self.iat_mode,
            epoch_hour: self.epoch_hour,

            len_seed: self.len_seed,
            _state: f,
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
        _state: Initialized,
    }
}

impl ClientSession<Initialized> {
    pub async fn handshake<'a, T>(mut self, mut stream: &'a mut T) -> Result<Obfs4Stream<'a, T>>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let materials = HandshakeMaterials::new(
            &self.session_keys,
            &self.node_id,
            self.node_pubkey,
            self.session_id,
        );

        // set up for handshake
        let mut session = self.transition(ClientHandshaking { });

        // complete handshake
        let handshake = handshake_client::new(materials)?;
        let handshake = handshake.start(&mut stream).await?;
        let handshake = handshake.retrieve_server_response(&mut stream).await?;
        let handshake = handshake.complete().await?;

        // retrieve handshake artifacts on success
        let handshake_artifacts = handshake.to_inner();
        let mut codec = handshake_artifacts.codec;
        let mut remainder = handshake_artifacts.remainder;

        // post handshake state updates
        session.set_session_id(handshake_artifacts.session_id);
        let res = codec.decode(&mut remainder);
        if let Ok(Some(framing::Message::PrngSeed(seed))) = res {
            // try to parse the remainder of the server hello packet as a
            // PrngSeed since it should be there.
            let len_seed = drbg::Seed::from(seed);
            session.set_len_seed(len_seed);
        } else {
            debug!("NOPE {res:?}");
        }

        // mark session as Established
        let session_state: ClientSession<Established> = session.transition(Established{});
        info!("{} handshake complete", session_state.session_id());

        codec.handshake_complete();
        let mut o4 = O4Stream::new(stream, codec, Session::Client(session_state));

        Ok(Obfs4Stream::from_o4(o4))
    }
}

impl ClientSession<ClientHandshaking> {
    // pub(crate) fn handle_server_response(&mut self, server_hs: ServerHandshakeMessage, remainder: BytesMut) -> Result<Obfs4Codec> {
    //     let ntor_hs_result: HandShakeResult = match ntor::HandShakeResult::client_handshake(
    //         &self.session_keys,
    //         &server_hs.server_pubkey(),
    //         &self.node_pubkey,
    //         &self.node_id,
    //     )
    //     .into()
    //     {
    //         Some(r) => r,
    //         None => {
    //             self.fault();
    //             Err(Error::NtorError(ntor::NtorError::HSFailure(
    //             "failed to derive sharedsecret".into(),
    //         )))?
    //         }
    //     };

    //     // use the derived seed value to bootstrap Read / Write crypto codec.
    //     let okm = ntor::kdf(
    //         ntor_hs_result.key_seed,
    //         KEY_MATERIAL_LENGTH * 2 + SESSION_ID_LEN,
    //     );
    //     let ekm: [u8; KEY_MATERIAL_LENGTH] = okm[..KEY_MATERIAL_LENGTH].try_into().unwrap();
    //     let dkm: [u8; KEY_MATERIAL_LENGTH] = okm[KEY_MATERIAL_LENGTH..KEY_MATERIAL_LENGTH * 2]
    //         .try_into()
    //         .unwrap();
    //     self.set_session_id(okm[KEY_MATERIAL_LENGTH * 2..].try_into().unwrap());

    //     let mut codec = Obfs4Codec::new(ekm, dkm);
    //     let res = codec.decode(&mut remainder);
    //     if let Ok(Some(framing::Message::PrngSeed(seed))) = res {
    //         // try to parse the remainder of the server hello packet as a
    //         // PrngSeed since it should be there.
    //         self.set_len_seed(params.len_seed);
    //     } else {
    //         debug!("NOPE {res:?}");
    //     }
    //     Ok(codec)
    // }

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

    _state: S,
}

struct ServerHandshaking {}

struct ServerHandshakeFailed {
    details: String,
}

trait ServerSessionState {}
impl ServerSessionState for Initialized {}
impl ServerSessionState for ServerHandshaking {}
impl ServerSessionState for Established {}

impl ServerSessionState for ServerHandshakeFailed {}
impl Fault for ServerHandshakeFailed {}

impl<'a, S: ServerSessionState> ServerSession<'a, S> {
    pub fn session_id(&self) -> String {
        String::from("c-") + &colorize(&self.session_id)
    }

    pub(crate) fn set_session_id(&mut self, id: [u8; SESSION_ID_LEN]) {
        debug!(
            "{} -> {} server updating session id",
            colorize(&self.session_id),
            colorize(&id)
        );
        self.session_id = id;
    }
}

pub fn new_server_session<'a>(
    station_id: ntor::ID,
    station_pubkey: ntor::PublicKey,
    iat_mode: IAT,
) -> Result<ServerSession<'a, Initialized>> {

    Ok(ServerSession { iat_mode: (), node_id: (), identity_keys: (), replay_filter: (), session_keys: (), session_id: (), len_seed: (), iat_seed: (), _state: () })

}
impl<'b> ServerSession<'b, Initialized> {

    pub async fn handshake<'a, T>(mut self, mut stream: T) -> Result<Obfs4Stream<'a, T>>
    where
        'b: 'a,
        T: AsyncRead + AsyncWrite + Unpin,
    {

        // success!
        info!("{} handshake complete", self.session_id());

        codec.handshake_complete();

        let session = ServerSession {

            _state: Established{},
        };
        let mut o4 = O4Stream::new(&mut stream, codec, Session::Server(session));
        Ok(Obfs4Stream::from_o4(o4))
    }
}
