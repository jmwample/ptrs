//
//

use super::{IAT, SESSION_ID_LEN};
/// Session state management as a way to organize session establishment.
use crate::{
    common::{colorize, drbg, ntor, replay_filter::ReplayFilter},
    obfs4::{
        framing::{self},
        proto::{
            handshake_client::{self, HandshakeMaterials as CHSMaterials},
            handshake_server::{self, HandshakeMaterials as SHSMaterials},
            O4Stream, Obfs4Stream,
        },
    },
    Result,
};

use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::Decoder;
use tracing::{debug, info};

/// Initial state for a Session, created with any params.
pub(crate) struct Initialized;

/// A session has completed the handshake and made it to steady state transfer.
pub(crate) struct Established;

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

    pub fn biased(&self) -> bool {
        match self {
            Session::Client(cs) => cs.biased,
            Session::Server(ss) => ss.biased,
        }
    }

    pub fn len_seed(&self) -> drbg::Seed {
        match self {
            Session::Client(cs) => cs.len_seed.clone(),
            Session::Server(ss) => ss.len_seed.clone(),
        }
    }
}

// ================================================================ //
//                       Client States                              //
// ================================================================ //

pub(crate) struct ClientSession<S: ClientSessionState> {
    node_id: ntor::ID,
    node_pubkey: ntor::PublicKey,
    session_keys: ntor::SessionKeyPair,
    session_id: [u8; SESSION_ID_LEN],
    iat_mode: IAT, // TODO: add IAT normal / paranoid writing modes
    epoch_hour: String,

    biased: bool,

    len_seed: drbg::Seed,

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
        String::from("c-") + &colorize(self.session_id)
    }

    pub(crate) fn set_session_id(&mut self, id: [u8; SESSION_ID_LEN]) {
        debug!(
            "{} -> {} client updating session id",
            colorize(self.session_id),
            colorize(id)
        );
        self.session_id = id;
    }

    /// Helper function to perform state transitions.
    fn transition<T: ClientSessionState>(self, t: T) -> ClientSession<T> {
        ClientSession {
            session_keys: self.session_keys,
            node_id: self.node_id,
            node_pubkey: self.node_pubkey,
            session_id: self.session_id,
            iat_mode: self.iat_mode,
            epoch_hour: self.epoch_hour,
            biased: self.biased,

            len_seed: self.len_seed,
            _state: t,
        }
    }

    /// Helper function to perform state transitions.
    fn fault<F: Fault + ClientSessionState>(self, f: F) -> ClientSession<F> {
        ClientSession {
            session_keys: self.session_keys,
            node_id: self.node_id,
            node_pubkey: self.node_pubkey,
            session_id: self.session_id,
            iat_mode: self.iat_mode,
            epoch_hour: self.epoch_hour,
            biased: self.biased,

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
        biased: false,

        len_seed: drbg::Seed::new().unwrap(),
        _state: Initialized,
    }
}

impl ClientSession<Initialized> {
    pub async fn handshake<'a, T>(self, mut stream: T) -> Result<Obfs4Stream<'a, T>>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        // set up for handshake
        let mut session = self.transition(ClientHandshaking {});

        let materials = CHSMaterials::new(
            &session.session_keys,
            &session.node_id,
            session.node_pubkey,
            session.session_id,
        );

        // complete handshake
        let handshake = handshake_client::new(materials)?;
        let handshake = handshake.start(&mut stream).await?;
        let handshake = handshake.retrieve_server_response(&mut stream).await?;
        let handshake = handshake.complete().await?;

        // retrieve handshake artifacts on success
        let handshake_artifacts = handshake.take_state();
        let mut codec = handshake_artifacts.codec;
        let mut remainder = handshake_artifacts.remainder;

        // post handshake state updates
        session.set_session_id(handshake_artifacts.session_id);
        let res = codec.decode(&mut remainder);
        if let Ok(Some(framing::Messages::PrngSeed(seed))) = res {
            // try to parse the remainder of the server hello packet as a
            // PrngSeed since it should be there.
            let len_seed = drbg::Seed::from(seed);
            session.set_len_seed(len_seed);
        } else {
            debug!("NOPE {res:?}");
        }

        // mark session as Established
        let session_state: ClientSession<Established> = session.transition(Established {});
        info!("{} handshake complete", session_state.session_id());

        codec.handshake_complete();
        let o4 = O4Stream::new(stream, codec, Session::Client(session_state))?;

        Ok(Obfs4Stream::from_o4(o4))
    }
}

impl ClientSession<ClientHandshaking> {
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

pub(crate) struct ServerSession<'a, S: ServerSessionState> {
    // fixed by server
    iat_mode: IAT,
    node_id: ntor::ID,
    identity_keys: &'a ntor::IdentityKeyPair,
    replay_filter: &'a mut ReplayFilter,
    biased: bool,

    // generated per session
    session_keys: ntor::SessionKeyPair,
    session_id: [u8; SESSION_ID_LEN],
    len_seed: drbg::Seed,
    iat_seed: drbg::Seed,

    _state: S,
}

pub(crate) struct ServerHandshaking {}

pub(crate) struct ServerHandshakeFailed {
    details: String,
}

pub(crate) trait ServerSessionState {}
impl ServerSessionState for Initialized {}
impl ServerSessionState for ServerHandshaking {}
impl ServerSessionState for Established {}

impl ServerSessionState for ServerHandshakeFailed {}
impl Fault for ServerHandshakeFailed {}

impl<'a, S: ServerSessionState> ServerSession<'a, S> {
    pub fn session_id(&self) -> String {
        String::from("c-") + &colorize(self.session_id)
    }

    pub(crate) fn set_session_id(&mut self, id: [u8; SESSION_ID_LEN]) {
        debug!(
            "{} -> {} server updating session id",
            colorize(self.session_id),
            colorize(id)
        );
        self.session_id = id;
    }

    /// Helper function to perform state transitions.
    fn transition<'s, T: ServerSessionState>(self, _state: T) -> ServerSession<'s, T>
    where
        'a: 's,
    {
        ServerSession {
            // fixed by server
            node_id: self.node_id,
            iat_mode: self.iat_mode,
            identity_keys: self.identity_keys,
            replay_filter: self.replay_filter,
            biased: self.biased,

            // generated per session
            session_keys: self.session_keys,
            session_id: self.session_id,
            len_seed: self.len_seed,
            iat_seed: self.iat_seed,

            _state,
        }
    }

    /// Helper function to perform state transitions.
    fn fault<'s, F: Fault + ServerSessionState>(self, f: F) -> ServerSession<'s, F>
    where
        'a: 's,
    {
        ServerSession {
            // fixed by server
            node_id: self.node_id,
            iat_mode: self.iat_mode,
            identity_keys: self.identity_keys,
            replay_filter: self.replay_filter,
            biased: self.biased,

            // generated per session
            session_keys: self.session_keys,
            session_id: self.session_id,
            len_seed: self.len_seed,
            iat_seed: self.iat_seed,

            _state: f,
        }
    }
}

pub fn new_server_session<'a>(
    identity_keys: &'a ntor::IdentityKeyPair,
    node_id: ntor::ID,
    iat_mode: IAT,
    replay_filter: &'a mut ReplayFilter,
) -> Result<ServerSession<'a, Initialized>> {
    let session_keys = ntor::SessionKeyPair::new(true);

    Ok(ServerSession {
        // fixed by server
        node_id,
        iat_mode,
        identity_keys,
        replay_filter,
        biased: false,

        // generated per session
        session_id: session_keys.public.to_bytes()[..SESSION_ID_LEN]
            .try_into()
            .unwrap(),
        session_keys,
        len_seed: drbg::Seed::new().unwrap(),
        iat_seed: drbg::Seed::new().unwrap(),

        _state: Initialized {},
    })
}

impl<'b> ServerSession<'b, Initialized> {
    pub async fn handshake<'a, T>(self, mut stream: T) -> Result<Obfs4Stream<'a, T>>
    where
        'b: 'a,
        T: AsyncRead + AsyncWrite + Unpin,
    {
        // set up for handshake
        let mut session = self.transition(ServerHandshaking {});

        let materials = SHSMaterials::new(
            session.node_id.clone(),
            session.identity_keys,
            &session.session_keys,
            session.replay_filter,
            session.session_id,
            session.len_seed.to_bytes(),
        );

        // complete handshake
        let handshake = handshake_server::new(materials)?;
        let handshake = handshake.retrieve_client_handshake(&mut stream).await?;
        // let handshake = handshake.process_client_handshake(&mut stream).await?;
        let handshake = handshake.complete(&mut stream).await?;

        // retrieve handshake artifacts on success
        let handshake_artifacts = handshake.take_state();
        let mut codec = handshake_artifacts.codec;
        // let mut remainder = handshake_artifacts.remainder;

        // post handshake state updates
        session.set_session_id(handshake_artifacts.session_id);

        // let res = codec.decode(&mut remainder);
        // if let Ok(Some(framing::Message::PrngSeed(seed))) = res {
        //     // try to parse the remainder of the server hello packet as a
        //     // PrngSeed since it should be there.
        //     let len_seed = drbg::Seed::from(seed);
        //     session.set_len_seed(len_seed);
        // } else {
        //     debug!("NOPE {res:?}");
        // }

        // mark session as Established
        let session_state: ServerSession<Established> = session.transition(Established {});
        info!("{} handshake complete", session_state.session_id());

        codec.handshake_complete();
        let o4 = O4Stream::new(stream, codec, Session::Server(session_state))?;

        Ok(Obfs4Stream::from_o4(o4))
    }
}
