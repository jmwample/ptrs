//
//

use std::vec;

use super::IAT;
/// Session state management as a way to organize session establishment.
use crate::{
    common::{
        colorize, discard, drbg, ntor_arti::{ClientHandshake, KeyGenerator, ServerHandshake}, replay_filter::ReplayFilter
    },
    obfs4::{
        constants::*, framing::{self, FrameError},
        handshake::{CHSMaterials, Obfs4NtorClient, Obfs4NtorPublicKey, Obfs4NtorSecretKey, Obfs4NtorServer, SHSMaterials},
        proto::{O4Stream, Obfs4Stream, CLIENT_HANDSHAKE_TIMEOUT},
    },
    Error, Result,
};

use rand_core::{RngCore, CryptoRng};
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use tokio::time::{Duration, Instant};
use tracing::{debug, info, trace};

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
    node_pubkey: Obfs4NtorPublicKey,
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

pub(crate) trait ClientSessionState {}
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
    station_pubkey: Obfs4NtorPublicKey,
    iat_mode: IAT,
) -> ClientSession<Initialized> {
    let mut session_id =  [0u8; SESSION_ID_LEN];
    rand::thread_rng().fill_bytes(&mut session_id);
    ClientSession {
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
    /// Perform a Handshake over the provided stream.
    /// ```
    ///
    /// ```
    ///
    /// TODO: make sure failure modes align with golang obfs4
    /// - FIN/RST based on buffered data.
    /// - etc.
    pub async fn handshake<'a, T>(
        self,
        mut stream: T,
        deadline: Option<Instant>,
    ) -> Result<Obfs4Stream<'a, T>>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        // set up for handshake
        let mut session = self.transition(ClientHandshaking {});

        let materials = CHSMaterials::new(
            session.node_pubkey,
            session.session_id,
        );

        let mut rng = rand::thread_rng();

        // default deadline
        let d_def = Instant::now() + CLIENT_HANDSHAKE_TIMEOUT;
        let handshake_fut = Self::complete_handshake(&mut stream, materials, &mut rng);
        let handshake =
            match tokio::time::timeout_at(deadline.unwrap_or(d_def), handshake_fut).await {
                Ok(result) => match result {
                    Ok(handshake) => handshake,
                    Err(e) => {
                        // non-timeout error,
                        let id = session.session_id();
                        let session = session.fault(ClientHandshakeFailed {
                            details: format!("{id} handshake failed {e}"),
                        });
                        // if a deadline was set and has not passed alread, discard
                        // from the stream until the deadline, then close.
                        if deadline.is_some_and(|d| d > Instant::now()) {
                            session
                                .discard(&mut stream, deadline.unwrap() - Instant::now())
                                .await?;
                        }
                        stream.shutdown().await?;
                        return Err(e);
                    }
                },
                Err(_) => {
                    let id = session.session_id();
                    let _ = session.fault(ClientHandshakeFailed {
                        details: format!("{id} timed out"),
                    });
                    return Err(Error::HandshakeTimeout);
                }
            };

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
        let o4 = O4Stream::new(stream, codec, Session::Client(session_state));

        Ok(Obfs4Stream::from_o4(o4))
    }

    async fn complete_handshake<'k, K, R, T>(
        mut stream: T,
        materials: CHSMaterials,
        rng: R,
    ) -> Result<K>
    where
        T: AsyncRead + AsyncWrite + Unpin,
        R: RngCore + CryptoRng,
        K: KeyGenerator + 'k,
    {
        // complete handshake
        let handshake = handshake_client::new(materials)?;
        let handshake = handshake.start(&mut stream).await?;
        let handshake = handshake.retrieve_server_response(&mut stream).await?;
        handshake.complete().await
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

impl ClientSession<ClientHandshakeFailed> {
    pub(crate) async fn discard<T>(&self, stream: T, d: Duration) -> Result<()>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        debug!("{} discarding due to: {}", self.session_id(), self._state.details);
        discard(stream, d).await
    }
}

impl<S: ClientSessionState> std::fmt::Debug for ClientSession<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[ id:{}, ident_pk:{}, iat:{:?}, epoch_hr:{} ]",
            hex::encode(self.node_pubkey.id.as_bytes()),
            hex::encode(self.node_pubkey.pk.as_bytes()),
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
    identity_keys: &'a Obfs4NtorSecretKey,
    replay_filter: &'a mut ReplayFilter,
    biased: bool,

    // generated per session
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
            iat_mode: self.iat_mode,
            identity_keys: self.identity_keys,
            replay_filter: self.replay_filter,
            biased: self.biased,

            // generated per session
            session_id: self.session_id,
            len_seed: self.len_seed,
            iat_seed: self.iat_seed,

            _state,
        }
    }

    /// Helper function to perform state transition on error.
    fn fault<'s, F: Fault + ServerSessionState>(self, f: F) -> ServerSession<'s, F>
    where
        'a: 's,
    {
        ServerSession {
            // fixed by server
            iat_mode: self.iat_mode,
            identity_keys: self.identity_keys,
            replay_filter: self.replay_filter,
            biased: self.biased,

            // generated per session
            session_id: self.session_id,
            len_seed: self.len_seed,
            iat_seed: self.iat_seed,

            _state: f,
        }
    }
}

pub fn new_server_session<'a>(
    identity_keys: &'a Obfs4NtorSecretKey,
    iat_mode: IAT,
    replay_filter: &'a mut ReplayFilter,
) -> Result<ServerSession<'a, Initialized>> {

    let mut session_id =  [0u8; SESSION_ID_LEN];
    rand::thread_rng().fill_bytes(&mut session_id);
    Ok(ServerSession {
        // fixed by server
        iat_mode,
        identity_keys,
        replay_filter,
        biased: false,

        // generated per session
        session_id,
        len_seed: drbg::Seed::new().unwrap(),
        iat_seed: drbg::Seed::new().unwrap(),

        _state: Initialized {},
    })
}

impl<'b> ServerSession<'b, Initialized> {
    pub async fn handshake<'a, T>(
        self,
        mut stream: T,
        deadline: Option<Instant>,
    ) -> Result<Obfs4Stream<'a, T>>
    where
        'b: 'a,
        T: AsyncRead + AsyncWrite + Unpin,
    {
        // set up for handshake
        let mut session = self.transition(ServerHandshaking {});

        let materials = SHSMaterials::new(
            session.identity_keys,
            session.replay_filter,
            session.session_id(),
            session.len_seed.to_bytes(),
        );

        // complete handshake
        let rng = rand::thread_rng();

        // default deadline
        let d_def = Instant::now() + SERVER_HANDSHAKE_TIMEOUT;
        let handshake_fut = Self::complete_handshake(&mut stream, materials, &mut rng);
        let keygen =
            match tokio::time::timeout_at(deadline.unwrap_or(d_def), handshake_fut).await {
                Ok(result) => match result {
                    Ok(handshake) => handshake,
                    Err(e) => {
                        // non-timeout error,
                        let id = session.session_id();
                        let session = session.fault(ServerHandshakeFailed {
                            details: format!("{id} handshake failed {e}"),
                        });
                        // if a deadline was set and has not passed alread, discard
                        // from the stream until the deadline, then close.
                        if deadline.is_some_and(|d| d > Instant::now()) {
                            session
                                .discard(&mut stream, deadline.unwrap() - Instant::now())
                                .await?;
                        }
                        stream.shutdown().await?;
                        return Err(e);
                    }
                },
                Err(_) => {
                    let id = session.session_id();
                    let _ = session.fault(ServerHandshakeFailed {
                        details: format!("{id} timed out"),
                    });
                    return Err(Error::HandshakeTimeout);
                }
            };

        // post handshake state updates
        session.set_session_id(keygen.session_id());
        let codec = keygen.take_codec();

        // mark session as Established
        let session_state: ServerSession<Established> = session.transition(Established {});
        info!("{} handshake complete", session_state.session_id());

        codec.handshake_complete();
        let o4 = O4Stream::new(stream, codec, Session::Server(session_state));

        Ok(Obfs4Stream::from_o4(o4))
    }

    async fn complete_handshake<'k, K, R, T>(
        mut stream: T,
        materials: SHSMaterials<'k>,
        rng: R,
    ) -> Result<K>
    where
        T: AsyncRead + AsyncWrite + Unpin,
        R: RngCore + CryptoRng,
        K: KeyGenerator + 'k,
    {
        // wait for and attempt to consume the client hello message
        let mut buf = [0_u8; MAX_HANDSHAKE_LENGTH];
        let keygen: K;
        let mut response: Vec<u8> = vec![];
        loop {
            let n = stream.read(&mut buf).await?;
            trace!("{} successful read {n}B", materials.session_id);

            let mut relay_ntsks = [*materials.identity_keys];

            let (kg, response) = match Obfs4NtorServer::server(&mut rng, &mut |_: &()| Some(()), &relay_ntsks[..], &buf){
                Ok(chs) => chs,
                Err(crate::common::ntor_arti::RelayHandshakeError::Fmt(tor_bytes::Error::Truncated)) => {
                    trace!("{} reading more", materials.session_id);
                    continue;
                }
                Err(e) => {
                    trace!(
                        "{} failed to parse client handshake: {e}",
                        materials.session_id,
                    );
                    return Err(e.into());
                }
            };

            break;
        }

        stream.write_all(&response).await?;

        Ok(keygen)

        // let handshake = handshake_server::new(materials)?;
        // let handshake = handshake.retrieve_client_handshake(&mut stream).await?;
        // handshake.complete(&mut stream).await
    }
}

impl<'b> ServerSession<'b, ServerHandshakeFailed> {
    pub(crate) async fn discard<T>(&self, stream: T, d: Duration) -> Result<()>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        debug!("{} discarding due to: {}", self.session_id(), self._state.details);
        discard(stream, d).await
    }
}
