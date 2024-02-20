//! obfs4 session details and construction
//!
/// Session state management as a way to organize session establishment and
/// steady state transfer.
use crate::{
    common::{
        colorize, discard, drbg,
        ntor_arti::{ClientHandshake, RelayHandshakeError, ServerHandshake},
    },
    obfs4::{
        constants::*,
        framing,
        handshake::{
            CHSMaterials, Obfs4Keygen, Obfs4NtorClient, Obfs4NtorPublicKey, Obfs4NtorSecretKey,
            Obfs4NtorServer, SHSMaterials,
        },
        server::Server,
        proto::{O4Stream, Obfs4Stream, IAT},
    },
    Error, Result,
};

use bytes::BytesMut;
use rand_core::{CryptoRng, RngCore};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;
use tokio_util::codec::Decoder;
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
            Session::Server(ss) => ss.server.biased, //biased,
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
    let mut session_id = [0u8; SESSION_ID_LEN];
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

        let materials = CHSMaterials::new(session.node_pubkey, session.session_id());

        let mut rng = rand::thread_rng();

        // default deadline
        let d_def = Instant::now() + CLIENT_HANDSHAKE_TIMEOUT;
        let handshake_fut = Self::complete_handshake(&mut stream, materials, &mut rng, deadline);
        let (mut remainder, mut keygen) =
            match tokio::time::timeout_at(deadline.unwrap_or(d_def), handshake_fut).await {
                Ok(result) => match result {
                    Ok(handshake) => handshake,
                    Err(e) => {
                        // non-timeout error,
                        let id = session.session_id();
                        let _ = session.fault(ClientHandshakeFailed {
                            details: format!("{id} handshake failed {e}"),
                        });
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

        // post handshake state updates
        session.set_session_id(keygen.session_id());
        let mut codec: framing::Obfs4Codec = keygen.into();

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

    async fn complete_handshake<R, T>(
        mut stream: T,
        materials: CHSMaterials,
        mut rng: R,
        deadline: Option<Instant>,
    ) -> Result<(BytesMut, impl Obfs4Keygen)>
    where
        T: AsyncRead + AsyncWrite + Unpin,
        R: RngCore + CryptoRng,
    {
        let (state, chs_message) = Obfs4NtorClient::client1(&mut rng, &materials.node_pubkey, &())?;
        stream.write_all(&chs_message).await?;

        let mut buf = [0u8; MAX_HANDSHAKE_LENGTH];
        let n = stream.read(&mut buf).await?;

        match Obfs4NtorClient::client2(state, &buf[..n]) {
            Ok(r) => Ok(r),
            Err(e) => {
                // if a deadline was set and has not passed alread, discard
                // from the stream until the deadline, then close.
                if deadline.is_some_and(|d| d > Instant::now()) {
                    debug!("{} discarding due to: {e}", materials.session_id);
                    discard(&mut stream, deadline.unwrap() - Instant::now()).await?;
                }
                stream.shutdown().await?;
                return Err(e);
            }
        }
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
            "[ id:{}, ident_pk:{}, iat:{:?}, epoch_hr:{} ]",
            hex::encode(self.node_pubkey.id.as_bytes()),
            hex::encode(self.node_pubkey.pk.as_bytes()),
            self.iat_mode,
            self.epoch_hour,
        )
    }
}

// ================================================================ //
//                   Server Sessions States                         //
// ================================================================ //

pub(crate) struct ServerSession<'a, S: ServerSessionState> {
    // fixed by server
    identity_keys: &'a Obfs4NtorSecretKey,
    server: &'a Server,

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
            identity_keys: self.identity_keys,
            server: self.server,

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
            identity_keys: self.identity_keys,
            server: self.server,

            // generated per session
            session_id: self.session_id,
            len_seed: self.len_seed,
            iat_seed: self.iat_seed,

            _state: f,
        }
    }
}

pub fn new_server_session<'a>(server: &Server) -> Result<ServerSession<'a, Initialized>> {
    let mut session_id = [0u8; SESSION_ID_LEN];
    rand::thread_rng().fill_bytes(&mut session_id);
    Ok(ServerSession {
        // fixed by server
        identity_keys: &server.identity_keys,
        server,

        // generated per session
        session_id,
        len_seed: drbg::Seed::new().unwrap(),
        iat_seed: drbg::Seed::new().unwrap(),

        _state: Initialized {},
    })
}

impl<'b> ServerSession<'b, Initialized> {
    /// Attempt to complete the handshake with a new client connection.
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
            session.session_id(),
            session.len_seed.to_bytes(),
        );

        // complete handshake
        let mut rng = rand::thread_rng();

        // default deadline
        let d_def = Instant::now() + SERVER_HANDSHAKE_TIMEOUT;
        let handshake_fut = Self::complete_handshake(
            &mut stream,
            materials,
            &mut rng,
            deadline,
            &mut session.server,
        );
        let mut keygen =
            match tokio::time::timeout_at(deadline.unwrap_or(d_def), handshake_fut).await {
                Ok(result) => match result {
                    Ok(handshake) => handshake,
                    Err(e) => {
                        // non-timeout error,
                        let id = session.session_id();
                        let _ = session.fault(ServerHandshakeFailed {
                            details: format!("{id} handshake failed {e}"),
                        });
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
        let mut codec: framing::Obfs4Codec = keygen.into();

        // mark session as Established
        let session_state: ServerSession<Established> = session.transition(Established {});
        info!("{} handshake complete", session_state.session_id());

        codec.handshake_complete();
        let o4 = O4Stream::new(stream, codec, Session::Server(session_state));

        Ok(Obfs4Stream::from_o4(o4))
    }

    /// Complete the handshake with the client. This function assumes that the
    /// client has already sent a message and that we do not know yet if the
    /// message is valid.
    async fn complete_handshake<'k, R, T>(
        mut stream: T,
        materials: SHSMaterials<'k>,
        mut rng: R,
        deadline: Option<Instant>,
        server: &Server,
    ) -> Result<impl Obfs4Keygen>
    where
        T: AsyncRead + AsyncWrite + Unpin,
        R: RngCore + CryptoRng,
    {
        // wait for and attempt to consume the client hello message
        let mut buf = [0_u8; MAX_HANDSHAKE_LENGTH];
        loop {
            let n = stream.read(&mut buf).await?;
            trace!("{} successful read {n}B", materials.session_id);

            match Obfs4NtorServer::server(
                &mut rng,
                &mut |_: &()| Some(()),
                &[materials.identity_keys.clone()],
                server,
                &buf,
            ) {
                Ok((keygen, response)) => {
                    stream.write_all(&response).await?;
                    return Ok(keygen);
                }
                Err(RelayHandshakeError::EAgain) => {
                    trace!("{} reading more", materials.session_id);
                    continue;
                }
                Err(e) => {
                    trace!(
                        "{} failed to parse client handshake: {e}",
                        materials.session_id,
                    );
                    // if a deadline was set and has not passed already, discard
                    // from the stream until the deadline, then close.
                    if deadline.is_some_and(|d| d > Instant::now()) {
                        debug!("{} discarding due to: {e}", materials.session_id);
                        discard(&mut stream, deadline.unwrap() - Instant::now()).await?
                    }
                    stream.shutdown().await?;
                    return Err(e.into());
                }
            };
        }
    }
}
