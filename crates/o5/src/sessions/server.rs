use crate::{
    common::{
        discard, drbg,
        ntor_arti::{
            AuxDataReply, RelayHandshakeError, ServerHandshake, SessionID, SessionIdentifier,
        },
    },
    constants::*,
    framing,
    handshake::{NtorV3KeyGen, SHSMaterials},
    proto::{O5Stream, ObfuscatedStream},
    server::Server,
    sessions::{Established, Fault, Initialized, Session},
    Error, Result,
};

use std::io::{Error as IoError, ErrorKind as IoErrorKind};

use kemeleon::OKemCore;
use ptrs::{debug, info, trace};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

// ================================================================ //
//                   Server Sessions States                         //
// ================================================================ //

pub(crate) struct ServerSession<S: ServerSessionState> {
    // -------- fixed by server --------
    pub(crate) biased: bool,

    // pub(crate) server: &'a Server,

    // -------- generated per session --------
    /// Session Identifier
    ///
    /// Generated randomly to begin with then deterministically derived from the
    /// shared secret once session is established such that the client and server
    /// session_id values match.
    pub(crate) session_id: SessionID,
    /// Packet (padding) length seed
    ///
    /// Used when selecting lengths to add onto packets to obscure client data length.
    pub(crate) len_seed: drbg::Seed,
    /// Inter-packet timing seed
    ///
    /// Used when generating delays between packets.
    pub(crate) ipt_seed: drbg::Seed,

    pub(crate) _state: S,
}

pub(crate) struct ServerHandshaking {}

#[allow(unused)]
pub(crate) struct ServerHandshakeFailed {
    details: String,
}

pub(crate) trait ServerSessionState {}
impl ServerSessionState for Initialized {}
impl ServerSessionState for ServerHandshaking {}
impl ServerSessionState for Established {}

impl ServerSessionState for ServerHandshakeFailed {}
impl Fault for ServerHandshakeFailed {}

impl<S: ServerSessionState> ServerSession<S> {
    pub fn session_id(&self) -> String {
        String::from("s-") + &self.session_id.to_string()
    }

    pub(crate) fn biased(&self) -> bool {
        self.biased
    }

    pub fn len_seed(&self) -> drbg::Seed {
        self.len_seed.clone()
    }

    pub(crate) fn set_session_id(&mut self, id: SessionID) {
        debug!("{} -> {} server updating session id", self.session_id, id);
        self.session_id = id;
    }

    /// Helper function to perform state transitions.
    fn transition<T: ServerSessionState>(self, _state: T) -> ServerSession<T> {
        ServerSession {
            // fixed by server
            biased: self.biased,

            // generated per session
            session_id: self.session_id,
            len_seed: self.len_seed,
            ipt_seed: self.ipt_seed,

            _state,
        }
    }

    /// Helper function to perform state transition on error.
    fn fault<F: Fault + ServerSessionState>(self, f: F) -> ServerSession<F> {
        ServerSession {
            // fixed by server
            biased: self.biased,

            // generated per session
            session_id: self.session_id,
            len_seed: self.len_seed,
            ipt_seed: self.ipt_seed,

            _state: f,
        }
    }
}

impl ServerSession<Initialized> {
    /// Attempt to complete the handshake with a new client connection.
    pub async fn handshake<T, K>(
        self,
        server: &Server<K>,
        mut stream: T,
        extensions_handler: &mut impl AuxDataReply<Server<K>>,
        deadline: Option<Instant>,
    ) -> Result<O5Stream<T, K>>
    where
        T: AsyncRead + AsyncWrite + Unpin,
        K: OKemCore,
    {
        // set up for handshake
        let mut session = self.transition(ServerHandshaking {});

        let materials = SHSMaterials::new(session.session_id(), session.len_seed.to_bytes());

        // default deadline
        let d_def = Instant::now() + SERVER_HANDSHAKE_TIMEOUT;
        let handshake_fut =
            server.complete_handshake(&mut stream, extensions_handler, materials, deadline);

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
        let mut codec: framing::O5Codec = keygen.into();

        // mark session as Established
        let session_state: ServerSession<Established> = session.transition(Established {});

        codec.handshake_complete();
        let o4 = ObfuscatedStream::new(stream, codec, Session::Server(session_state));

        Ok(O5Stream::from_o4(o4))
    }
}

impl<K: OKemCore> Server<K> {
    /// Complete the handshake with the client. This function assumes that the
    /// client has already sent a message and that we do not know yet if the
    /// message is valid.
    async fn complete_handshake<REPLY: AuxDataReply<Self>, T>(
        &self,
        mut stream: T,
        reply_fn: &mut REPLY,
        materials: SHSMaterials,
        deadline: Option<Instant>,
    ) -> Result<impl NtorV3KeyGen<ID = SessionID>>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let session_id = materials.session_id.clone();

        // wait for and attempt to consume the client hello message
        let mut buf = [0_u8; MAX_HANDSHAKE_LENGTH];
        loop {
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                stream.shutdown().await?;
                return Err(IoError::from(IoErrorKind::UnexpectedEof).into());
            }
            trace!("{} successful read {n}B", session_id);

            match self.server(reply_fn, &materials, &buf[..n]) {
                Ok((keygen, response)) => {
                    stream.write_all(&response).await?;
                    info!("{} handshake complete", session_id);
                    return Ok(keygen);
                }
                Err(RelayHandshakeError::EAgain) => {
                    trace!("{} reading more", session_id);
                    continue;
                }
                Err(e) => {
                    trace!("{} failed to parse client handshake: {e}", session_id);
                    // if a deadline was set and has not passed already, discard
                    // from the stream until the deadline, then close.
                    if deadline.is_some_and(|d| d > Instant::now()) {
                        debug!("{} discarding due to: {e}", session_id);
                        discard(&mut stream, deadline.unwrap() - Instant::now()).await?
                    }
                    stream.shutdown().await?;
                    return Err(e.into());
                }
            };
        }
    }
}
