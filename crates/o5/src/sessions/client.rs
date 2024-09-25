use crate::{
    common::{
        discard, drbg,
        ntor_arti::{
            ClientHandshake, KeyGenerator, RelayHandshakeError, SessionID, SessionIdentifier,
        },
    },
    constants::*,
    framing,
    handshake::{CHSMaterials, NtorV3Client, NtorV3KeyGen, NtorV3PublicKey},
    proto::{O4Stream, O5Stream, IAT},
    sessions::{Established, Fault, Initialized, Session},
    // server::Server,
    Error,
    Result,
};

use std::io::{Error as IoError, ErrorKind as IoErrorKind};

use bytes::BytesMut;
use ptrs::{debug, info};
use rand_core::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;
use tokio_util::codec::Decoder;

// ================================================================ //
//                       Client States                              //
// ================================================================ //

pub(crate) struct ClientSession<S: ClientSessionState> {
    node_pubkey: NtorV3PublicKey,
    session_id: SessionID,
    iat_mode: IAT, // TODO: add IAT normal / paranoid writing modes
    epoch_hour: String,

    biased: bool,

    len_seed: drbg::Seed,

    _state: S,
}

#[allow(unused)]
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
        String::from("c-") + &self.session_id.to_string()
    }

    pub(crate) fn set_session_id(&mut self, id: SessionID) {
        debug!("{} -> {} client updating session id", self.session_id, id);
        self.session_id = id;
    }

    pub(crate) fn biased(&self) -> bool {
        self.biased
    }

    pub fn len_seed(&self) -> drbg::Seed {
        self.len_seed.clone()
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
    station_pubkey: NtorV3PublicKey,
    iat_mode: IAT,
) -> ClientSession<Initialized> {
    let mut session_id = [0u8; SESSION_ID_LEN];
    rand::thread_rng().fill_bytes(&mut session_id);
    ClientSession {
        node_pubkey: station_pubkey,
        session_id: session_id.into(),
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
    pub async fn handshake<T>(self, mut stream: T, deadline: Option<Instant>) -> Result<O5Stream<T>>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        // set up for handshake
        let mut session = self.transition(ClientHandshaking {});

        let materials = CHSMaterials::new(&session.node_pubkey, session.session_id());

        // default deadline
        let d_def = Instant::now() + CLIENT_HANDSHAKE_TIMEOUT;
        let handshake_fut = Self::complete_handshake(&mut stream, materials, deadline);
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

        // post-handshake state updates
        session.set_session_id(keygen.session_id());
        let mut codec: framing::O5Codec = keygen.into();

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

        Ok(O5Stream::from_o4(o4))
    }

    async fn complete_handshake<T>(
        mut stream: T,
        materials: CHSMaterials,
        deadline: Option<Instant>,
    ) -> Result<(BytesMut, impl NtorV3KeyGen<ID = SessionID>)>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let (state, chs_message) = NtorV3Client::client1(&materials, &())?;
        // let mut file = tokio::fs::File::create("message.hex").await?;
        // file.write_all(&chs_message).await?;
        stream.write_all(&chs_message).await?;

        debug!(
            "{} handshake sent {}B, waiting for sever response",
            materials.session_id,
            chs_message.len()
        );

        let mut buf = [0u8; MAX_HANDSHAKE_LENGTH];
        loop {
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                Err(Error::IOError(IoError::new(
                    IoErrorKind::UnexpectedEof,
                    "read 0B in client handshake",
                )))?
            }
            debug!(
                "{} read {n}/{}B of server handshake",
                materials.session_id,
                buf.len()
            );

            match NtorV3Client::client2(state, &buf[..n]) {
                Ok(r) => return Ok(r),
                Err(Error::HandshakeErr(RelayHandshakeError::EAgain)) => continue,
                Err(e) => {
                    // if a deadline was set and has not passed already, discard
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
