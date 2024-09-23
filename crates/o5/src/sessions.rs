//! obfs4 session details and construction
//!
/// Session state management as a way to organize session establishment and
/// steady state transfer.
use crate::{
    common::{
        colorize, discard, drbg,
        ntor_arti::{KeyGenerator, RelayHandshakeError, ServerHandshake},
    },
    constants::*,
    framing,
    handshake::{CHSMaterials, NtorV3Client, NtorV3PublicKey, NtorV3SecretKey, SHSMaterials},
    proto::{O4Stream, O5Stream, IAT},
    // server::Server,
    Error,
    Result,
};

use std::io::{Error as IoError, ErrorKind as IoErrorKind};

use ptrs::{debug, info, trace};
use rand_core::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;
use tokio_util::codec::Decoder;

mod client;
use client::*;

mod server;
pub(crate) use server::ServerSession;

/// Initial state for a Session, created with any params.
pub(crate) struct Initialized;

/// A session has completed the handshake and made it to steady state transfer.
pub(crate) struct Established;

/// The session broke due to something like a timeout, reset, lost connection, etc.
trait Fault {}

pub enum Session {
    Client(ClientSession<Established>),
    Server(ServerSession<Established>),
}

impl Session {
    #[allow(unused)]
    pub fn id(&self) -> String {
        match self {
            Session::Client(cs) => format!("c{}", cs.session_id()),
            Session::Server(ss) => format!("s{}", ss.session_id()),
        }
    }

    pub fn biased(&self) -> bool {
        match self {
            Session::Client(cs) => cs.biased(),
            Session::Server(ss) => ss.biased, //biased,
        }
    }

    pub fn len_seed(&self) -> drbg::Seed {
        match self {
            Session::Client(cs) => cs.len_seed(),
            Session::Server(ss) => ss.len_seed(),
        }
    }
}
