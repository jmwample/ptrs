use crate::{common::AsyncDiscard, stream::Stream, Result};

use tokio::io::AsyncWriteExt;
use tokio_util::bytes::Bytes;
use tracing::{trace, warn};

use std::time::Duration;

mod client;
pub(super) use client::{Client, ClientSession};
mod server;
pub(super) use server::{Server, ServerSession};

const TRANSPORT_NAME: &str = "obfs4";

const NODE_ID_ARG: &str = "node-id";
const PUBLIC_KEY_ARG: &str = "public-key";
const PRIVATE_KEY_ARG: &str = "private-key";
const SEED_ARG: &str = "drbg-seed";
const IAT_ARG: &str = "iat-mode";
const CERT_ARG: &str = "cert";

const BIAS_CMD_ARG: &str = "obfs4-distBias";
const CLIENT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);
const SERVER_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);
const REPLAY_TTL: Duration = Duration::from_secs(60);

const MAX_IAT_DELAY: usize = 100;
const MAX_CLOSE_DELAY: usize = 60;

#[derive(Default, Debug, Clone, Copy, PartialEq)]
enum IAT {
    #[default]
    Off,
    Enabled,
    Paranoid,
}

pub(super) enum Session<'a> {
    Server(ServerSession),
    Client(&'a ClientSession),
}

impl<'a> Session<'a> {
    pub(crate) async fn handshake(&self) -> Result<()> {
        todo!()
    }
}

pub struct Obfs4Stream<'a> {
    inner: &'a mut dyn Stream<'a>,
    session: Session<'a>,
    session_id: Vec<u8>,
}

impl<'a> Obfs4Stream<'a> {
    fn new(stream: &'a mut dyn Stream<'a>, owner: Session<'a>) -> Self {
        Self {
            inner: stream,
            session: owner,
            session_id: vec![0_u8; 16],
        }
    }

    async fn handshake(&mut self) -> Result<()> {
        self.session.handshake().await
    }

    async fn close_after_delay(&mut self, d: Duration) {
        let r = AsyncDiscard::new(&mut self.inner);

        if let Err(_) = tokio::time::timeout(d, r.discard()).await {
            trace!(
                "{} timed out while discarding",
                hex::encode(&self.session_id)
            );
        }
        if let Err(e) = self.inner.shutdown().await {
            warn!(
                "{} encountered an error while closing: {e}",
                hex::encode(&self.session_id)
            );
        };
    }

    fn pad_burst(&self, buf: Bytes, pad_to: u32) {}
}
