use crate::{
    common::{drbg, AsyncDiscard},
    obfs4::{
        constants::*,
        framing,
        packet::{self, Packet, PacketType},
    },
    stream::Stream,
    Result,
};

use bytes::BytesMut;
use hmac::{digest::Reset, Hmac, Mac};
use sha2::{Sha256, Sha256VarCore};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tracing::{trace, warn};

use std::{
    io::Error as IoError,
    pin::Pin,
    result::Result as StdResult,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

mod client;
pub(super) use client::{Client, ClientHandshake, ClientSession};
mod server;
pub(super) use server::{Server, ServerHandshake, ServerSession};
mod utils;
pub(crate) use utils::*;

pub(crate) type HmacSha256 = Hmac<Sha256>;

#[derive(Default, Debug, Clone, Copy, PartialEq)]
enum IAT {
    #[default]
    Off,
    Enabled,
    Paranoid,
}

pub(super) enum Session<'a> {
    Server(ServerSession<'a>),
    Client(ClientSession),
}

impl<'a> Session<'a> {
    fn id(&self) -> String {
        match self {
            Session::Client(cs) => cs.session_id(),
            Session::Server(ss) => ss.session_id(),
        }
    }
}

pub struct Obfs4Stream<'a> {
    s: Arc<Mutex<O4Stream<'a>>>,
}

impl<'a> Obfs4Stream<'a> {
    pub(crate) fn from_o4(o4: O4Stream<'a>) -> Self {
        Obfs4Stream {
            s: Arc::new(Mutex::new(o4)),
        }
    }
}

struct O4Stream<'a> {
    inner: &'a mut dyn Stream<'a>,
    session: Session<'a>,
    codec: framing::Obfs4Codec,
}

impl<'a> O4Stream<'a> {
    fn new(
        stream: &'a mut dyn Stream<'a>,
        codec: framing::Obfs4Codec,
        session: Session<'a>,
    ) -> Self {
        Self {
            inner: stream,
            session,
            codec,
        }
    }

    async fn close_after_delay(&mut self, d: Duration) {
        let r = AsyncDiscard::new(&mut self.inner);

        if let Err(_) = tokio::time::timeout(d, r.discard()).await {
            trace!(
                "{} timed out while discarding",
                hex::encode(&self.session.id())
            );
        }
        if let Err(e) = self.inner.shutdown().await {
            warn!(
                "{} encountered an error while closing: {e}",
                hex::encode(&self.session.id())
            );
        };
    }

    fn pad_burst(&self, buf: &mut BytesMut, to_pad_to: usize) -> Result<()> {
        let tail_len = buf.len();

        let mut pad_len = 0;
        if to_pad_to >= tail_len {
            pad_len = to_pad_to - tail_len;
        } else {
            pad_len = (framing::MAX_SEGMENT_LENGTH - tail_len) + to_pad_to
        }

        let data: Option<Vec<u8>> = None;
        if pad_len > HEADER_LENGTH {
            packet::build(buf, PacketType::Payload, data, pad_len - HEADER_LENGTH);
        } else if pad_len > 0 {
            // TODO: I think this double pad might be a mistake and there should be an else in
            // between
            packet::build(
                buf.clone(),
                PacketType::Payload,
                data.clone(),
                packet::MAX_PACKET_PAYLOAD_LENGTH,
            );
            // } else {
            packet::build(buf, PacketType::Payload, data, pad_len);
        }

        Ok(())
    }
}

impl<'a> AsyncWrite for Obfs4Stream<'a> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<StdResult<usize, IoError>> {
        todo!()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<StdResult<(), IoError>> {
        todo!()
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<StdResult<(), IoError>> {
        todo!()
    }
}

impl<'a> AsyncRead for Obfs4Stream<'a> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<StdResult<(), IoError>> {
        todo!()
    }
}
