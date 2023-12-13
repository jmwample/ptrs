use crate::{
    common::{drbg, AsyncDiscard},
    obfs4::{
        constants::*,
        framing::{self, PacketType},
    },
    stream::Stream,
    Result,
};

use bytes::{Buf, BytesMut};
use futures::{
    sink::{Sink, SinkExt},
    stream::{Stream as FStream, StreamExt},
};
use pin_project::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio_util::{
    codec::{Decoder, Encoder, Framed},
    io::StreamReader,
};
use tracing::{debug, trace, warn};

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

use super::framing::LENGTH_LENGTH;

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
            Session::Client(cs) => format!("c{}", cs.session_id()),
            Session::Server(ss) => format!("s{}", ss.session_id()),
        }
    }
    pub(crate) fn set_len_seed(&mut self, seed: drbg::Seed) {
        debug!(
            "{} setting length seed {}",
            self.id(),
            hex::encode(seed.as_bytes())
        );
        match self {
            Session::Client(cs) => cs.set_len_seed(seed),
            _ => {} // pass}
        }
    }
}

#[pin_project]
pub struct Obfs4Stream<'a, T>
where
    T: AsyncRead + AsyncWrite,
{
    // s: Arc<Mutex<O4Stream<'a, T>>>,
    #[pin]
    s: O4Stream<'a, T>,
}

impl<'a, T> Obfs4Stream<'a, T>
where
    T: AsyncRead + AsyncWrite,
{
    pub(crate) fn from_o4(o4: O4Stream<'a, T>) -> Self {
        Obfs4Stream {
            // s: Arc::new(Mutex::new(o4)),
            s: o4,
        }
    }
}

#[pin_project]
struct O4Stream<'a, T>
where
    T: AsyncRead + AsyncWrite,
{
    #[pin]
    pub stream: Framed<T, framing::Obfs4Codec>,

    pub session: Session<'a>,
}

impl<'a, T> O4Stream<'a, T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn new(
        // inner: &'a mut dyn Stream<'a>,
        inner: T,
        codec: framing::Obfs4Codec,
        session: Session<'a>,
    ) -> Self {
        Self {
            stream: codec.framed(inner),
            session,
        }
    }

    fn try_handle_non_payload_packet(&mut self) -> Result<()> {
        let buf = self.stream.read_buffer_mut();

        debug!("ATTEMPTING TO PARSE EXPECTED PACKET");
        if !buf.has_remaining() {
            return Ok(());
        } else if buf.remaining() < PACKET_OVERHEAD {
            return Ok(());
        }

        debug!("HERHERE ({}) {}", buf.remaining(), buf[0]);
        let proto_type = PacketType::try_from(buf[0])?;
        if proto_type == PacketType::Payload {
            return Ok(());
        }

        let length = u16::from_be_bytes(buf[1..3].try_into().unwrap()) as usize;

        if length > buf.remaining() - PACKET_OVERHEAD {
            debug!("HERHERE {length} > {}", buf.remaining() - PACKET_OVERHEAD);
            // somehow we don't have the full packet yet.
            return Ok(());
        }

        // we have enough bytes. advance past the header and try to parse the frame.
        let m = framing::Message::try_parse(buf)?;
        if let framing::Message::PrngSeed(len_seed) = m {
            self.session.set_len_seed(drbg::Seed::from(len_seed));
        }

        Ok(())
    }

    async fn close_after_delay(&mut self, d: Duration) {
        let s = self.stream.get_mut();

        let r = AsyncDiscard::new(s);

        if let Err(_) = tokio::time::timeout(d, r.discard()).await {
            trace!(
                "{} timed out while discarding",
                hex::encode(&self.session.id())
            );
        }

        let s = self.stream.get_mut();
        if let Err(e) = s.shutdown().await {
            warn!(
                "{} encountered an error while closing: {e}",
                hex::encode(&self.session.id())
            );
        };
    }

    fn pad_burst(&self, buf: &mut BytesMut, to_pad_to: usize) -> Result<()> {
        let tail_len = buf.len() % framing::MAX_SEGMENT_LENGTH;

        let mut pad_len = 0;
        if to_pad_to >= tail_len {
            pad_len = to_pad_to - tail_len;
        } else {
            pad_len = (framing::MAX_SEGMENT_LENGTH - tail_len) + to_pad_to
        }

        let data = vec![];
        if pad_len > HEADER_LENGTH {
            // pad_len > 19
            Ok(framing::build_and_marshall(
                buf,
                PacketType::Payload,
                data,
                pad_len - HEADER_LENGTH,
            )?)
        } else if pad_len > 0 {
            // TODO: I think this double pad might be a mistake and there should
            // be an else in between.
            framing::build_and_marshall(
                buf,
                PacketType::Payload,
                data.clone(),
                framing::MAX_PACKET_PAYLOAD_LENGTH,
            )?;
            // } else {
            Ok(framing::build_and_marshall(
                buf,
                PacketType::Payload,
                data,
                pad_len,
            )?)
        } else {
            Ok(())
        }
    }
}

impl<'a, T> AsyncWrite for O4Stream<'a, T>
where
    T: AsyncRead + AsyncWrite,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<StdResult<usize, IoError>> {
        trace!("{} writing", self.session.id());
        todo!()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<StdResult<(), IoError>> {
        trace!("{} flushing", self.session.id());
        todo!()
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<StdResult<(), IoError>> {
        trace!("{} shutting down", self.session.id());
        todo!()
    }
}

impl<'a, T> AsyncRead for O4Stream<'a, T>
where
    T: AsyncRead + AsyncWrite,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<StdResult<(), IoError>> {
        trace!("{} reading", self.session.id());
        // let mut pinned = std::pin::pin!(self.stream);
        // pinned.as_mut().poll_read(cx, buf)
        todo!()
    }
}

impl<'a, T> AsyncWrite for Obfs4Stream<'a, T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<StdResult<usize, IoError>> {
        let this = self.project();
        this.s.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<StdResult<(), IoError>> {
        let this = self.project();
        this.s.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<StdResult<(), IoError>> {
        let this = self.project();
        this.s.poll_shutdown(cx)
    }
}

impl<'a, T> AsyncRead for Obfs4Stream<'a, T>
where
    T: AsyncRead + AsyncWrite,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<StdResult<(), IoError>> {
        let this = self.project();
        this.s.poll_read(cx, buf)
    }
}
