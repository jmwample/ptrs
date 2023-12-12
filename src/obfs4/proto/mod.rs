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
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio_util::{
    codec::{Decoder, Encoder, Framed},
    io::StreamReader,
};
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

pub struct Obfs4Stream<'a, T>
where
    T: AsyncRead + AsyncWrite,
{
    s: Arc<Mutex<O4Stream<'a, T>>>,
}

impl<'a, T> Obfs4Stream<'a, T>
where
    T: AsyncRead + AsyncWrite,
{
    pub(crate) fn from_o4(o4: O4Stream<'a, T>) -> Self {
        Obfs4Stream {
            s: Arc::new(Mutex::new(o4)),
        }
    }
}

struct O4Stream<'a, T>
where
    T: AsyncRead + AsyncWrite,
{
    // sink: Box<dyn Sink<B, Error=framing::FrameError>>,
    // stream: Box<dyn FStream<Item=std::result::Result<framing::Message, framing::FrameError>>>,
    stream: Framed<T, framing::Obfs4Codec>,

    session: Session<'a>,
}

impl<'a, T> O4Stream<'a, T>
where
    T: AsyncRead + AsyncWrite,
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

    async fn close_after_delay(&mut self, d: Duration) {
        // let r = AsyncDiscard::new(&mut StreamReader::new(self.stream));

        // if let Err(_) = tokio::time::timeout(d, r.discard()).await {
        //     trace!(
        //         "{} timed out while discarding",
        //         hex::encode(&self.session.id())
        //     );
        // }
        // if let Err(e) = self.sink.close().await {
        //     warn!(
        //         "{} encountered an error while closing: {e}",
        //         hex::encode(&self.session.id())
        //     );
        // };
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
        todo!()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<StdResult<(), IoError>> {
        todo!()
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<StdResult<(), IoError>> {
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
        todo!()
    }
}

impl<'a, T> AsyncWrite for Obfs4Stream<'a, T>
where
    T: AsyncRead + AsyncWrite,
{
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

impl<'a, T> AsyncRead for Obfs4Stream<'a, T>
where
    T: AsyncRead + AsyncWrite,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<StdResult<(), IoError>> {
        todo!()
    }
}
