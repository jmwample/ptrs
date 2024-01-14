use crate::{
    common::AsyncDiscard,
    obfs4::{
        constants::*,
        framing::{self, MessageType, MessageTypes},
    },
    Result,
};

use bytes::{Buf, BytesMut};
use futures::{Sink, Stream};
use pin_project::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio_util::codec::{Decoder, Framed};
use tracing::{debug, trace, warn};

use std::{
    io::Error as IoError,
    pin::Pin,
    result::Result as StdResult,
    task::{Context, Poll},
    time::Duration,
};

mod client;
pub(super) use client::Client;
mod server;
#[allow(unused)]
pub(super) use server::Server;

mod utils;
pub(crate) use utils::*;

mod sessions;
pub(crate) use sessions::Session;

mod handshake_client;
mod handshake_server;



#[allow(dead_code,unused)]
#[derive(Default, Debug, Clone, Copy, PartialEq)]
pub(crate) enum IAT {
    #[default]
    Off,
    Enabled,
    Paranoid,
}

#[pin_project]
pub struct Obfs4Stream<'a, T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    // s: Arc<Mutex<O4Stream<'a, T>>>,
    #[pin]
    s: O4Stream<'a, T>,
}

impl<'a, T> Obfs4Stream<'a, T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub(crate) fn from_o4(o4: O4Stream<'a, T>) -> Self {
        Obfs4Stream {
            // s: Arc::new(Mutex::new(o4)),
            s: o4,
        }
    }
}

#[pin_project]
pub(crate) struct O4Stream<'a, T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    #[pin]
    pub stream: Framed<T, framing::Obfs4Codec>,

    pub session: Session<'a>,
}

impl<'a, T> O4Stream<'a, T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub(crate) fn new(
        // inner: &'a mut dyn Stream<'a>,
        inner: T,
        codec: framing::Obfs4Codec,
        session: Session<'a>,
    ) -> O4Stream<'a, T> {
        let stream = codec.framed(inner);
        Self {
            stream,
            // reader: &StreamReader::new(&mut stream),
            // writer: &SinkWriter::new(&mut stream),
            session,
        }
    }


    pub(crate) fn try_recv_non_payload_packet(&mut self) -> Result<()> {
        let buf = self.stream.read_buffer_mut();

        if !buf.has_remaining() {
            return Ok(());
        } else if buf.remaining() < PACKET_OVERHEAD {
            return Ok(());
        }

        let proto_type = MessageTypes::try_from(buf[0])?;
        if proto_type == MessageTypes::Payload {
            return Ok(());
        }

        let length = u16::from_be_bytes(buf[1..3].try_into().unwrap()) as usize;

        if length > buf.remaining() - PACKET_OVERHEAD {
            // somehow we don't have the full packet yet.
            return Ok(());
        }

        // we have enough bytes. advance past the header and try to parse the frame.
        let m = framing::Messages::try_parse(buf)?;
        self.try_handle_non_payload_message(m)
    }


    pub(crate) fn try_handle_non_payload_message(&mut self, _msg: framing::Messages) -> Result<()> {
        {}

        Ok(())
    }

    pub(crate) async fn close_after_delay(&mut self, d: Duration) {
        let s = self.stream.get_mut();

        let r = AsyncDiscard::new(s);

        if let Err(_) = tokio::time::timeout(d, r.discard()).await {
            trace!(
                "{} timed out while discarding",
                hex::encode(self.session.id())
            );
        }

        let s = self.stream.get_mut();
        if let Err(e) = s.shutdown().await {
            warn!(
                "{} encountered an error while closing: {e}",
                hex::encode(self.session.id())
            );
        };
    }

    /// Attempts to pad a burst of data so that the last packet is of the length
    /// `to_pad_to`. This can involve creating multiple packets, making this
    /// slightly complex.
    ///
    /// TODO: document logic more clearly
    pub(crate) fn pad_burst(&self, buf: &mut BytesMut, to_pad_to: usize) -> Result<()> {
        let tail_len = buf.len() % framing::MAX_SEGMENT_LENGTH;

        let mut pad_len = 0;
        if to_pad_to >= tail_len {
            pad_len = to_pad_to - tail_len;
        } else {
            pad_len = (framing::MAX_SEGMENT_LENGTH - tail_len) + to_pad_to
        }

        if pad_len > HEADER_LENGTH {
            // pad_len > 19
            Ok(framing::build_and_marshall(
                buf,
                MessageTypes::Payload.into(),
                vec![],
                pad_len - HEADER_LENGTH,
            )?)
        } else if pad_len > 0 {
            framing::build_and_marshall(
                buf,
                MessageTypes::Payload.into(),
                vec![],
                framing::MAX_PACKET_PAYLOAD_LENGTH,
            )?;
            // } else {
            Ok(framing::build_and_marshall(
                buf,
                MessageTypes::Payload.into(),
                vec![],
                pad_len,
            )?)
        } else {
            Ok(())
        }
    }
}

impl<'a, T> AsyncWrite for O4Stream<'a, T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<StdResult<usize, IoError>> {
        trace!("{} writing", self.session.id());
        let mut this = self.as_mut().project();

        // is the stream ready to send an event?
        if futures::Sink::<&[u8]>::poll_ready(this.stream.as_mut(), cx) == Poll::Pending {
            return Poll::Pending;
        }
        debug!("here 1");

        // put the buf into the send queue for the framed to each chunks off and
        // send one piece at a time.
        match this.stream.as_mut().start_send(buf) {
            Ok(()) => {} // return Poll::Ready(Ok(buf.len())),
            Err(e) => return Poll::Ready(Err(e.into())),
        };

        debug!("here 2");
        match  self.poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }

        /*
        let mut this = self.as_mut().project();


        let msg_len = buf.len();

        // while we have bytes in the buffer write MAX_FRAME_PAYLOAD_LENGTH
        // chunks until we have less than that amount left.
        // TODO: asyncwrite - apply length_dist instead of just full payloads
        let mut len_sent: usize = 0;
        let mut out_buf = BytesMut::with_capacity(framing::MAX_FRAME_PAYLOAD_LENGTH);
        while msg_len - len_sent > framing::MAX_FRAME_PAYLOAD_LENGTH {
            let payload = framing::Message::Payload(
                buf[len_sent..len_sent + framing::MAX_FRAME_PAYLOAD_LENGTH].to_vec(),
            );

            // payload.marshall(&mut out_buf);
            this.stream.as_mut().start_send(&buf[len_sent..len_sent + framing::MAX_FRAME_PAYLOAD_LENGTH])?;

            len_sent += framing::MAX_FRAME_PAYLOAD_LENGTH;
            out_buf.clear();
        }

        let payload = framing::Message::Payload(buf[len_sent..].to_vec());

        let mut out_buf = BytesMut::new();
        payload.marshall(&mut out_buf);
        this.stream.as_mut().start_send(out_buf)?;
        */
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<StdResult<(), IoError>> {
        trace!("{} flushing", self.session.id());
        let mut this = self.project();
        match futures::Sink::<&[u8]>::poll_flush(this.stream.as_mut(), cx) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<StdResult<(), IoError>> {
        trace!("{} shutting down", self.session.id());
        let mut this = self.project();
        match futures::Sink::<&[u8]>::poll_close(this.stream.as_mut(), cx) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<'a, T> AsyncRead for O4Stream<'a, T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<StdResult<(), IoError>> {
        // trace!("{} reading", self.session.id());

        // If there is no payload from the previous Read() calls, consume data off
        // the network.  Not all data received is guaranteed to be usable payload,
        // so do this in a loop until we would block on a read or an error occurs.
        loop {
            let msg = {
                // mutable borrow of self is dropped at the end of this block
                let mut this = self.as_mut().project();
                match this.stream.as_mut().poll_next(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(res) => {
                        // TODO: when would this be None?
                        // It seems like this maybe happens when reading an EOF
                        // or reading from a closed connection
                        if res.is_none() {
                            return Poll::Ready(Ok(()));
                        }

                        match res.unwrap() {
                            Ok(m) => m,
                            Err(e) => Err(e)?,
                        }
                    }
                }
            };

            if let framing::Messages::Payload(message) = msg {
                buf.put_slice(&message);
                return Poll::Ready(Ok(()));
            }

            match self.as_mut().try_handle_non_payload_message(msg) {
                Ok(_) => continue,
                Err(e) => return Poll::Ready(Err(e.into())),
            }
        }
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
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<StdResult<(), IoError>> {
        let this = self.project();
        this.s.poll_read(cx, buf)
    }
}
