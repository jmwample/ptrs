use crate::{
    common::{
        delay, drbg, probdist::{self, WeightedDist}
    },
    constants::*,
    framing,
    sessions::Session,
    Error, Result,
};

use bytes::{Buf, BytesMut};
use futures::{sink::Sink, stream::{Stream, StreamExt}};
use pin_project::pin_project;
use ptrs::trace;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Duration, Instant};
use tokio_util::codec::Framed;

use std::{
    io::Error as IoError,
    pin::Pin,
    result::Result as StdResult,
    task::{Context, Poll},
};

use super::framing::{FrameError, Messages};

#[allow(dead_code, unused)]
#[derive(Default, Debug, Clone, Copy, PartialEq)]
pub enum IAT {
    #[default]
    Off,
    Enabled,
    Paranoid,
}

pub trait Transport<B,E,I>: Sink<B, Error=E> + Stream<Item=I> + Unpin + Send {}

#[derive(Debug, Clone)]
pub(crate) enum MaybeTimeout {
    Default_,
    Fixed(Instant),
    Length(Duration),
    Unset,
}

impl std::str::FromStr for IAT {
    type Err = Error;
    fn from_str(s: &str) -> StdResult<Self, Self::Err> {
        match s {
            "0" => Ok(IAT::Off),
            "1" => Ok(IAT::Enabled),
            "2" => Ok(IAT::Paranoid),
            _ => Err(format!("invalid iat-mode '{s}'").into()),
        }
    }
}

impl std::fmt::Display for IAT {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IAT::Off => write!(f, "0")?,
            IAT::Enabled => write!(f, "1")?,
            IAT::Paranoid => write!(f, "2")?,
        }
        Ok(())
    }
}

impl MaybeTimeout {
    pub(crate) fn duration(&self) -> Option<Duration> {
        match self {
            MaybeTimeout::Default_ => Some(CLIENT_HANDSHAKE_TIMEOUT),
            MaybeTimeout::Fixed(i) => {
                if *i < Instant::now() {
                    None
                } else {
                    Some(*i - Instant::now())
                }
            }
            MaybeTimeout::Length(d) => Some(*d),
            MaybeTimeout::Unset => None,
        }
    }
}

#[pin_project]
pub struct Obfs4Stream {
    // s: Arc<Mutex<O4Stream<'a, T>>>,
    #[pin]
    s: O4Stream,
}

impl Obfs4Stream {
    pub(crate) fn from_o4(o4: O4Stream<>) -> Self {
        Obfs4Stream {
            // s: Arc::new(Mutex::new(o4)),
            s: o4,
        }
    }
}

#[pin_project]
pub(crate) struct O4Stream{
    #[pin]
    // pub stream: Framed<T, framing::Obfs4Codec>,
    // pub stream: Box<dyn Transport<BytesMut, IoError, Messages>>,
    pub stream: Box<dyn Stream<Item=Messages> + Send + Unpin>,
    #[pin]
    pub sink: Box<dyn Sink<BytesMut, Error=IoError> + Send + Unpin>,

    pub length_dist: probdist::WeightedDist,
    pub iat_dist: probdist::WeightedDist,

    pub session: Session,
}

impl O4Stream {
    pub(crate) fn new<T>(
        // inner: &'a mut dyn Stream<'a>,
        inner: T,
        codec: framing::Obfs4Codec,
        mut session: Session,
    ) -> O4Stream
    where
        T: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let delay_fn = match session.get_iat_mode() {
            IAT::Off => || Duration::ZERO,
            IAT::Enabled | IAT::Paranoid => session.iat_duration_sampler(),
        };
        let (sink, stream) = Framed::new(inner, codec).split();
        let sink = delay::DelayedSink::new(sink, delay_fn);

        let sink: Box<dyn Sink<BytesMut, Error = IoError> + Send + Unpin> = Box::new(sink);
        let stream: Box<dyn Stream<Item = Messages> + Send + Unpin> = Box::new(stream);

        let len_seed = session.len_seed();

        let mut hasher = Sha256::new();
        hasher.update(len_seed.as_bytes());
        // the result of a sha256 haash is 32 bytes (256 bits) so we will
        // always have enough for a seed here.
        let iat_seed = drbg::Seed::try_from(&hasher.finalize()[..SEED_LENGTH]).unwrap();

        let length_dist = WeightedDist::new(
            len_seed,
            0,
            framing::MAX_SEGMENT_LENGTH as i32,
            session.biased(),
        );
        let iat_dist = WeightedDist::new(
            iat_seed,
            0,
            framing::MAX_SEGMENT_LENGTH as i32,
            session.biased(),
        );

        Self {
            sink,
            stream,
            session,
            length_dist,
            iat_dist,
        }
    }

    pub(crate) fn try_handle_non_payload_message(&mut self, msg: framing::Messages) -> Result<()> {
        match msg {
            Messages::Payload(_) => Err(FrameError::InvalidMessage.into()),
            Messages::Padding(_) => Ok(()),

            // TODO: Handle other Messages
            _ => Ok(()),
        }
    }
}


impl AsyncWrite for O4Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<StdResult<usize, IoError>> {
        let msg_len = buf.remaining();
        let mut this = self.as_mut().project();

        // determine if the stream is ready to send an event?
        match futures::Sink::<BytesMut>::poll_ready(this.sink.as_mut(), cx) {
            Poll::Pending => return Poll::Pending,
            _ => {}
        }

        // while we have bytes in the buffer write MAX_MESSAGE_PAYLOAD_LENGTH
        // chunks until we have less than that amount left.
        // TODO: asyncwrite - apply length_dist instead of just full payloads
        let mut len_sent: usize = 0;
        let mut out_buf = BytesMut::with_capacity(framing::MAX_MESSAGE_PAYLOAD_LENGTH);
        while msg_len - len_sent > framing::MAX_MESSAGE_PAYLOAD_LENGTH {
            // package one chunk of the mesage as a payload
            let payload = framing::Messages::Payload(
                buf[len_sent..len_sent + framing::MAX_MESSAGE_PAYLOAD_LENGTH].to_vec(),
            );

            // send the marshalled payload
            payload.marshall(&mut out_buf)?;
            this.stream.as_mut().start_send(&mut out_buf)?;

            len_sent += framing::MAX_MESSAGE_PAYLOAD_LENGTH;
            out_buf.clear();

            // determine if the stream is ready to send more data. if not back off
            match futures::Sink::<BytesMut>::poll_ready(this.sink.as_mut(), cx) {
                Poll::Pending => return Poll::Ready(Ok(len_sent)),
                _ => {}
            }
        }

        let payload = framing::Messages::Payload(buf[len_sent..].to_vec());

        let mut out_buf = BytesMut::new();
        payload.marshall(&mut out_buf)?;
        this.sink.as_mut().start_send(out_buf)?;

        Poll::Ready(Ok(msg_len))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<StdResult<(), IoError>> {
        trace!("{} flushing", self.session.id());
        let mut this = self.project();
        match futures::Sink::<BytesMut>::poll_flush(this.sink.as_mut(), cx) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<StdResult<(), IoError>> {
        trace!("{} shutting down", self.session.id());
        let mut this = self.project();
        match futures::Sink::<BytesMut>::poll_close(this.sink.as_mut(), cx) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncRead for O4Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<StdResult<(), IoError>> {
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

                        res.unwrap()
                    }
                }
            };

            if let framing::Messages::Payload(message) = msg {
                buf.put_slice(&message);
                return Poll::Ready(Ok(()));
            }
            if let Messages::Padding(_) = msg {
                continue;
            }

            match self.as_mut().try_handle_non_payload_message(msg) {
                Ok(_) => continue,
                Err(e) => return Poll::Ready(Err(e.into())),
            }
        }
    }
}

impl AsyncWrite for Obfs4Stream {
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
        Sink::poll_flush(this.s, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<StdResult<(), IoError>> {
        let this = self.project();
        this.s.poll_shutdown(cx)
    }
}

impl AsyncRead for Obfs4Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<StdResult<(), IoError>> {
        let this = self.project();
        this.s.poll_read(cx, buf)
    }
}

impl Sink<BytesMut> for O4Stream {
    type Error = IoError;
    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<StdResult<(), Self::Error>> {
        todo!();
    }

    fn start_send(self: Pin<&mut Self>, _item: BytesMut) -> StdResult<(), Self::Error> {
        todo!();
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<StdResult<(), Self::Error>> {
        todo!();
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<StdResult<(), Self::Error>> {
        todo!();
    }
}

impl Stream for O4Stream {
    type Item = Messages;

    // Required method
    fn poll_next(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>
    ) -> Poll<Option<Self::Item>> {
        todo!();
    }
}

impl Transport<BytesMut, IoError, Messages> for O4Stream {}


// TODO Apply pad_burst logic and IAT policy to Message assembly (probably as part of AsyncRead / AsyncWrite impl)
/// Attempts to pad a burst of data so that the last [`Message`] is of the length
/// `to_pad_to`. This can involve creating multiple packets, making this
/// slightly complex.
///
/// TODO: document logic more clearly
pub(crate) fn pad_burst(buf: &mut BytesMut, to_pad_to: usize) -> Result<()> {
    let tail_len = buf.len() % framing::MAX_SEGMENT_LENGTH;

    let pad_len: usize = if to_pad_to >= tail_len {
        to_pad_to - tail_len
    } else {
        (framing::MAX_SEGMENT_LENGTH - tail_len) + to_pad_to
    };

    if pad_len > HEADER_LENGTH {
        // pad_len > 19
        Ok(framing::build_and_marshall(
            buf,
            framing::MessageTypes::Payload.into(),
            vec![],
            pad_len - HEADER_LENGTH,
        )?)
    } else if pad_len > 0 {
        framing::build_and_marshall(
            buf,
            framing::MessageTypes::Payload.into(),
            vec![],
            framing::MAX_MESSAGE_PAYLOAD_LENGTH,
        )?;
        // } else {
        Ok(framing::build_and_marshall(
            buf,
            framing::MessageTypes::Payload.into(),
            vec![],
            pad_len,
        )?)
    } else {
        Ok(())
    }
}

/*
///
/// Off:
///     pad burst = send max-frame-length frames while available, pad the last with
///     send with no delay
///     [                           msg                         ]
///     [  max-pkt  ][  max-pkt  ][  max-pkt  ][  max-pkt  ][pkt]{pad}
/// Enabled:
///     pad burst = send max-frame-length frames while available, pad the last with
///     send with sampled delay
///     [                           msg                         ]
///     [  max-pkt  ]... [  max-pkt  ]. [  max-pkt  ].. [  max-pkt  ].... [pkt]{pad}
/// Paranoid:
///     ??
///     send with sampled delay
///     [                           msg                         ]
///     [  max-pkt  ]... [  max-pkt  ]. [  max-pkt  ].. [  max-pkt  ].... [pkt]{pad}
fn split_and_pad(iat: IAT) {
    // Send maximum sized frames. while they are available
    let payload_chunks = b.chunks(MAX_MESSAGE_PAYLOAD_LENGTH);

    match iat {
        IAT::Off => {}
        IAT::Enabled => {}
        IAT::Paranoid => {}
    }
}


    if conn.iatMode != iatParanoid {
        // For non-paranoid IAT, pad once per burst.  Paranoid IAT handles
        // things differently.
        if err = conn.padBurst(&frameBuf, conn.lenDist.Sample()); err != nil {
            return 0, err
        }
    }

    // Write the pending data onto the network.  Partial writes are fatal,
    // because the frame encoder state is advanced, and the code doesn't keep
    // frameBuf around.  In theory, write timeouts and whatnot could be
    // supported if this wasn't the case, but that complicates the code.
    if conn.iatMode != iatNone {
        var iatFrame [framing.MaximumSegmentLength]byte
        for frameBuf.Len() > 0 {
            iatWrLen := 0

            switch conn.iatMode {
            case iatEnabled:
                // Standard (ScrambleSuit-style) IAT obfuscation optimizes for
                // bulk transport and will write ~MTU sized frames when
                // possible.
                iatWrLen, err = frameBuf.Read(iatFrame[:])

            case iatParanoid:
                // Paranoid IAT obfuscation throws performance out of the
                // window and will sample the length distribution every time a
                // write is scheduled.
                targetLen := conn.lenDist.Sample()
                if frameBuf.Len() < targetLen {
                    // There's not enough data buffered for the target write,
                    // so padding must be inserted.
                    if err = conn.padBurst(&frameBuf, targetLen); err != nil {
                        return 0, err
                    }
                    if frameBuf.Len() != targetLen {
                        // Ugh, padding came out to a value that required more
                        // than one frame, this is relatively unlikely so just
                        // resample since there's enough data to ensure that
                        // the next sample will be written.
                        continue
                    }
                }
                iatWrLen, err = frameBuf.Read(iatFrame[:targetLen])
            }
            if err != nil {
                return 0, err
            } else if iatWrLen == 0 {
                panic(fmt.Sprintf("BUG: Write(), iat length was 0"))
            }

            // Calculate the delay.  The delay resolution is 100 usec, leading
            // to a maximum delay of 10 msec.
            iatDelta := time.Duration(conn.iatDist.Sample() * 100)

            // Write then sleep.
            _, err = conn.Conn.Write(iatFrame[:iatWrLen])
            if err != nil {
                return 0, err
            }
            time.Sleep(iatDelta * time.Microsecond)
        }
    } else {
        _, err = conn.Conn.Write(frameBuf.Bytes())
    }

    return
}

/*
    chopBuf := bytes.NewBuffer(b)
    var payload [maxPacketPayloadLength]byte
    var frameBuf bytes.Buffer


    // Chop the pending data into payload frames.
    for chopBuf.Len() > 0 {
        rdLen := 0
        rdLen, err = chopBuf.Read(payload[:])
        if err != nil {
            return 0, err
        } else if rdLen == 0 {
            panic(fmt.Sprintf("BUG: Write(), chopping length was 0"))
        }
        n += rdLen

        err = conn.makePacket(&frameBuf, packetTypePayload, payload[:rdLen], 0)
        if err != nil {
            return 0, err
        }
    }
*/
*/
