use crate::{
    common::drbg,
    obfs4::framing::{self, FrameError, Messages},
};

use futures::sink::{Sink, SinkExt};

use tokio_util::bytes::{Buf, BufMut, Bytes, BytesMut};
use tracing::trace;

pub(crate) const MESSAGE_OVERHEAD: usize = 2 + 1;
pub(crate) const MAX_MESSAGE_PAYLOAD_LENGTH: usize =
    framing::MAX_FRAME_PAYLOAD_LENGTH - MESSAGE_OVERHEAD;
// pub(crate) const MAX_MESSAGE_PADDING_LENGTH: usize = MAX_MESSAGE_PAYLOAD_LENGTH;

pub(crate) const CONSUME_READ_SIZE: usize = framing::MAX_SEGMENT_LENGTH * 16;

pub type MessageType = u8;
pub trait Message {
    type Output;
    fn as_pt(&self) -> MessageType;

    fn marshall<T: BufMut>(&self, dst: &mut T) -> Result<(), FrameError>;

    fn try_parse<T: BufMut + Buf>(buf: &mut T) -> Result<Self::Output, FrameError>;
}

const SHA256_SIZE: usize = 32;
const MARK_LENGTH: usize = SHA256_SIZE / 2;
const MAC_LENGTH: usize = SHA256_SIZE / 2;

/// Frames are:
/// ```txt
///   type      u8;               // MessageType
///   length    u16               // Length of the payload (Big Endian).
///   payload   [u8; length];     // Data payload.
///   padding   [0_u8; pad_len];  // Padding.
/// ```
pub fn build_and_marshall<T: BufMut>(
    dst: &mut T,
    pt: MessageType,
    data: impl AsRef<[u8]>,
    pad_len: usize,
) -> Result<(), FrameError> {
    // is the provided pad_len too long?
    if pad_len > u16::MAX as usize {
        Err(FrameError::InvalidPayloadLength(pad_len))?
    }

    // is the provided data a reasonable size?
    let buf = data.as_ref();
    let total_size = buf.len() + pad_len;
    trace!(
        "building: total size = {}+{}={} / {MAX_MESSAGE_PAYLOAD_LENGTH}",
        buf.len(),
        pad_len,
        total_size,
    );
    if total_size >= MAX_MESSAGE_PAYLOAD_LENGTH {
        Err(FrameError::InvalidPayloadLength(total_size))?
    }

    dst.put_u8(pt.into());
    dst.put_u16(buf.len() as u16);
    dst.put(buf);
    if pad_len != 0 {
        dst.put_bytes(0_u8, pad_len);
    }
    Ok(())
}

/*
 * pub async fn send_payload<S, T>(sink: &mut S, buf: &T) -> Result<(), <S as Sink<Bytes>>::Error>
where
    S: Sink<Bytes> + Unpin,
    T: AsRef<[u8]>,
{
    let mut m = BytesMut::new();
    Messages::Payload(buf.as_ref().to_vec()).marshall(&mut m)?;

    sink.send(m.freeze()).await
}
*/
