use crate::framing::{self, FrameError};

// TODO: drbg for size sampling
//common::drbg,
//
// use futures::sink::{Sink, SinkExt};

use ptrs::trace;
use tokio_util::bytes::{Buf, BufMut};

pub(crate) const MESSAGE_OVERHEAD: usize = 2 + 1;
pub(crate) const MAX_MESSAGE_PAYLOAD_LENGTH: usize =
    framing::MAX_FRAME_PAYLOAD_LENGTH - MESSAGE_OVERHEAD;
// pub(crate) const MAX_MESSAGE_PADDING_LENGTH: usize = MAX_MESSAGE_PAYLOAD_LENGTH;

pub type MessageType = u8;
pub trait Message {
    type Output;
    fn as_pt(&self) -> MessageType;

    fn marshall<T: BufMut>(&self, dst: &mut T) -> Result<(), FrameError>;

    fn try_parse<T: BufMut + Buf>(buf: &mut T) -> Result<Self::Output, FrameError>;
}

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

    dst.put_u8(pt);
    dst.put_u16(buf.len() as u16);
    dst.put(buf);
    if pad_len != 0 {
        dst.put_bytes(0_u8, pad_len);
    }
    Ok(())
}
