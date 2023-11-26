/// Package framing implements the obfs4 link framing and cryptography.
///
/// The Encoder/Decoder shared secret format is:
///
///     uint8_t[32] NaCl secretbox key
///     uint8_t[16] NaCl Nonce prefix
///     uint8_t[16] SipHash-2-4 key (used to obfsucate length)
///     uint8_t[8]  SipHash-2-4 IV
///
/// The frame format is:
///
///     uint16_t length (obfsucated, big endian)
///     NaCl secretbox (Poly1305/XSalsa20) containing:
///       uint8_t[16] tag (Part of the secretbox construct)
///       uint8_t[]   payload
///
/// The length field is length of the NaCl secretbox XORed with the truncated
/// SipHash-2-4 digest ran in OFB mode.
///
///     Initialize K, IV[0] with values from the shared secret.
///     On each packet, IV[n] = H(K, IV[n - 1])
///     mask[n] = IV[n][0:2]
///     obfsLen = length ^ mask[n]
///
/// The NaCl secretbox (Poly1305/XSalsa20) nonce format is:
///
///     uint8_t[24] prefix (Fixed)
///     uint64_t    counter (Big endian)
///
/// The counter is initialized to 1, and is incremented on each frame.  Since
/// the protocol is designed to be used over a reliable medium, the nonce is not
/// transmitted over the wire as both sides of the conversation know the prefix
/// and the initial counter value.  It is imperative that the counter does not
/// wrap, and sessions MUST terminate before 2^64 frames are sent.

use crate::common::drbg::{self, Drbg};

use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use tokio_util::codec::{Encoder,Decoder};
use bytes::{BytesMut, Buf};
use futures::{Sink, Stream, StreamExt, SinkExt};


// MaximumSegmentLength is the length of the largest possible segment
// including overhead.
const MAXIMUM_SEGMENT_LENGTH: usize = 1500 - (40 + 12);

// secre box overhead is fixed length prefix and counter
const SECRET_BOX_OVERHEAD: usize = NONCE_PREFIX_LENGTH + NONCE_COUNTER_LENGTH;

// FrameOverhead is the length of the framing overhead.
const FRAME_OVERHEAD: usize = LENGTH_LENGTH + SECRET_BOX_OVERHEAD;

// MaximumFramePayloadLength is the length of the maximum allowed payload
// per frame.
const MAXIMUM_FRAME_PAYLOAD_LENGTH: usize = MAXIMUM_SEGMENT_LENGTH - FRAME_OVERHEAD;


const MAX_FRAME_LENGTH: usize = MAXIMUM_SEGMENT_LENGTH - LENGTH_LENGTH;
const MIN_FRAME_LENGTH: usize = FRAME_OVERHEAD - LENGTH_LENGTH;

const NONCE_PREFIX_LENGTH: usize  = 16;
const NONCE_COUNTER_LENGTH: usize = 8;
const NONCE_LENGTH: usize = NONCE_PREFIX_LENGTH + NONCE_COUNTER_LENGTH;

const LENGTH_LENGTH: usize = 2;

const KEY_LENGTH: usize = 32;

// KeyLength is the length of the Encoder/Decoder secret key.
const KEY_MATERIAL_LENGTH: usize = KEY_LENGTH + NONCE_PREFIX_LENGTH + drbg::SEED_LENGTH;


/// 
struct NonceBox {
    prefix: [u8; NONCE_PREFIX_LENGTH],
    counter: u64,
}

/// Encoder is a frame encoder instance.
struct Obfs4Encoder {
    key: [u8; KEY_LENGTH],
    nonce: NonceBox,
    drbg: Drbg
}
impl Obfs4Encoder {
    fn new() -> Self {
        Self {
        }
    }
}

///Decoder is a frame decoder instance.
struct Obfs4Decoder {
    key: [u8; KEY_LENGTH],
    nonce: NonceBox,
    drbg: Drbg,

    next_nonce: [u8; NONCE_LENGTH],
    next_length: u16,
    next_length_inalid: bool,
}

impl Obfs4Decoder {
    fn new() -> Self {
        Self {
        }
    }
}

struct Obfs4Codec {
    encoder: Obfs4Encoder,
    decoder: Obfs4Decoder,
}

impl Obfs4Codec {
    fn new() -> Self {
        Self {
            encoder: Obfs4Encoder::new(),
            decoder: Obfs4Decoder::new(),
        }
    }
}


enum Obfs4Message {
    ClientHandshake,
    ServerHandshake,
    ProxyMessage,
}

impl Decoder for Obfs4Codec {
    type Item = Obfs4Message;
    type Error = std::io::Error;

    fn decode(
        &mut self,
        src: &mut BytesMut
    ) -> std::result::Result<Option<Self::Item>, Self::Error> {
        if src.len() < 4 {
            // Not enough data to read length marker.
            return Ok(None);
        }

        // Read length marker.
        let mut length_bytes = [0u8; 4];
        length_bytes.copy_from_slice(&src[..4]);
        let length = u32::from_le_bytes(length_bytes) as usize;

        // Check that the length is not too large to avoid a denial of
        // service attack where the server runs out of memory.
        if length > MAX {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Frame of length {} is too large.", length)
            ));
        }

        if src.len() < 4 + length {
            // The full string has not yet arrived.
            //
            // We reserve more space in the buffer. This is not strictly
            // necessary, but is a good idea performance-wise.
            src.reserve(4 + length - src.len());

            // We inform the Framed that we need more bytes to form the next
            // frame.
            return Ok(None);
        }

        // Use advance to modify src such that it no longer contains
        // this frame.
        let data = src[4..4 + length].to_vec();
        src.advance(4 + length);

        // Convert the data to a string, or fail if it is not valid utf-8.
        match String::from_utf8(data) {
            Ok(string) => Ok(Some(string)),
            Err(utf8_error) => {
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    utf8_error.utf8_error(),
                ))
            },
        }
    }
}


impl Encoder<String> for Obfs4Codec {
    type Error = std::io::Error;

    fn encode(&mut self, item: String, dst: &mut BytesMut) -> std::result::Result<(), Self::Error> {
        // Don't send a string if it is longer than the other end will
        // accept.
        if item.len() > MAX {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Frame of length {} is too large.", item.len())
            ));
        }

        // Convert the length into a byte array.
        // The cast to u32 cannot overflow due to the length check above.
        let len_slice = u32::to_le_bytes(item.len() as u32);

        // Reserve space in the buffer.
        dst.reserve(4 + item.len());

        // Write the length and string to the buffer.
        dst.extend_from_slice(&len_slice);
        dst.extend_from_slice(item.as_bytes());
        Ok(())
    }
}

#[cfg(test)]
mod testing;

#[cfg(test)]
mod generic_test;
