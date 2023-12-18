/// Package framing implements the obfs4 link framing and cryptography.
///
/// The Encoder/Decoder shared secret format is:
///
/// ```txt
///     NaCl_secretbox_key  [u8; 32];
///     NaCl_Nonce_prefix   [u8; 16];
///     SipHash_24_key      [u8; 16]; // (used to obfsucate length)
///     SipHash_24_IV       [u8; 8];
/// ```
///
/// The frame format is:
///
/// ```txt
///     length      u16; // (obfsucated, big endian)
///     // NaCl secretbox (Poly1305/XSalsa20) containing:
///         tag     [u8; 16]; // (Part of the secretbox construct)
///         payload [u8];
/// ```
///
/// The length field is length of the NaCl secretbox XORed with the truncated
/// SipHash-2-4 digest ran in OFB mode.
///
/// ```txt
///     // Initialize K, IV[0] with values from the shared secret.
///     // On each packet, IV[n] = H(K, IV[n - 1])
///     // mask_n = IV[n][0:2]
///     // obfs_len = length ^ mask[n]
/// ```
///
/// The NaCl secretbox (Poly1305/XSalsa20) nonce format is:
///
/// ```txt
///     prefix  [u8; 24]; //(Fixed)
///     counter u64; // (Big endian)
/// ```
///
/// The counter is initialized to 1, and is incremented on each frame.  Since
/// the protocol is designed to be used over a reliable medium, the nonce is not
/// transmitted over the wire as both sides of the conversation know the prefix
/// and the initial counter value.  It is imperative that the counter does not
/// wrap, and sessions MUST terminate before 2^64 frames are sent.
use crate::common::drbg::{self, Drbg, Seed};

use bytes::{Buf, BufMut, BytesMut};
use crypto_secretbox::{
    aead::{generic_array::GenericArray, Aead, AeadCore, KeyInit, OsRng},
    Nonce, XSalsa20Poly1305,
};
use futures::{Sink, SinkExt, Stream, StreamExt};
use rand::prelude::*;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::codec::{Decoder, Encoder};
use tracing::{error, trace};

mod packet;
pub use packet::*;

/// MaximumSegmentLength is the length of the largest possible segment
/// including overhead.
pub(crate) const MAX_SEGMENT_LENGTH: usize = 1500 - (40 + 12);

/// secret box overhead is fixed length prefix and counter
const SECRET_BOX_OVERHEAD: usize = TAG_SIZE;

/// FrameOverhead is the length of the framing overhead.
pub(crate) const FRAME_OVERHEAD: usize = LENGTH_LENGTH + SECRET_BOX_OVERHEAD;

/// MaximumFramePayloadLength is the length of the maximum allowed payload
/// per frame.
pub(crate) const MAX_FRAME_PAYLOAD_LENGTH: usize = MAX_SEGMENT_LENGTH - FRAME_OVERHEAD;

pub(crate) const MAX_FRAME_LENGTH: usize = MAX_SEGMENT_LENGTH - LENGTH_LENGTH;
pub(crate) const MIN_FRAME_LENGTH: usize = FRAME_OVERHEAD - LENGTH_LENGTH;

pub(crate) const NONCE_PREFIX_LENGTH: usize = 16;
pub(crate) const NONCE_COUNTER_LENGTH: usize = 8;
pub(crate) const NONCE_LENGTH: usize = NONCE_PREFIX_LENGTH + NONCE_COUNTER_LENGTH;

pub(crate) const LENGTH_LENGTH: usize = 2;

/// KEY_LENGTH is the length of the Encoder/Decoder secret key.
pub(crate) const KEY_LENGTH: usize = 32;

pub(crate) const TAG_SIZE: usize = 16;

pub(crate) const KEY_MATERIAL_LENGTH: usize = KEY_LENGTH + NONCE_PREFIX_LENGTH + drbg::SEED_LENGTH;

pub trait Marshall {
    fn marshall(&mut self, buf: &mut impl BufMut) -> Result<(), FrameError>;
}

pub trait TryParse {
    type Output;
    fn try_parse(&mut self, buf: &mut impl Buf) -> Result<Self::Output, FrameError>
    where
        Self: Sized;
}

// TODO: make this (Obfs4Codec) threadsafe
pub struct Obfs4Codec {
    // key: [u8; KEY_LENGTH],
    encoder: Obfs4Encoder,
    decoder: Obfs4Decoder,
}

impl Obfs4Codec {
    pub fn new(
        encoder_key_material: [u8; KEY_MATERIAL_LENGTH],
        decoder_key_material: [u8; KEY_MATERIAL_LENGTH],
    ) -> Self {
        // let mut key: [u8; KEY_LENGTH] =  key_material[..KEY_LENGTH].try_into().unwrap();
        Self {
            // key,
            encoder: Obfs4Encoder::new(encoder_key_material),
            decoder: Obfs4Decoder::new(decoder_key_material),
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
    next_length_invalid: bool,
}

impl Obfs4Decoder {
    // Creates a new Decoder instance.  It must be supplied a slice
    // containing exactly KeyLength bytes of keying material.
    fn new(key_material: [u8; KEY_MATERIAL_LENGTH]) -> Self {
        trace!("new decoder key_material: {}", hex::encode(&key_material));
        let mut key: [u8; KEY_LENGTH] = key_material[..KEY_LENGTH].try_into().unwrap();
        let nonce = NonceBox::new(&key_material[KEY_LENGTH..(KEY_LENGTH + NONCE_PREFIX_LENGTH)]);
        let seed = Seed::try_from(&key_material[(KEY_LENGTH + NONCE_PREFIX_LENGTH)..]).unwrap();
        let d = Drbg::new(Some(seed)).unwrap();

        Self {
            key,
            drbg: d,
            nonce,

            next_nonce: [0_u8; NONCE_LENGTH],
            next_length: 0,
            next_length_invalid: false,
        }
    }
}

impl Decoder for Obfs4Codec {
    type Item = Message;
    type Error = FrameError;

    // Decode decodes a stream of data and returns the length if any.  ErrAgain is
    // a temporary failure, all other errors MUST be treated as fatal and the
    // session aborted.
    fn decode(
        &mut self,
        src: &mut BytesMut,
    ) -> std::result::Result<Option<Self::Item>, Self::Error> {
        trace!(
            "decoding src:{}B {} {}",
            src.remaining(),
            self.decoder.next_length,
            self.decoder.next_length_invalid
        );
        // A length of 0 indicates that we do not know the expected size of
        // the next frame. we use this to store the length of a packet when we
        // receive the length at the beginning, but not the whole packet, since
        // future reads may not have the who packet (including length) available
        if self.decoder.next_length == 0 {
            // Attempt to pull out the next frame length
            if LENGTH_LENGTH > src.remaining() {
                return Ok(None);
            }

            // derive the nonce that the peer would have used
            self.decoder.next_nonce = self.decoder.nonce.next()?;

            // Remove the field length from the buffer
            // let mut len_buf: [u8; LENGTH_LENGTH] = src[..LENGTH_LENGTH].try_into().unwrap();
            let mut length = src.get_u16();

            // De-obfuscate the length field
            let length_mask = self.decoder.drbg.uint64() as u16;
            trace!(
                "decoding {length:04x}^{length_mask:04x} {:04x}B",
                length ^ length_mask
            );
            length ^= length_mask;
            if MAX_FRAME_LENGTH < length as usize || MIN_FRAME_LENGTH > length as usize {
                // Per "Plaintext Recovery Attacks Against SSH" by
                // Martin R. Albrecht, Kenneth G. Paterson and Gaven J. Watson,
                // there are a class of attacks againt protocols that use similar
                // sorts of framing schemes.
                //
                // While obfs4 should not allow plaintext recovery (CBC mode is
                // not used), attempt to mitigate out of bound frame length errors
                // by pretending that the length was a random valid range as pe
                // the countermeasure suggested by Denis Bider in section 6 of the
                // paper.

                let invalid_length = length;
                self.decoder.next_length_invalid = true;

                length = rand::thread_rng().gen::<u16>()
                    % (MAX_FRAME_LENGTH - MIN_FRAME_LENGTH) as u16
                    + MIN_FRAME_LENGTH as u16;
                error!(
                    "invalid length {invalid_length} {length} {}",
                    self.decoder.next_length_invalid
                );
            }

            self.decoder.next_length = length;
        }

        let next_len = self.decoder.next_length as usize;

        if next_len > src.len() {
            // The full string has not yet arrived.
            //
            // We reserve more space in the buffer. This is not strictly
            // necessary, but is a good idea performance-wise.
            if !self.decoder.next_length_invalid {
                src.reserve(next_len - src.len());
            }

            trace!(
                "next_len > src.len --> reading more {} {}",
                self.decoder.next_length,
                self.decoder.next_length_invalid
            );

            // We inform the Framed that we need more bytes to form the next
            // frame.
            return Ok(None);
        }

        // Use advance to modify src such that it no longer contains this frame.
        let data = src.get(..next_len).unwrap().to_vec();

        // Unseal the frame
        let key = GenericArray::from_slice(&self.decoder.key);
        let cipher = XSalsa20Poly1305::new(&key);
        let nonce = GenericArray::from_slice(&self.decoder.next_nonce); // unique per message

        let res = cipher.decrypt(&nonce, data.as_ref());
        if res.is_err() {
            let e = res.unwrap_err();
            trace!("failed to decrypt result: {e}");
            return Err(e.into());
        }
        let plaintext = res?;

        // Clean up and prepare for the next frame
        //
        // we read a whole frame, we no longer know the size of the next pkt
        self.decoder.next_length = 0;
        src.advance(next_len);

        trace!("decoded: {next_len}B src:{}B", src.remaining());
        let msg = Message::try_parse(&mut BytesMut::from(plaintext.as_slice()))?;

        Ok(Some(msg))
    }
}

/// Encoder is a frame encoder instance.
struct Obfs4Encoder {
    key: [u8; KEY_LENGTH],
    nonce: NonceBox,
    drbg: Drbg,
}

impl Obfs4Encoder {
    /// Creates a new Encoder instance. It must be supplied a slice
    /// containing exactly KeyLength bytes of keying material.  
    fn new(key_material: [u8; KEY_MATERIAL_LENGTH]) -> Self {
        trace!("new encoder key_material: {}", hex::encode(&key_material));
        let mut key: [u8; KEY_LENGTH] = key_material[..KEY_LENGTH].try_into().unwrap();
        let nonce = NonceBox::new(&key_material[KEY_LENGTH..(KEY_LENGTH + NONCE_PREFIX_LENGTH)]);
        let seed = Seed::try_from(&key_material[(KEY_LENGTH + NONCE_PREFIX_LENGTH)..]).unwrap();
        let d = Drbg::new(Some(seed)).unwrap();

        Self {
            key,
            nonce,
            drbg: d,
        }
    }
}

impl<T: Buf> Encoder<T> for Obfs4Codec {
    type Error = FrameError;

    /// Encode encodes a single frame worth of payload and returns
    /// [`InvalidPayloadLength`] is recoverable, all other errors MUST be
    /// treated as fatal and the session aborted.
    fn encode(
        &mut self,
        mut plaintext: T,
        dst: &mut BytesMut,
    ) -> std::result::Result<(), Self::Error> {
        trace!(
            "encoding {}/{MAX_FRAME_PAYLOAD_LENGTH}",
            plaintext.remaining()
        );

        // Don't send a string if it is longer than the other end will accept.
        if plaintext.remaining() > MAX_FRAME_PAYLOAD_LENGTH {
            return Err(FrameError::InvalidPayloadLength(plaintext.remaining()));
        }

        // Generate a new nonce
        let nonce_bytes = self.encoder.nonce.next()?;

        // Encrypt and MAC payload
        let key = GenericArray::from_slice(&self.encoder.key);
        let cipher = XSalsa20Poly1305::new(&key);
        let nonce = GenericArray::from_slice(&nonce_bytes); // unique per message

        let mut plaintext_u8 = vec![0_u8; plaintext.remaining()];
        plaintext.copy_to_slice(&mut plaintext_u8[..]);
        let mut ciphertext = cipher.encrypt(&nonce, plaintext_u8.as_ref())?;
        trace!("[encode] finished encrypting");

        // Obfuscate the length
        let mut length = ciphertext.len() as u16;
        let length_mask: u16 = self.encoder.drbg.uint64() as u16;
        trace!(
            "encoded {length}B, {length:04x}^{length_mask:04x} {:04x}",
            length ^ length_mask
        );
        length ^= length_mask;

        // Write the length and payload to the buffer.
        dst.extend_from_slice(&length.to_be_bytes()[..]);
        dst.extend_from_slice(&ciphertext);
        Ok(())
    }
}

/// internal nonce management for NaCl secret boxes
struct NonceBox {
    prefix: [u8; NONCE_PREFIX_LENGTH],
    counter: u64,
}

impl NonceBox {
    pub fn new(prefix: impl AsRef<[u8]>) -> Self {
        assert!(
            prefix.as_ref().len() >= NONCE_PREFIX_LENGTH,
            "prefix too short: {} < {NONCE_PREFIX_LENGTH}",
            prefix.as_ref().len()
        );
        Self {
            prefix: prefix.as_ref()[..NONCE_PREFIX_LENGTH].try_into().unwrap(),
            counter: 1,
        }
    }

    pub fn next(&mut self) -> std::result::Result<[u8; NONCE_LENGTH], FrameError> {
        // The security guarantee of Poly1305 is broken if a nonce is ever reused
        // for a given key.  Detect this by checking for counter wraparound since
        // we start each counter at 1.  If it ever happens that more than 2^64 - 1
        // frames are transmitted over a given connection, support for rekeying
        // will be neccecary, but that's unlikely to happen.

        if self.counter == u64::MAX {
            return Err(FrameError::NonceCounterWrapped);
        }
        let mut nonce = self.prefix.clone().to_vec();
        nonce.append(&mut self.counter.clone().to_be_bytes().to_vec());

        let nonce_l: [u8; NONCE_LENGTH] = nonce[..].try_into().unwrap();

        trace!("fresh nonce: {}", hex::encode(nonce_l));
        self.inc();
        Ok(nonce_l)
    }

    fn inc(&mut self) {
        self.counter += 1;
    }
}

impl std::error::Error for FrameError {}

#[derive(Debug, PartialEq, Eq)]
pub enum FrameError {
    /// is the error returned when [`encode`] rejects the payload length.
    InvalidPayloadLength(usize),

    /// A cryptographic error occured.
    Crypto(crypto_secretbox::Error),

    /// An error occured with the I/O processing
    IO(String),

    /// Returned when [`decode`] requires more data to continue.
    EAgain,

    /// Returned when [`decode`] failes to authenticate a frame.
    TagMismatch,

    /// Returned when the NaCl secretbox nonce's counter wraps (FATAL).
    NonceCounterWrapped,

    /// Returned when the buffer provided for writing a frame is too small.
    ShortBuffer,

    /// Error indicating that a message decoded, or a message provided for
    /// encoding is of an innapropriate type for the context.
    InvalidMessage,

    /// Failed while trying to parse a handshake message
    InvalidHandshake,

    /// Received either a REALLY unfortunate random, or a replayed handshake message
    ReplayedHandshake,

    /// An unknown packet type was received in a non-handshake packet frame.
    UnknownPacketType(u8),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            FrameError::InvalidPayloadLength(s) => {
                write!(f, "framing: Invalid payload length: {s}")
            }
            FrameError::Crypto(e) => write!(f, "framing: Secretbox encrypt/decrypt error: {e}"),
            FrameError::IO(e) => {
                write!(f, "framing: i/o error occured while processing frame: {e}")
            }
            FrameError::EAgain => write!(f, "framing: more data needed to decode"),
            FrameError::TagMismatch => write!(f, "framing: Poly1305 tag mismatch"),
            FrameError::NonceCounterWrapped => write!(f, "framing: Nonce counter wrapped"),
            FrameError::ShortBuffer => write!(
                f,
                "framing: provided bytes buffer was too short for payload"
            ),
            FrameError::InvalidMessage => write!(f, "framing: incorrect message for context"),
            FrameError::InvalidHandshake => write!(f, "framing: failed to parse handshake message"),
            FrameError::ReplayedHandshake => write!(f, "framing: handshake replayed within TTL"),
            FrameError::UnknownPacketType(pt) => write!(f, "framing: unknown packet type ({pt})"),
        }
    }
}

impl From<crypto_secretbox::Error> for FrameError {
    fn from(value: crypto_secretbox::Error) -> Self {
        FrameError::Crypto(value)
    }
}

impl From<std::io::Error> for FrameError {
    fn from(value: std::io::Error) -> Self {
        FrameError::IO(value.to_string())
    }
}

impl From<FrameError> for std::io::Error {
    fn from(value: FrameError) -> Self {
        std::io::Error::new(std::io::ErrorKind::Other, format!("{}", value))
    }
}

#[cfg(test)]
mod generic_test;
#[cfg(test)]
mod testing;
