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

use crate::common::drbg::{self, Drbg, Seed};

use tracing::trace;
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use tokio_util::codec::{Encoder,Decoder};
use bytes::{BytesMut, Buf};
use futures::{Sink, Stream, StreamExt, SinkExt};
use crypto_secretbox::{
    aead::{AeadCore, Aead, KeyInit, OsRng, generic_array::GenericArray},
    XSalsa20Poly1305, Nonce,
};

/// MaximumSegmentLength is the length of the largest possible segment
/// including overhead.
const MAXIMUM_SEGMENT_LENGTH: usize = 1500 - (40 + 12);

/// secret box overhead is fixed length prefix and counter
const SECRET_BOX_OVERHEAD: usize = TAG_SIZE;

/// FrameOverhead is the length of the framing overhead.
const FRAME_OVERHEAD: usize = LENGTH_LENGTH + SECRET_BOX_OVERHEAD;

/// MaximumFramePayloadLength is the length of the maximum allowed payload
/// per frame.
const MAXIMUM_FRAME_PAYLOAD_LENGTH: usize = MAXIMUM_SEGMENT_LENGTH - FRAME_OVERHEAD;


const MAX_FRAME_LENGTH: usize = MAXIMUM_SEGMENT_LENGTH - LENGTH_LENGTH;
const MIN_FRAME_LENGTH: usize = FRAME_OVERHEAD - LENGTH_LENGTH;

const NONCE_PREFIX_LENGTH: usize  = 16;
const NONCE_COUNTER_LENGTH: usize = 8;
const NONCE_LENGTH: usize = NONCE_PREFIX_LENGTH + NONCE_COUNTER_LENGTH;

const LENGTH_LENGTH: usize = 2;

const KEY_LENGTH: usize = 32;

const TAG_SIZE: usize = 16;

/// KeyLength is the length of the Encoder/Decoder secret key.
const KEY_MATERIAL_LENGTH: usize = KEY_LENGTH + NONCE_PREFIX_LENGTH + drbg::SEED_LENGTH;


///Decoder is a frame decoder instance.
struct Obfs4Decoder {
    nonce: NonceBox,
    drbg: Drbg,

    next_nonce: [u8; NONCE_LENGTH],
    next_length: u16,
    next_length_inalid: bool,
}

impl Obfs4Decoder {
    // Creates a new Decoder instance.  It must be supplied a slice
    // containing exactly KeyLength bytes of keying material.
    fn new(key_material: [u8; KEY_MATERIAL_LENGTH]) -> Self {
        let mut key: [u8; KEY_LENGTH] =  key_material[..KEY_LENGTH].try_into().unwrap();
        let nonce = NonceBox::new(&key_material[KEY_LENGTH .. (KEY_LENGTH + NONCE_PREFIX_LENGTH)]);
        let seed = Seed::try_from(&key_material[(KEY_LENGTH+NONCE_PREFIX_LENGTH)..]).unwrap();
        let d = Drbg::new(Some(seed)).unwrap();

        Self {
            drbg: d,
            nonce,

            next_nonce: [0_u8; NONCE_LENGTH],
            next_length: 0,
            next_length_inalid: false,
        }
    }
}

struct Obfs4Codec {
    key: [u8; KEY_LENGTH],
    encoder: Obfs4Encoder,
    decoder: Obfs4Decoder,
}

impl Obfs4Codec {
    fn new(key_material: [u8; KEY_MATERIAL_LENGTH]) -> Self {
        let mut key: [u8; KEY_LENGTH] =  key_material[..KEY_LENGTH].try_into().unwrap();
        Self {
            key,
            encoder: Obfs4Encoder::new(key_material),
            decoder: Obfs4Decoder::new(key_material),
        }
    }
}

#[derive(Debug)]
enum Obfs4Message {
    ClientHandshake,
    ServerHandshake,
    ProxyPayload(Vec<u8>),
}

impl Decoder for Obfs4Codec {
    type Item = Obfs4Message;
    type Error = FrameError;

    // Decode decodes a stream of data and returns the length if any.  ErrAgain is
    // a temporary failure, all other errors MUST be treated as fatal and the
    // session aborted.
    fn decode(
        &mut self,
        src: &mut BytesMut
    ) -> std::result::Result<Option<Self::Item>, Self::Error> {
        trace!("decoding");
        // A length of 0 indicates that we do not know the expected size of
        // the next frame.
        if self.decoder.next_length == 0 {
            // Attempt to pull out the next frame length
            if LENGTH_LENGTH > src.len() {
                return Ok(None)
            }

            // Remove the field length from the buffer
            let mut len_buf: [u8; LENGTH_LENGTH] = src[..LENGTH_LENGTH].try_into().unwrap();

            // derive the nonce that the peer would have used
            self.decoder.next_nonce = self.decoder.nonce.next()?;

            // De-obfuscate the length field
            let mut length = u16::from_be_bytes(len_buf);
            let length_mask = self.decoder.drbg.uint64() as u16;
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
                self.decoder.next_length_inalid = true;
                getrandom::getrandom(&mut len_buf);
                length = u16::from_be_bytes(len_buf) % (MAX_FRAME_LENGTH-MIN_FRAME_LENGTH)as u16 + MIN_FRAME_LENGTH as u16;
                trace!("invalid length {invalid_length} {length} {}", self.decoder.next_length_inalid);
            }

            self.decoder.next_length = length;
        }

        let next_len = self.decoder.next_length as usize;

        if next_len > src.len() {
            // The full string has not yet arrived.
            //
            // We reserve more space in the buffer. This is not strictly
            // necessary, but is a good idea performance-wise.
            src.reserve(next_len - src.len());

            // We inform the Framed that we need more bytes to form the next
            // frame.
            return Ok(None);
        }

        // Use advance to modify src such that it no longer contains this frame.
        let data = src[2..2+next_len].to_vec();
        src.advance(2 + next_len);


        // Unseal the frame
        let key = GenericArray::from_slice(&self.key);
        let cipher = XSalsa20Poly1305::new(&key);
        let nonce = GenericArray::from_slice(&self.decoder.next_nonce); // unique per message

        let plaintext = cipher.decrypt(&nonce, data.as_ref())?;

        // Clean uo and prepare for the next frame
        self.decoder.next_length = 0;
        self.decoder.nonce.counter += 1;

        Ok(Some(Obfs4Message::ProxyPayload(plaintext)))
    }
}

/// Encoder is a frame encoder instance.
struct Obfs4Encoder {
    nonce: NonceBox,
    drbg: Drbg
}

impl Obfs4Encoder {
    /// Creates a new Encoder instance. It must be supplied a slice
    /// containing exactly KeyLength bytes of keying material.  
    fn new(key_material: [u8; KEY_MATERIAL_LENGTH]) -> Self {
        let mut key: [u8; KEY_LENGTH] =  key_material[..KEY_LENGTH].try_into().unwrap();
        let nonce = NonceBox::new(&key_material[KEY_LENGTH .. (KEY_LENGTH + NONCE_PREFIX_LENGTH)]);
        let seed = Seed::try_from(&key_material[(KEY_LENGTH + NONCE_PREFIX_LENGTH)..]).unwrap();
        let d = Drbg::new(Some(seed)).unwrap();

        Self {
            nonce,
            drbg: d,
        }
    }
}


impl Encoder<Obfs4Message> for Obfs4Codec {
    type Error = FrameError;

    /// Encode encodes a single frame worth of payload and returns
    /// [`InvalidPayloadLength`] is recoverable, all other errors MUST be
    /// treated as fatal and the session aborted.
    fn encode(&mut self, item: Obfs4Message, dst: &mut BytesMut) -> std::result::Result<(), Self::Error> {
        trace!("encoding");
        let item = match item {
            Obfs4Message::ProxyPayload(m) => m,
            _ => return Err(FrameError::InvalidMessage)
        };

        // Don't send a string if it is longer than the other end will accept.
        if MAXIMUM_FRAME_PAYLOAD_LENGTH < item.len() {
            return Err(FrameError::InvalidPayloadLength(item.len()));
        }

        // Generate a new nonce
        let nonce_bytes = self.encoder.nonce.next()?;

        // Encrypt and MAC payload
        let key = GenericArray::from_slice(&self.key);
        let cipher = XSalsa20Poly1305::new(&key);
        let nonce = GenericArray::from_slice(&nonce_bytes); // unique per message

        trace!("encode: all things generated");
        let ciphertext = cipher.encrypt(&nonce, item.as_ref())?;
        trace!("encode: encrypted");

        // Obfuscate the length
        let mut length = ciphertext.len() as u16;
        let length_mask: u16 = self.encoder.drbg.uint64() as u16;
        length ^= length_mask;

        // Reserve space in the buffer.
        dst.reserve(ciphertext.len() + LENGTH_LENGTH);

        // Write the length and string to the buffer.
        dst.extend_from_slice(&length.to_be_bytes());
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
        assert!(prefix.as_ref().len() >= NONCE_PREFIX_LENGTH, "prefix too short: {} < {NONCE_PREFIX_LENGTH}", prefix.as_ref().len());
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

        self.inc();
        Ok(nonce_l)
    }

    fn inc(&mut self) {
        self.counter += 1;
    }
}


impl std::error::Error for FrameError {}

#[derive(Debug, PartialEq, Eq)]
enum FrameError {
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
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            FrameError::InvalidPayloadLength(s) => write!(f, "framing: Invalid payload length: {s}"),
            FrameError::Crypto(e) => write!(f, "framing: Secretbox encrypt/decrypt error: {e}"),
            FrameError::IO(e) => write!(f, "framing: i/o error occured while processing frame: {e}"),
            FrameError::EAgain => write!(f, "framing: More data needed to decode"),
            FrameError::TagMismatch => write!(f, "framing: Poly1305 tag mismatch"),
            FrameError::NonceCounterWrapped => write!(f, "framing: Nonce counter wrapped"),
            FrameError::ShortBuffer => write!(f, "framing: provided bytes buffer was too short for payload"),
            FrameError::InvalidMessage => write!(f, "framing: incorrect message for context"),
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

#[cfg(test)]
mod testing;
#[cfg(test)]
mod generic_test;
