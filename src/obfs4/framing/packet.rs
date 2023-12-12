use crate::{
    common::{
        drbg,
        elligator2::{Representative, REPRESENTATIVE_LENGTH},
        ntor, HmacSha256,
    },
    obfs4::{
        constants::*,
        framing::{self, FrameError, Marshall, TryParse, LENGTH_LENGTH},
    },
    Error,
};

use std::io::Cursor;
use std::time::{SystemTime, UNIX_EPOCH};

use rand_core::{OsRng, RngCore};
use subtle::ConstantTimeEq;
use tokio_util::bytes::{Buf, BufMut, Bytes, BytesMut};
use tracing::trace;

pub(crate) const PACKET_OVERHEAD: usize = 2 + 1;
pub(crate) const MAX_PACKET_PAYLOAD_LENGTH: usize =
    framing::MAX_FRAME_PAYLOAD_LENGTH - PACKET_OVERHEAD;
pub(crate) const MAX_PACKET_PADDING_LENGTH: usize = MAX_PACKET_PAYLOAD_LENGTH;
pub(crate) const SEED_PACKET_PAYLOAD_LENGTH: usize = drbg::SEED_LENGTH;

pub(crate) const CONSUME_READ_SIZE: usize = framing::MAX_SEGMENT_LENGTH * 16;

const SHA256_SIZE: usize = 32;
const MARK_LENGTH: usize = SHA256_SIZE / 2;
const MAC_LENGTH: usize = SHA256_SIZE / 2;

/// Frames are:
/// ```txt
///   type      u8;               // packetTypePayload (0x00)
///   length    u16               // Length of the payload (Big Endian).
///   payload   [u8; length];     // Data payload.
///   padding   [0_u8; pad_len];  // Padding.
/// ```
pub fn build_and_marshall<T: BufMut>(
    dst: &mut T,
    pt: PacketType,
    data: impl AsRef<[u8]>,
    pad_len: usize,
) -> Result<(), FrameError> {
    // is the provided pad_len too long?
    if pad_len > u16::MAX as usize {
        Err(FrameError::InvalidPayloadLength(pad_len))?
    }
    // is the provided data a reasonable size?
    let buf = data.as_ref();
    let total_size = PACKET_OVERHEAD + buf.len() + pad_len;
    if total_size > MAX_PACKET_PAYLOAD_LENGTH {
        Err(FrameError::InvalidPayloadLength(total_size))?
    }

    dst.put_u8(pt.into());
    dst.put_u16(buf.len() as u16);
    dst.put(buf);
    dst.put_bytes(0_u8, pad_len);
    Ok(())
}

#[derive(Debug)]
pub enum PacketType {
    Payload,
    PrngSeed,
}
impl PacketType {
    const PAYLOAD: u8 = 0;
    const PRNG_SEED: u8 = 1;
}

impl From<PacketType> for u8 {
    fn from(value: PacketType) -> Self {
        match value {
            PacketType::Payload => 0_u8,
            PacketType::PrngSeed => 1_u8,
        }
    }
}

impl TryFrom<u8> for PacketType {
    type Error = FrameError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            PacketType::PAYLOAD => Ok(PacketType::Payload),
            PacketType::PRNG_SEED => Ok(PacketType::PrngSeed),
            _ => Err(FrameError::UnknownPacketType(value)),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum Message {
    Payload(Vec<u8>),
    PrngSeed([u8; SEED_LENGTH]),
}

impl Message {
    fn try_parse<T: Buf>(buf: &mut T) -> Result<Self, FrameError> {
        if buf.remaining() < PACKET_OVERHEAD {
            Err(FrameError::InvalidMessage)?
        }
        let pt: PacketType = buf.get_u8().try_into()?;
        let length = buf.get_u16() as usize;

        match pt {
            PacketType::Payload => {
                let mut dst = vec![];
                dst.put(buf.take(length));
                trace!("{}B padding?", buf.remaining());
                assert_eq!(buf.remaining(), Self::drain_padding(buf));
                Ok(Message::Payload(dst))
            }
            PacketType::PrngSeed => {
                let mut seed = [0_u8; 24];
                buf.copy_to_slice(&mut seed[..]);
                trace!("{}B padding?", buf.remaining());
                assert_eq!(buf.remaining(), Self::drain_padding(buf));
                Ok(Message::PrngSeed(seed))
            }
        }
    }

    fn drain_padding<T: Buf>(b: &mut T) -> usize {
        if !b.has_remaining() {
            return 0;
        }

        let mut count = b.remaining();
        // make a shallow copy that we can work with so that we can continually
        // check first byte without actually removing it (advancing the pointer
        // in the Bytes object).
        let mut buf = b.copy_to_bytes(b.remaining());
        for i in 0..buf.remaining() {
            if buf[i] != 0 {
                count = i;
                break;
            }
        }

        // b.advance(count);
        trace!(
            "drained {count}B, {}B remaining, {}",
            b.remaining(),
            buf.remaining()
        );
        count
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::init_subscriber;

    use rand::prelude::*;

    #[test]
    fn drain_padding() {
        let test_cases = [
            ("", 0, 0),
            ("00", 1, 0),
            ("0000", 2, 0),
            ("0000000000000000", 8, 0),
            ("000000000000000001", 8, 0),
            ("0000010000000000", 2, 6),
            ("0102030000000000", 0, 8),
        ];

        for case in test_cases {
            let mut buf = &hex::decode(case.0).expect("failed to decode hex");
            let mut b = Bytes::copy_from_slice(&buf);
            let cnt = Message::drain_padding(&mut b);
            assert_eq!(cnt, case.1);
            assert_eq!(b.remaining(), case.2);
        }
    }

    #[test]
    fn prngseed() -> Result<(), FrameError> {
        init_subscriber();

        let mut buf = BytesMut::new();
        let mut rng = rand::thread_rng();
        let pad_len = rng.gen_range(0..100);
        let mut seed = [0_u8; SEED_LENGTH];
        rng.fill_bytes(&mut seed);

        build_and_marshall(&mut buf, PacketType::PrngSeed, &seed, pad_len)?;

        let pkt = Message::try_parse(&mut buf)?;
        assert_eq!(Message::PrngSeed(seed), pkt);

        Ok(())
    }

    #[test]
    fn payload() -> Result<(), FrameError> {
        init_subscriber();

        let mut buf = BytesMut::new();
        let mut rng = rand::thread_rng();
        let pad_len = rng.gen_range(0..100);
        let mut payload = [0_u8; 1000];
        rng.fill_bytes(&mut payload);

        build_and_marshall(&mut buf, PacketType::Payload, &payload, pad_len)?;

        let pkt = Message::try_parse(&mut buf)?;
        assert_eq!(Message::Payload(payload.to_vec()), pkt);

        Ok(())
    }
}