use crate::{
    common::{
        drbg,
        elligator2::{Representative, REPRESENTATIVE_LENGTH},
        ntor,
    },
    obfs4::{
        constants::*,
        framing::{self, FrameError},
    },
    Error, Result,
};

use std::time::{SystemTime, UNIX_EPOCH};

use rand_core::{OsRng, RngCore};
use subtle::ConstantTimeEq;
use tokio_util::bytes::{Buf, BufMut, Bytes};
use tracing::trace;

use super::proto::{ClientHandshake, HmacSha256, ServerHandshake};

pub(crate) const PACKET_OVERHEAD: usize = 2 + 1;
pub(crate) const MAX_PACKET_PAYLOAD_LENGTH: usize =
    framing::MAX_FRAME_PAYLOAD_LENGTH - PACKET_OVERHEAD;
pub(crate) const MAX_PACKET_PADDING_LENGTH: usize = MAX_PACKET_PAYLOAD_LENGTH;
pub(crate) const SEED_PACKET_PAYLOAD_LENGTH: usize = drbg::SEED_LENGTH;

pub(crate) const CONSUME_READ_SIZE: usize = framing::MAX_SEGMENT_LENGTH * 16;

const SHA256_SIZE: usize = 32;
const MARK_LENGTH: usize = SHA256_SIZE / 2;
const MAC_LENGTH: usize = SHA256_SIZE / 2;

#[derive(Debug)]
pub(crate) enum PacketType {
    Payload,
    PrngSeed,
}

pub enum Message {
    Payload(Payload),
    PrngSeed(PrngSeedMessage),
}

pub fn build(
    buf: impl BufMut,
    pkt: PacketType,
    data: Option<impl AsRef<[u8]>>,
    pad_len: usize,
) -> impl Packet {
    return PrngSeedMessage {
        len_seed: [0_u8; drbg::SEED_LENGTH],
    };
}

pub trait Packet: Marshall + TryParse {}

pub trait Marshall {
    fn marshall(&mut self, buf: &mut impl BufMut) -> Result<()>;
}

pub trait TryParse {
    type Output;
    fn try_parse(&mut self, buf: impl AsRef<[u8]>) -> Result<Self::Output>
    where
        Self: Sized;
}

pub struct Payload {
    pub(crate) data: Vec<u8>,
    pub(crate) pad_len: usize,
}

impl Payload {
    pub fn new(data: Vec<u8>, pad_len: usize) -> Self {
        Self { data, pad_len }
    }
}

impl Packet for Payload {}
impl Marshall for Payload {
    fn marshall(&mut self, buf: &mut impl BufMut) -> Result<()> {
        trace!("serializing payload packet");
        if self.pad_len > u16::MAX as usize {
            return Err(Error::EncodeError("padding length too long".into()));
        }
        Err(Error::NotImplemented)
    }
}
impl TryParse for Payload {
    type Output = ();
    fn try_parse(&mut self, buf: impl AsRef<[u8]>) -> Result<Self::Output> {
        trace!("parsing payload packet");
        Err(Error::NotImplemented)
    }
}

pub struct PrngSeedMessage {
    len_seed: [u8; drbg::SEED_LENGTH],
}

impl PrngSeedMessage {
    pub fn new(len_seed: drbg::Seed) -> Self {
        Self {
            len_seed: len_seed.to_bytes(),
        }
    }
}

impl Packet for PrngSeedMessage {}
impl Marshall for PrngSeedMessage {
    fn marshall(&mut self, buf: &mut impl BufMut) -> Result<()> {
        trace!("AAAAAAAAAA");
        // TODO: Actually implement this.
        // Err(Error::NotImplemented)
        Ok(())
    }
}

impl TryParse for PrngSeedMessage {
    type Output = ();
    fn try_parse(&mut self, buf: impl AsRef<[u8]>) -> Result<Self::Output> {
        Err(Error::NotImplemented)
    }
}
