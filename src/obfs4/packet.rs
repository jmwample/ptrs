
use crate::{
    obfs4::framing,
    common::drbg,
    Result, Error
};

use tokio_util::bytes::{Bytes, BufMut};

pub(crate) const PACKET_OVERHEAD: usize            = 2 + 1;
pub(crate) const MAX_PACKET_PAYLOAD_LENGTH: usize  = framing::MAX_FRAME_PAYLOAD_LENGTH - PACKET_OVERHEAD;
pub(crate) const MAX_PACKET_PADDING_LENGTH: usize  = MAX_PACKET_PAYLOAD_LENGTH;
pub(crate) const SEED_PACKET_PAYLOAD_LENGTH: usize = drbg::SEED_LENGTH;

pub(crate) const CONSUME_READ_SIZE: usize = framing::MAX_SEGMENT_LENGTH * 16;

pub(crate) enum PacketType {
    Payload,
    PrngSeed,
    ClientHandshake,
    ServerHandshake,
}


pub trait Packet {
    fn marshall(&mut self, buf: &mut impl BufMut) -> Result<()>;

    fn try_parse(buf: impl AsRef<[u8]>) -> Result<Self> where Self: Sized;
}


pub struct ClientHandshakeMessage {}

impl ClientHandshakeMessage {
    pub fn get_seed(&self) -> Result<drbg::Seed> {
        // TODO: Actual derive from messsage
        return drbg::Seed::new()
    }
}

impl Packet for ClientHandshakeMessage {
    fn marshall(&mut self, buf: &mut impl BufMut) -> Result<()> {
        Err(Error::NotImplemented)
    }

    fn try_parse(buf: impl AsRef<[u8]>) -> Result<Self> {
        Err(Error::NotImplemented)
    }

}

pub struct ServerHandshakeMessage {}

impl ServerHandshakeMessage {
    pub fn get_seed(&self) -> Result<drbg::Seed> {
        // TODO: Actual derive from messsage
        return drbg::Seed::new()
    }
}

impl Packet for ServerHandshakeMessage {
    fn marshall(&mut self, buf: &mut impl BufMut) -> Result<()> {
        Err(Error::NotImplemented)
    }

    fn try_parse(buf: impl AsRef<[u8]>) -> Result<Self> {
        Err(Error::NotImplemented)
    }
}

pub struct Payload {
    pad_len: usize,
}

impl Packet for Payload {
    fn marshall(&mut self, buf: &mut impl BufMut) -> Result<()> {
        if self.pad_len > u16::MAX as usize {
             return Err(Error::EncodeError("padding length too long".into()));
        }
        Err(Error::NotImplemented)
    }

    fn try_parse(buf: impl AsRef<[u8]>) -> Result<Self> {
        Err(Error::NotImplemented)
    }

}

