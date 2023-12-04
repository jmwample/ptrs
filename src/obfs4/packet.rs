use crate::{common::drbg, obfs4::framing, Error, Result};

use tokio_util::bytes::{BufMut, Bytes};
use tracing::trace;

pub(crate) const PACKET_OVERHEAD: usize = 2 + 1;
pub(crate) const MAX_PACKET_PAYLOAD_LENGTH: usize =
    framing::MAX_FRAME_PAYLOAD_LENGTH - PACKET_OVERHEAD;
pub(crate) const MAX_PACKET_PADDING_LENGTH: usize = MAX_PACKET_PAYLOAD_LENGTH;
pub(crate) const SEED_PACKET_PAYLOAD_LENGTH: usize = drbg::SEED_LENGTH;

pub(crate) const CONSUME_READ_SIZE: usize = framing::MAX_SEGMENT_LENGTH * 16;

#[derive(Debug)]
pub(crate) enum PacketType {
    Payload,
    PrngSeed,
    ClientHandshake,
    ServerHandshake,
}

pub enum Message {
    Payload(Payload),
    PrngSeed(PrngSeedMessage),
    ClientHandshake(ClientHandshakeMessage),
    ServerHandshake(ServerHandshakeMessage),
}

pub fn build(
    buf: impl BufMut,
    pkt: PacketType,
    data: Option<impl AsRef<[u8]>>,
    pad_len: usize,
) -> impl Packet {
    return ClientHandshakeMessage {};
}

pub trait Packet {
    fn marshall(&mut self, buf: &mut impl BufMut) -> Result<()>;

    fn try_parse(buf: impl AsRef<[u8]>) -> Result<Self>
    where
        Self: Sized;
}

pub struct ClientHandshakeMessage {}

impl ClientHandshakeMessage {
    pub fn get_seed(&self) -> Result<drbg::Seed> {
        // TODO: Actual derive from messsage
        return drbg::Seed::new();
    }
}

impl Packet for ClientHandshakeMessage {
    fn marshall(&mut self, buf: &mut impl BufMut) -> Result<()> {
        trace!("serializing client handshake");
        Err(Error::NotImplemented)
    }

    fn try_parse(buf: impl AsRef<[u8]>) -> Result<Self> {
        trace!("parsing client handshake");
        Err(Error::NotImplemented)
    }
}

pub struct ServerHandshakeMessage {}

impl ServerHandshakeMessage {
    pub fn get_seed(&self) -> Result<drbg::Seed> {
        // TODO: Actual derive from messsage
        return drbg::Seed::new();
    }
}

impl Packet for ServerHandshakeMessage {
    fn marshall(&mut self, buf: &mut impl BufMut) -> Result<()> {
        trace!("serializing server handshake");
        Err(Error::NotImplemented)
    }

    fn try_parse(buf: impl AsRef<[u8]>) -> Result<Self> {
        trace!("parsing server handshake");
        Err(Error::NotImplemented)
    }
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

pub struct PrngSeedMessage {}

impl Packet for PrngSeedMessage {
    fn marshall(&mut self, buf: &mut impl BufMut) -> Result<()> {
        Err(Error::NotImplemented)
    }

    fn try_parse(buf: impl AsRef<[u8]>) -> Result<Self> {
        Err(Error::NotImplemented)
    }
}
