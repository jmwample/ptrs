//! Version 1 of the Protocol Messagess to be included in constructed frames.
//!
//! ## Compatability concerns:
//!
//! Server - when operating as a server we may want to support clients using v0
//! as well as clients using v1. In order to accomplish this the server can
//! look for the presence of the [`ClientParams`] message. If it is included as
//! a part of the clients handshake we can affirmatively assign protocol message
//! set v1 to the clients session. If we complete the handshake without
//! receiving a [`ClientParams`] messsage then we default to v0 (if the server
//! enables support).
//!
//! Client - When operating as a client we want to support the option to connect
//! with either v0 or v1 servers. when running as a v1 client the server will
//! ignore the unknown frames including [`ClientParams`] and [`CryptoOffer`]. 
//! This means that the `SevrerHandshake` will not include [`ServerParams`] or
//! [`CryptoAccept`] frames which indicates to a v1 client that it is speaking
//! with a server unwilling or incapable of speaking v1. This should allow
//! cross compatibility.

use crate::obfs4::{
    framing::{FrameError, PACKET_OVERHEAD},
    constants::*,
};

use tracing::trace;
use tokio_util::bytes::{Buf, BufMut};

#[derive(Debug, PartialEq)]
pub enum MessageTypes {
    Payload,
    PrngSeed,
    Padding,
    HeartbeatPing,
    HeartbeatPong,

    ClientParams,
    ServerParams,
    CryptoOffer,
    CryptoAccept,

    HandshakeEnd,
}

impl MessageTypes {
    // Steady state message types (and required backwards compatibility messages)
    const PAYLOAD: u8 = 0x00;
    const PRNG_SEED: u8 = 0x01;
    const PADDING: u8 = 0x02;
    const HEARTBEAT_PING: u8 = 0x03;
    const HEARTBEAT_PONG: u8 = 0x04;

    // Handshake messages
    const CLIENT_PARAMS: u8 = 0x10;
    const SERVER_PARAMS: u8 = 0x11;
    const CRYPTO_OFFER: u8 = 0x12;
    const CRYPTO_ACCEPT: u8 = 0x13;
    //...
    const HANDSHAKE_END: u8 = 0x1f;
}

impl From<MessageTypes> for u8 {
    fn from(value: MessageTypes) -> Self {
        match value {
            MessageTypes::Payload => MessageTypes::PAYLOAD,
            MessageTypes::PrngSeed => MessageTypes::PRNG_SEED,
            MessageTypes::Padding => MessageTypes::PADDING,
            MessageTypes::HeartbeatPing => MessageTypes::HEARTBEAT_PING,
            MessageTypes::HeartbeatPong => MessageTypes::HEARTBEAT_PONG,
            MessageTypes::ClientParams => MessageTypes::CLIENT_PARAMS,
            MessageTypes::ServerParams => MessageTypes::SERVER_PARAMS,
            MessageTypes::CryptoOffer => MessageTypes::CRYPTO_OFFER,
            MessageTypes::CryptoAccept => MessageTypes::CRYPTO_ACCEPT,
            MessageTypes::HandshakeEnd => MessageTypes::HANDSHAKE_END,
        }
    }
}

impl TryFrom<u8> for MessageTypes {
    type Error = FrameError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            MessageTypes::PAYLOAD => Ok(MessageTypes::Payload),
            MessageTypes::PRNG_SEED => Ok(MessageTypes::PrngSeed),
            _ => Err(FrameError::UnknownMessageType(value)),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum Messages {
    Payload(Vec<u8>),
    PrngSeed([u8; SEED_LENGTH]),
    Padding(u16),
    HeartbeatPing,
    HeartbeatPong,

    ClientParams,
    ServerParams,
    CryptoOffer,
    CryptoAccept,

    HandshakeEnd,
}

impl Messages {
    pub(crate) fn as_pt(&self) -> MessageTypes {
        match self {
            Messages::Payload(_) => MessageTypes::Payload,
            Messages::PrngSeed(_) => MessageTypes::PrngSeed,
            Messages::Padding(_) => MessageTypes::Padding,
            Messages::HeartbeatPing => MessageTypes::HeartbeatPing,
            Messages::HeartbeatPong => MessageTypes::HeartbeatPong,
            Messages::ClientParams => MessageTypes::ClientParams,
            Messages::ServerParams => MessageTypes::ServerParams,
            Messages::CryptoOffer => MessageTypes::CryptoOffer,
            Messages::CryptoAccept => MessageTypes::CryptoAccept,
            Messages::HandshakeEnd => MessageTypes::HandshakeEnd,
        }
    }

    pub(crate) fn marshall<T: BufMut>(&self, dst: &mut T) -> Result<(), FrameError> {
        dst.put_u8(self.as_pt().into());
        match self {
            Messages::Payload(buf) => {
                dst.put_u16(buf.len() as u16);
                dst.put(&buf[..]);
            }
            Messages::PrngSeed(buf) => {
                dst.put_u16(buf.len() as u16);
                dst.put(&buf[..]);
            }
            Messages::Padding(pad_len) => {
                dst.put_u16(*pad_len);
                if *pad_len > 0 {
                    let buf = vec![0_u8; *pad_len as usize];
                    dst.put(&buf[..]);
                }
            }

            _ => {
                dst.put_u16(0_u16);
            }
        }
        Ok(())
    }

    pub(crate) fn try_parse<T: BufMut + Buf>(buf: &mut T) -> Result<Self, FrameError> {
        if buf.remaining() < PACKET_OVERHEAD {
            Err(FrameError::InvalidMessage)?
        }
        let pt: MessageTypes = buf.get_u8().try_into()?;
        let length = buf.get_u16() as usize;

        match pt {
            MessageTypes::Payload => {
                let mut dst = vec![];
                dst.put(buf.take(length));
                trace!("{}B remainng", buf.remaining());
                assert_eq!(buf.remaining(), Self::drain_padding(buf));
                Ok(Messages::Payload(dst))
            }

            MessageTypes::PrngSeed => {
                let mut seed = [0_u8; 24];
                buf.copy_to_slice(&mut seed[..]);
                assert_eq!(buf.remaining(), Self::drain_padding(buf));
                Ok(Messages::PrngSeed(seed))
            }

            MessageTypes::Padding => {
                Ok(Messages::Padding(length as u16))
            }

            MessageTypes::HeartbeatPing => {
                Ok(Messages::HeartbeatPing)
            }

            MessageTypes::HeartbeatPong => {
                Ok(Messages::HeartbeatPong)
            }

            MessageTypes::ClientParams => {
                Ok(Messages::ClientParams)
            }

            MessageTypes::ServerParams => {
                Ok(Messages::ServerParams)
            }

            MessageTypes::CryptoOffer => {
                Ok(Messages::CryptoOffer)
            }

            MessageTypes::CryptoAccept => {
                Ok(Messages::CryptoAccept)
            }

            MessageTypes::HandshakeEnd => {
                Ok(Messages::HandshakeEnd)
            }
        }
    }

    fn drain_padding<T: BufMut + Buf>(b: &mut T) -> usize {
        if !b.has_remaining() {
            return 0;
        }

        let length = b.remaining();
        let mut count = length;
        // make a shallow copy that we can work with so that we can continually
        // check first byte without actually removing it (advancing the pointer
        // in the Bytes object).
        let mut buf = b.copy_to_bytes(b.remaining());
        for i in 0..length {
            if buf[0] != 0 {
                count = i;
                break;
            }
            _ = buf.get_u8();
        }

        b.put(buf);
        trace!("drained {count}B, {}B remaining", b.remaining(),);
        count
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::init_subscriber;
    use crate::obfs4::framing::*;

    use rand::prelude::*;
    use tokio_util::bytes::BytesMut;

    #[test]
    fn drain_padding() {
        init_subscriber();
        let test_cases = [
            ("", 0, 0),
            ("00", 1, 0),
            ("0000", 2, 0),
            ("0000000000000000", 8, 0),
            ("000000000000000001", 8, 1),
            ("0000010000000000", 2, 6),
            ("0102030000000000", 0, 8),
        ];

        for case in test_cases {
            let buf = hex::decode(case.0).expect("failed to decode hex");
            let mut b = BytesMut::from(&buf as &[u8]);
            let cnt = Messages::drain_padding(&mut b);
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

        build_and_marshall(&mut buf, MessageTypes::PrngSeed.into(), seed, pad_len)?;

        let pkt = Messages::try_parse(&mut buf)?;
        assert_eq!(Messages::PrngSeed(seed), pkt);

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

        build_and_marshall(&mut buf, MessageTypes::Payload.into(), payload, pad_len)?;

        let pkt = Messages::try_parse(&mut buf)?;
        assert_eq!(Messages::Payload(payload.to_vec()), pkt);

        Ok(())
    }
}
