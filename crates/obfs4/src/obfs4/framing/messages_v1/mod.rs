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

// mod crypto;
// use crypto::CryptoExtension;

use crate::obfs4::{
    constants::*,
    framing::{FrameError, MESSAGE_OVERHEAD},
};

use tokio_util::bytes::{Buf, BufMut};
use tracing::trace;

const PAD: [u8; MAX_MESSAGE_PADDING_LENGTH] = [0u8; MAX_MESSAGE_PADDING_LENGTH];

#[derive(Debug, PartialEq)]
pub enum MessageTypes {
    Payload,
    PrngSeed,
}

impl MessageTypes {
    // Steady state message types (and required backwards compatibility messages)
    const PAYLOAD: u8 = 0x00;
    const PRNG_SEED: u8 = 0x01;
}

impl From<MessageTypes> for u8 {
    fn from(value: MessageTypes) -> Self {
        match value {
            MessageTypes::Payload => MessageTypes::PAYLOAD,
            MessageTypes::PrngSeed => MessageTypes::PRNG_SEED,
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
    Padding(usize),
}

impl Messages {
    pub(crate) fn as_pt(&self) -> MessageTypes {
        match self {
            Messages::Payload(_) => MessageTypes::Payload,
            Messages::PrngSeed(_) => MessageTypes::PrngSeed,
            Messages::Padding(_) => MessageTypes::Payload,
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
                if *pad_len > MAX_MESSAGE_PADDING_LENGTH {
                    return Err(FrameError::InvalidPayloadLength(*pad_len));
                }
                dst.put_u16(0u16);
                if *pad_len > 0 {
                    dst.put(&PAD[..*pad_len]);
                }
            }
        }
        Ok(())
    }

    pub(crate) fn try_parse<T: BufMut + Buf>(buf: &mut T) -> Result<Self, FrameError> {
        let r: usize = buf.remaining();
        if buf.remaining() < MESSAGE_OVERHEAD {
            Err(FrameError::InvalidMessage)?
        }

        let type_u8 = buf.get_u8();
        let pt: MessageTypes =  type_u8.clone().try_into()?;
        let length = buf.get_u16() as usize;
        trace!("parsing msg: type:{type_u8} frame_len={r} msg_len={length}");

        match pt {
            MessageTypes::Payload => {
                let mut dst = vec![];
                if length == 0 {
                    // this "packet" is all padding -> get rid of it
                    trace!("padding payload len={r}");
                    let n = buf.remaining();
                    buf.advance(n);
                    return Ok(Messages::Padding(n));
                }
                trace!("content payload len={r}");

                dst.put(buf.take(length));
                trace!("{}B remainng", buf.remaining());
                Ok(Messages::Payload(dst))
            }

            MessageTypes::PrngSeed => {
                let mut seed = [0_u8; 24];
                buf.copy_to_slice(&mut seed[..]);
                Ok(Messages::PrngSeed(seed))
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::obfs4::framing::*;
    use crate::test_utils::init_subscriber;

    use rand::prelude::*;
    use tokio_util::bytes::BytesMut;

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
