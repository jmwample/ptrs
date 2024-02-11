
use crate::obfs4::framing::{Message, MessageType, FrameError};
use super::MessageTypes;
use crate::common::ntor::kyber::{KyberXSessionKeys, KyberXPublicKey};

use bytes::BytesMut;

#[derive(Debug,PartialEq)]
pub(crate) enum CryptoExtensionTypes {
    Kyber1024Supplement,
    Kyber1024X25519,
}

#[derive(PartialEq, Debug)]
pub enum CryptoExtension {
    Kyber,
}

#[derive(PartialEq, Debug)]
pub(crate) struct OfferMessage {
    crypto_type: CryptoExtensionTypes,
    data: BytesMut,
}

impl From<&KyberXSessionKeys> for OfferMessage {
    fn from(value: &KyberXSessionKeys) -> Self {
        OfferMessage{
            crypto_type: CryptoExtensionTypes::Kyber1024Supplement,
            data: BytesMut::new(),
        }
    }
}

#[derive(PartialEq, Debug)]
pub(crate) struct AcceptMessage {
    crypto_type: CryptoExtensionTypes,
    data: BytesMut,
}

impl Message for OfferMessage {
    type Output = ();
    fn as_pt(&self) -> MessageType {
        MessageTypes::CryptoOffer.into()
    }

    fn marshall<T: bytes::BufMut>(&self, dst: &mut T) -> Result<(), FrameError> {
        Ok(())
    }

    fn try_parse<T: bytes::BufMut + bytes::Buf>(buf: &mut T) -> Result<Self::Output, FrameError> {
        Ok(())
    }
}


#[derive(PartialEq, Debug)]
struct KyberAcceptMessage {}

impl Message for AcceptMessage {
    type Output = ();
    fn as_pt(&self) -> MessageType {
        MessageTypes::CryptoAccept.into()
    }

    fn marshall<T: bytes::BufMut>(&self, dst: &mut T) -> Result<(), FrameError> {
        Ok(())
    }

    fn try_parse<T: bytes::BufMut + bytes::Buf>(buf: &mut T) -> Result<Self::Output, FrameError> {
        Ok(())
    }
}


impl From<&KyberXSessionKeys> for AcceptMessage {
    fn from(value: &KyberXSessionKeys) -> Self {
        AcceptMessage{
            crypto_type: CryptoExtensionTypes::Kyber1024Supplement,
            data: BytesMut::new(),
        }
    }
}



#[cfg(test)]
#[allow(unused)]
mod tests {

}
