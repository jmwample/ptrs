use crate::{
    common::{drbg, elligator2::Representative, ntor},
    obfs4::framing,
    Error, Result,
};

use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{digest::Reset, Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha2::{Sha256, Sha256VarCore};
use subtle::ConstantTimeEq;
use tokio_util::bytes::{Buf, BufMut, Bytes};
use tracing::trace;

pub(crate) const PACKET_OVERHEAD: usize = 2 + 1;
pub(crate) const MAX_PACKET_PAYLOAD_LENGTH: usize =
    framing::MAX_FRAME_PAYLOAD_LENGTH - PACKET_OVERHEAD;
pub(crate) const MAX_PACKET_PADDING_LENGTH: usize = MAX_PACKET_PAYLOAD_LENGTH;
pub(crate) const SEED_PACKET_PAYLOAD_LENGTH: usize = drbg::SEED_LENGTH;

pub(crate) const CONSUME_READ_SIZE: usize = framing::MAX_SEGMENT_LENGTH * 16;

type HmacSha256 = Hmac<Sha256>;

const SHA256_SIZE: usize = 32;
const MARK_LENGTH: usize = SHA256_SIZE / 2;
const MAC_LENGTH: usize = SHA256_SIZE / 2;

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
    return PrngSeedMessage {
        len_seed: [0_u8; drbg::SEED_LENGTH],
    };
}

pub trait Packet {
    fn marshall(&mut self, buf: &mut impl BufMut) -> Result<()>;

    fn try_parse(buf: impl AsRef<[u8]>) -> Result<Self>
    where
        Self: Sized;
}

pub struct ClientHandshakeMessage {
    pad_len: usize,
    repres: Representative,
    epoch_hour: String,
    mac: HmacSha256,
}

impl ClientHandshakeMessage {
    pub fn new(
        repres: Representative,
        station_id_pubkey: ntor::PublicKey,
        node_id: ntor::ID,
    ) -> Self {
        let mut key = station_id_pubkey.as_bytes().to_vec();
        key.append(&mut node_id.to_bytes().to_vec());
        let mut h = HmacSha256::new_from_slice(&key[..]).unwrap();
        Self {
            pad_len: 0,
            repres,
            epoch_hour: "".into(),
            mac: h,
        }
    }

    pub fn get_seed(&self) -> Result<drbg::Seed> {
        // TODO: Actual derive from message
        return drbg::Seed::new();
    }

    pub fn get_mark(&self) -> Result<[u8; MARK_LENGTH]> {
        todo!()
    }

    pub fn get_representative(&self) -> Result<Representative> {
        todo!()
    }
}

impl Packet for ClientHandshakeMessage {
    fn marshall(&mut self, buf: &mut impl BufMut) -> Result<()> {
        trace!("serializing client handshake");

        Mac::reset(&mut self.mac);
        self.mac.update(self.repres.as_bytes().as_ref());
        let mark: &[u8] = &self.mac.finalize_reset().into_bytes()[..];

        // The client handshake is X | P_C | M_C | MAC(X | P_C | M_C | E) where:
        //  * X is the client's ephemeral Curve25519 public key representative.
        //  * P_C is [clientMinPadLength,clientMaxPadLength] bytes of random padding.
        //  * M_C is HMAC-SHA256-128(serverIdentity | NodeID, X)
        //  * MAC is HMAC-SHA256-128(serverIdentity | NodeID, X .... E)
        //  * E is the string representation of the number of hours since the UNIX
        //    epoch.

        // Generate the padding
        let pad: &[u8] = &make_pad(self.pad_len)?;

        // Write X, P_C, M_C
        let mut params = vec![];
        params.extend_from_slice(self.repres.as_bytes());
        params.extend_from_slice(pad);
        params.extend_from_slice(mark);
        buf.put(params.as_slice());

        // Calculate and write MAC
        self.mac.update(&params);
        self.epoch_hour = format!("{}", get_epoch_hour());
        self.mac.update(self.epoch_hour.as_bytes());
        buf.put(&self.mac.finalize_reset().into_bytes()[..]);

        Ok(())
    }

    fn try_parse(buf: impl AsRef<[u8]>) -> Result<Self> {
        trace!("parsing client handshake");
        Err(Error::NotImplemented)
    }
}

pub struct ServerHandshakeMessage {
    server_auth: Vec<u8>,
    pad_len: usize,
    repres: Representative,
    epoch_hour: String,
    mac: HmacSha256,

    client_mark: [u8; MARK_LENGTH],
    client_repres: Representative,
}

impl ServerHandshakeMessage {
    pub fn new(
        repres: Representative,
        station_id_pubkey: ntor::PublicKey,
        node_id: ntor::ID,
        server_auth: Vec<u8>,
        client_repres: Representative,
        client_mark: [u8; MARK_LENGTH],
    ) -> Self {
        let mut key = station_id_pubkey.as_bytes().to_vec();
        key.append(&mut node_id.to_bytes().to_vec());
        let mut h = HmacSha256::new_from_slice(&key[..]).unwrap();
        Self {
            server_auth,
            pad_len: 0,
            repres,
            epoch_hour: "".into(),
            mac: h,

            client_repres,
            client_mark,
        }
    }

    pub fn get_seed(&self) -> Result<drbg::Seed> {
        // TODO: Actual derive from message
        return drbg::Seed::new();
    }
}

impl Packet for ServerHandshakeMessage {
    fn marshall(&mut self, buf: &mut impl BufMut) -> Result<()> {
        trace!("serializing server handshake");

        Mac::reset(&mut self.mac);
        self.mac.update(self.repres.as_bytes().as_ref());
        let mark: &[u8] = &self.mac.finalize_reset().into_bytes()[..];

        // The server handshake is Y | AUTH | P_S | M_S | MAC(Y | AUTH | P_S | M_S | E) where:
        //  * Y is the server's ephemeral Curve25519 public key representative.
        //  * AUTH is the ntor handshake AUTH value.
        //  * P_S is [serverMinPadLength,serverMaxPadLength] bytes of random padding.
        //  * M_S is HMAC-SHA256-128(serverIdentity | NodeID, Y)
        //  * MAC is HMAC-SHA256-128(serverIdentity | NodeID, Y .... E)
        //  * E is the string representation of the number of hours since the UNIX
        //    epoch.

        // Generate the padding
        let pad: &[u8] = &make_pad(self.pad_len)?;

        // Write Y, AUTH, P_S, M_S.
        let mut params = vec![];
        params.extend_from_slice(self.repres.as_bytes());
        params.extend_from_slice(&self.server_auth);
        params.extend_from_slice(pad);
        params.extend_from_slice(mark);
        buf.put(params.as_slice());

        // Calculate and write MAC
        self.mac.update(&params);
        self.epoch_hour = format!("{}", get_epoch_hour());
        self.mac.update(self.epoch_hour.as_bytes());
        buf.put(&self.mac.finalize_reset().into_bytes()[..]);

        Ok(())
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
        trace!("serializing payload packet");
        if self.pad_len > u16::MAX as usize {
            return Err(Error::EncodeError("padding length too long".into()));
        }
        Err(Error::NotImplemented)
    }

    fn try_parse(buf: impl AsRef<[u8]>) -> Result<Self> {
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

impl Packet for PrngSeedMessage {
    fn marshall(&mut self, buf: &mut impl BufMut) -> Result<()> {
        Err(Error::NotImplemented)
    }

    fn try_parse(buf: impl AsRef<[u8]>) -> Result<Self> {
        Err(Error::NotImplemented)
    }
}

pub fn get_epoch_hour() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 3600
}

pub fn make_pad(pad_len: usize) -> Result<Vec<u8>> {
    let mut pad = Vec::with_capacity(pad_len);
    OsRng.fill_bytes(&mut pad);
    Ok(pad)
}

pub fn find_mac_mark(
    mark: [u8; MARK_LENGTH],
    buf: impl AsRef<[u8]>,
    start_pos: usize,
    max_pos: usize,
    from_tail: bool,
) -> Option<usize> {
    let buffer = buf.as_ref();
    if buffer.len() < MARK_LENGTH {
        return None;
    }

    if start_pos > buffer.len() {
        return None;
    }

    let mut end_pos = buffer.len();
    if end_pos > max_pos {
        end_pos = max_pos;
    }

    if end_pos - start_pos < MARK_LENGTH + MAC_LENGTH {
        return None;
    }

    let mut pos: usize = 0;
    if from_tail {
        // The server can optimize the search process by only examining the
        // tail of the buffer.  The client can't send valid data past M_C |
        // MAC_C as it does not have the server's public key yet.
        pos = end_pos - (MARK_LENGTH + MAC_LENGTH);
        if (&mark[..])
            .ct_eq(buffer[pos..pos + MARK_LENGTH].as_ref())
            .into()
        {
            return Some(pos);
        }
        return None;
    }

    // The client has to actually do a substring search since the server can
    // and will send payload trailing the response.
    //
    // XXX: .windows().position() uses a naive search, which kind of sucks.
    // but better algorithms (like `contains` for String) aren't implemented
    // for byte slices in std.
    pos = buffer[start_pos..end_pos]
        .windows(MARK_LENGTH)
        .position(|window| window.ct_eq(&mark[..]).into())?;

    // Ensure that there is enough trailing data for the MAC.
    if start_pos + pos + MARK_LENGTH + MAC_LENGTH > end_pos {
        println!("HERE! 1");
        return None;
    }

    // Return the index relative to the start of the slice.
    pos += start_pos;
    Some(pos)
}

#[cfg(test)]
mod test {
    use super::*;
    use bytes::Bytes;
    use std::iter;

    struct MacMarkTest {
        mark: [u8; MARK_LENGTH],
        buf: Vec<u8>,
        start_pos: usize,
        max_pos: usize,
        from_tail: bool,
        expected: Option<usize>,
    }

    #[test]
    fn find_mac_mark_thorough() -> Result<()> {
        let cases = vec![
            MacMarkTest {
                mark: [0_u8; MARK_LENGTH],
                buf: vec![0_u8; 100],
                start_pos: 0,
                max_pos: 100,
                from_tail: false,
                expected: Some(0),
            },
            MacMarkTest {
                mark: hex::decode("00112233445566778899aabbccddeeff")
                    .unwrap()
                    .try_into()
                    .unwrap(),
                buf: hex::decode(
                    "00112233445566778899aabbccddeeff00000000000000000000000000000000",
                )
                .unwrap(),
                start_pos: 0,
                max_pos: 100,
                from_tail: false,
                expected: Some(0),
            },
            MacMarkTest {
                // from tail
                mark: hex::decode("00112233445566778899aabbccddeeff")
                    .unwrap()
                    .try_into()
                    .unwrap(),
                buf: hex::decode(
                    "00112233445566778899aabbccddeeff00000000000000000000000000000000",
                )
                .unwrap(),
                start_pos: 0,
                max_pos: 100,
                from_tail: true,
                expected: Some(0),
            },
            MacMarkTest {
                // from tail not align with start
                mark: hex::decode("00112233445566778899aabbccddeeff")
                    .unwrap()
                    .try_into()
                    .unwrap(),
                buf: hex::decode(
                    "000000112233445566778899aabbccddeeff00000000000000000000000000000000",
                )
                .unwrap(),
                start_pos: 0,
                max_pos: 100,
                from_tail: true,
                expected: Some(2),
            },
            MacMarkTest {
                mark: hex::decode("00112233445566778899aabbccddeeff")
                    .unwrap()
                    .try_into()
                    .unwrap(),
                buf: hex::decode(
                    "000000112233445566778899aabbccddeeff00000000000000000000000000000000",
                )
                .unwrap(),
                start_pos: 0,
                max_pos: 100,
                from_tail: false,
                expected: Some(2),
            },
            MacMarkTest {
                mark: hex::decode("00112233445566778899aabbccddeeff")
                    .unwrap()
                    .try_into()
                    .unwrap(),
                buf: hex::decode(
                    "00000000112233445566778899aabbccddeeff00000000000000000000000000000000",
                )
                .unwrap(),
                start_pos: 2,
                max_pos: 100,
                from_tail: false,
                expected: Some(3),
            },
            MacMarkTest {
                // Not long enough to contain MAC
                mark: hex::decode("00112233445566778899aabbccddeeff")
                    .unwrap()
                    .try_into()
                    .unwrap(),
                buf: hex::decode("00112233445566778899aabbccddeeff").unwrap(),
                start_pos: 0,
                max_pos: 100,
                from_tail: false,
                expected: None,
            },
            MacMarkTest {
                // Access from tail success
                mark: [0_u8; MARK_LENGTH],
                buf: vec![0_u8; 100],
                start_pos: 0,
                max_pos: 100,
                from_tail: true,
                expected: Some(100 - MARK_LENGTH - MAC_LENGTH),
            },
            MacMarkTest {
                // from tail fail
                mark: [0_u8; MARK_LENGTH],
                buf: hex::decode(
                    "00112233445566778899aabbccddeeff00000000000000000000000000000000",
                )
                .unwrap(),
                start_pos: 0,
                max_pos: 100,
                from_tail: true,
                expected: None,
            },
            MacMarkTest {
                // provided buf too short
                mark: [0_u8; MARK_LENGTH],
                buf: vec![0_u8; MARK_LENGTH - 1],
                start_pos: 0,
                max_pos: 100,
                from_tail: false,
                expected: None,
            },
            MacMarkTest {
                // provided buf cant contain mark and mac
                mark: [0_u8; MARK_LENGTH],
                buf: vec![0_u8; MARK_LENGTH + MAC_LENGTH - 1],
                start_pos: 0,
                max_pos: 100,
                from_tail: false,
                expected: None,
            },
        ];

        for m in cases {
            let actual = find_mac_mark(
                m.mark,
                &Bytes::from(m.buf),
                m.start_pos,
                m.max_pos,
                m.from_tail,
            );
            assert_eq!(actual, m.expected);
        }

        Ok(())
    }

    #[test]
    fn epoch_format() {
        let h = format!("{}", get_epoch_hour());
        // println!("{h} {}", hex::encode(h.as_bytes()));
    }
}
