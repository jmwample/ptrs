#![allow(unused)]

use crate::{
    common::{
        elligator2::{Representative, REPRESENTATIVE_LENGTH},
        ntor::{self, AUTH_LENGTH},
    },
    obfs4::{
        framing::{FrameError, Obfs4Codec, KEY_LENGTH, KEY_MATERIAL_LENGTH},
        packet::{Marshall, Packet, TryParse},
        proto::server::ServerHandshakeMessage,
    },
    stream::Stream,
    Error, Result,
};

use super::*;

use bytes::{BufMut, BytesMut};
use rand::prelude::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use std::sync::{Arc, Mutex};

pub struct ClientParams {
    pub iat_mode: IAT,
    pub node_id: ntor::ID,
    pub station_pubkey: ntor::PublicKey,
}

pub struct Client {
    pub iat_mode: IAT,
    pub station_pubkey: ntor::PublicKey,
    pub id: ntor::ID,
}

impl Client {
    pub fn set_args(&mut self, _args: &dyn std::any::Any) -> Result<&Self> {
        Ok(self)
    }

    pub async fn wrap<'a>(&self, stream: &'a mut impl Stream<'a>) -> Result<Obfs4Stream<'a>> {
        tokio::select! {
            r = ClientHandshake::new(&self.id, &self.station_pubkey, self.iat_mode).complete(stream) => r,
            e = tokio::time::sleep(CLIENT_HANDSHAKE_TIMEOUT) => Err(Error::HandshakeTimeout),
        }
    }

    pub fn from_params(params: ClientParams) -> Self {
        Self {
            iat_mode: params.iat_mode,
            station_pubkey: params.station_pubkey,
            id: params.node_id,
        }
    }
}

pub struct ClientSession {
    node_id: ntor::ID,
    node_pubkey: ntor::PublicKey,
    session_keys: ntor::SessionKeyPair,
    session_id: [u8; SESSION_ID_LEN],
    iat_mode: IAT,
}

impl ClientSession {
    pub fn new(station_id: ntor::ID, station_pubkey: ntor::PublicKey, iat_mode: IAT) -> Self {
        Self {
            node_id: station_id,
            node_pubkey: station_pubkey,
            session_keys: ntor::SessionKeyPair::new(true),
            // TODO: generate session id
            session_id: [0_u8; SESSION_ID_LEN],
            iat_mode,
        }
    }

    pub fn session_id(&self) -> String {
        return hex::encode(self.session_id);
    }
}

pub struct ClientHandshake {
    session: ClientSession,
}

impl ClientHandshake {
    pub fn new(id: &ntor::ID, station_pubkey: &ntor::PublicKey, iat_mode: IAT) -> Self {
        Self {
            session: ClientSession::new(id.clone(), *station_pubkey, iat_mode),
        }
    }

    pub fn for_session(session: ClientSession) -> Result<Self> {
        Ok(Self { session })
    }

    pub async fn complete<'a>(mut self, stream: &'a mut dyn Stream<'a>) -> Result<Obfs4Stream> {
        if self.session.session_keys.representative.is_none() {
            return Err(Error::Other("Bad session keys".into()));
        }

        // build client handshake message
        let mut ch_msg = ClientHandshakeMessage::new(
            self.session.session_keys.representative.clone().unwrap(),
            None,
            "".into(),
            [0_u8; MARK_LENGTH],
        );
        let mut buf = BytesMut::with_capacity(MAX_HANDSHAKE_LENGTH);
        let mut key = self.session.node_pubkey.as_bytes().to_vec();
        key.append(&mut self.session.node_id.to_bytes().to_vec());
        let mut h = HmacSha256::new_from_slice(&key[..]).unwrap();
        ch_msg.marshall(&mut buf, h)?;

        // send client Handshake
        stream.write_all(&buf).await?;
        trace!("client handshake sent, waiting for sever response");

        // Wait for and attempt to consume server handshake
        let mut buf = [0_u8; MAX_HANDSHAKE_LENGTH];
        let mut seed: [u8; SEED_LENGTH];
        loop {
            let n = stream.read(&mut buf).await?;

            // validate sever
            seed = match self.try_parse(&mut buf) {
                Ok(shs) => shs.get_seed()?.to_bytes(),
                Err(Error::Obfs4Framing(FrameError::EAgain)) => continue,
                Err(e) => return Err(e)?,
            };
            break;
        }

        // use the derived seed value to bootstrap Read / Write crypto codec.
        let okm = ntor::kdf(seed, KEY_MATERIAL_LENGTH * 2);
        let ekm: [u8; KEY_MATERIAL_LENGTH] = okm[..KEY_MATERIAL_LENGTH].try_into().unwrap();
        let dkm: [u8; KEY_MATERIAL_LENGTH] = okm[KEY_MATERIAL_LENGTH..].try_into().unwrap();

        let codec = Obfs4Codec::new(ekm, dkm);
        Ok(Obfs4Stream::from_o4(O4Stream::new(
            stream,
            codec,
            Session::Client(self.session),
        )))
    }

    fn try_parse(&mut self, buf: impl AsRef<[u8]>) -> Result<ServerHandshakeMessage> {
        trace!("parsing server handshake");
        let buf = buf.as_ref();

        if buf.len() < SERVER_MIN_HANDSHAKE_LENGTH {
            Err(Error::Obfs4Framing(FrameError::EAgain))?
        }

        let server_repres = Representative::try_from_bytes(&buf[0..REPRESENTATIVE_LENGTH])?;
        let server_auth = ntor::Auth::new(
            buf[REPRESENTATIVE_LENGTH..REPRESENTATIVE_LENGTH + AUTH_LENGTH].try_into()?,
        );

        // derive the server mark
        let mut key = self.session.node_pubkey.as_bytes().to_vec();
        key.append(&mut self.session.node_id.to_bytes().to_vec());
        let mut h = HmacSha256::new_from_slice(&key[..]).unwrap();
        Mac::reset(&mut h); // disambiguate reset() implementations Mac v digest
        h.update(server_repres.as_bytes().as_ref());
        let server_mark = h.finalize_reset().into_bytes()[..].try_into()?;

        //attempt to find the mark + MAC
        let start_pos = REPRESENTATIVE_LENGTH + AUTH_LENGTH + SERVER_MIN_PAD_LENGTH;
        let pos = match find_mac_mark(server_mark, buf, start_pos, MAX_HANDSHAKE_LENGTH, false) {
            Some(p) => p,
            None => {
                if buf.len() > MAX_HANDSHAKE_LENGTH {
                    Err(Error::Obfs4Framing(FrameError::InvalidHandshake))?
                }
                Err(Error::Obfs4Framing(FrameError::EAgain))?
            }
        };

        // validate the MAC
        Mac::reset(&mut h); // disambiguate reset() implementations Mac v digest
        h.update(&buf[..pos + MARK_LENGTH]);
        h.update(self.client_hs.epoch_hour.as_bytes());
        let mac_calculated = h.finalize_reset().into_bytes()[..].try_into()?;
        let mac_received = &buf[pos + MARK_LENGTH..pos + MARK_LENGTH + MAC_LENGTH];
        if !mac_calculated.ct_eq(mac_received).into() {
            // received the incorrect mac
            Err(Error::Obfs4Framing(FrameError::TagMismatch))?
        }

        Ok(ServerHandshakeMessage::new(
            server_repres,
            server_auth,
            self.session.session_keys.representative.unwrap(),
            server_mark,
        ))
    }
}

pub struct ClientHandshakeMessage {
    pad_len: usize,
    repres: Representative,

    // only used when parsing (i.e. on the server side)
    epoch_hour: String,
    mark: [u8; MARK_LENGTH],
}

impl ClientHandshakeMessage {
    pub fn parse(&mut self) -> Result<&Self> {
        Err(FrameError::InvalidHandshake.into())
    }

    pub fn new(
        repres: Representative,
        pad_len: Option<usize>,
        epoch_hour: String,
        mark: [u8; MARK_LENGTH],
    ) -> Self {
        let pad_len_alt: usize = rand::thread_rng().gen::<usize>()
            % (CLIENT_MAX_PAD_LENGTH - CLIENT_MIN_PAD_LENGTH)
            + CLIENT_MIN_PAD_LENGTH;

        Self {
            pad_len: pad_len.unwrap_or(pad_len_alt),
            repres,

            // only used when parsing (i.e. on the server side)
            epoch_hour,
            mark,
        }
    }

    pub fn get_seed(&self) -> Result<drbg::Seed> {
        // TODO: Actual derive from message
        return drbg::Seed::new();
    }

    pub fn get_mark(&self) -> [u8; MARK_LENGTH] {
        self.mark
    }

    pub fn get_representative(&self) -> Representative {
        self.repres.clone()
    }

    fn marshall(&mut self, buf: &mut impl BufMut, mut h: HmacSha256) -> Result<()> {
        trace!("serializing client handshake");

        Mac::reset(&mut h); // disambiguate reset() implementations Mac v digest
        h.update(self.repres.as_bytes().as_ref());
        let mark: &[u8] = &h.finalize_reset().into_bytes()[..];

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
        h.update(&params);
        h.update(format!("{}", get_epoch_hour()).as_bytes());
        buf.put(&h.finalize_reset().into_bytes()[..]);

        Ok(())
    }
}
