#![allow(unused)]

use crate::{
    common::{
        colorize,
        ntor::{self, HandShakeResult, AUTH_LENGTH, Representative, REPRESENTATIVE_LENGTH},
        HmacSha256,
    },
    obfs4::{
        framing::{FrameError, Marshall, Obfs4Codec, TryParse, KEY_LENGTH, KEY_MATERIAL_LENGTH},
        proto::server::ServerHandshakeMessage,
    },
    stream::Stream,
    Error, Result,
};

use super::*;

use bytes::{Buf, BufMut, BytesMut};
use hmac::{Hmac, Mac};
use rand::prelude::*;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info};

use std::io::{Error as IoError, ErrorKind as IoErrorKind};
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

    pub async fn wrap<'a, T>(&self, stream: T) -> Result<Obfs4Stream<'a, T>>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
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
    iat_mode: IAT, // TODO: add IAT normal / paranoid writing modes
    epoch_hour: String,
    pad_len: usize,

    len_seed: drbg::Seed, // TODO: initialize the distributions using the seed
}

impl std::fmt::Debug for ClientSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[ id:{}, ident_pk:{}, sess_key:{:?}, iat:{:?}, epoch_hr:{}, pad_len:{} ]",
            hex::encode(self.node_id.as_bytes()),
            hex::encode(self.node_pubkey.as_bytes()),
            self.session_keys,
            self.iat_mode,
            self.epoch_hour,
            self.pad_len,
        )
    }
}

impl ClientSession {
    pub fn new(station_id: ntor::ID, station_pubkey: ntor::PublicKey, iat_mode: IAT) -> Self {
        let session_keys = ntor::SessionKeyPair::new(true);
        let session_id = session_keys.get_public().to_bytes()[..SESSION_ID_LEN]
            .try_into()
            .unwrap();
        Self {
            session_keys,
            node_id: station_id,
            node_pubkey: station_pubkey,
            session_id,
            iat_mode,
            epoch_hour: "".into(),
            pad_len: rand::thread_rng().gen_range(CLIENT_MIN_PAD_LENGTH..CLIENT_MAX_PAD_LENGTH),

            len_seed: drbg::Seed::new().unwrap(),
        }
    }

    pub fn session_id(&self) -> String {
        String::from("c-") + &colorize(&self.session_id)
    }

    pub(crate) fn set_session_id(&mut self, id: [u8; SESSION_ID_LEN]) {
        debug!(
            "{} -> {} client updating session id",
            colorize(&self.session_id),
            colorize(&id)
        );
        self.session_id = id;
    }

    pub(crate) fn set_len_seed(&mut self, seed: drbg::Seed) {
        debug!(
            "{} setting length seed {}",
            self.session_id(),
            hex::encode(seed.as_bytes())
        );
        self.len_seed = seed;
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

    pub async fn complete<'a, T>(mut self, mut stream: T) -> Result<Obfs4Stream<'a, T>>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        if self.session.session_keys.representative.is_none() {
            return Err(Error::Other("Bad session keys".into()));
        }

        // build client handshake message
        let mut ch_msg = ClientHandshakeMessage::new(
            self.session.session_keys.representative.clone().unwrap(),
            self.session.pad_len,
            "".into(),
            [0_u8; MARK_LENGTH],
        );
        self.session.pad_len = ch_msg.pad_len;

        let mut buf = BytesMut::with_capacity(MAX_HANDSHAKE_LENGTH);
        let mut key = self.session.node_pubkey.as_bytes().to_vec();
        key.append(&mut self.session.node_id.to_bytes().to_vec());
        let mut h = HmacSha256::new_from_slice(&key[..]).unwrap();
        ch_msg.marshall(&mut buf, h)?;
        self.session.epoch_hour = ch_msg.epoch_hour;

        trace!("{:?}", self.session);
        // let mut file = tokio::fs::File::create("message.hex").await?;
        // file.write_all(&buf).await?;

        // send client Handshake
        stream.write_all(&buf).await?;
        debug!(
            "{} handshake sent {}B, waiting for sever response",
            self.session.session_id(),
            buf.len()
        );

        // Wait for and attempt to consume server handshake
        let mut remainder = BytesMut::new();
        let mut buf = [0_u8; MAX_HANDSHAKE_LENGTH];
        let mut server_hs: ServerHandshakeMessage;
        loop {
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                Err(Error::IOError(IoError::new(
                    IoErrorKind::UnexpectedEof,
                    "read 0B in client handshake",
                )))?
            }
            debug!(
                "{} read {n}/{}B of server handshake",
                self.session.session_id(),
                buf.len()
            );

            // validate sever
            server_hs = match self.try_parse(&mut buf[..n]) {
                Ok((shs, len)) => {
                    // TODO: make sure bytes after server hello get put back
                    // into the read buffer for message handling
                    remainder.put(&buf[n - SEED_PACKET_LENGTH..n]);
                    shs
                }
                Err(Error::Obfs4Framing(FrameError::EAgain)) => continue,
                Err(e) => return Err(e)?,
            };
            break;
        }

        let ntor_hs_result: HandShakeResult = match ntor::HandShakeResult::client_handshake(
            &self.session.session_keys,
            &server_hs.server_pubkey(),
            &self.session.node_pubkey,
            &self.session.node_id,
        )
        .into()
        {
            Some(r) => r,
            None => Err(Error::NtorError(ntor::NtorError::HSFailure(
                "failed to derive sharedsecret".into(),
            )))?,
        };

        // use the derived seed value to bootstrap Read / Write crypto codec.
        let okm = ntor::kdf(
            ntor_hs_result.key_seed,
            KEY_MATERIAL_LENGTH * 2 + SESSION_ID_LEN,
        );
        let ekm: [u8; KEY_MATERIAL_LENGTH] = okm[..KEY_MATERIAL_LENGTH].try_into().unwrap();
        let dkm: [u8; KEY_MATERIAL_LENGTH] = okm[KEY_MATERIAL_LENGTH..KEY_MATERIAL_LENGTH * 2]
            .try_into()
            .unwrap();
        self.session
            .set_session_id(okm[KEY_MATERIAL_LENGTH * 2..].try_into().unwrap());

        info!("{} handshake complete", self.session.session_id());

        let mut codec = Obfs4Codec::new(ekm, dkm);
        let res = codec.decode(&mut remainder);
        if let Ok(Some(framing::Message::PrngSeed(seed))) = res {
            // try to parse the remainder of the server hello packet as a
            // PrngSeed since it should be there.
            self.session.set_len_seed(drbg::Seed::from(seed));
        } else {
            debug!("NOPE {res:?}");
        }
        let mut o4 = O4Stream::new(stream, codec, Session::Client(self.session));

        Ok(Obfs4Stream::from_o4(o4))
    }

    fn try_parse(&mut self, buf: impl AsRef<[u8]>) -> Result<(ServerHandshakeMessage, usize)> {
        let buf = buf.as_ref();
        trace!(
            "{} parsing server handshake {}",
            self.session.session_id(),
            buf.len()
        );

        if buf.len() < SERVER_MIN_HANDSHAKE_LENGTH {
            Err(Error::Obfs4Framing(FrameError::EAgain))?
        }

        let repres_bytes: [u8; 32] = buf[0..REPRESENTATIVE_LENGTH].try_into().unwrap();
        let server_repres = Representative::from(repres_bytes);
        let server_auth: [u8; AUTH_LENGTH] =
            buf[REPRESENTATIVE_LENGTH..REPRESENTATIVE_LENGTH + AUTH_LENGTH].try_into()?;

        // derive the server mark
        let mut key = self.session.node_pubkey.as_bytes().to_vec();
        key.append(&mut self.session.node_id.to_bytes().to_vec());
        let mut h = HmacSha256::new_from_slice(&key[..]).unwrap();
        h.reset(); // disambiguate reset() implementations Mac v digest
        h.update(server_repres.as_bytes().as_ref());
        let server_mark = h.finalize_reset().into_bytes()[..MARK_LENGTH].try_into()?;

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
        h.reset(); // disambiguate `reset()` implementations Mac v digest
        h.update(&buf[..pos + MARK_LENGTH]);
        h.update(&self.session.epoch_hour.as_bytes());
        let mac_calculated = &h.finalize_reset().into_bytes()[..MAC_LENGTH];
        let mac_received = &buf[pos + MARK_LENGTH..pos + MARK_LENGTH + MAC_LENGTH];
        trace!(
            "client mac check {}-{}",
            hex::encode(mac_calculated),
            hex::encode(mac_received)
        );
        if mac_calculated.ct_eq(mac_received).into() {
            return Ok((
                ServerHandshakeMessage::new(
                    server_repres,
                    server_auth,
                    self.session.session_keys.representative.clone().unwrap(),
                    server_mark,
                    Some(pos + MARK_LENGTH + MAC_LENGTH),
                    self.session.epoch_hour.clone(),
                ),
                pos + MARK_LENGTH + MAC_LENGTH,
            ));
        }

        // received the incorrect mac
        Err(Error::Obfs4Framing(FrameError::TagMismatch))
    }
}

pub struct ClientHandshakeMessage {
    pad_len: usize,
    repres: Representative,
    pubkey: Option<ntor::PublicKey>,

    // only used when parsing (i.e. on the server side)
    epoch_hour: String,
    mark: [u8; MARK_LENGTH],
}

impl ClientHandshakeMessage {
    pub fn new(
        repres: Representative,
        pad_len: usize,
        epoch_hour: String,
        mark: [u8; MARK_LENGTH],
    ) -> Self {
        Self {
            pad_len,
            repres,
            pubkey: None,

            // only used when parsing (i.e. on the server side)
            epoch_hour,
            mark,
        }
    }

    pub fn get_public(&mut self) -> ntor::PublicKey {
        match self.pubkey {
            Some(pk) => pk,
            None => {
                let pk = ntor::PublicKey::from(&self.repres);
                self.pubkey = Some(pk); 
                pk
            }
        }
    }

    pub fn get_mark(&self) -> [u8; MARK_LENGTH] {
        self.mark
    }

    pub fn get_representative(&self) -> Representative {
        self.repres.clone()
    }

    pub fn get_epoch_hr(&self) -> String {
        self.epoch_hour.clone()
    }

    fn marshall(&mut self, buf: &mut impl BufMut, mut h: HmacSha256) -> Result<()> {
        trace!("serializing client handshake");

        h.reset(); // disambiguate reset() implementations Mac v digest
        h.update(self.repres.as_bytes().as_ref());
        let mark: &[u8] = &h.finalize_reset().into_bytes()[..MARK_LENGTH];

        // The client handshake is X | P_C | M_C | MAC(X | P_C | M_C | E) where:
        //  * X is the client's ephemeral Curve25519 public key representative.
        //  * P_C is [clientMinPadLength,clientMaxPadLength] bytes of random padding.
        //  * M_C is HMAC-SHA256-128(serverIdentity | NodeID, X)
        //  * MAC is HMAC-SHA256-128(serverIdentity | NodeID, X .... E)
        //  * E is the string representation of the number of hours since the UNIX
        //    epoch.

        // Generate the padding
        let pad = make_pad(self.pad_len)?;

        // Write X, P_C, M_C
        let mut params = vec![];
        params.extend_from_slice(self.repres.as_bytes());
        params.extend_from_slice(&pad);
        params.extend_from_slice(mark);
        buf.put(params.as_slice());

        // Calculate and write MAC
        h.update(&params);
        self.epoch_hour = format!("{}", get_epoch_hour());
        h.update(self.epoch_hour.as_bytes());
        let mac = &h.finalize_reset().into_bytes()[..MARK_LENGTH];
        buf.put(mac);

        trace!("mark: {}, mac: {}", hex::encode(mark), hex::encode(mac));

        Ok(())
    }
}
