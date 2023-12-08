#![allow(unused)]

use crate::{
    common::{
        drbg,
        elligator2::{Representative, REPRESENTATIVE_LENGTH},
        ntor::{self, AUTH_LENGTH},
        replay_filter::{self, ReplayFilter},
    },
    obfs4::{
        constants::*,
        framing::{FrameError, Obfs4Codec, KEY_MATERIAL_LENGTH},
        packet::{Marshall, TryParse},
        proto::client::{ClientHandshakeMessage, ClientParams},
    },
    stream::Stream,
    Error, Result,
};

use super::*;

use bytes::BufMut;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use std::time::Instant;

pub struct Server {
    identity_keys: ntor::IdentityKeyPair,
    node_id: ntor::ID,
    iat_mode: IAT,
    replay_filter: ReplayFilter,
}

impl Server {
    pub fn new_from_random() -> Self {
        Self {
            identity_keys: ntor::IdentityKeyPair::new(),
            node_id: ntor::ID::new(),
            iat_mode: IAT::Off,
            replay_filter: ReplayFilter::new(REPLAY_TTL),
        }
    }

    pub async fn wrap<'a>(&'a mut self, stream: &'a mut dyn Stream<'a>) -> Result<Obfs4Stream<'a>> {
        let session = self.new_session();
        tokio::select! {
            r = ServerHandshake::new(session).complete(stream) => r,
            e = tokio::time::sleep(CLIENT_HANDSHAKE_TIMEOUT) => Err(Error::HandshakeTimeout),
        }
    }

    pub fn set_args(&mut self, args: &dyn std::any::Any) -> Result<&Self> {
        Ok(self)
    }

    pub fn new_from_statefile() -> Result<Self> {
        Err(Error::NotImplemented)
    }

    pub fn write_statefile(f: std::fs::File) -> Result<()> {
        Err(Error::NotImplemented)
    }

    pub fn client_params(&self) -> ClientParams {
        ClientParams {
            station_pubkey: self.identity_keys.public,
            node_id: self.node_id.clone(),
            iat_mode: self.iat_mode.clone(),
        }
    }

    pub fn new_session(&mut self) -> ServerSession {
        let session_keys = ntor::SessionKeyPair::new(true);

        ServerSession {
            session_id: session_keys.public.to_bytes()[..SESSION_ID_LEN]
                .try_into()
                .unwrap(),

            session_keys,
            identity_keys: &self.identity_keys,

            iat_mode: self.iat_mode.clone(),
            node_id: self.node_id.clone(),
            len_seed: drbg::Seed::new().unwrap(),
            iat_seed: drbg::Seed::new().unwrap(),
            replay_filter: &mut self.replay_filter,
        }
    }
}

pub(crate) struct ServerSession<'a> {
    // fixed by server
    iat_mode: IAT,
    node_id: ntor::ID,
    identity_keys: &'a ntor::IdentityKeyPair,
    replay_filter: &'a mut ReplayFilter,

    // generated per session
    session_keys: ntor::SessionKeyPair,
    session_id: [u8; SESSION_ID_LEN],
    len_seed: drbg::Seed,
    iat_seed: drbg::Seed,
}

impl<'a> ServerSession<'a> {
    pub fn session_id(&self) -> String {
        return hex::encode(self.session_id);
    }
}

pub struct ServerHandshake<'a> {
    session: ServerSession<'a>,
}

impl<'b> ServerHandshake<'b> {
    pub fn new(session: ServerSession<'b>) -> Self {
        Self { session }
    }

    pub fn get_hmac(&self) -> HmacSha256 {
        let mut key = self.session.identity_keys.public.as_bytes().to_vec();
        key.append(&mut self.session.node_id.to_bytes().to_vec());
        HmacSha256::new_from_slice(&key[..]).unwrap()
    }

    pub async fn complete<'a>(
        mut self,
        mut stream: &'a mut dyn Stream<'a>,
    ) -> Result<Obfs4Stream<'a>>
    where
        'b: 'a,
    {
        // wait for and attempt to consume the client hello message
        let mut buf = [0_u8; MAX_HANDSHAKE_LENGTH];
        let mut client_hs: ClientHandshakeMessage;
        loop {
            let n = stream.read(&mut buf).await?;
            trace!("server-{} successful read {n}B", self.session.session_id());

            client_hs = match self.try_parse_client_handshake(&mut buf[..n]) {
                Ok(chs) => chs,
                Err(Error::Obfs4Framing(FrameError::EAgain)) => {
                    trace!("server-{} reading more", self.session.session_id());
                    continue;
                }
                Err(e) => {
                    trace!(
                        "server-{} failed to parse client handshake: {e}",
                        self.session.session_id()
                    );
                    return Err(e)?;
                }
            };

            break;
        }

        let client_mark = client_hs.get_mark();
        let client_repres = client_hs.get_representative();
        let server_auth = [0_u8; AUTH_LENGTH];

        trace!(
            "server-{} successfully parsed client handshake",
            self.session.session_id()
        );

        // Since the current and only implementation always sends a PRNG seed for
        // the length obfuscation, this makes the amount of data received from the
        // server inconsistent with the length sent from the client.
        //
        // Re-balance this by tweaking the client minimum padding/server maximum
        // padding, and sending the PRNG seed unpadded (As in, treat the PRNG seed
        // as part of the server response).  See inlineSeedFrameLength in
        // handshake_ntor.go.

        // Generate/send the response.
        let mut sh_msg = ServerHandshakeMessage::new(
            self.session.session_keys.representative.clone().unwrap(),
            server_auth,
            client_repres,
            client_mark,
            None,
        );

        let mut h = self.get_hmac();
        let mut buf = BytesMut::with_capacity(MAX_HANDSHAKE_LENGTH);
        sh_msg.marshall(&mut buf, h)?;

        // Send the PRNG seed as part of the first packet.
        packet::PrngSeedMessage::new(self.session.len_seed.clone()).marshall(&mut buf)?;

        stream.write(&mut buf).await?;

        // success!
        let ntor_hs_result: ntor::HandShakeResult = match ntor::HandShakeResult::server_handshake(
            &client_hs.get_public()?,
            &self.session.session_keys,
            &self.session.identity_keys,
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
        let okm = ntor::kdf(ntor_hs_result.key_seed, KEY_MATERIAL_LENGTH * 2);
        let ekm: [u8; KEY_MATERIAL_LENGTH] = okm[..KEY_MATERIAL_LENGTH].try_into().unwrap();
        let dkm: [u8; KEY_MATERIAL_LENGTH] = okm[KEY_MATERIAL_LENGTH..].try_into().unwrap();

        let codec = Obfs4Codec::new(ekm, dkm);
        let o4 = O4Stream::new(stream, codec, Session::Server(self.session));
        Ok(Obfs4Stream::from_o4(o4))
    }

    fn try_parse_client_handshake(
        &mut self,
        buf: impl AsRef<[u8]>,
    ) -> Result<ClientHandshakeMessage> {
        let mut buf = buf.as_ref();
        let mut h = self.get_hmac();

        if CLIENT_MIN_HANDSHAKE_LENGTH > buf.len() {
            Err(Error::Obfs4Framing(FrameError::EAgain))?;
        }

        let r = &buf[0..REPRESENTATIVE_LENGTH];
        let repres = Representative::try_from_bytes(r)?;

        trace!("here");

        // derive the mark
        h.update(r);
        let m = h.finalize_reset().into_bytes();
        trace!("{}, {}", hex::encode(m), m.len());
        let mark: [u8; MARK_LENGTH] = m[..MARK_LENGTH].try_into()?;

        // find mark + mac position
        let pos = match find_mac_mark(
            mark,
            &buf,
            REPRESENTATIVE_LENGTH + CLIENT_MIN_PAD_LENGTH,
            MAX_HANDSHAKE_LENGTH,
            true,
        ) {
            Some(p) => p,
            None => {
                trace!("didn't find mark");
                if buf.len() > MAX_HANDSHAKE_LENGTH {
                    Err(Error::Obfs4Framing(FrameError::InvalidHandshake))?
                }
                Err(Error::Obfs4Framing(FrameError::EAgain))?
            }
        };

        // validate he MAC
        let mut mac_found = false;
        let mut epoch_hr = String::new();
        for offset in [0_i64, -1, 1] {
            // Allow the epoch to be off by up to one hour in either direction
            trace!("server trying offset: {offset}");
            let eh = format!("{}", offset + get_epoch_hour() as i64);

            Mac::reset(&mut h);
            h.update(&buf[..pos + MARK_LENGTH]);
            h.update(eh.as_bytes());
            let mac_calculated = &h.finalize_reset().into_bytes()[..MAC_LENGTH];
            let mac_received = &buf[pos + MARK_LENGTH..pos + MARK_LENGTH + MAC_LENGTH];
            trace!(
                "server {}-{}",
                hex::encode(mac_calculated),
                hex::encode(mac_received)
            );
            if mac_calculated.ct_eq(mac_received).into() {
                trace!("correct mac");
                // Ensure that this handshake has not been seen previously.
                if self
                    .session
                    .replay_filter
                    .test_and_set(Instant::now(), mac_received)
                {
                    // The client either happened to generate exactly the same
                    // session key and padding, or someone is replaying a previous
                    // handshake.  In either case, fuck them.
                    Err(Error::Obfs4Framing(FrameError::ReplayedHandshake))?
                }

                epoch_hr = eh;
                mac_found = true;
                // we could break here, but in the name of reducing timing
                // variance, we just evaluate all three MACs.
            }
        }
        if !mac_found {
            // This could be a [`FrameError::TagMismatch`] :shrug:
            Err(Error::Obfs4Framing(FrameError::InvalidHandshake))?
        }

        // client should never send any appended padding at the end.
        if buf.len() != pos + MARK_LENGTH + MAC_LENGTH {
            Err(Error::Obfs4Framing(FrameError::InvalidHandshake))?
        }

        Ok(ClientHandshakeMessage::new(
            repres,
            Some(0), // doesn't matter when we are reading client handshake msg
            epoch_hr,
            [0_u8; MARK_LENGTH],
        ))
    }
}

pub struct ServerHandshakeMessage {
    server_auth: [u8; AUTH_LENGTH],
    pad_len: usize,
    repres: Representative,
    epoch_hour: String,

    /// Part of the obfs4 handshake is to send the PRNG Seed Message concatenated
    /// with the ServerHandshake Message since it will be padded anyways. We
    /// need the hs offset so we can parse the PRNG message.
    hs_end_pos: usize,

    client_mark: [u8; MARK_LENGTH],
    client_repres: Representative,
}

impl ServerHandshakeMessage {
    pub fn new(
        repres: Representative,
        server_auth: [u8; AUTH_LENGTH],
        client_repres: Representative,
        client_mark: [u8; MARK_LENGTH],
        hs_end_pos: Option<usize>,
    ) -> Self {
        Self {
            server_auth,
            pad_len: 0,
            repres,
            epoch_hour: "".into(),
            hs_end_pos: hs_end_pos.unwrap_or(0),

            client_mark,
            client_repres,
        }
    }

    pub fn server_pubkey(self) -> Result<ntor::PublicKey> {
        self.repres.to_public()
    }

    pub fn server_auth(self) -> [u8; AUTH_LENGTH] {
        self.server_auth
    }

    fn marshall(&mut self, buf: &mut impl BufMut, mut h: HmacSha256) -> Result<()> {
        trace!("serializing server handshake");

        Mac::reset(&mut h);
        h.update(self.repres.as_bytes().as_ref());
        let mark: &[u8] = &h.finalize_reset().into_bytes()[..];

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
        h.update(&params);
        h.update(format!("{}", get_epoch_hour()).as_bytes());
        buf.put(&h.finalize_reset().into_bytes()[..]);

        Ok(())
    }
}
