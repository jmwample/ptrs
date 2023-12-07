#![allow(unused)]

use crate::{
    common::{drbg, elligator2::Representative, ntor, replay_filter::ReplayFilter},
    obfs4::{
        framing::{FrameError, Obfs4Codec, KEY_MATERIAL_LENGTH},
        packet::ClientHandshakeMessage,
        proto::client::ClientParams,
    },
    stream::Stream,
    Error, Result,
};

use super::*;

use bytes::BufMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

    pub async fn wrap<'a>(&'a self, stream: &'a mut dyn Stream<'a>) -> Result<Obfs4Stream<'a>> {
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

    pub fn new_session(&self) -> ServerSession {
        ServerSession {
            // TODO: generate session id
            session_id: [0_u8; SESSION_ID_LEN],

            session_keys: ntor::SessionKeyPair::new(true),
            identity_keys: &self.identity_keys,

            iat_mode: self.iat_mode.clone(),
            node_id: self.node_id.clone(),
            len_seed: drbg::Seed::new().unwrap(),
            iat_seed: drbg::Seed::new().unwrap(),
            replay_filter: &self.replay_filter,
        }
    }
}

pub(crate) struct ServerSession<'a> {
    // fixed by server
    iat_mode: IAT,
    node_id: ntor::ID,
    identity_keys: &'a ntor::IdentityKeyPair,
    replay_filter: &'a ReplayFilter,

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

    pub async fn complete<'a>(self, mut stream: &'a mut dyn Stream<'a>) -> Result<Obfs4Stream<'a>>
    where
        'b: 'a,
    {
        // wait for and attempt to consume the client hello message
        let mut buf = [0_u8; MAX_HANDSHAKE_LENGTH];
        let mut chs: ClientHandshakeMessage;
        loop {
            let n = stream.read(&mut buf).await?;
            trace!("server-{} successful read {n}B", self.session.session_id());

            chs = match ClientHandshakeMessage::try_parse(&mut buf) {
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

        let seed = chs.get_seed()?.to_bytes();
        let client_mark = chs.get_mark()?;
        let client_repres = chs.get_representative()?;
        let server_auth = vec![];

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
        let mut sh_msg = packet::ServerHandshakeMessage::new(
            self.session.session_keys.representative.clone().unwrap(),
            self.session.identity_keys.public,
            self.session.node_id.clone(),
            server_auth,
            client_repres,
            client_mark,
        );

        let mut buf = BytesMut::with_capacity(MAX_HANDSHAKE_LENGTH);
        sh_msg.marshall(&mut buf)?;

        // Send the PRNG seed as part of the first packet.
        packet::PrngSeedMessage::new(self.session.len_seed.clone()).marshall(&mut buf)?;

        stream.write(&mut buf).await?;

        // success!

        // use the derived seed value to bootstrap Read / Write crypto codec.
        let okm = ntor::kdf(seed, KEY_MATERIAL_LENGTH * 2);
        let ekm: [u8; KEY_MATERIAL_LENGTH] = okm[..KEY_MATERIAL_LENGTH].try_into().unwrap();
        let dkm: [u8; KEY_MATERIAL_LENGTH] = okm[KEY_MATERIAL_LENGTH..].try_into().unwrap();

        let codec = Obfs4Codec::new(ekm, dkm);
        let o4 = O4Stream::new(stream, codec, Session::Server(self.session));
        Ok(Obfs4Stream::from_o4(o4))
    }
}
