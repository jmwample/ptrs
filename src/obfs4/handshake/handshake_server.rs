
use super::*;
use crate::{
    common::{
        curve25519::{PublicKey, PublicRepresentative, REPRESENTATIVE_LENGTH},
        ntor_arti::RelayHandshakeError,
        replay_filter, HmacSha256
    },
    obfs4::{
        framing::{ClientHandshakeMessage, ServerHandshakeMessage, Messages, MessageTypes, build_and_marshall},
        // constants::*,
        // handshake::{
        //     utils::find_mac_mark,
        // },
    },
};

use tracing::{debug, trace};
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use tokio_util::codec::Encoder;

use std::time::Instant;

// #[derive(Debug)]
pub(crate) struct HandshakeMaterials<'a> {
    pub(crate) identity_keys: &'a Obfs4NtorSecretKey,
    pub(crate) replay_filter: &'a mut replay_filter::ReplayFilter,

    pub(crate) session_id: String,
    pub(crate) len_seed: [u8; SEED_LENGTH],
}

impl<'a> HandshakeMaterials<'a> {
    pub fn get_hmac(&self) -> HmacSha256 {
        let mut key = self.identity_keys.pk.pk.as_bytes().to_vec();
        key.append(&mut self.identity_keys.pk.id.as_bytes().to_vec());
        HmacSha256::new_from_slice(&key[..]).unwrap()
    }

    pub fn new<'b>(
        identity_keys: &'b Obfs4NtorSecretKey,
        replay_filter: &'b mut replay_filter::ReplayFilter,
        session_id: String,
        len_seed: [u8; SEED_LENGTH],
    ) -> Self
    where
        'b: 'a,
    {
        HandshakeMaterials {
            identity_keys,
            replay_filter,
            session_id,
            len_seed,
        }
    }
}


/// Perform a server-side ntor handshake.
///
/// On success returns a key generator and a server onionskin.
pub(super) fn server_handshake_obfs4<R, T>(
    rng: &mut R,
    msg: T,
    keys: &[Obfs4NtorSecretKey],
) -> RelayHandshakeResult<(NtorHkdfKeyGenerator, Vec<u8>)>
where
    R: RngCore + CryptoRng,
    T: AsRef<[u8]>,
{
    let ephem = EphemeralSecret::random_from_rng(rng);
    let ephem_pub = PublicKey::from(&ephem);

    server_handshake_obfs4_no_keygen(ephem_pub, ephem, msg, keys)
}

/// Helper: perform a server handshake without generating any new keys.
pub(crate) fn server_handshake_obfs4_no_keygen<T>(
    ephem_pub: PublicKey,
    ephem: EphemeralSecret,
    msg: T,
    keys: &[Obfs4NtorSecretKey],
) -> RelayHandshakeResult<(NtorHkdfKeyGenerator, Vec<u8>)>
where
    T: AsRef<[u8]>,
{
    if CLIENT_MIN_HANDSHAKE_LENGTH > msg.as_ref().len() {
        Err(RelayHandshakeError::EAgain)?;
    }

    let mut cur = Reader::from_slice(msg.as_ref());

    let my_id: RsaIdentity = cur.extract()?;
    let my_key_bytes: [u8; 32] = cur.extract()?;
    let my_key = PublicKey::from(my_key_bytes);
    let their_pk_bytes: [u8; 32] = cur.extract()?;
    let their_pk = PublicKey::from(their_pk_bytes);

    let keypair = ct_lookup(keys, |key| key.matches_pk(&my_key));
    let keypair = match keypair {
        Some(k) => k,
        None => return Err(RelayHandshakeError::MissingKey),
    };

    if my_id != keypair.pk.id {
        return Err(RelayHandshakeError::MissingKey);
    }

    let xy = ephem.diffie_hellman(&their_pk);
    let xb = keypair.sk.diffie_hellman(&their_pk);

    let okay =
        ct::bool_to_choice(xy.was_contributory()) & ct::bool_to_choice(xb.was_contributory());

    let (keygen, authcode) = ntor_derive(&xy, &xb, &keypair.pk, &their_pk, &ephem_pub)
        .map_err(into_internal!("Error deriving keys"))?;

    let mut reply: Vec<u8> = Vec::new();
    tor_bytes::Writer::write(&mut reply, &ephem_pub.as_bytes())
        .and_then(|_| reply.write_and_consume(authcode))
        .map_err(into_internal!(
            "Generated relay handshake we couldn't encode"
        ))?;

    if okay.into() {
        Ok((keygen, reply))
    } else {
        Err(RelayHandshakeError::BadClientHandshake)
    }
}


pub async fn retrieve_client_handshake<'a, T>(
    stream: &mut T,
    materials: &mut HandshakeMaterials<'a>,
) -> Result<ClientHandshakeMessage>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    // wait for and attempt to consume the client hello message
    let mut buf = [0_u8; MAX_HANDSHAKE_LENGTH];
    let client_hs: ClientHandshakeMessage;
    loop {
        let n = stream.read(&mut buf).await?;
        trace!("{} successful read {n}B", materials.session_id);

        client_hs = match try_parse_client_handshake(&mut buf[..n], materials) {
            Ok(chs) => chs,
            Err(Error::HandshakeErr(RelayHandshakeError::EAgain)) => {
                trace!("{} reading more", materials.session_id);
                continue;
            }
            Err(e) => {
                trace!("{} failed to parse client handshake: {e}", materials.session_id);
                return Err(e)?;
            }
        };

        break;
    }

    debug!("{} successfully parsed client handshake", materials.session_id);

    Ok(client_hs)
}


pub async fn complete<'a, T>(
    mut stream: T,
    client_hs: &mut ClientHandshakeMessage,
    materials: HandshakeMaterials<'a>,
) -> Result<(NtorHkdfKeyGenerator, Vec<u8>)>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    // let client_hs = &mut self._h_state.client_hs;

    // derive key materials
    let ntor_hs_result: ntor::HandShakeResult = match ntor::HandShakeResult::server_handshake(
        &client_hs.get_public(),
        materials.session_keys,
        materials.identity_keys,
        &materials.node_id,
    )
    .into()
    {
        Some(r) => r,
        None => Err(Error::NtorError(ntor::NtorError::HSFailure(
            "failed to derive sharedsecret".into(),
        )))?,
    };

    let epoch_hr = client_hs.get_epoch_hr();
    let server_auth = ntor_hs_result.auth;

    // use the derived seed value to bootstrap Read / Write crypto codec.
    let okm = kdf(
        ntor_hs_result.key_seed,
        KEY_MATERIAL_LENGTH * 2 + SESSION_ID_LEN,
    );
    let ekm: [u8; KEY_MATERIAL_LENGTH] = okm[KEY_MATERIAL_LENGTH..KEY_MATERIAL_LENGTH * 2]
        .try_into()
        .unwrap();
    let dkm: [u8; KEY_MATERIAL_LENGTH] = okm[..KEY_MATERIAL_LENGTH].try_into().unwrap();

    // self.set_session_id(okm[KEY_MATERIAL_LENGTH * 2..].try_into().unwrap());
    let session_id = okm[KEY_MATERIAL_LENGTH * 2..].try_into().unwrap();

    let mut codec = Obfs4Codec::new(ekm, dkm);

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
        materials.session_keys.representative.clone().unwrap(),
        server_auth.to_bytes(),
        epoch_hr,
    );

    let h = materials.get_hmac();
    let mut buf = BytesMut::with_capacity(MAX_HANDSHAKE_LENGTH);
    sh_msg.marshall(&mut buf, h)?;
    trace!("adding encoded prng seed");

    // Send the PRNG seed as part of the first packet.
    let mut prng_pkt_buf = BytesMut::new();
    build_and_marshall(
        &mut prng_pkt_buf,
        MessageTypes::PrngSeed.into(),
        materials.len_seed,
        0,
    )?;

    codec.encode(prng_pkt_buf, &mut buf)?;

    debug!(
        "{} writing server handshake {}B",
        materials.session_id,
        buf.len()
    );

    stream.write_all(&buf).await?;

    Ok(ServerHandshake {
        materials: self.materials,
        _h_state: ServerHandshakeSuccess { session_id, codec },
    })
}


fn try_parse_client_handshake(
    buf: impl AsRef<[u8]>,
    materials: &mut HandshakeMaterials,
) -> Result<ClientHandshakeMessage> {
    let buf = buf.as_ref();
    let mut h = materials.get_hmac();

    if CLIENT_MIN_HANDSHAKE_LENGTH > buf.len() {
        Err(Error::HandshakeErr(RelayHandshakeError::EAgain))?;
    }

    let r_bytes: [u8; 32] = buf[0..REPRESENTATIVE_LENGTH].try_into().unwrap();
    let repres = PublicRepresentative::from(&r_bytes);

    // derive the mark
    h.update(&r_bytes[..]);
    let m = h.finalize_reset().into_bytes();
    let mark: [u8; MARK_LENGTH] = m[..MARK_LENGTH].try_into()?;

    // find mark + mac position
    let pos = match find_mac_mark(
        mark,
        buf,
        REPRESENTATIVE_LENGTH + CLIENT_MIN_PAD_LENGTH,
        MAX_HANDSHAKE_LENGTH,
        true,
    ) {
        Some(p) => p,
        None => {
            trace!("didn't find mark");
            if buf.len() > MAX_HANDSHAKE_LENGTH {
                Err(Error::HandshakeErr(RelayHandshakeError::BadClientHandshake))?
            }
            Err(Error::HandshakeErr(RelayHandshakeError::EAgain))?
        }
    };

    // validate he MAC
    let mut mac_found = false;
    let mut epoch_hr = String::new();
    for offset in [0_i64, -1, 1] {
        // Allow the epoch to be off by up to one hour in either direction
        trace!("server trying offset: {offset}");
        let eh = format!("{}", offset + get_epoch_hour() as i64);

        h.reset();
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
            if materials
                .replay_filter
                .test_and_set(Instant::now(), mac_received)
            {
                // The client either happened to generate exactly the same
                // session key and padding, or someone is replaying a previous
                // handshake.  In either case, fuck them.
                Err(Error::HandshakeErr(RelayHandshakeError::ReplayedHandshake))?
            }

            epoch_hr = eh;
            mac_found = true;
            // we could break here, but in the name of reducing timing
            // variance, we just evaluate all three MACs.
        }
    }
    if !mac_found {
        // This could be a [`RelayHandshakeError::TagMismatch`] :shrug:
        Err(Error::HandshakeErr(RelayHandshakeError::BadClientHandshake))?
    }

    // client should never send any appended padding at the end.
    if buf.len() != pos + MARK_LENGTH + MAC_LENGTH {
        Err(Error::HandshakeErr(RelayHandshakeError::BadClientHandshake))?
    }

    Ok(ClientHandshakeMessage::new(
        repres,
        0, // doesn't matter when we are reading client handshake msg
        epoch_hr,
    ))
}
