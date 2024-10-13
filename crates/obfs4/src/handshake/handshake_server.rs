use super::*;
use crate::{
    common::{
        x25519_elligator2::{PublicRepresentative, REPRESENTATIVE_LENGTH},
        HmacSha256,
    },
    framing::{build_and_marshall, ClientHandshakeMessage, MessageTypes, ServerHandshakeMessage},
};

use ptrs::{debug, trace};
use rand::thread_rng;
use tokio_util::codec::Encoder;

use std::time::Instant;

#[derive(Clone)]
pub(crate) struct HandshakeMaterials {
    pub(crate) identity_keys: Obfs4NtorSecretKey,
    pub(crate) session_id: String,
    pub(crate) len_seed: [u8; SEED_LENGTH],
}

impl HandshakeMaterials {
    pub fn get_hmac(&self) -> HmacSha256 {
        let mut key = self.identity_keys.pk.pk.as_bytes().to_vec();
        key.append(&mut self.identity_keys.pk.id.as_bytes().to_vec());
        HmacSha256::new_from_slice(&key[..]).unwrap()
    }

    pub fn new(
        identity_keys: &Obfs4NtorSecretKey,
        session_id: String,
        len_seed: [u8; SEED_LENGTH],
    ) -> Self {
        HandshakeMaterials {
            identity_keys: identity_keys.clone(),
            session_id,
            len_seed,
        }
    }
}

impl Server {
    /// Perform a server-side ntor handshake.
    ///
    /// On success returns a key generator and a server onionskin.
    pub(super) fn server_handshake_obfs4<T>(
        &self,
        msg: T,
        materials: HandshakeMaterials,
    ) -> RelayHandshakeResult<(NtorHkdfKeyGenerator, Vec<u8>)>
    where
        T: AsRef<[u8]>,
    {
        let rng = thread_rng();
        let session_sk = Keys::ephemeral_from_rng(rng);

        self.server_handshake_obfs4_no_keygen(session_sk, msg, materials)
    }

    /// Helper: perform a server handshake without generating any new keys.
    pub(crate) fn server_handshake_obfs4_no_keygen<T>(
        &self,
        session_sk: EphemeralSecret,
        msg: T,
        mut materials: HandshakeMaterials,
    ) -> RelayHandshakeResult<(NtorHkdfKeyGenerator, Vec<u8>)>
    where
        T: AsRef<[u8]>,
    {
        if CLIENT_MIN_HANDSHAKE_LENGTH > msg.as_ref().len() {
            Err(RelayHandshakeError::EAgain)?;
        }

        let mut client_hs = match self.try_parse_client_handshake(msg, &mut materials) {
            Ok(chs) => chs,
            Err(Error::HandshakeErr(RelayHandshakeError::EAgain)) => {
                return Err(RelayHandshakeError::EAgain);
            }
            Err(_e) => {
                debug!(
                    "{} failed to parse client handshake: {_e}",
                    materials.session_id
                );
                return Err(RelayHandshakeError::BadClientHandshake);
            }
        };

        debug!(
            "{} successfully parsed client handshake",
            materials.session_id
        );
        let their_pk = client_hs.get_public();
        let ephem_pub = (&session_sk).into();
        let session_repres = PublicRepresentative::from(&session_sk);

        let xy = session_sk.diffie_hellman(&their_pk);
        let xb = materials.identity_keys.sk.diffie_hellman(&their_pk);

        // Ensure that none of the keys are broken (i.e. equal to zero).
        let okay =
            ct::bool_to_choice(xy.was_contributory()) & ct::bool_to_choice(xb.was_contributory());
        trace!("x {} y {}", hex::encode(their_pk), hex::encode(ephem_pub));

        let (key_seed, authcode) =
            ntor_derive(&xy, &xb, &materials.identity_keys.pk, &their_pk, &ephem_pub)
                .map_err(into_internal!("Error deriving keys"))?;
        trace!(
            "seed: {} auth: {}",
            hex::encode(key_seed.as_slice()),
            hex::encode(authcode)
        );

        let mut keygen = NtorHkdfKeyGenerator::new(key_seed, false);

        let reply =
            self.complete_server_hs(&client_hs, materials, session_repres, &mut keygen, authcode)?;

        if okay.into() {
            Ok((keygen, reply))
        } else {
            Err(RelayHandshakeError::BadClientHandshake)
        }
    }

    pub(crate) fn complete_server_hs(
        &self,
        client_hs: &ClientHandshakeMessage,
        materials: HandshakeMaterials,
        session_repres: PublicRepresentative,
        keygen: &mut NtorHkdfKeyGenerator,
        authcode: Authcode,
    ) -> RelayHandshakeResult<Vec<u8>> {
        let epoch_hr = client_hs.get_epoch_hr();

        // Since the current and only implementation always sends a PRNG seed for
        // the length obfuscation, this makes the amount of data received from the
        // server inconsistent with the length sent from the client.
        //
        // Re-balance this by tweaking the client minimum padding/server maximum
        // padding, and sending the PRNG seed unpadded (As in, treat the PRNG seed
        // as part of the server response).  See inlineSeedFrameLength in
        // handshake_ntor.go.

        // Generate/send the response.
        let mut sh_msg = ServerHandshakeMessage::new(session_repres, authcode, epoch_hr);

        let h = materials.get_hmac();
        let mut buf = BytesMut::with_capacity(MAX_HANDSHAKE_LENGTH);
        sh_msg
            .marshall(&mut buf, h)
            .map_err(|e| RelayHandshakeError::FrameError(format!("{e}")))?;
        trace!("adding encoded prng seed");

        // Send the PRNG seed as part of the first packet.
        let mut prng_pkt_buf = BytesMut::new();
        build_and_marshall(
            &mut prng_pkt_buf,
            MessageTypes::PrngSeed.into(),
            materials.len_seed,
            0,
        )
        .map_err(|e| RelayHandshakeError::FrameError(format!("{e}")))?;

        let codec = &mut keygen.codec;
        codec
            .encode(prng_pkt_buf.clone(), &mut buf)
            .map_err(|e| RelayHandshakeError::FrameError(format!("{e}")))?;

        debug!(
            "{} writing server handshake {}B ...{}",
            materials.session_id,
            buf.len(),
            hex::encode(&buf[buf.len() - 10..]),
        );

        Ok(buf.to_vec())
    }

    fn try_parse_client_handshake(
        &self,
        buf: impl AsRef<[u8]>,
        materials: &mut HandshakeMaterials,
    ) -> Result<ClientHandshakeMessage> {
        let buf = buf.as_ref();
        let mut h = materials.get_hmac();

        if CLIENT_MIN_HANDSHAKE_LENGTH > buf.len() {
            Err(Error::HandshakeErr(RelayHandshakeError::EAgain))?;
        }

        let r_bytes: [u8; 32] = buf[0..REPRESENTATIVE_LENGTH].try_into().unwrap();

        // derive the mark based on the literal bytes on the wire
        h.update(&r_bytes[..]);

        // The elligator library internally clears the high-order bits of the
        // representative to force a LSR value, but we use the wire format for
        // deriving the mark (i.e. without cleared bits).
        let repres = PublicRepresentative::from(&r_bytes);

        let m = h.finalize_reset().into_bytes();
        let mark: [u8; MARK_LENGTH] = m[..MARK_LENGTH].try_into()?;

        trace!("{} mark?:{}", materials.session_id, hex::encode(mark));

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
                trace!("{} didn't find mark", materials.session_id);
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
                if self
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
            repres, 0, // pad_len doesn't matter when we are reading client handshake msg
            epoch_hr,
        ))
    }
}
