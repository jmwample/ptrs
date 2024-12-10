use crate::{
    common::{
        ct,
        drbg::SEED_LENGTH,
        ntor_arti::{AuxDataReply, RelayHandshakeError, RelayHandshakeResult, ServerHandshake},
        utils::{find_mac_mark, get_epoch_hour},
    },
    constants::*,
    framing::{ClientHandshakeMessage, ClientStateIncoming, ClientStateOutgoing},
    handshake::*,
    Error, Result, Server,
};

use std::time::Instant;

// use cipher::KeyIvInit;
use digest::{Digest, ExtendableOutput, XofReader};
use hmac::{Hmac, Mac};
use kemeleon::OKemCore;
use keys::NtorV3KeyGenerator;
use ptrs::{debug, trace};
use rand_core::{CryptoRng, CryptoRngCore, RngCore};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tor_bytes::{Reader, SecretBuf, Writer};
use tor_cell::relaycell::extend::NtorV3Extension;
use tor_error::into_internal;
use tor_llcrypto::d::{Sha3_256, Shake256};
use tor_llcrypto::pk::ed25519::Ed25519Identity;
use typenum::Unsigned;
use zeroize::Zeroizing;

/// Server Materials needed for completing a handshake
pub(crate) struct HandshakeMaterials {
    pub(crate) session_id: String,
    pub(crate) len_seed: [u8; SEED_LENGTH],
}

impl HandshakeMaterials {
    pub fn new(session_id: String, len_seed: [u8; SEED_LENGTH]) -> Self {
        HandshakeMaterials {
            session_id,
            len_seed,
        }
    }
}

impl<K: OKemCore> ServerHandshake for Server<K> {
    type HandshakeParams = SHSMaterials;
    type KeyGen = NtorV3KeyGenerator;
    type ClientAuxData = [NtorV3Extension];
    type ServerAuxData = Vec<NtorV3Extension>;

    fn server<REPLY: AuxDataReply<Self>, T: AsRef<[u8]>>(
        &self,
        reply_fn: &mut REPLY,
        materials: &Self::HandshakeParams, // TODO: do we need materials during server handshake?
        msg: T,
    ) -> RelayHandshakeResult<(Self::KeyGen, Vec<u8>)> {
        let mut bytes_reply_fn = |bytes: &[u8]| -> Option<Vec<u8>> {
            let client_exts = NtorV3Extension::decode(bytes).ok()?;
            let reply_exts = reply_fn.reply(&client_exts)?;
            let mut out = vec![];
            NtorV3Extension::write_many_onto(&reply_exts, &mut out).ok()?;
            Some(out)
        };
        let mut rng = rand::thread_rng();

        let (res, reader) = self.server_handshake_ntor_v3(
            &mut rng,
            &mut bytes_reply_fn,
            msg.as_ref(),
            &materials,
            NTOR3_CIRC_VERIFICATION,
        )?;
        Ok((NtorV3KeyGenerator::new::<ServerRole>(reader), res))
    }
}

impl<K: OKemCore> Server<K> {
    const CLIENT_CT_SIZE: usize = <<K as OKemCore>::Ciphertext as Encode>::EncodedSize::USIZE;
    const CLIENT_EK_SIZE: usize = <<K as OKemCore>::EncapsulationKey as Encode>::EncodedSize::USIZE;

    /// Complete an ntor v3 handshake as a server.
    ///
    /// Use the provided `rng` to generate keys; use the provided
    /// `reply_fn` to handle incoming client secret message and decide how
    /// to reply.  The client's handshake is in `message`.  Our private
    /// key(s) are in `keys`.  The `verification` string must match the
    /// string provided by the client.
    ///
    /// On success, return the server handshake message to send, and an XofReader
    /// to use in generating circuit keys.
    pub(crate) fn server_handshake_ntor_v3(
        &self,
        rng: &mut impl CryptoRngCore,
        reply_fn: &mut impl MsgReply,
        message: impl AsRef<[u8]>,
        materials: HandshakeMaterials,
        verification: &[u8],
    ) -> RelayHandshakeResult<(Vec<u8>, NtorV3XofReader)> {
        let (dk_session, _ek_session) = K::generate(rng);
        let ephemeral_dk = EphemeralKey::new(dk_session);
        self.server_handshake_ntor_v3_no_keygen(
            rng,
            reply_fn,
            &ephemeral_dk,
            message,
            materials,
            verification,
        )
    }

    /// As `server_handshake_ntor_v3`, but take a secret key instead of an RNG.
    pub(crate) fn server_handshake_ntor_v3_no_keygen(
        &self,
        rng: &mut impl CryptoRngCore,
        reply_fn: &mut impl MsgReply,
        secret_key_y: &EphemeralKey<K>,
        message: impl AsRef<[u8]>,
        materials: HandshakeMaterials,
        verification: &[u8],
    ) -> RelayHandshakeResult<(Vec<u8>, NtorV3XofReader)> {
        let msg = message.as_ref();
        if CLIENT_MIN_HANDSHAKE_LENGTH > msg.len() {
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

        // let xb = keypair
        //     .hpke(rng, &client_pk)
        //     .map_err(|e| Error::Crypto(e.into()))?;

        // let (enc_key, mut mac) = kdf_msgkdf(&xb, &keypair.pk, &client_pk, verification)
        //     .map_err(into_internal!("Can't apply ntor3 kdf."))?;

        // // Verify the message we received.
        // let computed_mac: DigestVal = {
        //     mac.write(client_msg)
        //         .map_err(into_internal!("Can't compute MAC input."))?;
        //     mac.take().finalize().into()
        // };
        // let y_pk = SessionPublicKey::from(secret_key_y);
        // let xy = secret_key_y.hpke(rng, &client_pk)?;

        // let mut okay = computed_mac.ct_eq(&msg_mac)
        //     & ct::bool_to_choice(xy.was_contributory())
        //     & ct::bool_to_choice(xb.was_contributory());

        // let plaintext_msg = decrypt(&enc_key, client_msg);

        // // Handle the message and decide how to reply.
        // let reply = reply_fn.reply(&plaintext_msg);

        // // It's not exactly constant time to use is_some() and
        // // unwrap_or_else() here, but that should be somewhat
        // // hidden by the rest of the computation.
        // okay &= ct::bool_to_choice(reply.is_some());
        // let reply = reply.unwrap_or_default();

        // // If we reach this point, we are actually replying, or pretending
        // // that we're going to reply.

        // if okay.into() {
        //     Ok((reply, NtorV3XofReader::new(keystream)))
        // } else {
        //     Err(RelayHandshakeError::BadClientHandshake)
        // }
        todo!("server handshake");
    }

    pub(crate) fn complete_server_hs(
        &self,
        client_hs: &ClientHandshakeMessage<K, ClientStateIncoming>,
        materials: HandshakeMaterials,
        keygen: &mut NtorV3KeyGenerator,
        authcode: Authcode,
    ) -> RelayHandshakeResult<Vec<u8>> {
        todo!("waiting on parse")
    }

    fn try_parse_client_handshake(
        &self,
        b: impl AsRef<[u8]>,
        materials: &mut HandshakeMaterials,
    ) -> Result<ClientHandshakeMessage<K, ClientStateIncoming>> {
        let buf = b.as_ref();

        if CLIENT_MIN_HANDSHAKE_LENGTH > buf.len() {
            Err(Error::HandshakeErr(RelayHandshakeError::EAgain))?;
        }

        // chunk off the clients encapsulation key
        let mut client_ek_obfs = [0u8; Self::CLIENT_CT_SIZE];
        client_ek_obfs.copy_from_slice(&buf[0..Self::CLIENT_EK_SIZE]);

        // chunk off the ciphertext
        let mut client_ct_obfs = [0u8; Self::CLIENT_CT_SIZE];
        client_ct_obfs.copy_from_slice(
            &buf[Self::CLIENT_EK_SIZE..Self::CLIENT_EK_SIZE + Self::CLIENT_CT_SIZE],
        );

        // decapsulate the secret encoded by the client
        let shared_secret_1 = self.identity_keys.sk.decapsulate(&client_ct_obfs);

        // Compute the Ephemeral Secret
        let mut f2 = Hmac::<Sha3_256>::new_from_slice(materials.node_id.as_bytes())
            .expect("keying server f2 hmac should never fail");
        f2.update(&shared_secret_1.as_bytes()[..]);
        let mut ephemeral_secret = Zeroizing::new([0u8; ENC_KEY_LEN]);
        ephemeral_secret.copy_from_slice(&f2.finalize_reset().into_bytes()[..ENC_KEY_LEN]);

        // derive the mark from the Ephemeral Secret
        let mut f1_es = Hmac::<Sha3_256>::new_from_slice(ephemeral_secret.as_ref())
            .expect("Keying server f1_es hmac should never fail");
        f1_es.update(&client_ek_obfs);
        f1_es.update(&client_ct_obfs);
        f1_es.update(MARK_ARG.as_bytes());
        let client_mark = f1_es.finalize_reset().into_bytes();

        trace!(
            "{} mark?:{}",
            materials.session_id,
            hex::encode(client_mark)
        );

        let min_position = Self::CLIENT_CT_SIZE + Self::CLIENT_EK_SIZE + CLIENT_MIN_PAD_LENGTH;

        // find mark + mac position
        let pos = match find_mac_mark(
            client_mark.into(),
            buf,
            min_position,
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
        let mut epoch_hour = String::new();
        for offset in [0_i64, -1, 1] {
            // Allow the epoch to be off by up to one hour in either direction
            trace!("server trying offset: {offset}");
            let eh = format!("{}", offset + get_epoch_hour() as i64);

            // compute the expected MAC (if the epoch hour is within the valid range)
            f1_es.reset();
            f1_es.update(&buf[..pos + MARK_LENGTH]);
            f1_es.update(eh.as_bytes());
            let mac_calculated = &f1_es.finalize_reset().into_bytes()[..MAC_LENGTH];
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

                epoch_hour = eh;
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

        // // pad_len doesn't matter when we are reading client handshake msg
        // state: ClientStateIncoming {},
        Ok(ClientHandshakeMessage::<K, ClientStateIncoming>::new(
            client_ek_obfs,
            ClientStateIncoming {},
            Some(epoch_hour),
        ))

        // -----------------------------------[NTor V3]-------------------------------
        // // TODO: Maybe use the Reader / Ntor interface, it is nice and clean.
        // // Decode the message.
        // let mut r = Reader::from_slice(message);
        // let id: Ed25519Identity = r.extract()?;
        // let requested_pk: IdentityPublicKey<K> = r.extract()?;
        // let client_pk: SessionPublicKey = r.extract()?;
        // let client_msg = if let Some(msg_len) = r.remaining().checked_sub(MAC_LEN) {
        //     r.take(msg_len)?
        // } else {
        //     let deficit = (MAC_LEN - r.remaining())
        //         .try_into()
        //         .expect("miscalculated!");
        //     return Err(Error::incomplete_error(deficit).into());
        // };

        // let msg_mac: MessageMac = r.extract()?;
        // r.should_be_exhausted()?;

        // // See if we recognize the provided (id,requested_pk) pair.
        // let keypair = match keys.matches(id, requested_pk.pk).into() {
        //     Some(k) => keys,
        //     None => return Err(RelayHandshakeError::MissingKey),
        // };
    }
}
