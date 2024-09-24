use crate::{
    common::{
        ct,
        mlkem1024_x25519::{PublicKey, SharedSecret, StaticSecret},
        ntor_arti::ClientHandshake,
    },
    constants::*,
    handshake::*,
    Error, Result,
};

use core::borrow::Borrow;

use cipher::KeyIvInit;
use rand::{CryptoRng, RngCore};
use tor_bytes::{EncodeResult, Reader, SecretBuf, Writer};
use tor_cell::relaycell::extend::NtorV3Extension;
use tor_error::into_internal;
use tor_llcrypto::d::{Sha3_256, Shake256};
use zeroize::Zeroizing;

/// materials required to initiate a handshake from the client role.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct HandshakeMaterials {
    pub(crate) node_pubkey: NtorV3PublicKey,
    pub(crate) pad_len: usize,
    pub(crate) session_id: String,
}

impl HandshakeMaterials {
    pub(crate) fn new(node_pubkey: NtorV3PublicKey, session_id: String) -> Self {
        HandshakeMaterials {
            node_pubkey,
            session_id,
            pad_len: rand::thread_rng().gen_range(CLIENT_MIN_PAD_LENGTH..CLIENT_MAX_PAD_LENGTH),
        }
    }
}

//------------------------------[obfs4]-----------------------------------------//

/// Client state for the o5 (ntor v3) handshake.
///
/// The client needs to hold this state between when it sends its part
/// of the handshake and when it receives the relay's reply.
pub(crate) struct HandshakeState {
    /// The temporary curve25519 secret (x) that we've generated for
    /// this handshake.
    // We'd like to EphemeralSecret here, but we can't since we need
    // to use it twice.
    my_sk: StaticSecret,

    /// handshake materials
    materials: HandshakeMaterials,

    /// the computed hour at which the initial portion of the handshake was sent.
    epoch_hr: String,

    /// The shared secret generated as Bx or Xb.
    shared_secret: SharedSecret, // Bx

    /// The MAC of our original encrypted message.
    msg_mac: MessageMac, // msg_mac
}

//-----------------------------[ntorv3]----------------------------------------//

// /// Client state for the ntor v3 handshake.
// ///
// /// The client needs to hold this state between when it sends its part
// /// of the handshake and when it receives the relay's reply.
// pub(crate) struct HandshakeState {
//     /// The public key of the relay we're communicating with.
//     relay_public: NtorV3PublicKey, // B, ID.
//     /// Our ephemeral secret key for this handshake.
//     my_sk: StaticSecret, // x
//     /// Our ephemeral public key for this handshake.
//     my_public: PublicKey, // X
//
//     /// The shared secret generated as Bx or Xb.
//     shared_secret: SharedSecret, // Bx
//     /// The MAC of our original encrypted message.
//     msg_mac: MessageMac, // msg_mac
// }

/// Client side of the ntor v3 handshake.
pub(crate) struct NtorV3Client;

impl ClientHandshake for NtorV3Client {
    type KeyType = NtorV3PublicKey;
    type StateType = HandshakeState;
    type KeyGen = NtorV3KeyGenerator;
    type ClientAuxData = [NtorV3Extension];
    type ServerAuxData = Vec<NtorV3Extension>;

    /// Generate a new client onionskin for a relay with a given onion key.
    /// If any `extensions` are provided, encode them into to the onionskin.
    ///
    /// On success, return a state object that will be used to complete the handshake, along
    /// with the message to send.
    fn client1<M: Borrow<Self::ClientAuxData>>(
        key: &Self::KeyType,
        client_aux_data: &M,
    ) -> Result<(Self::StateType, Vec<u8>)> {
        let mut rng = rand::thread_rng();
        let mut message = Vec::new();
        NtorV3Extension::write_many_onto(client_aux_data.borrow(), &mut message)
            .map_err(|e| Error::from_bytes_enc(e, "ntor3 handshake extensions"))?;
        Ok(
            client_handshake_ntor_v3(&mut rng, key, &message, NTOR3_CIRC_VERIFICATION)
                .map_err(into_internal!("Can't encode ntor3 client handshake."))?,
        )
    }

    /// Handle an onionskin from a relay, and produce a key generator.
    ///
    /// The state object must match the one that was used to make the
    /// client onionskin that the server is replying to.
    fn client2<T: AsRef<[u8]>>(
        state: Self::StateType,
        msg: T,
    ) -> Result<(Vec<NtorV3Extension>, Self::KeyGen)> {
        let (message, xofreader) =
            client_handshake_ntor_v3_part2(&state, msg.as_ref(), NTOR3_CIRC_VERIFICATION)?;
        let extensions = NtorV3Extension::decode(&message).map_err(|err| Error::CellDecodeErr {
            object: "ntor v3 extensions",
            err,
        })?;
        let keygen = NtorV3KeyGenerator { reader: xofreader };

        Ok((extensions, keygen))
    }
}

/// Client-side Ntor version 3 handshake, part one.
///
/// Given a secure `rng`, a relay's public key, a secret message to send,
/// and a shared verification string, generate a new handshake state
/// and a message to send to the relay.
pub(crate) fn client_handshake_ntor_v3<R: RngCore + CryptoRng>(
    rng: &mut R,
    relay_public: &NtorV3PublicKey,
    client_msg: &[u8],
    verification: &[u8],
) -> EncodeResult<(HandshakeState, Vec<u8>)> {
    let my_sk = StaticSecret::random_from_rng(rng);
    client_handshake_ntor_v3_no_keygen(relay_public, client_msg, verification, my_sk)
}

/// As `client_handshake_ntor_v3`, but don't generate an ephemeral DH
/// key: instead take that key an arguments `my_sk`.
pub(crate) fn client_handshake_ntor_v3_no_keygen(
    relay_public: &NtorV3PublicKey,
    client_msg: &[u8],
    verification: &[u8],
    my_sk: StaticSecret,
) -> EncodeResult<(HandshakeState, Vec<u8>)> {
    let my_public = PublicKey::from(&my_sk);
    let bx = my_sk.diffie_hellman(&relay_public.pk);

    let (enc_key, mut mac) = kdf_msgkdf(&bx, relay_public, &my_public, verification)?;

    //encrypted_msg = ENC(ENC_K1, CM)
    // msg_mac = MAC_msgmac(MAC_K1, ID | B | X | encrypted_msg)
    let encrypted_msg = encrypt(&enc_key, client_msg);
    let msg_mac: DigestVal = {
        use digest::Digest;
        mac.write(&encrypted_msg)?;
        mac.take().finalize().into()
    };

    let mut message = Vec::new();
    message.write(&relay_public.id)?;
    message.write(&relay_public.pk)?;
    message.write(&my_public)?;
    message.write(&encrypted_msg)?;
    message.write(&msg_mac)?;

    let state = HandshakeState {
        relay_public: relay_public.clone(),
        my_sk,
        my_public,
        shared_secret: bx,
        msg_mac,
    };

    Ok((state, message))
}

/// Finalize the handshake on the client side.
///
/// Called after we've received a message from the relay: try to
/// complete the handshake and verify its correctness.
///
/// On success, return the server's reply to our original encrypted message,
/// and an `XofReader` to use in generating circuit keys.
pub(crate) fn client_handshake_ntor_v3_part2(
    state: &HandshakeState,
    relay_handshake: &[u8],
    verification: &[u8],
) -> Result<(Vec<u8>, NtorV3XofReader)> {
    let mut reader = Reader::from_slice(relay_handshake);
    let y_pk: PublicKey = reader
        .extract()
        .map_err(|e| Error::from_bytes_err(e, "v3 ntor handshake"))?;
    let auth: DigestVal = reader
        .extract()
        .map_err(|e| Error::from_bytes_err(e, "v3 ntor handshake"))?;
    let encrypted_msg = reader.into_rest();

    // TODO: Some of this code is duplicated from the server handshake code!  It
    // would be better to factor it out.
    let yx = state.my_sk.diffie_hellman(&y_pk);
    let secret_input = {
        let mut si = SecretBuf::new();
        si.write(&yx)
            .and_then(|_| si.write(&state.shared_secret))
            .and_then(|_| si.write(&state.relay_public.id))
            .and_then(|_| si.write(&state.relay_public.pk))
            .and_then(|_| si.write(&state.my_public))
            .and_then(|_| si.write(&y_pk))
            .and_then(|_| si.write(PROTOID))
            .and_then(|_| si.write(&Encap(verification)))
            .map_err(into_internal!("error encoding ntor3 secret_input"))?;
        si
    };
    let ntor_key_seed = h_key_seed(&secret_input);
    let verify = h_verify(&secret_input);

    let computed_auth: DigestVal = {
        use digest::Digest;
        let mut auth = DigestWriter(Sha3_256::default());
        auth.write(&T_AUTH)
            .and_then(|_| auth.write(&verify))
            .and_then(|_| auth.write(&state.relay_public.id))
            .and_then(|_| auth.write(&state.relay_public.pk))
            .and_then(|_| auth.write(&y_pk))
            .and_then(|_| auth.write(&state.my_public))
            .and_then(|_| auth.write(&state.msg_mac))
            .and_then(|_| auth.write(&Encap(encrypted_msg)))
            .and_then(|_| auth.write(PROTOID))
            .and_then(|_| auth.write(&b"Server"[..]))
            .map_err(into_internal!("error encoding ntor3 authentication input"))?;
        auth.take().finalize().into()
    };

    let okay = computed_auth.ct_eq(&auth)
        & ct::bool_to_choice(yx.was_contributory())
        & ct::bool_to_choice(state.shared_secret.was_contributory());

    let (enc_key, keystream) = {
        use digest::{ExtendableOutput, XofReader};
        let mut xof = DigestWriter(Shake256::default());
        xof.write(&T_FINAL)
            .and_then(|_| xof.write(&ntor_key_seed))
            .map_err(into_internal!("error encoding ntor3 xof input"))?;
        let mut r = xof.take().finalize_xof();
        let mut enc_key = Zeroizing::new([0_u8; ENC_KEY_LEN]);
        r.read(&mut enc_key[..]);
        (enc_key, r)
    };
    let server_reply = decrypt(&enc_key, encrypted_msg);

    if okay.into() {
        Ok((server_reply, NtorV3XofReader(keystream)))
    } else {
        Err(Error::BadCircHandshakeAuth)
    }
}
