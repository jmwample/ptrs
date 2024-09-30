use crate::{
    common::{
        ct,
        mlkem1024_x25519::SharedSecret,
        ntor_arti::{ClientHandshake, ClientHandshakeMaterials},
    },
    constants::*,
    framing::handshake::ClientHandshakeMessage,
    handshake::*,
    Error, Result,
};

use bytes::BytesMut;
use hmac::{Hmac, Mac};
use keys::NtorV3KeyGenerator;
// use cipher::KeyIvInit;
use rand::{CryptoRng, Rng, RngCore};
use subtle::ConstantTimeEq;
use tor_bytes::{EncodeResult, Reader, SecretBuf, Writer};
use tor_cell::relaycell::extend::NtorV3Extension;
use tor_error::into_internal;
use tor_llcrypto::d::{Sha3_256, Shake256};
use zeroize::Zeroizing;

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
    my_sk: NtorV3SecretKey,

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

/// materials required to initiate a handshake from the client role.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct HandshakeMaterials {
    pub(crate) node_pubkey: NtorV3PublicKey,
    pub(crate) pad_len: usize,
    pub(crate) session_id: String,
    aux_data: Vec<NtorV3Extension>,
}

impl HandshakeMaterials {
    pub(crate) fn new(node_pubkey: &NtorV3PublicKey, session_id: String) -> Self {
        HandshakeMaterials {
            node_pubkey: node_pubkey.clone(),
            session_id,
            pad_len: rand::thread_rng().gen_range(CLIENT_MIN_PAD_LENGTH..CLIENT_MAX_PAD_LENGTH),
            aux_data: vec![],
        }
    }

    pub fn with_aux_data(mut self, data: impl AsRef<[NtorV3Extension]>) -> Self {
        self.aux_data = data.as_ref().to_vec();
        self
    }
}

impl ClientHandshakeMaterials for HandshakeMaterials {
    type IdentityKeyType = NtorV3PublicKey;
    type ClientAuxData = Vec<NtorV3Extension>;

    fn node_pubkey(&self) -> &Self::IdentityKeyType {
        &self.node_pubkey
    }

    fn aux_data(&self) -> Option<&Self::ClientAuxData> {
        Some(&self.aux_data)
    }
}

/// Client side of the ntor v3 handshake.
pub(crate) struct NtorV3Client;

impl ClientHandshake for NtorV3Client {
    type StateType = HandshakeState;
    type KeyGen = NtorV3KeyGenerator;
    type ServerAuxData = Vec<NtorV3Extension>;
    type HandshakeMaterials = HandshakeMaterials;

    /// Generate a new client onionskin for a relay with a given onion key.
    /// If any `extensions` are provided, encode them into to the onionskin.
    ///
    /// On success, return a state object that will be used to complete the handshake, along
    /// with the message to send.
    fn client1(hs_materials: Self::HandshakeMaterials) -> Result<(Self::StateType, Vec<u8>)> {
        let mut rng = rand::thread_rng();

        Ok(
            client_handshake_ntor_v3(&mut rng, hs_materials, NTOR3_CIRC_VERIFICATION)
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
        let keygen = NtorV3KeyGenerator::new::<ClientRole>(xofreader);

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
    materials: HandshakeMaterials,
    verification: &[u8],
) -> EncodeResult<(HandshakeState, Vec<u8>)> {
    let my_sk = NtorV3SecretKey::random_from_rng(rng);
    client_handshake_ntor_v3_no_keygen(my_sk, materials, verification)
}

/// As `client_handshake_ntor_v3`, but don't generate an ephemeral DH
/// key: instead take that key an arguments `my_sk`.
pub(crate) fn client_handshake_ntor_v3_no_keygen(
    my_sk: NtorV3SecretKey,
    materials: HandshakeMaterials,
    verification: &[u8],
) -> EncodeResult<(HandshakeState, Vec<u8>)> {
    let client_msg = ClientHandshakeMessage::new(my_sk.pk.clone(), &materials);

    // --------
    let node_pubkey = materials.node_pubkey();
    let my_public = NtorV3PublicKey::from(&my_sk);
    // let bx = my_sk.diffie_hellman(&node_pubkey);
    let mut rng = rand::thread_rng();
    let bx = my_sk.hpke(&mut rng, node_pubkey)?;
    // .map_err(|e| Error::Crypto(e.to_string()));

    let (enc_key, mut mac) = kdf_msgkdf(&my_sk, node_pubkey, &my_public, verification)?;

    // encrypted_msg = ENC(ENC_K1, CM)
    // msg_mac = MAC_msgmac(MAC_K1, ID | B | X | encrypted_msg)
    let encrypted_msg = encrypt(&enc_key, client_msg);
    let msg_mac: DigestVal = {
        use digest::Digest;
        mac.write(&encrypted_msg)?;
        mac.take().finalize().into()
    };

    let mut message = Vec::new();
    message.write(&node_pubkey.id)?;
    message.write(&node_pubkey.pk.as_bytes())?;
    message.write(&my_public.pk.as_bytes())?;
    message.write(&encrypted_msg)?;
    message.write(&msg_mac)?;
    // --------

    let mut buf = BytesMut::with_capacity(MAX_HANDSHAKE_LENGTH);
    let mut key = materials.node_pubkey.pk.as_bytes().to_vec();
    key.append(&mut materials.node_pubkey.id.as_bytes().to_vec());
    let h = Hmac::<Sha3_256>::new_from_slice(&key[..]).unwrap();
    client_msg.marshall(&mut buf, h);
    let message = buf.to_vec();

    let state = HandshakeState {
        materials,
        my_sk,
        shared_secret: bx,
        msg_mac,
        epoch_hr: client_msg.get_epoch_hr(),
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
    let y_pk: NtorV3PublicKey = reader
        .extract()
        .map_err(|e| Error::from_bytes_err(e, "v3 ntor handshake"))?;
    let auth: DigestVal = reader
        .extract()
        .map_err(|e| Error::from_bytes_err(e, "v3 ntor handshake"))?;
    let encrypted_msg = reader.into_rest();
    let my_public = NtorV3PublicKey::from(&state.my_sk);

    // TODO: Some of this code is duplicated from the server handshake code!  It
    // would be better to factor it out.
    let yx = state.my_sk.diffie_hellman(&y_pk);
    let secret_input = {
        let mut si = SecretBuf::new();
        si.write(&yx)
            .and_then(|_| si.write(&state.shared_secret.as_bytes()))
            .and_then(|_| si.write(&state.relay_public.id))
            .and_then(|_| si.write(&state.relay_public.pk.as_bytes()))
            .and_then(|_| si.write(&my_public.pk.as_bytes()))
            .and_then(|_| si.write(&y_pk.pk.as_bytes()))
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
            .and_then(|_| auth.write(&state.relay_public.pk.as_bytes()))
            .and_then(|_| auth.write(&y_pk.pk.as_bytes()))
            .and_then(|_| auth.write(&my_public.pk.as_bytes()))
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
        Ok((server_reply, NtorV3XofReader::new(keystream)))
    } else {
        Err(Error::BadCircHandshakeAuth)
    }
}
