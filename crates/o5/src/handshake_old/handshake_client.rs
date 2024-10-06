use super::*;
use crate::{
    common::{
        curve25519::{PublicKey, PublicRepresentative, REPRESENTATIVE_LENGTH},
        HmacSha256,
    },
    framing::handshake::{ClientHandshakeMessage, ServerHandshakeMessage},
};

use ptrs::trace;
use rand::Rng;

/// materials required to initiate a handshake from the client role.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct HandshakeMaterials {
    pub(crate) node_pubkey: O5NtorPublicKey,
    pub(crate) pad_len: usize,
    pub(crate) session_id: String,
}

impl HandshakeMaterials {
    pub(crate) fn new(node_pubkey: O5NtorPublicKey, session_id: String) -> Self {
        HandshakeMaterials {
            node_pubkey,
            session_id,
            pad_len: rand::thread_rng().gen_range(CLIENT_MIN_PAD_LENGTH..CLIENT_MAX_PAD_LENGTH),
        }
    }
}


/// Client state for the o5 (ntor v3) handshake.
///
/// The client needs to hold this state between when it sends its part
/// of the handshake and when it receives the relay's reply.
#[derive(Clone)]
pub(crate) struct O5NtorHandshakeState {
    /// The temporary curve25519 secret (x) that we've generated for
    /// this handshake.
    // We'd like to EphemeralSecret here, but we can't since we need
    // to use it twice.
    my_sk: curve25519::StaticSecret,

    /// handshake materials
    materials: HandshakeMaterials,

    /// the computed hour at which the initial portion of the handshake was sent.
    epoch_hr: String,

    /// The shared secret generated as Bx or Xb.
    shared_secret: curve25519::SharedSecret, // Bx

    /// The MAC of our original encrypted message.
    msg_mac: MacVal, // msg_mac
}

/// Client-side Ntor version 3 handshake, part one.
///
/// Given a secure `rng`, a relay's public key, a secret message to send,
/// and a shared verification string, generate a new handshake state
/// and a message to send to the relay.
pub(super) fn client_handshake_o5(
    materials: &HandshakeMaterials,
) -> Result<(O5NtorHandshakeState, Vec<u8>)> {
    let rng = rand::thread_rng();
    let my_sk = Representable::static_from_rng(rng);
    client_handshake_o5_no_keygen(my_sk, materials.clone())
}
// fn client_handshake_o5(
//     relay_public: &NtorV3PublicKey,
//     client_msg: &[u8],
//     verification: &[u8],
// ) -> EncodeResult<(NtorV3HandshakeState, Vec<u8>)> {
//     let mut rng = rand::thread_rng();
//     let my_sk = curve25519::StaticSecret::random_from_rng(rng);
//     client_handshake_ntor_v3_no_keygen(relay_public, client_msg, verification, my_sk)
// }

/// As `client_handshake_ntor_v3`, but don't generate an ephemeral DH
/// key: instead take that key an arguments `my_sk`.
// fn client_handshake_ntor_o5_keygen(
//     relay_public: &NtorV3PublicKey,
//     client_msg: &[u8],
//     verification: &[u8],
//     my_sk: curve25519::StaticSecret,
// ) -> EncodeResult<(NtorV3HandshakeState, Vec<u8>)> {
pub(crate) fn client_handshake_o5_no_keygen(
    my_sk: curve25519::StaticSecret,
    materials: HandshakeMaterials,
) -> Result<(O5NtorHandshakeState, Vec<u8>)> {
    let my_public = curve25519::PublicKey::from(&my_sk);
    let bx = my_sk.diffie_hellman(&materials.node_pubkey.pk);

    let (enc_key, mut mac) = kdf_msgkdf(&bx, materials.node_pubkey, &my_public, verification)?;

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

    let state = O5NtorHandshakeState {
        relay_public: relay_public.clone(),
        my_sk,
        my_public,
        shared_secret: bx,
        msg_mac,
    };

    Ok((state, message))
}

/// Helper: client handshake _without_ generating  new keys.
pub(crate) fn client_handshake_obfs4_no_keygen(
    ephem: StaticSecret,
    materials: HandshakeMaterials,
) -> Result<(O5NtorHandshakeState, Vec<u8>)> {
    let repres: Option<PublicRepresentative> = (&ephem).into();

    // build client handshake message
    let mut ch_msg = ClientHandshakeMessage::new(
        repres.unwrap(),
        materials.pad_len,
        materials.session_id.clone(),
    );

    let mut buf = BytesMut::with_capacity(MAX_HANDSHAKE_LENGTH);
    let mut key = materials.node_pubkey.pk.as_bytes().to_vec();
    key.append(&mut materials.node_pubkey.id.as_bytes().to_vec());
    let h = HmacSha256::new_from_slice(&key[..]).unwrap();
    ch_msg.marshall(&mut buf, h)?;

    let state = O5NtorHandshakeState {
        my_sk: ephem,
        materials,
        epoch_hr: ch_msg.epoch_hour,
    };

    Ok((state, buf.to_vec()))
}

/// Complete a client handshake, returning a key generator on success.
///
/// Called after we've received a message from the relay: try to
/// complete the handshake and verify its correctness.
///
/// On success, return the server's reply to our original encrypted message,
/// and an `XofReader` to use in generating circuit keys.
// fn client_handshake_ntor_v3_part2(
//     state: &NtorV3HandshakeState,
//     relay_handshake: &[u8],
//     verification: &[u8],
// ) -> Result<(Vec<u8>, NtorV3XofReader)> {
pub(super) fn client_handshake_o5_part2<T>(
    msg: T,
    state: &O5NtorHandshakeState,
) -> Result<(O5NtorKeyGenerator, Vec<u8>)>
where
    T: AsRef<[u8]>,
{
    let mut reader = Reader::from_slice(relay_handshake);
    let y_pk: curve25519::PublicKey = reader
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

#[cfg(test)]
// TODO: THIS IS STILL OBFS4
pub(crate) fn client_handshake2_no_auth_check_o5<T>(
    msg: T,
    state: &O5NtorHandshakeState,
) -> Result<(O5NtorKeyGenerator, Authcode)>
where
    T: AsRef<[u8]>,
{
    // try to parse the message as an incoming server handshake.
    let (mut shs_msg, _) = try_parse(&msg, state)?;

    let their_pk = shs_msg.server_pubkey();
    // let auth: Authcode = shs_msg.server_auth();

    let node_pubkey = &state.materials.node_pubkey;
    let my_public: PublicKey = (&state.my_sk).into();

    let xy = state.my_sk.diffie_hellman(&their_pk);
    let xb = state.my_sk.diffie_hellman(&node_pubkey.pk);

    let (key_seed, authcode) = ntor_derive(&xy, &xb, node_pubkey, &my_public, &their_pk)
        .map_err(into_internal!("Error deriving keys"))?;

    let keygen = O5NtorKeyGenerator::new(key_seed, true);

    Ok((keygen, authcode))
}

fn try_parse(
    buf: impl AsRef<[u8]>,
    state: &O5NtorHandshakeState,
) -> Result<(ServerHandshakeMessage, usize)> {
    let buf = buf.as_ref();
    trace!(
        "{} parsing server handshake {}",
        state.materials.session_id,
        buf.len()
    );

    if buf.len() < SERVER_MIN_HANDSHAKE_LENGTH {
        Err(RelayHandshakeError::EAgain)?
    }

    // derive the server mark
    let mut key = state.materials.node_pubkey.pk.as_bytes().to_vec();
    key.append(&mut state.materials.node_pubkey.id.as_bytes().to_vec());
    let mut h = HmacSha256::new_from_slice(&key[..]).unwrap();
    h.reset(); // disambiguate reset() implementations Mac v digest

    let mut r_bytes: [u8; 32] = buf[0..REPRESENTATIVE_LENGTH].try_into().unwrap();
    h.update(&r_bytes);

    // clear the inconsistent elligator2 bits of the representative after
    // using the wire format for deriving the mark
    r_bytes[31] &= 0x3f;
    let server_repres = PublicRepresentative::from(r_bytes);
    let server_auth: [u8; AUTHCODE_LENGTH] =
        buf[REPRESENTATIVE_LENGTH..REPRESENTATIVE_LENGTH + AUTHCODE_LENGTH].try_into()?;

    let server_mark = h.finalize_reset().into_bytes()[..MARK_LENGTH].try_into()?;

    //attempt to find the mark + MAC
    let start_pos = REPRESENTATIVE_LENGTH + AUTHCODE_LENGTH + SERVER_MIN_PAD_LENGTH;
    let pos = match find_mac_mark(server_mark, buf, start_pos, MAX_HANDSHAKE_LENGTH, false) {
        Some(p) => p,
        None => {
            if buf.len() > MAX_HANDSHAKE_LENGTH {
                Err(RelayHandshakeError::BadServerHandshake)?
            }
            Err(RelayHandshakeError::EAgain)?
        }
    };

    // validate the MAC
    h.reset(); // disambiguate `reset()` implementations Mac v digest
    h.update(&buf[..pos + MARK_LENGTH]);
    h.update(state.epoch_hr.as_bytes());
    let mac_calculated = &h.finalize_reset().into_bytes()[..MAC_LENGTH];
    let mac_received = &buf[pos + MARK_LENGTH..pos + MARK_LENGTH + MAC_LENGTH];
    trace!(
        "client mac check {}-{}",
        hex::encode(mac_calculated),
        hex::encode(mac_received)
    );
    if mac_calculated.ct_eq(mac_received).into() {
        let mut r_bytes = server_repres.to_bytes();
        r_bytes[31] &= 0x3f;
        return Ok((
            ServerHandshakeMessage::new(server_repres, server_auth, state.epoch_hr.clone()),
            pos + MARK_LENGTH + MAC_LENGTH,
        ));
    }

    // received the incorrect mac
    Err(RelayHandshakeError::BadServerHandshake.into())
}
