use super::*;
use crate::{
    common::{
        curve25519::{
            PublicKey, PublicRepresentative, Representable, StaticSecret, REPRESENTATIVE_LENGTH,
        },
        HmacSha256,
    },
    obfs4::{
        framing::handshake::{ClientHandshakeMessage, ServerHandshakeMessage},
        handshake::utils::find_mac_mark,
    },
};

use rand::Rng;
use tracing::trace;

/// materials required to initiate a handshake from the client role.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct HandshakeMaterials {
    pub(crate) node_pubkey: Obfs4NtorPublicKey,
    pub(crate) pad_len: usize,
    pub(crate) session_id: String,
}

impl HandshakeMaterials {
    pub(crate) fn new(node_pubkey: Obfs4NtorPublicKey, session_id: String) -> Self {
        HandshakeMaterials {
            node_pubkey,
            session_id,
            pad_len: rand::thread_rng().gen_range(CLIENT_MIN_PAD_LENGTH..CLIENT_MAX_PAD_LENGTH),
        }
    }
}

/// Client state for an ntor handshake.
#[derive(Clone)]
pub(crate) struct NtorHandshakeState {
    /// The temporary curve25519 secret (x) that we've generated for
    /// this handshake.
    // We'd like to EphemeralSecret here, but we can't since we need
    // to use it twice.
    my_sk: StaticSecret,

    /// handshake materials
    materials: HandshakeMaterials,

    /// the computed hour at which the initial portion of the handshake was sent.
    epoch_hr: String,
}

/// Perform a client handshake, generating an onionskin and a state object
pub(super) fn client_handshake_obfs4<R>(
    rng: &mut R,
    materials: &HandshakeMaterials,
) -> Result<(NtorHandshakeState, Vec<u8>)>
where
    R: RngCore + CryptoRng,
{
    let my_sk = Representable::static_from_rng(rng);
    client_handshake_obfs4_no_keygen(my_sk, materials.clone())
}

/// Helper: client handshake _without_ generating  new keys.
pub(crate) fn client_handshake_obfs4_no_keygen(
    ephem: StaticSecret,
    materials: HandshakeMaterials,
) -> Result<(NtorHandshakeState, Vec<u8>)> {
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

    let state = NtorHandshakeState {
        my_sk: ephem,
        materials,
        epoch_hr: ch_msg.epoch_hour,
    };

    Ok((state, buf.to_vec()))
}

/// Complete a client handshake, returning a key generator on success.
pub(super) fn client_handshake2_obfs4<T>(
    msg: T,
    state: &NtorHandshakeState,
) -> Result<(NtorHkdfKeyGenerator, Vec<u8>)>
where
    T: AsRef<[u8]>,
{
    // try to parse the message as an incoming server handshake.
    let (mut shs_msg, n) = try_parse(&msg, state)?;

    let their_pk = shs_msg.server_pubkey();
    let auth: Authcode = shs_msg.server_auth();

    let node_pubkey = &state.materials.node_pubkey;
    let my_public: PublicKey = (&state.my_sk).into();

    let xy = state.my_sk.diffie_hellman(&their_pk);
    let xb = state.my_sk.diffie_hellman(&node_pubkey.pk);

    let (key_seed, authcode) = ntor_derive(&xy, &xb, node_pubkey, &my_public, &their_pk)
        .map_err(into_internal!("Error deriving keys"))?;

    let keygen = NtorHkdfKeyGenerator::new(key_seed, true);

    let okay: bool = (authcode.ct_eq(&auth)
        & ct::bool_to_choice(xy.was_contributory())
        & ct::bool_to_choice(xb.was_contributory()))
    .into();

    if !okay {
        return Err(Error::BadCircHandshakeAuth);
    }

    if msg.as_ref().len() < n {
        return Err(RelayHandshakeError::BadServerHandshake.into());
    }

    let remainder = msg.as_ref()[n..].to_vec();

    Ok((keygen, remainder))
}

#[cfg(test)]
pub(crate) fn client_handshake2_no_auth_check_obfs4<T>(
    msg: T,
    state: &NtorHandshakeState,
) -> Result<(NtorHkdfKeyGenerator, Authcode)>
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

    let (key_seed, authcode) = ntor_derive(&xy, &xb, &node_pubkey, &my_public, &their_pk)
        .map_err(into_internal!("Error deriving keys"))?;

    let keygen = NtorHkdfKeyGenerator::new(key_seed, true);

    Ok((keygen, authcode))
}

fn try_parse(
    buf: impl AsRef<[u8]>,
    state: &NtorHandshakeState,
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

    let repres_bytes: [u8; 32] = buf[0..REPRESENTATIVE_LENGTH].try_into().unwrap();
    let server_repres = PublicRepresentative::from(repres_bytes);
    let server_auth: [u8; AUTHCODE_LENGTH] =
        buf[REPRESENTATIVE_LENGTH..REPRESENTATIVE_LENGTH + AUTHCODE_LENGTH].try_into()?;

    // derive the server mark
    let mut key = state.materials.node_pubkey.pk.as_bytes().to_vec();
    key.append(&mut state.materials.node_pubkey.id.as_bytes().to_vec());
    let mut h = HmacSha256::new_from_slice(&key[..]).unwrap();
    h.reset(); // disambiguate reset() implementations Mac v digest
    h.update(server_repres.as_bytes().as_ref());
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
        return Ok((
            ServerHandshakeMessage::new(server_repres, server_auth, state.epoch_hr.clone()),
            pos + MARK_LENGTH + MAC_LENGTH,
        ));
    }

    // received the incorrect mac
    Err(RelayHandshakeError::BadServerHandshake.into())
}
