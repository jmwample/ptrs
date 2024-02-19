
use super::*;
use crate::{
    common::{curve25519::{PublicKey, PublicRepresentative}, HmacSha256},
    obfs4::{
        handshake::utils::{get_epoch_hour, make_pad, find_mac_mark},
        framing::handshake::ServerHandshakeMessage,
    },
};

use rand::Rng;
use tracing::trace;
use bytes::BufMut;


/// materials required to initiate a handshake from the client role.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct HandshakeMaterials {
    pub(crate) node_pubkey: Obfs4NtorPublicKey,
    pub(crate) pad_len: usize,
    pub(crate) session_id: String,
}

impl<'a> HandshakeMaterials {
    pub(crate) fn new(
        node_pubkey: Obfs4NtorPublicKey,
        session_id: String,
    ) -> Self {
        HandshakeMaterials {
            node_pubkey,
            session_id,
            pad_len: rand::thread_rng().gen_range(CLIENT_MIN_PAD_LENGTH..CLIENT_MAX_PAD_LENGTH),
        }
    }
}


/// Perform a client handshake, generating an onionskin and a state object
pub(super) fn client_handshake_obfs4<R>(
    rng: &mut R,
    relay_public: &Obfs4NtorPublicKey,
) -> Result<(NtorHandshakeState, Vec<u8>)>
where
    R: RngCore + CryptoRng,
{
    let my_sk = StaticSecret::random_from_rng(rng);
    let my_public = PublicKey::from(&my_sk);

    client_handshake_obfs4_no_keygen(my_public, my_sk, relay_public)
}

/// Helper: client handshake _without_ generating  new keys.
pub(crate) fn client_handshake_obfs4_no_keygen(
    my_public: PublicKey,
    my_sk: StaticSecret,
    relay_public: &Obfs4NtorPublicKey,
) -> Result<(NtorHandshakeState, Vec<u8>)> {
    let mut v: Vec<u8> = Vec::new();

    v.write(&relay_public.id)
        .and_then(|_| v.write(&relay_public.pk.as_bytes()))
        .and_then(|_| v.write(&my_public.as_bytes()))
        .map_err(|e| Error::from_bytes_enc(e, "Can't encode client handshake."))?;

    assert_eq!(v.len(), 20 + 32 + 32);

    let state = NtorHandshakeState {
        relay_public: relay_public.clone(),
        my_public,
        my_sk,
    };

    Ok((state, v))
}

/// Complete a client handshake, returning a key generator on success.
pub(super) fn client_handshake2_obfs4<T>(msg: T, state: &NtorHandshakeState) -> Result<(BytesMut, NtorHkdfKeyGenerator)>
where
    T: AsRef<[u8]>,
{
    let mut cur = Reader::from_slice(msg.as_ref());
    let their_pk_bytes: [u8; 32] = cur
        .extract()
        .map_err(|e| Error::from_bytes_err(e, "v3 ntor handshake"))?;
    let their_pk = PublicKey::from(their_pk_bytes);
    let auth: Authcode = cur
        .extract()
        .map_err(|e| Error::from_bytes_err(e, "v3 ntor handshake"))?;

    let xy = state.my_sk.diffie_hellman(&their_pk);
    let xb = state.my_sk.diffie_hellman(&state.relay_public.pk);

    let (keygen, authcode) = ntor_derive(&xy, &xb, &state.relay_public, &state.my_public, &their_pk)
        .map_err(into_internal!("Error deriving keys"))?;

    let okay = authcode.ct_eq(&auth)
        & ct::bool_to_choice(xy.was_contributory())
        & ct::bool_to_choice(xb.was_contributory());

    if okay.into() {
        Ok((BytesMut::from(cur.into_rest()), keygen))
    } else {
        Err(Error::BadCircHandshakeAuth)
    }
}







#[cfg(test)]
pub(crate) fn client_handshake2_no_auth_check_obfs4<T>(
    msg: T,
    state: &NtorHandshakeState,
) -> Result<(NtorHkdfKeyGenerator, Authcode)>
where
    T: AsRef<[u8]>,
{
    let mut cur = Reader::from_slice(msg.as_ref());
    let their_pk_bytes: [u8; 32] = cur
        .extract()
        .map_err(|e| Error::from_bytes_err(e, "v3 ntor handshake"))?;
    let their_pk = PublicKey::from(their_pk_bytes);

    let xy = state.my_sk.diffie_hellman(&their_pk);
    let xb = state.my_sk.diffie_hellman(&state.relay_public.pk);

    ntor_derive(&xy, &xb, &state.relay_public, &state.my_public, &their_pk)
        .map_err(into_internal!("Error deriving keys"))
        .map_err(|e| Error::Bug(e))
}

