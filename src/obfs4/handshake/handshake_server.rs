
use super::*;

use crate::common::HmacSha256;
use crate::common::replay_filter;

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
    reply
        .write(&ephem_pub.as_bytes())
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