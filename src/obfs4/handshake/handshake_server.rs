
use super::*;

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
    // TODO(nickm): we generate this key whether or not we are
    // actually going to find our nodeid or keyid. Perhaps we should
    // delay that till later?  It shouldn't matter for most cases,
    // though.
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
