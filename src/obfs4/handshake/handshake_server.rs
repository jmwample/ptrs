
use super::*;
use crate::{
    common::{
        curve25519::{PublicRepresentative, PublicKey}, HmacSha256, replay_filter,
    },
    // obfs4::{
    //     constants::*,
    //     handshake::{
    //         utils::find_mac_mark,
    //     },
    // },
};

use bytes::BufMut;
use rand::Rng;
use tracing::trace;

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


pub struct ServerHandshakeMessage {
    server_auth: [u8; AUTHCODE_LENGTH],
    pad_len: usize,
    repres: PublicRepresentative,
    pubkey: Option<PublicKey>,
    epoch_hour: String,
}

impl ServerHandshakeMessage {
    pub fn new(repres: PublicRepresentative, server_auth: [u8; AUTHCODE_LENGTH], epoch_hr: String) -> Self {
        Self {
            server_auth,
            pad_len: rand::thread_rng().gen_range(SERVER_MIN_PAD_LENGTH..SERVER_MAX_PAD_LENGTH),
            repres,
            pubkey: None,
            epoch_hour: epoch_hr,
        }
    }

    pub fn server_pubkey(&mut self) -> PublicKey {
        match self.pubkey {
            Some(pk) => pk,
            None => {
                let pk = PublicKey::from(&self.repres);
                self.pubkey = Some(pk);
                pk
            }
        }
    }

    pub fn server_auth(self) -> [u8; AUTHCODE_LENGTH] {
        self.server_auth
    }

    fn marshall(&mut self, buf: &mut impl BufMut, mut h: HmacSha256) -> Result<()> {
        trace!("serializing server handshake");

        h.reset();
        h.update(self.repres.as_bytes().as_ref());
        let mark: &[u8] = &h.finalize_reset().into_bytes()[..MARK_LENGTH];

        // The server handshake is Y | AUTH | P_S | M_S | MAC(Y | AUTH | P_S | M_S | E) where:
        //  * Y is the server's ephemeral Curve25519 public key representative.
        //  * AUTH is the ntor handshake AUTH value.
        //  * P_S is [serverMinPadLength,serverMaxPadLength] bytes of random padding.
        //  * M_S is HMAC-SHA256-128(serverIdentity | NodeID, Y)
        //  * MAC is HMAC-SHA256-128(serverIdentity | NodeID, Y .... E)
        //  * E is the string representation of the number of hours since the UNIX
        //    epoch.

        // Generate the padding
        let pad: &[u8] = &make_pad(self.pad_len)?;

        // Write Y, AUTH, P_S, M_S.
        let mut params = vec![];
        params.extend_from_slice(self.repres.as_bytes());
        params.extend_from_slice(&self.server_auth);
        params.extend_from_slice(pad);
        params.extend_from_slice(mark);
        buf.put(params.as_slice());

        // Calculate and write MAC
        h.update(&params);
        h.update(self.epoch_hour.as_bytes());
        buf.put(&h.finalize_reset().into_bytes()[..MAC_LENGTH]);

        Ok(())
    }
}
