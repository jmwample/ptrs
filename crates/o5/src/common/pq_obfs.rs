//! ## KyberX25519 Ntor Handshake
//!
//! ### As Described in draft-tls-westerbaan-xyber768d00-03
//!
//! ```
//! 3.  Construction
//!
//!    We instantiate draft-ietf-tls-hybrid-design-06 with X25519 [rfc7748]
//!    and Kyber768Draft00 [kyber].  The latter is Kyber as submitted to
//!    round 3 of the NIST PQC process [KyberV302].
//!
//!    For the client's share, the key_exchange value contains the
//!    concatenation of the client's X25519 ephemeral share (32 bytes) and
//!    the client's Kyber768Draft00 public key (1184 bytes).  The resulting
//!    key_exchange value is 1216 bytes in length.
//!
//!    For the server's share, the key_exchange value contains the
//!    concatenation of the server's X25519 ephemeral share (32 bytes) and
//!    the Kyber768Draft00 ciphertext (1088 bytes) returned from
//!    encapsulation for the client's public key.  The resulting
//!    key_exchange value is 1120 bytes in length.
//!
//!    The shared secret is calculated as the concatenation of the X25519
//!    shared secret (32 bytes) and the Kyber768Draft00 shared secret (32
//!    bytes).  The resulting shared secret value is 64 bytes in length.
//!
//! 4.  Security Considerations
//!
//!    For TLS 1.3, this concatenation approach provides a secure key
//!    exchange if either component key exchange methods (X25519 or
//!    Kyber768Draft00) are secure [hybrid].
//! ```

// use crate::{
//     common::ntor_arti::{
//         derive_ntor_shared, Auth, HandshakeResult, IdentityKeyPair, KeySeed, NtorError, PublicKey,
//         SessionKeyPair, ID,
//     },
//     Error, Result,
// };
use crate::common::curve25519::PublicKey;

use subtle::{ConstantTimeEq, CtOption};

mod keys;
mod ntorv3;

pub struct SessionKeyPair(keys::HybridKey);

pub struct IdentityKeyPair(keys::HybridKey);




/// The client side uses the ntor derived shared secret based on the secret
/// input created by appending the shared secret derived between the client's
/// session keys and the server's sessions keys with the shared secret derived
/// between the clients session keys and the server's identity keys.
///
/// secret input = X25519(Y, x) | Kyber(Y, x) | X25519(B, x) | Kyber(B, x)
pub fn client_handshake(
    client_keys: &SessionKeyPair,
    server_public: &PublicKey,
    id_public: &PublicKey,
    id: &ID,
) -> CtOption<HandshakeResult> {
    let mut not_ok = 0;
    let mut secret_input: Vec<u8> = vec![];

    // EXP(Y,x)
    let exp = client_keys
        .x25519
        .private
        .diffie_hellman(&server_public.x25519);

    not_ok |= _ZERO_EXP[..].ct_eq(exp.as_bytes()).unwrap_u8();
    secret_input.append(&mut exp.as_bytes().to_vec());

    // EXP(B,x)
    let exp = client_keys.x25519.private.diffie_hellman(&id_public.x25519);
    not_ok |= _ZERO_EXP[..].ct_eq(exp.as_bytes()).unwrap_u8();
    secret_input.append(&mut exp.as_bytes().to_vec());

    let (key_seed, auth) = derive_ntor_shared(
        secret_input,
        id,
        id_public,
        &client_keys.get_public(),
        server_public,
    );

    // failed if not_ok != 0
    // if not_ok != 0 then scalar operations failed
    subtle::CtOption::new(HandshakeResult { key_seed, auth }, not_ok.ct_eq(&0_u8))
}

/// The server side uses the ntor derived shared secret based on the secret
/// input created by appending the shared secret derived between the server's
/// session keys and the client's sessions keys with the shared secret derived
/// between the server's identity keys and the clients session keys.
///
/// secret input = X25519(X, y) | Kyber(X, y) | X25519(X, b) | Kyber(X, b)
pub fn server_handshake(
    server_keys: &SessionKeys,
    client_public: &PublicKey,
    id_keys: &IdentityKeys,
    id: &ID,
) -> CtOption<HandshakeResult> {
    let mut not_ok = 0;
    let mut secret_input: Vec<u8> = vec![];

    // EXP(X,y)
    let exp = server_keys
        .x25519
        .private
        .diffie_hellman(&client_public.x25519);
    not_ok |= _ZERO_EXP[..].ct_eq(exp.as_bytes()).unwrap_u8();
    secret_input.append(&mut exp.as_bytes().to_vec());

    // EXP(X,b)
    let exp = id_keys.x25519.private.diffie_hellman(&client_public.x25519);
    not_ok |= _ZERO_EXP[..].ct_eq(exp.as_bytes()).unwrap_u8();
    secret_input.append(&mut exp.as_bytes().to_vec());

    let (key_seed, auth) = derive_ntor_shared(
        secret_input,
        id,
        &id_keys.get_public(),
        client_public,
        &server_keys.get_public(),
    );

    // failed if not_ok != 0
    // if not_ok != 0 then scalar operations failed
    CtOption::new(HandshakeResult { key_seed, auth }, not_ok.ct_eq(&0_u8))
}

#[cfg(test)]
#[allow(unused)]
mod tests {
    use crate::common::ntor::compare_auth;

    use super::*;
    use x25519_dalek::EphemeralSecret;

    #[test]
    fn kyberx25519_handshake_flow() {
        // long-term server id and keys
        let server_id_keys = KyberXIdentityKeys::new();
        let server_id_pub = server_id_keys.get_public();
        let server_id = ID::new();

        // client open session, generating the associated ephemeral keys
        let client_session = KyberXSessionKeys::new();

        // client sends kyber25519 session pubkey(s)
        let cpk = client_session.get_public();

        // server computes kyberx25519 combined shared secret
        let server_session = KyberXSessionKeys::new();
        let server_hs_res = server_handshake(&server_session, &cpk, &server_id_keys, &server_id);

        // server sends kyberx25519 session pubkey(s)
        let spk = client_session.get_public();

        // client computes kyberx25519 combined shared secret
        let client_hs_res = client_handshake(&client_session, &spk, &server_id_pub, &server_id);

        assert_ne!(client_hs_res.is_some().unwrap_u8(), 0);
        assert_ne!(server_hs_res.is_some().unwrap_u8(), 0);

        let chsres = client_hs_res.unwrap();
        let shsres = server_hs_res.unwrap();
        assert_eq!(chsres.key_seed, shsres.key_seed);
        assert_eq!(&chsres.auth, &shsres.auth);
    }

    #[test]
    fn kyber_handshake_supplement_flow() {
        // long-term server id and keys
        let server_id_keys = KyberXIdentityKeys::new();
        let server_id_pub = server_id_keys.get_public();
        let server_id = ID::new();

        // client open session, generating the associated ephemeral keys
        let client_session = KyberXSessionKeys::new();

        // client sends ed25519 session pubkey elligator2 encoded and includes
        // session Kyber1024Supplement CryptoOffer.
        let c_ed_pk = client_session.x25519.public;
        let c_ky_pk = client_session.kyber.public;
        let cpk = KyberXPublicKey::from_parts(c_ed_pk, c_ky_pk);

        // server computes KyberX25519 combined shared secret
        let server_session = KyberXSessionKeys::new();
        let server_hs_res = server_handshake(&server_session, &cpk, &server_id_keys, &server_id);

        // server sends ed25519 session pubkey elligator2 encoded and includes
        // session Kyber1024Supplement CryptoAccept.
        let s_ed_pk = client_session.x25519.public;
        let s_ky_pk = client_session.kyber.public;
        let spk = KyberXPublicKey::from_parts(c_ed_pk, c_ky_pk);

        // client computes KyberX25519 combined shared secret
        let client_hs_res = client_handshake(&client_session, &spk, &server_id_pub, &server_id);

        assert_ne!(client_hs_res.is_some().unwrap_u8(), 0);
        assert_ne!(server_hs_res.is_some().unwrap_u8(), 0);

        let chsres = client_hs_res.unwrap();
        let shsres = server_hs_res.unwrap();
        assert_eq!(chsres.key_seed, shsres.key_seed);
        assert_eq!(&chsres.auth, &shsres.auth);
    }
}

