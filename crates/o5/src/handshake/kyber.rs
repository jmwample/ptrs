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

use crate::{
    common::ntor::{
        derive_ntor_shared, Auth, HandshakeResult, IdentityKeyPair, KeySeed, NtorError, PublicKey,
        SessionKeyPair, ID,
    },
    Error, Result,
};

use bytes::BytesMut;
use pqc_kyber::*;
use subtle::{Choice, ConstantTimeEq, CtOption};

use super::{AUTH_LENGTH, KEY_SEED_LENGTH};

const _ZERO_EXP: [u8; 32] = [0_u8; 32];
const X25519_PUBKEY_LEN: usize = 32;
pub const KYBERX_PUBKEY_LEN: usize = KYBER_PUBLICKEYBYTES + X25519_PUBKEY_LEN;

pub struct KyberXPublicKey {
    pub kyber: pqc_kyber::PublicKey,
    pub x25519: PublicKey,
    contiguous: [u8; KYBERX_PUBKEY_LEN],
}

impl KyberXPublicKey {
    pub fn from_parts(x25519: PublicKey, kyber: pqc_kyber::PublicKey) -> Self {
        let mut contiguous = [0_u8; KYBERX_PUBKEY_LEN];
        contiguous[..X25519_PUBKEY_LEN].copy_from_slice(&x25519.to_bytes());
        contiguous[X25519_PUBKEY_LEN..].copy_from_slice(&kyber);

        KyberXPublicKey {
            kyber,
            x25519,
            contiguous,
        }
    }

    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> std::result::Result<Self, NtorError> {
        let value = bytes.as_ref();
        if value.len() != KYBERX_PUBKEY_LEN {
            return Err(NtorError::ParseError(String::from(
                "failed to parse kyberx25519 public key, incorrect length",
            )));
        }

        let mut x25519 = [0_u8; X25519_PUBKEY_LEN];
        x25519[..].copy_from_slice(&value[..X25519_PUBKEY_LEN]);

        let mut kyber = [0_u8; KYBER_PUBLICKEYBYTES];
        kyber[..].copy_from_slice(&value[X25519_PUBKEY_LEN..]);

        let mut contiguous = [0_u8; KYBERX_PUBKEY_LEN];
        contiguous[..].copy_from_slice(&value);

        Ok(KyberXPublicKey {
            x25519: PublicKey::from(x25519),
            kyber,
            contiguous,
        })
    }
}

impl From<&KyberXSessionKeys> for KyberXPublicKey {
    fn from(value: &KyberXSessionKeys) -> Self {
        value.get_public()
    }
}

impl From<&KyberXIdentityKeys> for KyberXPublicKey {
    fn from(value: &KyberXIdentityKeys) -> Self {
        value.get_public()
    }
}

impl AsRef<[u8]> for KyberXPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.contiguous
    }
}

pub struct KyberXSessionKeys {
    pub kyber: pqc_kyber::Keypair,
    pub x25519: SessionKeyPair,
}

impl KyberXSessionKeys {
    fn new() -> Self {
        let mut rng = rand::thread_rng();

        KyberXSessionKeys {
            x25519: SessionKeyPair::new(true),
            kyber: pqc_kyber::keypair(&mut rng).expect("kyber key generation failed"),
        }
    }

    pub fn from_random<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        KyberXSessionKeys {
            x25519: SessionKeyPair::new(true),
            kyber: pqc_kyber::keypair(rng).expect("kyber key generation failed"),
        }
    }

    /// Allow downgrade of key pair to x25519 only.
    pub fn to_x25519(self) -> SessionKeyPair {
        self.x25519
    }

    pub fn get_public(&self) -> KyberXPublicKey {
        let mut contiguous = [0_u8; KYBERX_PUBKEY_LEN];
        contiguous[..X25519_PUBKEY_LEN].copy_from_slice(&self.x25519.public.to_bytes());
        contiguous[X25519_PUBKEY_LEN..].copy_from_slice(&self.kyber.public);

        KyberXPublicKey {
            kyber: self.kyber.public,
            x25519: self.x25519.public,
            contiguous,
        }
    }
}

pub struct KyberXIdentityKeys {
    pub kyber: pqc_kyber::Keypair,
    pub x25519: IdentityKeyPair,
}

impl KyberXIdentityKeys {
    fn new() -> Self {
        let mut rng = rand::thread_rng();

        KyberXIdentityKeys {
            x25519: IdentityKeyPair::new(),
            kyber: pqc_kyber::keypair(&mut rng).expect("kyber key generation failed"),
        }
    }

    fn from_random<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        KyberXIdentityKeys {
            x25519: IdentityKeyPair::new(),
            kyber: pqc_kyber::keypair(rng).expect("kyber key generation failed"),
        }
    }

    /// Allow downgrade of key pair to x25519 only.
    pub fn to_x25519(self) -> IdentityKeyPair {
        self.x25519
    }

    pub fn get_public(&self) -> KyberXPublicKey {
        let mut contiguous = [0_u8; KYBERX_PUBKEY_LEN];
        contiguous[..X25519_PUBKEY_LEN].copy_from_slice(&self.x25519.public.to_bytes());
        contiguous[X25519_PUBKEY_LEN..].copy_from_slice(&self.kyber.public);

        KyberXPublicKey {
            kyber: self.kyber.public,
            x25519: self.x25519.public,
            contiguous,
        }
    }
}

/// The client side uses the ntor derived shared secret based on the secret
/// input created by appending the shared secret derived between the client's
/// session keys and the server's sessions keys with the shared secret derived
/// between the clients session keys and the server's identity keys.
///
/// secret input = X25519(Y, x) | Kyber(Y, x) | X25519(B, x) | Kyber(B, x)
pub fn client_handshake(
    client_keys: &KyberXSessionKeys,
    server_public: &KyberXPublicKey,
    id_public: &KyberXPublicKey,
    id: &ID,
) -> subtle::CtOption<HandshakeResult> {
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
    server_keys: &KyberXSessionKeys,
    client_public: &KyberXPublicKey,
    id_keys: &KyberXIdentityKeys,
    id: &ID,
) -> subtle::CtOption<HandshakeResult> {
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
    subtle::CtOption::new(HandshakeResult { key_seed, auth }, not_ok.ct_eq(&0_u8))
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

