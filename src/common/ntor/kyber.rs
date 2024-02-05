//!

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

pub fn client_handshake(
    client_keys: &KyberXSessionKeys,
    server_public: &KyberXPublicKey,
    id_public: &KyberXPublicKey,
    id: &ID,
) -> subtle::CtOption<HandshakeResult> {
    let mut not_ok = 0;
    let mut secret_input: Vec<u8> = vec![];

    // Client side uses EXP(Y,x) | EXP(B,x)
    let exp = client_keys
        .x25519
        .private
        .diffie_hellman(&server_public.x25519);
    not_ok |= _ZERO_EXP[..].ct_eq(exp.as_bytes()).unwrap_u8();
    secret_input.append(&mut exp.as_bytes().to_vec());

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

pub fn server_handshake(
    server_keys: &KyberXSessionKeys,
    client_public: &KyberXPublicKey,
    id_keys: &KyberXIdentityKeys,
    id: &ID,
) -> subtle::CtOption<HandshakeResult> {
    let mut not_ok = 0;
    let mut secret_input: Vec<u8> = vec![];

    // Server side uses EXP(X,y) | EXP(X,b)
    let exp = server_keys
        .x25519
        .private
        .diffie_hellman(&client_public.x25519);
    not_ok |= _ZERO_EXP[..].ct_eq(exp.as_bytes()).unwrap_u8();
    secret_input.append(&mut exp.as_bytes().to_vec());

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

    #[test]
    fn kyber1024x25519_handshake_plain() {
        let mut rng = rand::thread_rng();

        // Generate Keypair
        let alice_secret = EphemeralSecret::random_from_rng(&mut rng);
        let alice_public = PublicKey::from(&alice_secret);
        let keys_alice = keypair(&mut rng).expect("kyber keypair generation failed");
        // alice -> bob public keys
        let mut kyber1024x_pubkey = alice_public.as_bytes().to_vec();
        kyber1024x_pubkey.extend_from_slice(&keys_alice.public);

        assert_eq!(kyber1024x_pubkey.len(), 1600);

        let bob_secret = EphemeralSecret::random_from_rng(&mut rng);
        let bob_public = PublicKey::from(&bob_secret);

        // Bob encapsulates a shared secret using Alice's public key
        let (ciphertext, shared_secret_bob) =
            encapsulate(&keys_alice.public, &mut rng).expect("bob encapsulation failed");
        let bob_shared_secret = bob_secret.diffie_hellman(&alice_public);

        // // Alice decapsulates a shared secret using the ciphertext sent by Bob
        let shared_secret_alice =
            decapsulate(&ciphertext, &keys_alice.secret).expect("alice decapsulation failed");
        let alice_shared_secret = alice_secret.diffie_hellman(&bob_public);

        assert_eq!(alice_shared_secret.as_bytes(), bob_shared_secret.as_bytes());
        assert_eq!(shared_secret_bob, shared_secret_alice);
    }

    #[test]
    fn kyber1024_ake() {
        let mut rng = rand::thread_rng();

        // Server generates its keys
        let mut server = Ake::new();
        let server_kyber_id_keys = keypair(&mut rng).expect("key generation failed");

        // client generates new keys
        let mut client = Ake::new();
        let client_kyber_keys = keypair(&mut rng).expect("key generation failed");
        // client computes the beginning of it's half of the authenticated key exchange
        let client_init = client.client_init(&server_kyber_id_keys.public, &mut rng).expect("client handshake failed");

        // client sends the init message, and its public key
        // client_init, client_kyber_keys.public

        // server computes the authenticated key exchange generating the
        // necessary materials for the client to compute a matching
        // authenticated shared secret
        let server_send = server.server_receive(
          client_init, &client_kyber_keys.public, &server_kyber_id_keys.secret, &mut rng
        ).expect("server hands_kyberhake failed");

        // server sends completion materials to client

        // client completes the computation of the authenticated shares secret
        client.client_confirm(server_send, &client_kyber_keys.secret).expect("client handshake failed");

        // the shared secrets match
        assert_eq!(client.shared_secret, server.shared_secret);
    }
}
