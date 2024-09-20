use kem::{Decapsulate, Encapsulate};
use kemeleon::{DecapsulationKey, EncapsulationKey, Encode, EncodeError};
use rand::{CryptoRng, RngCore};
use rand_core::CryptoRngCore;
use x25519_dalek::ReusableSecret;

pub struct SessionKeyPair(HybridKey);

pub struct IdentityKeyPair(HybridKey);

struct HybridKey {
    x25519: ReusableSecret,
    mlkem: DecapsulationKey<ml_kem::MlKem1024>,
    pub_key: PublicKey,
}

struct PublicKey {
    x25519: x25519_dalek::PublicKey,
    mlkem: EncapsulationKey<ml_kem::MlKem1024>,
}

#[derive(PartialEq)]
pub struct SharedSecret {
    x25519: [u8; 32],
    mlkem: [u8; 32],
}

impl core::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} {}",
            hex::encode(self.x25519),
            hex::encode(self.mlkem)
        )
    }
}

impl HybridKey {
    fn new<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let (dk, ek) = kemeleon::MlKem1024::generate(rng);
        let x25519 = ReusableSecret::random_from_rng(rng);

        Self {
            pub_key: PublicKey {
                x25519: x25519_dalek::PublicKey::from(&x25519),
                mlkem: ek,
            },
            mlkem: dk,
            x25519,
        }
    }

    fn public_key(&self) -> &PublicKey {
        &self.pub_key
    }

    fn with_pub<'a>(&'a self, pubkey: &'a PublicKey) -> KeyMix<'a> {
        KeyMix {
            local_private: self,
            remote_public: pubkey,
        }
    }
}

pub struct KeyMix<'a> {
    local_private: &'a HybridKey,
    remote_public: &'a PublicKey,
}

impl Encapsulate<Ciphertext, SharedSecret> for KeyMix<'_> {
    type Error = EncodeError;

    // Diffie Helman  / Encapsulate
    fn encapsulate(
        &self,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Ciphertext, SharedSecret), Self::Error> {
        let (ciphertext, local_ss_mlkem) = self.remote_public.mlkem.encapsulate(rng).unwrap();
        let local_ss_x25519 = self
            .local_private
            .x25519
            .diffie_hellman(&self.remote_public.x25519);
        let ss = SharedSecret {
            mlkem: local_ss_mlkem.into(),
            x25519: local_ss_x25519.to_bytes(),
        };
        let mut ct = x25519_dalek::PublicKey::from(&self.local_private.x25519)
            .as_bytes()
            .to_vec();
        ct.append(&mut ciphertext.as_bytes().to_vec());
        Ok((ct, ss))
    }
}

type Ciphertext = Vec<u8>;

impl Decapsulate<Ciphertext, SharedSecret> for HybridKey {
    type Error = EncodeError;

    // Required method
    fn decapsulate(
        &self,
        encapsulated_key: &Ciphertext,
    ) -> Result<SharedSecret, Self::Error> {
        let arr = kemeleon::Ciphertext::try_from(&encapsulated_key[32..])?;
        let local_ss_mlkem = self.mlkem.decapsulate(&arr)?;

        let mut remote_public = [0u8; 32];
        remote_public[..32].copy_from_slice(&encapsulated_key[..32]);
        let local_ss_x25519 = self
            .x25519
            .diffie_hellman(&x25519_dalek::PublicKey::from(remote_public));

        Ok(SharedSecret {
            mlkem: local_ss_mlkem.into(),
            x25519: local_ss_x25519.to_bytes(),
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use kemeleon::MlKem1024;

    #[test]
    fn example_lib_usage() {
        let rng = &mut rand::thread_rng();
        let alice_priv_key = HybridKey::new(rng);
        let alice_pub = alice_priv_key.public_key();

        let bob_priv_key = HybridKey::new(rng);
        let (ct, bob_ss) = bob_priv_key.with_pub(alice_pub).encapsulate(rng).unwrap();

        let alice_ss = alice_priv_key.decapsulate(&ct).unwrap();
        assert_eq!(alice_ss, bob_ss);
    }

    #[test]
    fn it_works() {
        let mut rng = rand::thread_rng();

        // --- Generate Keypair (Alice) ---
        // x25519
        let alice_secret = ReusableSecret::random_from_rng(&mut rng);
        let alice_public = x25519_dalek::PublicKey::from(&alice_secret);
        // kyber
        let (alice_kyber_dk, alice_kyber_ek) = MlKem1024::generate(&mut rng);

        // --- alice -> bob (public keys) ---
        // alice sends bob the public key for her kyber1024 keypair with her
        // x25519 key appended to the end.
        let mut kyber1024x_pubkey = alice_public.as_bytes().to_vec();
        kyber1024x_pubkey.extend_from_slice(&alice_kyber_ek.as_bytes());

        assert_eq!(kyber1024x_pubkey.len(), 1562);

        // --- Generate Keypair (Bob) ---
        // x25519
        let bob_secret = ReusableSecret::random_from_rng(&mut rng);
        let bob_public = x25519_dalek::PublicKey::from(&bob_secret);

        // (Imagine) upon receiving the kyberx25519 public key bob parses them
        // into their respective structs from bytes

        // Bob encapsulates a shared secret using Alice's public key
        let (ciphertext, shared_secret_bob) = alice_kyber_ek.encapsulate(&mut rng).unwrap();
        let bob_shared_secret = bob_secret.diffie_hellman(&alice_public);

        // // Alice decapsulates a shared secret using the ciphertext sent by Bob
        let shared_secret_alice = alice_kyber_dk.decapsulate(&ciphertext).unwrap();
        let alice_shared_secret = alice_secret.diffie_hellman(&bob_public);

        assert_eq!(alice_shared_secret.as_bytes(), bob_shared_secret.as_bytes());
        assert_eq!(shared_secret_bob, shared_secret_alice);
        println!(
            "{} ?= {}",
            hex::encode(shared_secret_bob),
            hex::encode(shared_secret_alice)
        );
    }

    /*
    #[test]
    fn mlkem1024_x25519_handshake_flow() {
        let mut rng = rand::thread_rng();
        // long-term server id and keys
        let server_id_keys = HybridKey::new(&mut rng);
        let server_id_pub = server_id_keys.public_key();
        // let server_id = ID::new();

        // client open session, generating the associated ephemeral keys
        let client_session = HybridKey::new(&mut rng);

        // client sends kyber25519 session pubkey(s)
        let cpk = client_session.public_key();

        // server computes kyberx25519 combined shared secret
        let server_session = HybridKey::new(&mut rng);
        let server_hs_res = server_handshake(&server_session, &cpk, &server_id_keys, &server_id);

        // server sends kyberx25519 session pubkey(s)
        let spk = client_session.public_key();

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
        let mut rng = rand::thread_rng();
        // long-term server id and keys
        let server_id_keys = HybridKey::new(&mut rng);
        let server_id_pub = server_id_keys.public_key();
        // let server_id = ID::new();

        // client open session, generating the associated ephemeral keys
        let client_session = HybridKey::new(&mut rng);

        // client sends ed25519 session pubkey elligator2 encoded and includes
        // session Kyber1024Supplement CryptoOffer.
        let cpk = client_session.public_key();

        // server computes KyberX25519 combined shared secret
        let server_session = HybridKey::new(&mut rng);
        let server_hs_res = server_handshake(&server_session, &cpk, &server_id_keys, &server_id);

        // server sends ed25519 session pubkey elligator2 encoded and includes
        // session Kyber1024Supplement CryptoAccept.
        let spk = server_session.public_key();

        // client computes KyberX25519 combined shared secret
        let client_hs_res = client_handshake(&client_session, &spk, &server_id_pub, &server_id);

        assert_ne!(client_hs_res.is_some().unwrap_u8(), 0);
        assert_ne!(server_hs_res.is_some().unwrap_u8(), 0);

        let chsres = client_hs_res.unwrap();
        let shsres = server_hs_res.unwrap();
        assert_eq!(chsres.key_seed, shsres.key_seed);
        assert_eq!(&chsres.auth, &shsres.auth);
    }
    */
}
