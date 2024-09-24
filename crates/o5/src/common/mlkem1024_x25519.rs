use kem::{Decapsulate, Encapsulate};
use kemeleon::{DecapsulationKey, EncapsulationKey, Encode, EncodeError, OKemCore};
use rand::{CryptoRng, RngCore};
use rand_core::CryptoRngCore;

use crate::{Result, Error};

pub(crate) const X25519_PUBKEY_LEN: usize = 32;
pub(crate) const X25519_PRIVKEY_LEN: usize = 32;
pub(crate) const MLKEM1024_PUBKEY_LEN: usize = 1530;
pub(crate) const PUBKEY_LEN: usize = MLKEM1024_PUBKEY_LEN + X25519_PUBKEY_LEN;
pub(crate) const PRIVKEY_LEN: usize = 1;

pub struct StaticSecret(HybridKey);

struct HybridKey {
    x25519: x25519_dalek::StaticSecret,
    mlkem: DecapsulationKey<ml_kem::MlKem1024>,
    pub_key: PublicKey,
}

#[derive(Clone, PartialEq)]
pub(crate) struct PublicKey {
    x25519: x25519_dalek::PublicKey,
    mlkem: EncapsulationKey<ml_kem::MlKem1024>,
    pub_key: [u8; PUBKEY_LEN],
}

impl StaticSecret {
    pub fn random_from_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self(HybridKey::new(rng))
    }

    // TODO: THIS NEEDS TESTED
    pub fn try_from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let buf = bytes.as_ref();

        let sk: [u8; X25519_PRIVKEY_LEN] = core::array::from_fn(|i| buf[i]);
        let x25519 = x25519_dalek::StaticSecret::from(sk);

        let mlkem = DecapsulationKey::from_fips_bytes(&buf[X25519_PRIVKEY_LEN..])
            .map_err(|e| Error::EncodeError(e.into()))?;

        let pubkey_buf: [u8; PUBKEY_LEN] = core::array::from_fn(|i| buf[PRIVKEY_LEN + i]);
        let pub_key = PublicKey::try_from(pubkey_buf)?;

        Ok(Self(HybridKey {
            pub_key,
            mlkem,
            x25519,
        }))
    }

    pub fn as_bytes(&self) -> [u8; PRIVKEY_LEN + PUBKEY_LEN] {
        let mut out = [0u8; PRIVKEY_LEN + PUBKEY_LEN];
        out[..X25519_PRIVKEY_LEN].copy_from_slice(&self.0.x25519.to_bytes()[..]);
        out[X25519_PRIVKEY_LEN .. PRIVKEY_LEN].copy_from_slice(&self.0.mlkem.to_fips_bytes()[..]);
        out[PRIVKEY_LEN .. PRIVKEY_LEN+PUBKEY_LEN].copy_from_slice(&self.0.pub_key.as_bytes());
        out
    }
}

impl core::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.as_bytes()))
    }
}

impl PublicKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.pub_key
    }
}

impl From<&StaticSecret> for PublicKey {
    fn from(value: &StaticSecret) -> Self {
        value.0.public_key().clone()
    }
}

impl TryFrom<[u8; PUBKEY_LEN]> for PublicKey {
    type Error = Error;
    fn try_from(value: [u8; PUBKEY_LEN]) -> Result<Self> {
        let mut x25519 = [0u8; X25519_PUBKEY_LEN];
        x25519.copy_from_slice(&value[..X25519_PUBKEY_LEN]);

        let mlkem = EncapsulationKey::try_from_bytes(&value[X25519_PUBKEY_LEN..])
            .map_err(|e| Error::EncodeError(e.into()))?;

        Ok(Self {
            x25519: x25519.into(),
            mlkem,
            pub_key: value,
        })
    }
}

#[derive(PartialEq)]
pub struct SharedSecret {
    x25519: [u8; 32],
    mlkem: [u8; 32],
}

impl SharedSecret {
    // TODO: Test this layout to make sure this works.
    // SAFETY: the type of the SharedSecret object means this should never fail
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.x25519.as_ptr(), 64) }
    }
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
        let x25519 = x25519_dalek::StaticSecret::random_from_rng(rng);
        let x25519_pub = x25519_dalek::PublicKey::from(&x25519);
        let mut pub_key = [0u8; PUBKEY_LEN];
        pub_key[..X25519_PUBKEY_LEN].copy_from_slice(x25519_pub.as_bytes());
        pub_key[X25519_PUBKEY_LEN..].copy_from_slice(&ek.as_bytes());

        Self {
            pub_key: PublicKey {
                x25519: x25519_dalek::PublicKey::from(&x25519),
                mlkem: ek,
                pub_key,
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
    ) -> std::result::Result<(Ciphertext, SharedSecret), Self::Error> {
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
    fn decapsulate(&self, encapsulated_key: &Ciphertext) -> std::result::Result<SharedSecret, Self::Error> {
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
        let alice_secret = x25519_dalek::StaticSecret::random_from_rng(&mut rng);
        let alice_public = x25519_dalek::PublicKey::from(&alice_secret);
        // mlkem
        let (alice_mlkem_dk, alice_mlkem_ek) = MlKem1024::generate(&mut rng);

        // --- alice -> bob (public keys) ---
        // alice sends bob the public key for her mlkem1024 keypair with her
        // x25519 key appended to the end.
        let mut mlkem1024x_pubkey = alice_public.as_bytes().to_vec();
        mlkem1024x_pubkey.extend_from_slice(&alice_mlkem_ek.as_bytes());

        assert_eq!(mlkem1024x_pubkey.len(), 1562);

        // --- Generate Keypair (Bob) ---
        // x25519
        let bob_secret = x25519_dalek::StaticSecret::random_from_rng(&mut rng);
        let bob_public = x25519_dalek::PublicKey::from(&bob_secret);

        // (Imagine) upon receiving the mlkemx25519 public key bob parses them
        // into their respective structs from bytes

        // Bob encapsulates a shared secret using Alice's public key
        let (ciphertext, shared_secret_bob) = alice_mlkem_ek.encapsulate(&mut rng).unwrap();
        let bob_shared_secret = bob_secret.diffie_hellman(&alice_public);

        // // Alice decapsulates a shared secret using the ciphertext sent by Bob
        let shared_secret_alice = alice_mlkem_dk.decapsulate(&ciphertext).unwrap();
        let alice_shared_secret = alice_secret.diffie_hellman(&bob_public);

        assert_eq!(alice_shared_secret.as_bytes(), bob_shared_secret.as_bytes());
        assert_eq!(shared_secret_bob, shared_secret_alice);
        println!(
            "{} ?= {}",
            hex::encode(shared_secret_bob),
            hex::encode(shared_secret_alice)
        );
    }
}
