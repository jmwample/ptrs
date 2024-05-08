#![doc = include_str!("../README.md")]
// unexpected_cfgs are used to disable incomplete / WIP features and tests. This is
// not an error for this library.
#![allow(unexpected_cfgs)]

mod framing;
// mod handshake;
// mod transport;

#[cfg(test)]
#[allow(unused)]
mod ml_kem_tests {
    use anyhow::{anyhow, Context, Result};
    use ml_kem::*;
    use x25519_dalek::{EphemeralSecret, PublicKey};

    struct Kyber1024XKeypair {}

    impl Kyber1024XKeypair {
        fn new() -> Result<Self> {
            todo!()
        }
    }

    #[test]
    fn it_works() -> Result<()> {
        let mut rng = rand::thread_rng();

        // --- Generate Keypair (Alice) ---
        // x25519
        let alice_secret = EphemeralSecret::random_from_rng(&mut rng);
        let alice_public = PublicKey::from(&alice_secret);
        // kyber
        let (alice_kyber_dk, alice_kyber_ek) = MlKem1024::generate(&mut rng);

        // --- alice -> bob (public keys) ---
        // alice sends bob the public key for her kyber1024 keypair with her
        // x25519 key appended to the end.
        let mut kyber1024x_pubkey = alice_public.as_bytes().to_vec();
        kyber1024x_pubkey.extend_from_slice(&alice_kyber_ek.as_bytes());

        assert_eq!(kyber1024x_pubkey.len(), 1600);

        // --- Generate Keypair (Bob) ---
        // x25519
        let bob_secret = EphemeralSecret::random_from_rng(&mut rng);
        let bob_public = PublicKey::from(&bob_secret);

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

        Ok(())
    }
}

/*
#[cfg(test)]
#[allow(unused)]
mod pqc_kyber_tests {
    use pqc_kyber::*;
    use x25519_dalek::{EphemeralSecret, PublicKey};

    type Result<T> = std::result::Result<T, Error>;

    #[derive(Debug)]
    enum Error {
        PQCError(pqc_kyber::KyberError),
        Other(Box<dyn std::error::Error>),
    }

    impl From<pqc_kyber::KyberError> for Error {
        fn from(e: pqc_kyber::KyberError) -> Self {
            Error::PQCError(e)
        }
    }

    // impl From<&dyn std::error::Error> for Error {
    //     fn from(e: &dyn std::error::Error) -> Self {
    //         Error::Other(Box::new(e))
    //     }
    // }

    struct Kyber1024XKeypair {}

    impl Kyber1024XKeypair {
        fn new() -> Result<Self> {
            todo!()
        }
    }

    #[test]
    fn it_works() -> Result<()> {
        let mut rng = rand::thread_rng();

        // Generate Keypair
        let alice_secret = EphemeralSecret::random_from_rng(&mut rng);
        let alice_public = PublicKey::from(&alice_secret);
        let keys_alice = keypair(&mut rng)?;
        // alice -> bob public keys
        let mut kyber1024x_pubkey = alice_public.as_bytes().to_vec();
        kyber1024x_pubkey.extend_from_slice(&keys_alice.public);

        assert_eq!(kyber1024x_pubkey.len(), 1600);

        let bob_secret = EphemeralSecret::random_from_rng(&mut rng);
        let bob_public = PublicKey::from(&bob_secret);

        // Bob encapsulates a shared secret using Alice's public key
        let (ciphertext, shared_secret_bob) = encapsulate(&keys_alice.public, &mut rng)?;
        let bob_shared_secret = bob_secret.diffie_hellman(&alice_public);

        // // Alice decapsulates a shared secret using the ciphertext sent by Bob
        let shared_secret_alice = decapsulate(&ciphertext, &keys_alice.secret)?;
        let alice_shared_secret = alice_secret.diffie_hellman(&bob_public);

        assert_eq!(alice_shared_secret.as_bytes(), bob_shared_secret.as_bytes());
        assert_eq!(shared_secret_bob, shared_secret_alice);

        Ok(())
    }
}
*/
