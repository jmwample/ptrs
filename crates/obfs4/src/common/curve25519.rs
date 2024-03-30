//! Re-exporting Curve25519 implementations.
//!
//! *TODO*: Eventually we should probably recommend using this code via some
//! key-agreement trait, but for now we are just re-using the APIs from
//! [`x25519_dalek`].

// TODO: We may want eventually want to expose ReusableSecret instead of
// StaticSecret, for use in places where we need to use a single secret
// twice in one handshake, but we do not need that secret to be persistent.
//
// The trouble here is that if we use ReusableSecret in these cases, we
// cannot easily construct it for testing purposes.  We could in theory
// kludge something together using a fake Rng, but that might be more
// trouble than we want to go looking for.
#[allow(unused)]
pub use x25519_dalek::{
    EphemeralSecret, PublicKey, PublicRepresentative, ReusableSecret, SharedSecret, StaticSecret,
};

use rand_core::{CryptoRng, RngCore};

pub const REPRESENTATIVE_LENGTH: usize = 32;

/// Curve25519 keys that are guaranteed to have a valid Elligator2 representative.
/// As only certain Curve25519 keys can be obfuscated with Elligator2, the
/// representative must be checked when generating the secret key.
///
/// The probablility that a key does not have a representable elligator2 encoding
/// is ~50%, so we are (statistiscally) guaranteed to find a representable key
/// in relatively few iterations.
pub struct Representable;

const RETRY_LIMIT: usize = 128;

#[allow(unused)]
impl Representable {
    /// Generate a new Elligator2 representable ['StaticSecret'] with the supplied RNG.
    pub fn static_from_rng<R: RngCore + CryptoRng>(mut rng: R) -> StaticSecret {
        let mut private = StaticSecret::random_from_rng(&mut rng);
        let mut repres: Option<PublicRepresentative> = (&private).into();

        for _ in 0..RETRY_LIMIT {
            if repres.is_some() {
                return private;
            }
            private = StaticSecret::random_from_rng(&mut rng);
            repres = (&private).into();
        }

        panic!("failed to generate representable secret, bad RNG provided");
    }

    /// Generate a new Elligator2 representable ['ReusableSecret'] with the supplied RNG.
    pub fn reusable_from_rng<R: RngCore + CryptoRng>(mut rng: R) -> ReusableSecret {
        let mut private = ReusableSecret::random_from_rng(&mut rng);
        let mut repres: Option<PublicRepresentative> = (&private).into();

        for _ in 0..RETRY_LIMIT {
            if repres.is_some() {
                return private;
            }
            private = ReusableSecret::random_from_rng(&mut rng);
            repres = (&private).into();
        }

        panic!("failed to generate representable secret, bad RNG provided");
    }

    /// Generate a new Elligator2 representable ['EphemeralSecret'] with the supplied RNG.
    pub fn ephemeral_from_rng<R: RngCore + CryptoRng>(mut rng: R) -> EphemeralSecret {
        let mut private = EphemeralSecret::random_from_rng(&mut rng);
        let mut repres: Option<PublicRepresentative> = (&private).into();

        for _ in 0..RETRY_LIMIT {
            if repres.is_some() {
                return private;
            }
            private = EphemeralSecret::random_from_rng(&mut rng);
            repres = (&private).into();
        }

        panic!("failed to generate representable secret, bad RNG provided");
    }

    /// Generate a new Elligator2 representable ['StaticSecret'].
    pub fn random_static() -> StaticSecret {
        let mut private = StaticSecret::random();
        let mut repres: Option<PublicRepresentative> = (&private).into();

        for _ in 0..RETRY_LIMIT {
            if repres.is_some() {
                return private;
            }
            private = StaticSecret::random();
            repres = (&private).into();
        }

        panic!("failed to generate representable secret, getrandom failed");
    }

    /// Generate a new Elligator2 representable ['ReusableSecret'].
    pub fn random_reusable() -> ReusableSecret {
        let mut private = ReusableSecret::random();
        let mut repres: Option<PublicRepresentative> = (&private).into();

        for _ in 0..RETRY_LIMIT {
            if repres.is_some() {
                return private;
            }
            private = ReusableSecret::random();
            repres = (&private).into();
        }

        panic!("failed to generate representable secret, getrandom failed");
    }

    /// Generate a new Elligator2 representable ['EphemeralSecret'].
    pub fn random_ephemeral() -> EphemeralSecret {
        let mut private = EphemeralSecret::random();
        let mut repres: Option<PublicRepresentative> = (&private).into();

        for _ in 0..RETRY_LIMIT {
            if repres.is_some() {
                return private;
            }
            private = EphemeralSecret::random();
            repres = (&private).into();
        }

        panic!("failed to generate representable secret, getrandom failed");
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hex::FromHex;

    #[test]
    fn representative_match() {
        let mut repres = <[u8; 32]>::from_hex(
            "8781b04fefa49473ca5943ab23a14689dad56f8118d5869ad378c079fd2f4079",
        )
        .unwrap();
        let incorrect = "1af2d7ac95b5dd1ab2b5926c9019fa86f211e77dd796f178f3fe66137b0d5d15";
        let expected = "a946c3dd16d99b8c38972584ca599da53e32e8b13c1e9a408ff22fdb985c2d79";

        // we are not clearing the high order bits before translating the representative to a
        // public key.
        repres[31] &= 0x3f;

        let r = PublicRepresentative::from(repres);
        let p = PublicKey::from(&r);
        assert_ne!(incorrect, hex::encode(p.as_bytes()));
        assert_eq!(expected, hex::encode(p.as_bytes()));
    }
}
