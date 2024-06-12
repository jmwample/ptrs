//! Re-exporting Curve25519 implementations.
//!
//! *TODO*: Eventually we should probably recommend using this code via some
//! key-agreement trait, but for now we are just wrapping and re-using the APIs
//! from [`x25519_dalek`].

pub use curve25519_elligator2::{elligator2::representative_from_privkey, EdwardsPoint};
use getrandom::getrandom;
#[allow(unused)]
pub use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

/// You can do diffie-hellman with this key multiple times and derive the elligator2
/// representative, but you cannot write it out, as it is intended to be used only
/// ONCE (i.e. ephemperally). If the key generation succeeds, the key is guaranteed
/// to have a valid elligator2 representative.
#[derive(Clone)]
pub(crate) struct EphemeralSecret(x25519_dalek::StaticSecret, u8);

#[allow(unused)]
impl EphemeralSecret {
    pub(crate) fn random() -> Self {
        Keys::random_ephemeral()
    }

    pub(crate) fn random_from_rng<T: RngCore + CryptoRng>(csprng: T) -> Self {
        Keys::ephemeral_from_rng(csprng)
    }

    pub fn diffie_hellman(&self, their_public: &PublicKey) -> SharedSecret {
        self.0.diffie_hellman(their_public)
    }

    #[cfg(test)]
    /// As this function allows building an ['EphemeralSecret'] with a custom secret key,
    /// it is not guaranteed to have a valid elligator2 representative. As such, it
    /// is intended for testing purposes only.
    pub(crate) fn from_parts(sk: StaticSecret, tweak: u8) -> Self {
        Self(sk, tweak)
    }
}

impl From<EphemeralSecret> for PublicKey {
    fn from(value: EphemeralSecret) -> Self {
        let pk_bytes = EdwardsPoint::mul_base_clamped_dirty(value.0.to_bytes()).to_montgomery();
        PublicKey::from(*pk_bytes.as_bytes())
    }
}

impl<'a> Into<PublicKey> for &'a EphemeralSecret {
    fn into(self) -> PublicKey {
        let pk_bytes = EdwardsPoint::mul_base_clamped_dirty(self.0.to_bytes()).to_montgomery();
        PublicKey::from(*pk_bytes.as_bytes())
    }
}

/// [`PublicKey`] transformation to a format indistinguishable from uniform
/// random. Requires feature `elligator2`.
///
/// This allows public keys to be sent over an insecure channel without
/// revealing that an x25519 public key is being shared.
///
/// # Example
#[cfg_attr(feature = "elligator2", doc = "```")]
#[cfg_attr(not(feature = "elligator2"), doc = "```ignore")]
/// use rand_core::OsRng;
/// use rand_core::RngCore;
///
/// use x25519_dalek::x25519;
/// use x25519_ephemeralSecret;
/// use x25519_dalek::{PublicKey, PublicRepresentative};
///
/// // ~50% of points are not encodable as elligator representatives, but we
/// // want to ensure we select a keypair that is.
/// fn get_representable_ephemeral() -> EphemeralSecret {
///     for i in 0_u8..255 {
///         let secret = EphemeralSecret::random_from_rng(&mut OsRng);
///         match from(&secret) {
///             Some(_) => return secret,
///             None => continue,
///         }
///     }
///     panic!("we should definitely have found a key by now")
/// }
///
/// // Generate Alice's key pair.
/// let alice_secret = get_representable_ephemeral();
/// let alice_representative = Option::<PublicRepresentative>::from(&alice_secret).unwrap();
///
/// // Generate Bob's key pair.
/// let bob_secret = get_representable_ephemeral();
/// let bob_representative = Option::<PublicRepresentative>::from(&bob_secret).unwrap();
///
/// // Alice and Bob should now exchange their representatives and reveal the
/// // public key from the other person.
/// let bob_public = PublicKey::from(&bob_representative);
///
/// let alice_public = PublicKey::from(&alice_representative);
///
/// // Once they've done so, they may generate a shared secret.
/// let alice_shared = alice_secret.diffie_hellman(&bob_public);
/// let bob_shared = bob_secret.diffie_hellman(&alice_public);
///
/// assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
/// ```
#[derive(PartialEq, Eq, Hash, Copy, Clone, Debug)]
pub struct PublicRepresentative([u8; 32]);

impl PublicRepresentative {
    /// View this public representative as a byte array.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Extract this representative's bytes for serialization.
    #[inline]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl AsRef<[u8]> for PublicRepresentative {
    /// View this shared secret key as a byte array.
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl From<[u8; 32]> for PublicRepresentative {
    /// Build a Elligator2 Public key Representative from bytes
    fn from(r: [u8; 32]) -> PublicRepresentative {
        PublicRepresentative(r)
    }
}

impl<'a> From<&'a [u8; 32]> for PublicRepresentative {
    /// Build a Elligator2 Public key Representative from bytes by reference
    fn from(r: &'a [u8; 32]) -> PublicRepresentative {
        PublicRepresentative(*r)
    }
}

impl<'a> From<&'a EphemeralSecret> for PublicRepresentative {
    /// Given an x25519 [`EphemeralSecret`] key, compute its corresponding [`PublicRepresentative`].
    fn from(secret: &'a EphemeralSecret) -> PublicRepresentative {
        let res: Option<[u8; 32]> = representative_from_privkey(secret.0.as_bytes(), secret.1);
        PublicRepresentative(res.unwrap())
    }
}

impl<'a> From<&'a PublicRepresentative> for PublicKey {
    /// Given an elligator2 [`PublicRepresentative`], compute its corresponding [`PublicKey`].
    fn from(representative: &'a PublicRepresentative) -> PublicKey {
        let point = curve25519_elligator2::MontgomeryPoint::map_to_point(&representative.0);
        PublicKey::from(*point.as_bytes())
    }
}

use rand_core::{CryptoRng, RngCore};

pub const REPRESENTATIVE_LENGTH: usize = 32;

/// Curve25519 keys that are guaranteed to have a valid Elligator2 representative.
/// As only certain Curve25519 keys can be obfuscated with Elligator2, the
/// representative must be checked when generating the secret key.
///
/// The probablility that a key does not have a representable elligator2 encoding
/// is ~50%, so we are (statistiscally) guaranteed to find a representable key
/// in relatively few iterations.
pub struct Keys;

trait RetryLimit {
    const RETRY_LIMIT: usize = 128;
}

impl RetryLimit for Keys {}

#[allow(unused)]
impl Keys {
    /// Generate a new Elligator2 representable ['StaticSecret'] with the supplied RNG.
    pub fn static_from_rng<R: RngCore + CryptoRng>(mut rng: R) -> StaticSecret {
        StaticSecret::random_from_rng(&mut rng)
    }

    /// Generate a new Elligator2 representable ['StaticSecret'].
    pub fn random_static() -> StaticSecret {
        StaticSecret::random()
    }

    /// Generate a new Elligator2 representable ['EphemeralSecret'] with the supplied RNG.
    pub fn ephemeral_from_rng<R: RngCore + CryptoRng>(mut rng: R) -> EphemeralSecret {
        let mut private = StaticSecret::random_from_rng(&mut rng);
        let mut tweak = [0u8];
        rng.fill_bytes(&mut tweak);

        let mut repres = representative_from_privkey(&private.to_bytes(), tweak[0]);

        for _ in 0..Self::RETRY_LIMIT {
            if repres.is_some() {
                return EphemeralSecret(private, tweak[0]);
            }
            private = StaticSecret::random_from_rng(&mut rng);
            repres = representative_from_privkey(&private.to_bytes(), tweak[0]);
        }

        panic!("failed to generate representable secret, bad RNG provided");
    }

    /// Generate a new Elligator2 representable ['EphemeralSecret'].
    pub fn random_ephemeral() -> EphemeralSecret {
        let mut private = StaticSecret::random();
        let mut tweak = [0u8];
        getrandom(&mut tweak);
        let mut repres: Option<[u8; 32]> =
            representative_from_privkey(private.as_bytes(), tweak[0]);

        for _ in 0..Self::RETRY_LIMIT {
            if repres.is_some() {
                return EphemeralSecret(private, tweak[0]);
            }
            private = StaticSecret::random();
            repres = representative_from_privkey(private.as_bytes(), tweak[0]);
        }

        panic!("failed to generate representable secret, getrandom failed");
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Result;

    use hex::FromHex;

    #[test]
    fn representative_match() {
        let repres = <[u8; 32]>::from_hex(
            "8781b04fefa49473ca5943ab23a14689dad56f8118d5869ad378c079fd2f4079",
        )
        .unwrap();
        let incorrect = "1af2d7ac95b5dd1ab2b5926c9019fa86f211e77dd796f178f3fe66137b0d5d15";
        let expected = "a946c3dd16d99b8c38972584ca599da53e32e8b13c1e9a408ff22fdb985c2d79";

        let r = PublicRepresentative::from(repres);
        let p = PublicKey::from(&r);
        assert_ne!(incorrect, hex::encode(p.as_bytes()));
        assert_eq!(expected, hex::encode(p.as_bytes()));
    }

    #[test]
    fn about_half() -> Result<()> {
        let mut rng = rand::thread_rng();

        let mut success = 0;
        let mut not_found = 0;
        let mut not_match = 0;
        for _ in 0..1_000 {
            let sk = StaticSecret::random_from_rng(&mut rng);
            let rp: Option<[u8; 32]> = representative_from_privkey(sk.as_bytes(), 0u8);
            let repres = match rp {
                Some(r) => PublicRepresentative::from(r),
                None => {
                    not_found += 1;
                    continue;
                }
            };

            let pk_bytes = EdwardsPoint::mul_base_clamped_dirty(sk.to_bytes()).to_montgomery();

            let pk = PublicKey::from(*pk_bytes.as_bytes());

            let decoded_pk = PublicKey::from(&repres);
            if hex::encode(pk) != hex::encode(decoded_pk) {
                not_match += 1;
                continue;
            }
            success += 1;
        }

        if not_match != 0 {
            println!("{not_found}/{not_match}/{success}/10_000");
            assert_eq!(not_match, 0);
        }
        assert!(not_found < 600);
        assert!(not_found > 400);
        Ok(())
    }
}
