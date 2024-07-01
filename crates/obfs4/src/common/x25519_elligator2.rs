//! Re-exporting Curve25519 implementations.
//!
//! *TODO*: Eventually we should probably recommend using this code via some
//! key-agreement trait, but for now we are just wrapping and re-using the APIs
//! from [`x25519_dalek`].

pub use curve25519_elligator2::{MapToPointVariant, Randomized};
use getrandom::getrandom;
#[allow(unused)]
pub use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

/// Ephemeral Key for X25519 Handshakes which intentionally makes writing out the
/// private key value difficult.
///
/// You can do a Diffie-Hellman exchange with this key multiple times and derive
/// the elligator2 representative, but you cannot write it out, as it is
/// intended to be used only ONCE (i.e. ephemerally). If the key generation
/// succeeds, the key is guaranteed to have a valid elligator2 representative.
#[derive(Clone)]
pub struct EphemeralSecret(x25519_dalek::StaticSecret, u8);

#[allow(unused)]
impl EphemeralSecret {
    pub fn random() -> Self {
        Keys::random_ephemeral()
    }

    pub fn random_from_rng<T: RngCore + CryptoRng>(csprng: T) -> Self {
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
        let pk_bytes = Randomized::mul_base_clamped(value.0.to_bytes()).to_montgomery();
        PublicKey::from(*pk_bytes.as_bytes())
    }
}

impl<'a> From<&'a EphemeralSecret> for PublicKey {
    fn from(val: &'a EphemeralSecret) -> Self {
        let pk_bytes = Randomized::mul_base_clamped(val.0.to_bytes()).to_montgomery();
        PublicKey::from(*pk_bytes.as_bytes())
    }
}

/// [`PublicKey`] transformation to a format indistinguishable from uniform
/// random.
///
/// This allows public keys to be sent over an insecure channel without
/// revealing that an x25519 public key is being shared.
///
/// # Example
/// ```
/// use obfs4::common::x25519_elligator2::{Keys, PublicRepresentative, PublicKey};
///
/// // Generate Alice's key pair.
/// let alice_secret = Keys::random_ephemeral();
/// let alice_representative = PublicRepresentative::from(&alice_secret);
///
/// // Generate Bob's key pair.
/// let bob_secret = Keys::random_ephemeral();
/// let bob_representative = PublicRepresentative::from(&bob_secret);
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
        let res: Option<[u8; 32]> =
            Randomized::to_representative(secret.0.as_bytes(), secret.1).into();
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

impl From<PublicRepresentative> for PublicKey {
    /// Given an elligator2 [`PublicRepresentative`], compute its corresponding [`PublicKey`].
    fn from(representative: PublicRepresentative) -> PublicKey {
        let point = curve25519_elligator2::MontgomeryPoint::map_to_point(&representative.0);
        PublicKey::from(*point.as_bytes())
    }
}

use rand_core::{CryptoRng, RngCore};

pub const REPRESENTATIVE_LENGTH: usize = 32;

/// A collection of functions for generating x25519 keys wrapping `x25519_dalek`. ['EphemeralSecret']
/// keys are guaranteed to have a valid elligator2 representative. In general ['StaticSecret'] should
/// not be converted to PublicRepresentative, use an EphemeralSecret instead.
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
    ///
    /// May panic if the provided csprng fails to generate random values such that no generated
    /// secret key maps to a valid elligator2 representative. This should never happen
    /// when system CSPRNGs are used (i.e `rand::thread_rng`).
    pub fn ephemeral_from_rng<R: RngCore + CryptoRng>(mut csprng: R) -> EphemeralSecret {
        let mut private = StaticSecret::random_from_rng(&mut csprng);

        // tweak only needs generated once as it doesn't affect the elligator2 representative validity.
        let mut tweak = [0u8];
        csprng.fill_bytes(&mut tweak);

        let mut repres: Option<[u8; 32]> =
            Randomized::to_representative(&private.to_bytes(), tweak[0]).into();

        for _ in 0..Self::RETRY_LIMIT {
            if repres.is_some() {
                return EphemeralSecret(private, tweak[0]);
            }
            private = StaticSecret::random_from_rng(&mut csprng);
            repres = Randomized::to_representative(&private.to_bytes(), tweak[0]).into();
        }

        panic!("failed to generate representable secret, bad RNG provided");
    }

    /// Generate a new Elligator2 representable ['EphemeralSecret'].
    ///
    /// May panic if the system random genereator fails such that no generated
    /// secret key maps to a valid elligator2 representative. This should never
    /// happen under normal use.
    pub fn random_ephemeral() -> EphemeralSecret {
        let mut private = StaticSecret::random();
        //
        // tweak only needs generated once as it doesn't affect the elligator2 representative validity.
        let mut tweak = [0u8];
        getrandom(&mut tweak);

        let mut repres: Option<[u8; 32]> =
            Randomized::to_representative(&private.to_bytes(), tweak[0]).into();

        for _ in 0..Self::RETRY_LIMIT {
            if repres.is_some() {
                return EphemeralSecret(private, tweak[0]);
            }
            private = StaticSecret::random();
            repres = Randomized::to_representative(&private.to_bytes(), tweak[0]).into();
        }

        panic!("failed to generate representable secret, getrandom failed");
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Result;

    use curve25519_elligator2::{
        traits::IsIdentity, EdwardsPoint, MapToPointVariant, MontgomeryPoint, Randomized, RFC9380,
    };
    use hex::FromHex;

    use rand::Rng;

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

    /// This test confirms that only about half of the `StaticSecret`s generated have
    /// valid representatives. This is expected - in ['Keys'] we rely on this fact
    /// to ensure that (given the provided csprng works) generating in a loop
    /// should statiscally never fail to generate a representable key.
    #[test]
    fn about_half() -> Result<()> {
        let mut rng = rand::thread_rng();

        let mut success = 0;
        let mut not_found = 0;
        let mut not_match = 0;
        for _ in 0..1_000 {
            let sk = StaticSecret::random_from_rng(&mut rng);
            let rp: Option<[u8; 32]> = Randomized::to_representative(sk.as_bytes(), 0_u8).into();
            let repres = match rp {
                Some(r) => PublicRepresentative::from(r),
                None => {
                    not_found += 1;
                    continue;
                }
            };

            let pk_bytes = Randomized::mul_base_clamped(sk.to_bytes()).to_montgomery();

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

    #[test]
    fn it_works() {
        // if this panics we are in trouble
        let k = EphemeralSecret::random();

        // internal serialization and deserialization works
        let k_bytes = k.0.as_bytes();
        let _k1 = EphemeralSecret::from_parts(StaticSecret::from(*k_bytes), 0u8);

        // if we send our representative over the wire then recover the pubkey they should match
        let pk = PublicKey::from(&k);
        let r = PublicRepresentative::from(&k);
        let r_bytes = r.to_bytes();
        // send r_bytes over the network
        let r1 = PublicRepresentative::from(r_bytes);
        let pk1 = PublicKey::from(r1);
        assert_eq!(hex::encode(pk.to_bytes()), hex::encode(pk1.to_bytes()));
    }

    const BASEPOINT_ORDER_MINUS_ONE: [u8; 32] = [
        0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];

    // Generates a new Keypair using, and returns the public key representative
    // along, with its public key as a newly allocated edwards25519.Point.
    fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> ([u8; 32], EdwardsPoint) {
        for _ in 0..63 {
            let y_sk = rng.gen::<[u8; 32]>();

            let y_repr_bytes = match Randomized::to_representative(&y_sk, 0xff).into() {
                Some(r) => r,
                None => continue,
            };
            let y_pk = Randomized::mul_base_clamped(y_sk);

            assert_eq!(
                MontgomeryPoint::from_representative::<Randomized>(&y_repr_bytes)
                    .expect("failed to re-derive point from representative"),
                y_pk.to_montgomery()
            );

            return (y_repr_bytes, y_pk);
        }
        panic!("failed to generate a valid keypair");
    }

    /// Returns a new edwards25519.Point that is v multiplied by the subgroup order.
    ///
    /// BASEPOINT_ORDER_MINUS_ONE is the same as scMinusOne in filippo.io/edwards25519.
    /// https://github.com/FiloSottile/edwards25519/blob/v1.0.0/scalar.go#L34
    fn scalar_mult_order(v: &EdwardsPoint) -> EdwardsPoint {
        let order = curve25519_elligator2::Scalar::from_bytes_mod_order(BASEPOINT_ORDER_MINUS_ONE);

        // v * (L - 1) + v => v * L
        let p = v * order;
        p + v
    }

    #[test]
    fn off_subgroup_check_edw() {
        let mut count = 0;
        let n_trials = 100;
        let mut rng = rand::thread_rng();
        for _ in 0..n_trials {
            let (repr, pk) = generate(&mut rng);

            // check if the generated public key is off the subgroup
            let v = scalar_mult_order(&pk);
            let _pk_off = !v.is_identity();

            // ----

            // check if the public key derived from the representative (top bit 0)
            // is off the subgroup
            let mut yr_255 = repr;
            yr_255[31] &= 0xbf;
            let pk_255 = EdwardsPoint::from_representative::<RFC9380>(&yr_255)
                .expect("from_repr_255, should never fail");
            let v = scalar_mult_order(&pk_255);
            let off_255 = !v.is_identity();

            // check if the public key derived from the representative (top two bits 0 - as
            // our representatives are) is off the subgroup.
            let mut yr_254 = repr;
            yr_254[31] &= 0x3f;
            let pk_254 = EdwardsPoint::from_representative::<RFC9380>(&yr_254)
                .expect("from_repr_254, should never fail");
            let v = scalar_mult_order(&pk_254);
            let off_254 = !v.is_identity();

            // println!("pk_gen: {pk_off}, pk_255: {off_255}, pk_254: {off_254}");
            if off_254 && off_255 {
                count += 1;
            }
        }
        assert!(count > 0);
        assert!(count < n_trials);
    }
}
