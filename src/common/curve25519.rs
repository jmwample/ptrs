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
pub use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret, StaticSecret, PublicRepresentative};

// pub trait Writeable {
//     /// Encode this object into the writer `b`.
//     fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) -> EncodeResult<()>;
// }
//
// // impl<W: Writeable + ?Sized> tor_bytes::Writeable for W {
// //     fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) -> EncodeResult<()> {
// //         (*self).write_onto(b)
// //     }
// // }
//
// impl<W: tor_bytes::Writeable + ?Sized> Writeable for W {
//     fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) -> EncodeResult<()> {
//         (*self).write_onto(b)
//     }
// }


// pub trait Readable: Sized {
//     /// Try to extract an object of this type from a Reader.
//     ///
//     /// Implementations should generally try to be efficient: this is
//     /// not the right place to check signatures or perform expensive
//     /// operations.  If you have an object that must not be used until
//     /// it is finally validated, consider making this function return
//     /// a wrapped type that can be unwrapped later on once it gets
//     /// checked.
//     fn take_from(b: &mut Reader<'_>) -> Result<Self>;
// }

// impl<R: Readable + ?Sized> tor_bytes::Readable for R {
//     fn take_from(b: &mut Reader<'_>) -> Result<Self> {
//         Self::take_from(b)
//     }
// }

// impl<R: tor_bytes::Readable + ?Sized> Readable for &R {
//     fn take_from(b: &mut Reader<'_>) -> Result<Self> {
//         Self::take_from(b)
//     }
// }

// impl<R: tor_bytes::Readable + ?Sized> Readable for R {
//     fn take_from(b: &mut Reader<'_>) -> Result<Self> {
//         Self::take_from(b)
//     }
// }



// /// A keypair containing a [`StaticSecret`] and its corresponding public key.
// #[allow(clippy::exhaustive_structs)]
// #[derive(Clone, Educe)]
// #[educe(Debug)]
// pub struct StaticKeypair {
//     /// The secret part of the key.
//     #[educe(Debug(ignore))]
//     pub secret: StaticSecret,
//     /// The public part of this key.
//     pub public: PublicKey,
// }
//
//
// impl Writeable for PublicKey {
//     fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) -> EncodeResult<()> {
//         b.write_all(self.as_bytes());
//         Ok(())
//     }
// }
//
// impl Readable for PublicKey {
//     fn take_from(b: &mut Reader<'_>) -> Result<Self> {
//         let bytes: [u8; 32] = b.extract()?;
//         Ok(bytes.into())
//     }
// }
//
// impl Writeable for SharedSecret {
//     fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) -> EncodeResult<()> {
//         b.write_all(self.as_bytes());
//         Ok(())
//     }
// }

