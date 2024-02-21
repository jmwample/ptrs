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
pub use x25519_dalek::{EphemeralSecret, ReusableSecret, PublicKey, SharedSecret, StaticSecret, PublicRepresentative};

pub const REPRESENTATIVE_LENGTH: usize = 32;
