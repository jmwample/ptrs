use crate::{
    common::{
        mlkem1024_x25519::{PublicKey, StaticSecret},
        ntor_arti::KeyGenerator,
    },
    Result,
};

#[cfg(test)]
use rand::{CryptoRng, RngCore};
use subtle::Choice;
use tor_bytes::SecretBuf;
use tor_llcrypto::d::Shake256Reader;
use tor_llcrypto::pk::ed25519::Ed25519Identity;

/// Key information about a relay used for the ntor v3 handshake.
///
/// Contains a single curve25519 ntor onion key, and the relay's ed25519
/// identity.
#[derive(Clone, Debug)]
pub struct NtorV3PublicKey {
    /// The relay's identity.
    pub(crate) id: Ed25519Identity,
    /// The relay's onion key.
    pub(crate) pk: PublicKey,
}

/// Secret key information used by a relay for the ntor v3 handshake.
pub struct NtorV3SecretKey {
    /// The relay's public key information
    pub(crate) pk: NtorV3PublicKey,
    /// The secret onion key.
    pub(super) sk: StaticSecret,
}

impl NtorV3SecretKey {
    /// Construct a new NtorV3SecretKey from its components.
    #[allow(unused)]
    pub(crate) fn new(sk: StaticSecret, pk: PublicKey, id: Ed25519Identity) -> Self {
        Self {
            pk: NtorV3PublicKey { id, pk },
            sk,
        }
    }

    /// Generate a key using the given `rng`, suitable for testing.
    #[cfg(test)]
    pub(crate) fn generate_for_test<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut id = [0_u8; 32];
        // Random bytes will work for testing, but aren't necessarily actually a valid id.
        rng.fill_bytes(&mut id);

        let sk = StaticSecret::random_from_rng(rng);

        let pk = NtorV3PublicKey {
            pk: (&sk).into(),
            id: id.into(),
        };
        Self { pk, sk }
    }

    /// Checks whether `id` and `pk` match this secret key.
    ///
    /// Used to perform a constant-time secret key lookup.
    pub(crate) fn matches(&self, id: Ed25519Identity, pk: PublicKey) -> Choice {
        id.as_bytes().ct_eq(self.pk.id.as_bytes()) & pk.as_bytes().ct_eq(self.pk.pk.as_bytes())
    }
}

/// A key generator returned from an ntor v3 handshake.
pub(crate) struct NtorV3KeyGenerator {
    /// The underlying `digest::XofReader`.
    pub(crate) reader: NtorV3XofReader,
}

impl KeyGenerator for NtorV3KeyGenerator {
    fn expand(mut self, keylen: usize) -> Result<SecretBuf> {
        use digest::XofReader;
        let mut ret: SecretBuf = vec![0; keylen].into();
        self.reader.read(ret.as_mut());
        Ok(ret)
    }
}

/// Opaque wrapper type for NtorV3's hash reader.
pub(crate) struct NtorV3XofReader(pub(crate) Shake256Reader);

impl digest::XofReader for NtorV3XofReader {
    fn read(&mut self, buffer: &mut [u8]) {
        self.0.read(buffer);
    }
}
