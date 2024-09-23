use crate::{
    common::{
        mlkem1024_x25519::{PublicKey, StaticSecret},
        ntor_arti::{KeyGenerator, SessionID, SessionIdentifier},
    },
    constants::SESSION_ID_LEN,
    framing::O5Codec,
    Result,
};

#[cfg(test)]
use rand::{CryptoRng, RngCore};
use subtle::{Choice, ConstantTimeEq};
use tor_bytes::SecretBuf;
use tor_llcrypto::d::Shake256Reader;
use tor_llcrypto::pk::rsa::RsaIdentity;

/// Key information about a relay used for the ntor v3 handshake.
///
/// Contains a single curve25519 ntor onion key, and the relay's ed25519
/// identity.
#[derive(Clone, Debug, PartialEq)]
pub struct NtorV3PublicKey {
    /// The relay's identity.
    pub(crate) id: RsaIdentity,
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
    pub(crate) fn new(sk: StaticSecret, id: RsaIdentity) -> Self {
        Self {
            pk: NtorV3PublicKey {
                id,
                pk: PublicKey::from(&sk),
            },
            sk,
        }
    }

    /// Generate a key using the given `rng`, suitable for testing.
    #[cfg(test)]
    pub(crate) fn generate_for_test<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut id = [0_u8; 20];
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
    pub(crate) fn matches(&self, id: RsaIdentity, pk: PublicKey) -> Choice {
        id.as_bytes().ct_eq(self.pk.id.as_bytes()) & pk.as_bytes().ct_eq(self.pk.pk.as_bytes())
    }
}

pub trait NtorV3KeyGen: KeyGenerator + SessionIdentifier + Into<O5Codec> {}

/// An instantiatable  key generator returned from an ntor v3 handshake.
pub(crate) struct NtorV3KeyGenerator {
    /// The underlying `digest::XofReader`.
    pub(crate) reader: NtorV3XofReader,
}

impl NtorV3KeyGen for NtorV3KeyGenerator {}

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

impl SessionIdentifier for NtorV3XofReader {
    type ID = SessionID;

    fn new_session_id(&mut self) -> Self::ID {
        let mut s = [0u8; SESSION_ID_LEN];
        <NtorV3XofReader as digest::XofReader>::read(self, &mut s);
        SessionID::from(s)
    }
}
