use super::*;
use crate::{
    framing::KEY_MATERIAL_LENGTH,
    common::{
        kdf::{Kdf, Ntor1Kdf},
        mlkem1024_x25519::{self, PublicKey, StaticSecret},
        ntor_arti::{KeyGenerator, SessionID, SessionIdentifier},
    },
    constants::*,
    framing::O5Codec,
    Error, Result,
};

use hmac::{Hmac, Mac};
use subtle::{Choice, ConstantTimeEq};
use tor_bytes::SecretBuf;
use tor_llcrypto::pk::rsa::RsaIdentity;
use tor_llcrypto::d::Sha256;
use base64::{Engine, engine::general_purpose::{STANDARD, STANDARD_NO_PAD}};

use rand::{CryptoRng, RngCore};

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

impl From<&NtorV3SecretKey> for NtorV3PublicKey {
    fn from(value: &NtorV3SecretKey) -> Self {
        value.pk.clone()
    }
}

impl NtorV3PublicKey {
    const CERT_LENGTH: usize = mlkem1024_x25519::PUBKEY_LEN;
    const CERT_SUFFIX: &'static str = "==";
    /// Construct a new NtorV3PublicKey from its components.
    #[allow(unused)]
    pub(crate) fn new(
        pk: [u8; mlkem1024_x25519::PUBKEY_LEN],
        id: [u8; NODE_ID_LENGTH],
    ) -> Result<Self> {
        Ok(Self {
            pk: pk.try_into()?,
            id: id.into(),
        })
    }
}

impl std::str::FromStr for NtorV3PublicKey {
    type Err = Error;
    fn from_str(s: &str) -> std::prelude::v1::Result<Self, Self::Err> {
        let mut cert = String::from(s);
        cert.push_str(Self::CERT_SUFFIX);
        let decoded = STANDARD
            .decode(cert.as_bytes())
            .map_err(|e| format!("failed to decode cert: {e}"))?;
        if decoded.len() != Self::CERT_LENGTH {
            return Err(format!("cert length {} is invalid", decoded.len()).into());
        }
        let id: [u8; NODE_ID_LENGTH] = decoded[..NODE_ID_LENGTH].try_into()?;
        let pk: [u8; NODE_PUBKEY_LENGTH] = decoded[NODE_ID_LENGTH..].try_into()?;
        NtorV3PublicKey::new(pk, id)
    }
}

#[allow(clippy::to_string_trait_impl)]
impl std::string::ToString for NtorV3PublicKey {
    fn to_string(&self) -> String {
        let mut s = Vec::from(self.id.as_bytes());
        s.extend(self.pk.as_bytes());
        STANDARD_NO_PAD.encode(s)
    }
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

    pub fn try_from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let buf = bytes.as_ref();
        if buf.len() < mlkem1024_x25519::PRIVKEY_LEN + NODE_ID_LENGTH {
            return Err(Error::new("bad station identity cert provided"));
        }

        let mut id = [0u8; NODE_ID_LENGTH];
        id.copy_from_slice(&buf[..NODE_ID_LENGTH]);
        let sk = StaticSecret::try_from_bytes(&buf[NODE_ID_LENGTH..])?;
        Ok(Self::new(sk, id.into()))
    }

    /// Generate a key using the given `rng`, suitable for testing.
    pub(crate) fn random_from_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut id = [0_u8; 20];
        // Random bytes will work for testing, but aren't necessarily actually a valid id.
        rng.fill_bytes(&mut id);
        let sk = StaticSecret::random_from_rng(rng);
        Self::new(sk, id.into())
    }

    /// Checks whether `id` and `pk` match this secret key.
    ///
    /// Used to perform a constant-time secret key lookup.
    pub(crate) fn matches(&self, id: RsaIdentity, pk: PublicKey) -> Choice {
        id.as_bytes().ct_eq(self.pk.id.as_bytes()) & pk.as_bytes().ct_eq(self.pk.pk.as_bytes())
    }
}

impl TryFrom<&[u8]> for NtorV3SecretKey {
    type Error = Error;
    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        Self::try_from_bytes(value)
    }
}

pub trait NtorV3KeyGen: KeyGenerator + SessionIdentifier + Into<O5Codec> {}

// /// An instantiatable  key generator returned from an ntor v3 handshake.
// pub(crate) struct NtorV3KeyGenerator {
//     /// The underlying `digest::XofReader`.
//     pub(crate) reader: NtorV3XofReader,
// }
//
// impl NtorV3KeyGen for NtorV3KeyGenerator {}
//
// impl KeyGenerator for NtorV3KeyGenerator {
//     fn expand(mut self, keylen: usize) -> Result<SecretBuf> {
//         let mut ret: SecretBuf = vec![0; keylen].into();
//         self.reader.read(ret.as_mut());
//         Ok(ret)
//     }
// }
//
// /// Opaque wrapper type for NtorV3's hash reader.
// pub(crate) struct NtorV3XofReader(pub(crate) Shake256Reader);
//
// impl digest::XofReader for NtorV3XofReader {
//     fn read(&mut self, buffer: &mut [u8]) {
//         self.0.read(buffer);
//     }
// }
//
// impl SessionIdentifier for NtorV3XofReader {
//     type ID = SessionID;
//
//     fn new_session_id(&mut self) -> Self::ID {
//         let mut s = [0u8; SESSION_ID_LEN];
//         <NtorV3XofReader as digest::XofReader>::read(self, &mut s);
//         SessionID::from(s)
//     }
// }

impl NtorV3KeyGen for NtorHkdfKeyGenerator {}

/// KeyGenerator for use with  handshake.
pub(crate) struct NtorHkdfKeyGenerator {
    /// Secret key information derived from the handshake, used as input
    /// to HKDF
    seed: SecretBuf,
    codec: O5Codec,
    session_id: SessionID,
}

impl SessionIdentifier for NtorHkdfKeyGenerator {
    type ID = SessionID;

    fn session_id(&mut self) -> Self::ID {
        self.session_id
    }
}

impl NtorHkdfKeyGenerator {
    /// Create a new key generator to expand a given seed
    pub(crate) fn new(seed: SecretBuf, is_client: bool) -> Self {
        // use the seed value to bootstrap Read / Write crypto codec.
        let okm = Self::kdf(&seed[..], KEY_MATERIAL_LENGTH * 2 + SESSION_ID_LEN)
            .expect("bug: failed to derive key material from seed");

        let ekm: [u8; KEY_MATERIAL_LENGTH] = okm[KEY_MATERIAL_LENGTH..KEY_MATERIAL_LENGTH * 2]
            .try_into()
            .unwrap();
        let dkm: [u8; KEY_MATERIAL_LENGTH] = okm[..KEY_MATERIAL_LENGTH].try_into().unwrap();

        let session_id = okm[KEY_MATERIAL_LENGTH * 2..].try_into().unwrap();

        // server ekm == client dkm and vice-versa
        let codec = match is_client {
            false => O5Codec::new(ekm, dkm),
            true => O5Codec::new(dkm, ekm),
        };

        NtorHkdfKeyGenerator {
            seed,
            codec,
            session_id,
        }
    }

    fn kdf(seed: impl AsRef<[u8]>, keylen: usize) -> Result<SecretBuf> {
        Ntor1Kdf::new(&T_KEY_SEED[..], &M_EXPAND[..]).derive(seed.as_ref(), keylen)
    }
}

impl KeyGenerator for NtorHkdfKeyGenerator {
    fn expand(self, keylen: usize) -> Result<SecretBuf> {
        let ntor1_key = &T_KEY_SEED[..];
        let ntor1_expand = &M_EXPAND[..];
        Ntor1Kdf::new(ntor1_key, ntor1_expand).derive(&self.seed[..], keylen)
    }
}

impl From<NtorHkdfKeyGenerator> for O5Codec {
    fn from(keygen: NtorHkdfKeyGenerator) -> Self {
        keygen.codec
    }
}

/// Alias for an HMAC output, used to validate correctness of a handshake.
pub(crate) type Authcode = [u8; 32];
pub(crate) const AUTHCODE_LENGTH: usize = 32;

/// helper: compute a key generator and an authentication code from a set
/// of ntor parameters.
///
/// These parameter names are as described in tor-spec.txt
fn ntor_derive(
    xy: &SharedSecret,
    xb: &SharedSecret,
    server_pk: &NtorV3PublicKey,
    x: &PublicKey,
    y: &PublicKey,
) -> EncodeResult<(SecretBuf, Authcode)> {
    // ) -> EncodeResult<(NtorHkdfKeyGenerator, Authcode)> {
    let server_string = &b"Server"[..];

    // obfs4 uses a different order than Ntor V1 and accidentally writes the
    // server's identity public key bytes twice.
    let mut suffix = SecretBuf::new();
    suffix.write(&server_pk.pk.as_bytes())?; // b
    suffix.write(&server_pk.pk.as_bytes())?; // b
    suffix.write(x.as_bytes())?; // x
    suffix.write(y.as_bytes())?; // y
    suffix.write(PROTOID)?; // PROTOID
    suffix.write(&server_pk.id)?; // ID

    // secret_input = EXP(X,y) | EXP(X,b)   OR    = EXP(Y,x) | EXP(B,x)
    // ^ these are the equivalent x25519 shared secrets concatenated
    //
    // message = (secret_input) | b | b | x | y | PROTOID | ID
    let mut message = SecretBuf::new();
    message.write(xy.as_bytes())?; // EXP(X,y)
    message.write(xb.as_bytes())?; // EXP(X,b)
    message.write(&suffix[..])?; // b | b | x | y | PROTOID | ID

    // verify = HMAC_SHA256(msg, T_VERIFY)
    let verify = {
        let mut m = Hmac::<Sha256>::new_from_slice(T_VERIFY).expect("Hmac allows keys of any size");
        m.update(&message[..]);
        m.finalize()
    };

    // auth_input = verify | (suffix) | "Server"
    // auth_input = verify | b | b | y | x | PROTOID | ID | "Server"
    //
    // Again obfs4 uses all of the same fields (with the servers identity public
    // key duplicated), but in a different order than Ntor V1.
    let mut auth_input = Vec::new();
    auth_input.write_and_consume(verify)?; // verify
    auth_input.write(&suffix[..])?; // b | b | x | y | PROTOID | ID
    auth_input.write(server_string)?; // "Server"

    // auth = HMAC_SHA256(auth_input, T_MAC)
    let auth_mac = {
        let mut m = Hmac::<Sha256>::new_from_slice(T_MAC).expect("Hmac allows keys of any size");
        m.update(&auth_input[..]);
        m.finalize()
    };
    let auth: [u8; 32] = auth_mac.into_bytes()[..].try_into().unwrap();

    // key_seed = HMAC_SHA256(message, T_KEY)
    let key_seed_bytes = {
        let mut m = Hmac::<Sha256>::new_from_slice(T_KEY).expect("Hmac allows keys of any size");
        m.update(&message[..]);
        m.finalize()
    };
    let mut key_seed = SecretBuf::new();
    key_seed.write_and_consume(key_seed_bytes)?;

    Ok((key_seed, auth))
}
