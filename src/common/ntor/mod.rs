#![allow(unused)]

use crate::obfs4::framing::KEY_LENGTH;
use crate::{Error, Result};

mod id;
pub use id::{ID, NODE_ID_LENGTH};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use x25519_dalek::{x25519, PublicRepresentative, ReusableSecret, SharedSecret, StaticSecret};

use std::convert::From;
use std::error::Error as StdError;
use std::fmt::{self, Debug, Display};

pub const REPRESENTATIVE_LENGTH: usize = 32;

pub(crate) const PROTO_ID: &[u8; 24] = b"ntor-curve25519-sha256-1";
pub(crate) const T_MAC: &[u8; 28] = b"ntor-curve25519-sha256-1:mac";
pub(crate) const T_VERIFY: &[u8; 35] = b"ntor-curve25519-sha256-1:key_verify";
pub(crate) const T_KEY: &[u8; 36] = b"ntor-curve25519-sha256-1:key_extract";

/// The length of the derived KEY_SEED.
pub(crate) const KEY_SEED_LENGTH: usize = 32; // sha256.Size;

/// The length of the derived AUTH.
pub(crate) const AUTH_LENGTH: usize = 32; //sha256.Size;

/// The key material that results from a handshake (KEY_SEED).
#[derive(Default, Debug, Clone)]
pub struct KeySeed([u8; KEY_SEED_LENGTH]);

impl KeySeed {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// The verifier that results from a handshake (AUTH).
#[derive(Default, Debug, Clone)]
pub struct Auth([u8; AUTH_LENGTH]);
impl Auth {
    pub fn new(b: [u8; AUTH_LENGTH]) -> Self {
        Self(b)
    }
    pub fn try_from_bytes(b: impl AsRef<[u8]>) -> Result<Self> {
        let buf = &b.as_ref();
        if buf.len() < AUTH_LENGTH {
            Err(Error::Other("bad auth length".into()))?
        }
        Ok(Auth(b.as_ref().try_into()?))
    }
    pub fn to_bytes(&self) -> [u8; AUTH_LENGTH] {
        self.0
    }
}

#[derive(Debug)]
pub enum NtorError {
    HSFailure(String),
    AuthError,
}

impl StdError for NtorError {}
impl Display for NtorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NtorError::HSFailure(es) => write!(f, "ntor handshake failure:{es}"),
            NtorError::AuthError => write!(f, "handshake authentication error!"),
        }
    }
}

/// Curve25519 keypair, there is no need for an elligator representative. This
/// is intended to be used for the stations long term key, potentially allowing
/// the key to be (de)serielized to/from a statefile.
pub struct IdentityKeyPair {
    pub private: StaticSecret,
    pub public: PublicKey,
}

impl IdentityKeyPair {
    pub fn from_privkey(private_key: [u8; KEY_LENGTH]) -> Self {
        let private = StaticSecret::from(private_key);
        let public = x25519_dalek::PublicKey::from(& private);
        Self { private, public }
    }
}

impl From<[u8; KEY_LENGTH * 2]> for  IdentityKeyPair {
    fn from(value: [u8; KEY_LENGTH * 2]) -> Self {
        let private: [u8; KEY_LENGTH] = value[0..KEY_LENGTH].try_into().unwrap();
        let public: [u8; KEY_LENGTH] = value[KEY_LENGTH..].try_into().unwrap();
        Self {
            private: StaticSecret::from(private),
            public: PublicKey::from(public),
        }
    }
}

/// Re-Export the public key type for consistency in usage.
pub type PublicKey = x25519_dalek::PublicKey;

/// Re-Export the public key type for consistency in usage.
pub type Representative = x25519_dalek::PublicRepresentative;

/// Curve25519 keypair with an optional Elligator representative.
/// As only certain Curve25519 keys can be obfuscated with Elligator, the
/// representative must be generated along with the keypair. The ReusableSecret
/// struct is used because we have no need to ever serialize the private key
/// from a session, and this provides auto-safeguards against doing so.
pub struct SessionKeyPair {
    pub private: ReusableSecret,
    pub public: PublicKey,
    pub representative: Option<Representative>,
}

impl Debug for SessionKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.representative {
            Some(r) => write!(
                f,
                "{}->[{}]",
                hex::encode(self.public.to_bytes()),
                hex::encode(r.as_bytes())
            ),
            None => write!(f, "{}->None", hex::encode(self.public.to_bytes())),
        }
    }
}

impl Default for IdentityKeyPair {
    fn default() -> Self {
        Self::new()
    }
}

impl IdentityKeyPair {
    /// Generates a new Curve25519 keypair
    pub fn new() -> Self {
        let private = StaticSecret::random();
        let public = PublicKey::from(&private);
        Self { private, public }
    }
}

impl SessionKeyPair {
    /// Generates a new Curve25519 keypair, and optionally also generates
    /// an Elligator representative of the public key.
    pub fn new(elligator: bool) -> Self {
        let mut private = ReusableSecret::random();
        let mut public = PublicKey::from(&private);
        let mut representative: Representative;
        let mut rp = Self {
            private,
            public,
            representative: None,
        };

        if elligator {
            loop {
                match Option::<Representative>::from(&rp.private) {
                    Some(representative) => {
                        rp.representative = Some(representative);
                    }
                    None => {
                        // Elligator representatives only exist for 50% of points
                        // iterate until we find one that works.
                        //
                        // failed to get representative - try again
                        rp.private = ReusableSecret::random();
                        rp.public = PublicKey::from(&rp.private);
                        continue;
                    }
                }
                break;
            }
        }

        rp
    }

    pub fn get_representative(&self) -> Option<Representative> {
        self.representative.clone()
    }

    pub fn get_public(&self) -> &PublicKey {
        &self.public
    }
}

/// Constant time compare of a Auth and a byte slice
/// (presumably received over a network).
pub fn compare_auth(auth1: &Auth, auth2: impl AsRef<[u8]>) -> Result<()> {
    match auth1.0[..].ct_eq(auth2.as_ref()).unwrap_u8() {
        0 => Err( NtorError::AuthError.into() ),
        _ => Ok(()),
    }
}

#[derive(Debug, Clone)]
pub struct HandShakeResult {
    pub key_seed: KeySeed,
    pub auth: Auth,
}

impl fmt::Display for HandShakeResult {
    // This trait requires `fmt` with this exact signature.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{} {}",
            hex::encode(self.key_seed.0),
            hex::encode(self.auth.0)
        )
    }
}

const _ZERO_EXP: [u8; 32] = [0_u8; 32];

impl HandShakeResult {
    fn new() -> Self {
        Self {
            key_seed: KeySeed([0_u8; KEY_SEED_LENGTH]),
            auth: Auth([0_u8; AUTH_LENGTH]),
        }
    }

    pub fn client_handshake(
        client_keys: &SessionKeyPair,
        server_public: &PublicKey,
        id_public: &PublicKey,
        id: &ID,
    ) -> subtle::CtOption<Self> {
        let mut not_ok = 0;
        let mut secret_input: Vec<u8> = vec![];

        // Client side uses EXP(Y,x) | EXP(B,x)
        let exp = client_keys.private.diffie_hellman(server_public);
        not_ok |= _ZERO_EXP[..].ct_eq(exp.as_bytes()).unwrap_u8();
        secret_input.append(&mut exp.as_bytes().to_vec());

        let exp = client_keys.private.diffie_hellman(id_public);
        not_ok |= _ZERO_EXP[..].ct_eq(exp.as_bytes()).unwrap_u8();
        secret_input.append(&mut exp.as_bytes().to_vec());

        let (key_seed, auth) = derive_ntor_shared(
            secret_input,
            id,
            id_public,
            &client_keys.public,
            server_public,
        );

        // failed if not_ok != 0
        // if not_ok != 0 then scalar operations failed
        subtle::CtOption::new(Self { key_seed, auth }, not_ok.ct_eq(&0_u8))
    }

    pub fn server_handshake(
        client_public: &PublicKey,
        server_keys: &SessionKeyPair,
        id_keys: &IdentityKeyPair,
        id: &ID,
    ) -> subtle::CtOption<Self> {
        let mut not_ok = 0;
        let mut secret_input: Vec<u8> = vec![];

        // Server side uses EXP(X,y) | EXP(X,b)
        let exp = server_keys.private.diffie_hellman(client_public);
        not_ok |= _ZERO_EXP[..].ct_eq(exp.as_bytes()).unwrap_u8();
        secret_input.append(&mut exp.as_bytes().to_vec());

        let exp = id_keys.private.diffie_hellman(client_public);
        not_ok |= _ZERO_EXP[..].ct_eq(exp.as_bytes()).unwrap_u8();
        secret_input.append(&mut exp.as_bytes().to_vec());

        let (key_seed, auth) = derive_ntor_shared(
            secret_input,
            id,
            &id_keys.public,
            client_public,
            &server_keys.public,
        );

        // failed if not_ok != 0
        // if not_ok != 0 then scalar operations failed
        subtle::CtOption::new(Self { key_seed, auth }, not_ok.ct_eq(&0_u8))
    }
}

type HmacSha256 = Hmac<Sha256>;

fn derive_ntor_shared(
    secret_input: impl AsRef<[u8]>,
    id: &ID,
    b: &PublicKey,
    x: &PublicKey,
    y: &PublicKey,
) -> (KeySeed, Auth) {
    let mut key_seed = KeySeed::default();
    let mut auth = Auth::default();

    let mut message = secret_input.as_ref().to_vec();
    message.append(&mut b.to_bytes().to_vec());
    message.append(&mut x.to_bytes().to_vec());
    message.append(&mut y.to_bytes().to_vec());
    message.append(&mut PROTO_ID.to_vec());
    message.append(&mut id.to_bytes().to_vec());

    let mut h = HmacSha256::new_from_slice(&T_KEY[..]).unwrap();
    h.update(message.as_ref());
    let tmp: &[u8] = &h.finalize().into_bytes()[..];
    key_seed.0 = tmp.try_into().expect("unable to write key_seed");

    let mut h = HmacSha256::new_from_slice(&T_VERIFY[..]).unwrap();
    h.update(message.as_ref());
    let mut verify = h.finalize().into_bytes().to_vec();

    // auth_input = verify | ID | B | Y | X | PROTOID | "Server"
    verify.append(&mut message.to_vec());
    verify.append(&mut b"Server".to_vec());
    let mut h = HmacSha256::new_from_slice(&T_MAC[..]).unwrap();
    h.update(verify.as_ref());
    let mut tmp = &h.finalize().into_bytes()[..];
    auth.0 = tmp.try_into().expect("unable to write auth");

    (key_seed, auth)
}

pub fn process_client_handshake(
    client_public: &PublicKey,
    server_keys: &SessionKeyPair,
    id_keys: &IdentityKeyPair,
    id: &ID,
) -> subtle::CtOption<HandShakeResult> {
    HandShakeResult::server_handshake(client_public, server_keys, id_keys, id)
}

// Client side of a ntor handshake performed to derive shared, authenticated
// status, KEY_SEED, and AUTH.  If status is not true or AUTH does not match
// the value received from the server in the response, the handshake MUST be
// aborted.
pub fn process_server_handshake(
    client_keys: &SessionKeyPair,
    server_public: &PublicKey,
    id_public: &PublicKey,
    id: &ID,
) -> subtle::CtOption<HandShakeResult> {
    HandShakeResult::client_handshake(client_keys, server_public, id_public, id)
}

#[cfg(test)]
mod testing;
