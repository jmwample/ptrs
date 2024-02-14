//! Implements the ntor v3 key exchange, as described in proposal 332.
//!
//! The main difference between the ntor v3r handshake and the
//! original ntor handshake is that this this one allows each party to
//! encrypt data (without forward secrecy) after it sends the first
//! message.

// TODO:
//    Remove the "allow" item for dead_code.
//    Make terminology and variable names consistent with spec.

// This module is still unused: so allow some dead code for now.
#![allow(dead_code)]

use std::borrow::Borrow;

use crate::common::ntor_arti::{KeyGenerator, RelayHandshakeError, RelayHandshakeResult};
use crate::common::ct;
use crate::common::curve25519;
use crate::{Error, Result};
use tor_bytes::{EncodeResult, Reader, SecretBuf, Writeable, Writer};
use tor_error::into_internal;
use tor_llcrypto::d::{Sha3_256, Shake256, Shake256Reader};
use tor_llcrypto::pk::ed25519::Ed25519Identity;
use tor_llcrypto::util::ct::ct_lookup;

use cipher::{KeyIvInit, StreamCipher};

use rand_core::{CryptoRng, RngCore};
use subtle::{Choice, ConstantTimeEq};
use tor_cell::relaycell::extend::NtorV3Extension;
use tor_llcrypto::cipher::aes::Aes256Ctr;
use zeroize::Zeroizing;

/// The verification string to be used for circuit extension.
const OBFS4_CIRC_VERIFICATION: &[u8] = b"circuit extend";

/// The size of an encryption key in bytes.
const ENC_KEY_LEN: usize = 32;
/// The size of a MAC key in bytes.
const MAC_KEY_LEN: usize = 32;
/// The size of a curve25519 public key in bytes.
const PUB_KEY_LEN: usize = 32;
/// The size of a digest output in bytes.
const DIGEST_LEN: usize = 32;
/// The length of a MAC output in bytes.
const MAC_LEN: usize = 32;
/// The length of a node identity in bytes.
const ID_LEN: usize = 32;

/// The output of the digest, as an array.
type DigestVal = [u8; DIGEST_LEN];
/// The output of the MAC.
type MacVal = [u8; MAC_LEN];
/// A key for symmetric encryption or decryption.
//
// TODO (nickm): Any move operations applied to this key could subvert the zeroizing.
type EncKey = Zeroizing<[u8; ENC_KEY_LEN]>;
/// A key for message authentication codes.
type MacKey = [u8; MAC_KEY_LEN];

/// Opaque wrapper type for Obfs4Ntor's hash reader.
struct Obfs4NtorXofReader(Shake256Reader);

impl digest::XofReader for Obfs4NtorXofReader {
    fn read(&mut self, buffer: &mut [u8]) {
        self.0.read(buffer);
    }
}

/// An encapsulated value for passing as input to a MAC, digest, or
/// KDF algorithm.
///
/// This corresponds to the ENCAP() function in proposal 332.
struct Encap<'a>(&'a [u8]);

impl<'a> Writeable for Encap<'a> {
    fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) -> EncodeResult<()> {
        b.write_u64(self.0.len() as u64);
        b.write(self.0)
    }
}

impl<'a> Encap<'a> {
    /// Return the length of the underlying data in bytes.
    fn len(&self) -> usize {
        self.0.len()
    }
    /// Return the underlying data
    fn data(&self) -> &'a [u8] {
        self.0
    }
}

/// Helper to define a set of tweak values as instances of `Encap`.
macro_rules! define_tweaks {
    {
        $(#[$pid_meta:meta])*
        PROTOID = $protoid:expr;
        $( $(#[$meta:meta])* $name:ident <= $suffix:expr ; )*
    } => {
        $(#[$pid_meta])*
        const PROTOID: &'static [u8] = $protoid.as_bytes();
        $(
            $(#[$meta])*
            const $name : Encap<'static> =
                Encap(concat!($protoid, ":", $suffix).as_bytes());
        )*
    }
}

define_tweaks! {
    /// Protocol ID: concatenated with other things in the protocol to
    /// prevent hash confusion.
    PROTOID =  "ntor3-curve25519-sha3_256-1";

    /// Message MAC tweak: used to compute the MAC of an encrypted client
    /// message.
    T_MSGMAC <= "msg_mac";
    /// Message KDF tweak: used when deriving keys for encrypting and MACing
    /// client message.
    T_MSGKDF <= "kdf_phase1";
    /// Key seeding tweak: used to derive final KDF input from secret_input.
    T_KEY_SEED <= "key_seed";
    /// Verifying tweak: used to derive 'verify' value from secret_input.
    T_VERIFY <= "verify";
    /// Final KDF tweak: used to derive keys for encrypting relay message
    /// and for the actual tor circuit.
    T_FINAL <= "kdf_final";
    /// Authentication tweak: used to derive the final authentication
    /// value for the handshake.
    T_AUTH <= "auth_final";
}

/// Compute a tweaked hash.
fn hash(t: &Encap<'_>, data: &[u8]) -> DigestVal {
    use digest::Digest;
    let mut d = Sha3_256::new();
    d.update((t.len() as u64).to_be_bytes());
    d.update(t.data());
    d.update(data);
    d.finalize().into()
}

/// Perform a symmetric encryption operation and return the encrypted data.
///
/// (This isn't safe to do more than once with the same key, but we never
/// do that in this protocol.)
fn encrypt(key: &EncKey, m: &[u8]) -> Vec<u8> {
    let mut d = m.to_vec();
    let zero_iv = Default::default();
    let mut cipher = Aes256Ctr::new(key.as_ref().into(), &zero_iv);
    cipher.apply_keystream(&mut d);
    d
}
/// Perform a symmetric decryption operation and return the encrypted data.
fn decrypt(key: &EncKey, m: &[u8]) -> Vec<u8> {
    encrypt(key, m)
}

/// Wrapper around a Digest or ExtendedOutput object that lets us use it
/// as a tor_bytes::Writer.
struct DigestWriter<U>(U);
impl<U: digest::Update> tor_bytes::Writer for DigestWriter<U> {
    fn write_all(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }
}
impl<U> DigestWriter<U> {
    /// Consume this wrapper and return the underlying object.
    fn take(self) -> U {
        self.0
    }
}

/// Hash tweaked with T_KEY_SEED
fn h_key_seed(d: &[u8]) -> DigestVal {
    hash(&T_KEY_SEED, d)
}
/// Hash tweaked with T_VERIFY
fn h_verify(d: &[u8]) -> DigestVal {
    hash(&T_VERIFY, d)
}

/// Helper: compute the encryption key and mac_key for the client's
/// encrypted message.
///
/// Takes as inputs `xb` (the shared secret derived from
/// diffie-hellman as Bx or Xb), the relay's public key information,
/// the client's public key (B), and the shared verification string.
fn kdf_msgkdf(
    xb: &curve25519::SharedSecret,
    relay_public: &Obfs4NtorPublicKey,
    client_public: &curve25519::PublicKey,
    verification: &[u8],
) -> EncodeResult<(EncKey, DigestWriter<Sha3_256>)> {
    // secret_input_phase1 = Bx | ID | X | B | PROTOID | ENCAP(VER)
    // phase1_keys = KDF_msgkdf(secret_input_phase1)
    // (ENC_K1, MAC_K1) = PARTITION(phase1_keys, ENC_KEY_LEN, MAC_KEY_LEN
    use digest::{ExtendableOutput, XofReader};
    let mut msg_kdf = DigestWriter(Shake256::default());
    msg_kdf.write(&T_MSGKDF)?;
    msg_kdf.write(xb.as_bytes())?;
    msg_kdf.write(&relay_public.id)?;
    msg_kdf.write(client_public.as_bytes())?;
    msg_kdf.write(&relay_public.pk.as_bytes())?;
    msg_kdf.write(PROTOID)?;
    msg_kdf.write(&Encap(verification))?;
    let mut r = msg_kdf.take().finalize_xof();
    let mut enc_key = Zeroizing::new([0; ENC_KEY_LEN]);
    let mut mac_key = Zeroizing::new([0; MAC_KEY_LEN]);

    r.read(&mut enc_key[..]);
    r.read(&mut mac_key[..]);
    let mut mac = DigestWriter(Sha3_256::default());
    {
        mac.write(&T_MSGMAC)?;
        mac.write(&Encap(&mac_key[..]))?;
        mac.write(&relay_public.id)?;
        mac.write(&relay_public.pk.as_bytes())?;
        mac.write(client_public.as_bytes())?;
    }

    Ok((enc_key, mac))
}

/// Client side of the ntor v3 handshake.
pub(crate) struct Obfs4NtorClient;

impl crate::common::ntor_arti::ClientHandshake for Obfs4NtorClient {
    type KeyType = Obfs4NtorPublicKey;
    type StateType = Obfs4NtorHandshakeState;
    type KeyGen = Obfs4NtorKeyGenerator;
    type ClientAuxData = [NtorV3Extension];
    type ServerAuxData = Vec<NtorV3Extension>;

    /// Generate a new client onionskin for a relay with a given onion key.
    /// If any `extensions` are provided, encode them into to the onionskin.
    ///
    /// On success, return a state object that will be used to complete the handshake, along
    /// with the message to send.
    fn client1<R: RngCore + CryptoRng, M: Borrow<[NtorV3Extension]>>(
        rng: &mut R,
        key: &Obfs4NtorPublicKey,
        extensions: &M,
    ) -> Result<(Self::StateType, Vec<u8>)> {
        let mut message = Vec::new();
        NtorV3Extension::write_many_onto(extensions.borrow(), &mut message)
            .map_err(|e| Error::from_bytes_enc(e, "ntor3 handshake extensions"))?;
        Ok(
            client_handshake_obfs4(rng, key, &message, OBFS4_CIRC_VERIFICATION)
                .map_err(into_internal!("Can't encode obfs4 client handshake."))?,
        )
    }

    /// Handle an onionskin from a relay, and produce a key generator.
    ///
    /// The state object must match the one that was used to make the
    /// client onionskin that the server is replying to.
    fn client2<T: AsRef<[u8]>>(
        state: Self::StateType,
        msg: T,
    ) -> Result<(Vec<NtorV3Extension>, Self::KeyGen)> {
        let (message, xofreader) =
            client_handshake_obfs4_part2(&state, msg.as_ref(), OBFS4_CIRC_VERIFICATION)?;
        let extensions = NtorV3Extension::decode(&message).map_err(|err| Error::CellDecodeErr {
            object: "ntor v3 extensions",
            err,
        })?;
        let keygen = Obfs4NtorKeyGenerator { reader: xofreader };

        Ok((extensions, keygen))
    }
}

/// Server side of the ntor v3 handshake.
pub(crate) struct Obfs4NtorServer;

impl crate::common::ntor_arti::ServerHandshake for Obfs4NtorServer {
    type KeyType = Obfs4NtorSecretKey;
    type KeyGen = Obfs4NtorKeyGenerator;
    type ClientAuxData = [NtorV3Extension];
    type ServerAuxData = Vec<NtorV3Extension>;

    fn server<R: RngCore + CryptoRng, REPLY: crate::common::ntor_arti::AuxDataReply<Self>, T: AsRef<[u8]>>(
        rng: &mut R,
        reply_fn: &mut REPLY,
        key: &[Self::KeyType],
        msg: T,
    ) -> RelayHandshakeResult<(Self::KeyGen, Vec<u8>)> {
        let mut bytes_reply_fn = |bytes: &[u8]| -> Option<Vec<u8>> {
            let client_exts = NtorV3Extension::decode(bytes).ok()?;
            let reply_exts = reply_fn.reply(&client_exts)?;
            let mut out = vec![];
            NtorV3Extension::write_many_onto(&reply_exts, &mut out).ok()?;
            Some(out)
        };

        let (res, reader) = server_handshake_obfs4(
            rng,
            &mut bytes_reply_fn,
            msg.as_ref(),
            key,
            OBFS4_CIRC_VERIFICATION,
        )?;
        Ok((Obfs4NtorKeyGenerator { reader }, res))
    }
}

/// Key information about a relay used for the ntor v3 handshake.
///
/// Contains a single curve25519 ntor onion key, and the relay's ed25519
/// identity.
#[derive(Clone, Debug)]
pub(crate) struct Obfs4NtorPublicKey {
    /// The relay's identity.
    pub(crate) id: Ed25519Identity,
    /// The Bridge's identity key.
    pub(crate) pk: curve25519::PublicKey,
    /// The Elligator2 representative for the public key
    pub(crate) rp: curve25519::PublicRepresentative,
}

/// Secret key information used by a relay for the ntor v3 handshake.
pub(crate) struct Obfs4NtorSecretKey {
    /// The relay's public key information
    pk: Obfs4NtorPublicKey,
    /// The secret onion key.
    sk: curve25519::StaticSecret,
}

impl Obfs4NtorSecretKey {
    /// Construct a new Obfs4NtorSecretKey from its components.
    #[allow(unused)]
    pub(crate) fn new(
        sk: curve25519::StaticSecret,
        pk: curve25519::PublicKey,
        rp: curve25519::PublicRepresentative,
        id: Ed25519Identity,
    ) -> Self {
        Self {
            pk: Obfs4NtorPublicKey { id, pk, rp },
            sk,
        }
    }

    /// Generate a key using the given `rng`, suitable for testing.
    #[cfg(test)]
    pub(crate) fn generate_for_test<R: RngCore + CryptoRng>(mut rng: R) -> Self {
        let mut id = [0_u8; 32];
        // Random bytes will work for testing, but aren't necessarily actually a valid id.
        rng.fill_bytes(&mut id);

        let mut sk: curve25519::StaticSecret;
        let pk1: curve25519::PublicKey;
        let mut rp: Option<curve25519::PublicRepresentative>;

        loop {
            sk = curve25519::StaticSecret::random_from_rng(&mut rng);
            rp = (&sk).into();
            if rp.is_none() {
                continue
            }
            pk1 = (&sk).into();
            break
        }

        let pk = Obfs4NtorPublicKey {
            pk: pk1,
            id: id.into(),
            rp: rp.unwrap(),
        };
        Self { pk, sk }
    }

    /// Checks whether `id` and `pk` match this secret key.
    ///
    /// Used to perform a constant-time secret key lookup.
    fn matches(&self, id: Ed25519Identity, pk: curve25519::PublicKey) -> Choice {
        // TODO: use similar pattern in ntor_v1!
        id.as_bytes().ct_eq(self.pk.id.as_bytes()) & pk.as_bytes().ct_eq(self.pk.pk.as_bytes())
    }
}

/// Client state for the ntor v3 handshake.
///
/// The client needs to hold this state between when it sends its part
/// of the handshake and when it receives the relay's reply.
pub(crate) struct Obfs4NtorHandshakeState {
    /// The public key of the relay we're communicating with.
    relay_public: Obfs4NtorPublicKey, // B, ID.
    /// Our ephemeral secret key for this handshake.
    my_sk: curve25519::StaticSecret, // x
    /// Our ephemeral public key for this handshake.
    my_public: curve25519::PublicKey, // X

    /// The shared secret generated as Bx or Xb.
    shared_secret: curve25519::SharedSecret, // Bx
    /// The MAC of our original encrypted message.
    msg_mac: MacVal, // msg_mac
}

/// A key generator returned from an ntor v3 handshake.
pub(crate) struct Obfs4NtorKeyGenerator {
    /// The underlying `digest::XofReader`.
    reader: Obfs4NtorXofReader,
}

impl KeyGenerator for Obfs4NtorKeyGenerator {
    fn expand(mut self, keylen: usize) -> Result<SecretBuf> {
        use digest::XofReader;
        let mut ret: SecretBuf = vec![0; keylen].into();
        self.reader.read(ret.as_mut());
        Ok(ret)
    }
}

/// Client-side Ntor version 3 handshake, part one.
///
/// Given a secure `rng`, a relay's public key, a secret message to send,
/// and a shared verification string, generate a new handshake state
/// and a message to send to the relay.
fn client_handshake_obfs4<R: RngCore + CryptoRng>(
    rng: &mut R,
    relay_public: &Obfs4NtorPublicKey,
    client_msg: &[u8],
    verification: &[u8],
) -> EncodeResult<(Obfs4NtorHandshakeState, Vec<u8>)> {
    let my_sk = curve25519::StaticSecret::random_from_rng(rng);
    client_handshake_obfs4_no_keygen(relay_public, client_msg, verification, my_sk)
}

/// As `client_handshake_obfs4`, but don't generate an ephemeral DH
/// key: instead take that key an arguments `my_sk`.
fn client_handshake_obfs4_no_keygen(
    relay_public: &Obfs4NtorPublicKey,
    client_msg: &[u8],
    verification: &[u8],
    my_sk: curve25519::StaticSecret,
) -> EncodeResult<(Obfs4NtorHandshakeState, Vec<u8>)> {
    let my_public = curve25519::PublicKey::from(&my_sk);
    let bx = my_sk.diffie_hellman(&relay_public.pk);

    let (enc_key, mut mac) = kdf_msgkdf(&bx, relay_public, &my_public, verification)?;

    //encrypted_msg = ENC(ENC_K1, CM)
    // msg_mac = MAC_msgmac(MAC_K1, ID | B | X | encrypted_msg)
    let encrypted_msg = encrypt(&enc_key, client_msg);
    let msg_mac: DigestVal = {
        use digest::Digest;
        mac.write(&encrypted_msg)?;
        mac.take().finalize().into()
    };

    let mut message = Vec::new();
    message.write(&relay_public.id)?;
    message.write(&relay_public.pk.as_bytes())?;
    message.write(&my_public.as_bytes())?;
    message.write(&encrypted_msg)?;
    message.write(&msg_mac)?;

    let state = Obfs4NtorHandshakeState {
        relay_public: relay_public.clone(),
        my_sk,
        my_public,
        shared_secret: bx,
        msg_mac,
    };

    Ok((state, message))
}

/// Trait for an object that handle and incoming client message and
/// return a server's reply.
///
/// This is implemented for `FnMut(&[u8]) -> Option<Vec<u8>>` automatically.
pub(crate) trait MsgReply {
    /// Given a message received from a client, parse it and decide
    /// how (and whether) to reply.
    ///
    /// Return None if the handshake should fail.
    fn reply(&mut self, msg: &[u8]) -> Option<Vec<u8>>;
}

impl<F> MsgReply for F
where
    F: FnMut(&[u8]) -> Option<Vec<u8>>,
{
    fn reply(&mut self, msg: &[u8]) -> Option<Vec<u8>> {
        self(msg)
    }
}

/// Complete an ntor v3 handshake as a server.
///
/// Use the provided `rng` to generate keys; use the provided
/// `reply_fn` to handle incoming client secret message and decide how
/// to reply.  The client's handshake is in `message`.  Our private
/// key(s) are in `keys`.  The `verification` string must match the
/// string provided by the client.
///
/// On success, return the server handshake message to send, and an XofReader
/// to use in generating circuit keys.
fn server_handshake_obfs4<RNG: CryptoRng + RngCore, REPLY: MsgReply>(
    rng: &mut RNG,
    reply_fn: &mut REPLY,
    message: &[u8],
    keys: &[Obfs4NtorSecretKey],
    verification: &[u8],
) -> RelayHandshakeResult<(Vec<u8>, Obfs4NtorXofReader)> {
    let secret_key_y = curve25519::StaticSecret::random_from_rng(rng);
    server_handshake_obfs4_no_keygen(reply_fn, &secret_key_y, message, keys, verification)
}

/// As `server_handshake_obfs4`, but take a secret key instead of an RNG.
fn server_handshake_obfs4_no_keygen<REPLY: MsgReply>(
    reply_fn: &mut REPLY,
    secret_key_y: &curve25519::StaticSecret,
    message: &[u8],
    keys: &[Obfs4NtorSecretKey],
    verification: &[u8],
) -> RelayHandshakeResult<(Vec<u8>, Obfs4NtorXofReader)> {
    // Decode the message.
    let mut r = Reader::from_slice(message);
    let id: Ed25519Identity = r.extract()?;

    let pk_buf: [u8;32] = r.extract()?;
    let requested_pk = curve25519::PublicKey::from(pk_buf);
    let pk_buf: [u8;32] = r.extract()?;
    let client_pk = curve25519::PublicKey::from(pk_buf);
    let client_msg = if let Some(msg_len) = r.remaining().checked_sub(MAC_LEN) {
        r.take(msg_len)?
    } else {
        return Err(tor_bytes::Error::Truncated.into());
    };
    let msg_mac: MacVal = r.extract()?;
    r.should_be_exhausted()?;

    // See if we recognize the provided (id,requested_pk) pair.
    let keypair = ct_lookup(keys, |key| key.matches(id, requested_pk));
    let keypair = match keypair {
        Some(k) => k,
        None => return Err(RelayHandshakeError::MissingKey),
    };

    let xb = keypair.sk.diffie_hellman(&client_pk);
    let (enc_key, mut mac) = kdf_msgkdf(&xb, &keypair.pk, &client_pk, verification)
        .map_err(into_internal!("Can't apply obfs4 kdf."))?;
    // Verify the message we received.
    let computed_mac: DigestVal = {
        use digest::Digest;
        mac.write(client_msg)
            .map_err(into_internal!("Can't compute MAC input."))?;
        mac.take().finalize().into()
    };
    let y_pk: curve25519::PublicKey = (secret_key_y).into();
    let xy = secret_key_y.diffie_hellman(&client_pk);

    let mut okay = computed_mac.ct_eq(&msg_mac)
        & ct::bool_to_choice(xy.was_contributory())
        & ct::bool_to_choice(xb.was_contributory());

    let plaintext_msg = decrypt(&enc_key, client_msg);

    // Handle the message and decide how to reply.
    let reply = reply_fn.reply(&plaintext_msg);

    // It's not exactly constant time to use is_some() and
    // unwrap_or_else() here, but that should be somewhat
    // hidden by the rest of the computation.
    okay &= ct::bool_to_choice(reply.is_some());
    let reply = reply.unwrap_or_default();

    // If we reach this point, we are actually replying, or pretending
    // that we're going to reply.

    let secret_input = {
        let mut si = SecretBuf::new();
        si.write(&xy.as_bytes())
            .and_then(|_| si.write(&xb.as_bytes()))
            .and_then(|_| si.write(&keypair.pk.id))
            .and_then(|_| si.write(&keypair.pk.pk.as_bytes()))
            .and_then(|_| si.write(&client_pk.as_bytes()))
            .and_then(|_| si.write(&y_pk.as_bytes()))
            .and_then(|_| si.write(PROTOID))
            .and_then(|_| si.write(&Encap(verification)))
            .map_err(into_internal!("can't derive obfs4 secret_input"))?;
        si
    };
    let ntor_key_seed = h_key_seed(&secret_input);
    let verify = h_verify(&secret_input);

    let (enc_key, keystream) = {
        use digest::{ExtendableOutput, XofReader};
        let mut xof = DigestWriter(Shake256::default());
        xof.write(&T_FINAL)
            .and_then(|_| xof.write(&ntor_key_seed))
            .map_err(into_internal!("can't generate obfs4 xof."))?;
        let mut r = xof.take().finalize_xof();
        let mut enc_key = Zeroizing::new([0_u8; ENC_KEY_LEN]);
        r.read(&mut enc_key[..]);
        (enc_key, r)
    };
    let encrypted_reply = encrypt(&enc_key, &reply);
    let auth: DigestVal = {
        use digest::Digest;
        let mut auth = DigestWriter(Sha3_256::default());
        auth.write(&T_AUTH)
            .and_then(|_| auth.write(&verify))
            .and_then(|_| auth.write(&keypair.pk.id))
            .and_then(|_| auth.write(&keypair.pk.pk.as_bytes()))
            .and_then(|_| auth.write(&y_pk.as_bytes()))
            .and_then(|_| auth.write(&client_pk.as_bytes()))
            .and_then(|_| auth.write(&msg_mac))
            .and_then(|_| auth.write(&Encap(&encrypted_reply)))
            .and_then(|_| auth.write(PROTOID))
            .and_then(|_| auth.write(&b"Server"[..]))
            .map_err(into_internal!("can't derive obfs4 authentication"))?;
        auth.take().finalize().into()
    };

    let reply = {
        let mut reply = Vec::new();
        reply
            .write(&y_pk.as_bytes())
            .and_then(|_| reply.write(&auth))
            .and_then(|_| reply.write(&encrypted_reply))
            .map_err(into_internal!("can't encode obfs4 reply."))?;
        reply
    };

    if okay.into() {
        Ok((reply, Obfs4NtorXofReader(keystream)))
    } else {
        Err(RelayHandshakeError::BadClientHandshake)
    }
}

/// Finalize the handshake on the client side.
///
/// Called after we've received a message from the relay: try to
/// complete the handshake and verify its correctness.
///
/// On success, return the server's reply to our original encrypted message,
/// and an `XofReader` to use in generating circuit keys.
fn client_handshake_obfs4_part2(
    state: &Obfs4NtorHandshakeState,
    relay_handshake: &[u8],
    verification: &[u8],
) -> Result<(Vec<u8>, Obfs4NtorXofReader)> {
    let mut reader = Reader::from_slice(relay_handshake);
    let pk_buf: [u8;32] = reader
        .extract()
        .map_err(|e| Error::from_bytes_err(e, "v3 ntor handshake"))?;
    let y_pk = curve25519::PublicKey::from(pk_buf);
    let auth: DigestVal = reader
        .extract()
        .map_err(|e| Error::from_bytes_err(e, "v3 ntor handshake"))?;
    let encrypted_msg = reader.into_rest();

    // TODO: Some of this code is duplicated from the server handshake code!  It
    // would be better to factor it out.
    let yx = state.my_sk.diffie_hellman(&y_pk);
    let secret_input = {
        let mut si = SecretBuf::new();
        si.write(&yx.as_bytes())
            .and_then(|_| si.write(&state.shared_secret.as_bytes()))
            .and_then(|_| si.write(&state.relay_public.id))
            .and_then(|_| si.write(&state.relay_public.pk.as_bytes()))
            .and_then(|_| si.write(&state.my_public.as_bytes()))
            .and_then(|_| si.write(&y_pk.as_bytes()))
            .and_then(|_| si.write(PROTOID))
            .and_then(|_| si.write(&Encap(verification)))
            .map_err(into_internal!("error encoding obfs4 secret_input"))?;
        si
    };
    let ntor_key_seed = h_key_seed(&secret_input);
    let verify = h_verify(&secret_input);

    let computed_auth: DigestVal = {
        use digest::Digest;
        let mut auth = DigestWriter(Sha3_256::default());
        auth.write(&T_AUTH)
            .and_then(|_| auth.write(&verify))
            .and_then(|_| auth.write(&state.relay_public.id))
            .and_then(|_| auth.write(&state.relay_public.pk.as_bytes()))
            .and_then(|_| auth.write(&y_pk.as_bytes()))
            .and_then(|_| auth.write(&state.my_public.as_bytes()))
            .and_then(|_| auth.write(&state.msg_mac))
            .and_then(|_| auth.write(&Encap(encrypted_msg)))
            .and_then(|_| auth.write(PROTOID))
            .and_then(|_| auth.write(&b"Server"[..]))
            .map_err(into_internal!("error encoding obfs4 authentication input"))?;
        auth.take().finalize().into()
    };

    let okay = computed_auth.ct_eq(&auth)
        & ct::bool_to_choice(yx.was_contributory())
        & ct::bool_to_choice(state.shared_secret.was_contributory());

    let (enc_key, keystream) = {
        use digest::{ExtendableOutput, XofReader};
        let mut xof = DigestWriter(Shake256::default());
        xof.write(&T_FINAL)
            .and_then(|_| xof.write(&ntor_key_seed))
            .map_err(into_internal!("error encoding obfs4 xof input"))?;
        let mut r = xof.take().finalize_xof();
        let mut enc_key = Zeroizing::new([0_u8; ENC_KEY_LEN]);
        r.read(&mut enc_key[..]);
        (enc_key, r)
    };
    let server_reply = decrypt(&enc_key, encrypted_msg);

    if okay.into() {
        Ok((server_reply, Obfs4NtorXofReader(keystream)))
    } else {
        Err(Error::BadCircHandshakeAuth)
    }
}


#[cfg(test)]
mod integration;
