//! Implements the ntor v3 key exchange, as described in proposal 332.
//!
//! The main difference between the ntor v3r handshake and the
//! original ntor handshake is that this this one allows each party to
//! encrypt data (without forward secrecy) after it sends the first
//! message.

// TODO:  Make ntorv3 terminology and variable names consistent with spec.

use crate::common::mlkem1024_x25519::{PublicKey, SharedSecret};

use tor_bytes::{EncodeResult, Writeable, Writer};
use tor_llcrypto::cipher::aes::Aes256Ctr;
use tor_llcrypto::d::{Sha3_256, Shake256};
use zeroize::Zeroizing;

mod keys;
use keys::*;
pub use keys::{NtorV3KeyGen, NtorV3PublicKey, NtorV3SecretKey};

mod client;
pub(crate) use client::{HandshakeMaterials as CHSMaterials, NtorV3Client};

mod server;
pub(crate) use server::HandshakeMaterials as SHSMaterials;

pub(crate) mod constants {
    /// The verification string to be used for circuit extension.
    pub const NTOR3_CIRC_VERIFICATION: &[u8] = b"circuit extend";

    /// The size of an encryption key in bytes.
    pub const ENC_KEY_LEN: usize = 32;
    /// The size of a MAC key in bytes.
    pub const MAC_KEY_LEN: usize = 32;
    /// The size of a curve25519 public key in bytes.
    pub const PUB_KEY_LEN: usize = 32;
    /// The size of a digest output in bytes.
    pub const DIGEST_LEN: usize = 32;
    /// The length of a MAC output in bytes.
    pub const MAC_LEN: usize = 32;
    /// The length of a node identity in bytes.
    pub const ID_LEN: usize = 32;
}
use constants::*;

/// The output of the digest, as an array.
type DigestVal = [u8; DIGEST_LEN];
/// The output of the MAC.
type MessageMac = [u8; MAC_LEN];
/// A key for symmetric encryption or decryption.
type EncKey = Zeroizing<[u8; ENC_KEY_LEN]>;
/// A key for message authentication codes.
type MacKey = [u8; MAC_KEY_LEN];

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
    let k: &[u8; 32] = key;
    let mut cipher = Aes256Ctr::new(k.into(), &zero_iv);
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
    xb: &SharedSecret,
    relay_public: &NtorV3PublicKey,
    client_public: &PublicKey,
    verification: &[u8],
) -> EncodeResult<(EncKey, DigestWriter<Sha3_256>)> {
    // secret_input_phase1 = Bx | ID | X | B | PROTOID | ENCAP(VER)
    // phase1_keys = KDF_msgkdf(secret_input_phase1)
    // (ENC_K1, MAC_K1) = PARTITION(phase1_keys, ENC_KEY_LEN, MAC_KEY_LEN
    use digest::{ExtendableOutput, XofReader};
    let mut msg_kdf = DigestWriter(Shake256::default());
    msg_kdf.write(&T_MSGKDF)?;
    msg_kdf.write(xb)?;
    msg_kdf.write(&relay_public.id)?;
    msg_kdf.write(client_public)?;
    msg_kdf.write(&relay_public.pk)?;
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
        mac.write(&relay_public.pk)?;
        mac.write(client_public)?;
    }

    Ok((enc_key, mac))
}

/// Struct containing associated function for the PQ Obfs handshake.
///
/// In the obfs4 implementationI used the equivalent object (Obfs4NtorHandshake) because I needed
/// to implement the `ntor_arti::ClientHandshake` interface on. It is only used for client though
/// as the `ntor_arti::ServerHandshake` gets implemented on the `Server` type.
pub(crate) struct PqObfsHandshake;

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

#[cfg(test)]
#[allow(non_snake_case)] // to enable variable names matching the spec.
#[allow(clippy::many_single_char_names)] // ibid
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use crate::common::mlkem1024_x25519::{PublicKey, StaticSecret};
    use crate::common::ntor_arti::{ClientHandshake, ServerHandshake};
    use crate::Server;

    use super::*;
    use hex_literal::hex;
    use tor_basic_utils::test_rng::testing_rng;
    use tor_cell::relaycell::extend::NtorV3Extension;
    use tor_llcrypto::pk::ed25519::Ed25519Identity;

    #[test]
    fn test_ntor3_roundtrip() {
        let mut rng = rand::thread_rng();
        let relay_private = NtorV3SecretKey::generate_for_test(&mut testing_rng());

        let verification = &b"shared secret"[..];
        let client_message = &b"Hello. I am a client. Let's be friends!"[..];
        let relay_message = &b"Greetings, client. I am a robot. Beep boop."[..];

        let (c_state, c_handshake) = client::client_handshake_ntor_v3(
            &mut rng,
            &relay_private.pk,
            client_message,
            verification,
        )
        .unwrap();

        struct Rep(Vec<u8>, Vec<u8>);
        impl MsgReply for Rep {
            fn reply(&mut self, msg: &[u8]) -> Option<Vec<u8>> {
                self.0 = msg.to_vec();
                Some(self.1.clone())
            }
        }
        let mut rep = Rep(Vec::new(), relay_message.to_vec());

        let (s_handshake, mut s_keygen) = server::server_handshake_ntor_v3(
            &mut rng,
            &mut rep,
            &c_handshake,
            &[relay_private],
            verification,
        )
        .unwrap();

        let (s_msg, mut c_keygen) =
            client::client_handshake_ntor_v3_part2(&c_state, &s_handshake, verification).unwrap();

        assert_eq!(rep.0[..], client_message[..]);
        assert_eq!(s_msg[..], relay_message[..]);
        use digest::XofReader;
        let mut s_keys = [0_u8; 100];
        let mut c_keys = [0_u8; 1000];
        s_keygen.read(&mut s_keys);
        c_keygen.read(&mut c_keys);
        assert_eq!(s_keys[..], c_keys[..100]);
    }

    // Same as previous test, but use the higher-level APIs instead.
    #[test]
    fn test_ntor3_roundtrip_highlevel() {
        let relay_private = NtorV3SecretKey::generate_for_test(&mut testing_rng());

        let (c_state, c_handshake) = NtorV3Client::client1(&relay_private.pk, &[]).unwrap();

        let mut rep = |_: &[NtorV3Extension]| Some(vec![]);

        let server = Server {};
        let (s_keygen, s_handshake) = server
            .server(&mut rep, &[relay_private], &c_handshake)
            .unwrap();

        let (extensions, keygen) = NtorV3Client::client2(c_state, s_handshake).unwrap();

        assert!(extensions.is_empty());
        let c_keys = keygen.expand(1000).unwrap();
        let s_keys = s_keygen.expand(100).unwrap();
        assert_eq!(s_keys[..], c_keys[..100]);
    }

    // Same as previous test, but encode some congestion control extensions.
    #[test]
    fn test_ntor3_roundtrip_highlevel_cc() {
        let relay_private = NtorV3SecretKey::generate_for_test(&mut testing_rng());

        let client_exts = vec![NtorV3Extension::RequestCongestionControl];
        let reply_exts = vec![NtorV3Extension::AckCongestionControl { sendme_inc: 42 }];

        let (c_state, c_handshake) = NtorV3Client::client1(
            &relay_private.pk,
            &[NtorV3Extension::RequestCongestionControl],
        )
        .unwrap();

        let mut rep = |msg: &[NtorV3Extension]| -> Option<Vec<NtorV3Extension>> {
            assert_eq!(msg, client_exts);
            Some(reply_exts.clone())
        };

        let server = Server {};
        let (s_keygen, s_handshake) = server
            .server(&mut rep, &[relay_private], &c_handshake)
            .unwrap();

        let (extensions, keygen) = NtorV3Client::client2(c_state, s_handshake).unwrap();

        assert_eq!(extensions, reply_exts);
        let c_keys = keygen.expand(1000).unwrap();
        let s_keys = s_keygen.expand(100).unwrap();
        assert_eq!(s_keys[..], c_keys[..100]);
    }

    #[test]
    fn test_ntor3_testvec() {
        let b = hex!("4051daa5921cfa2a1c27b08451324919538e79e788a81b38cbed097a5dff454a");
        let id = hex!("9fad2af287ef942632833d21f946c6260c33fae6172b60006e86e4a6911753a2");
        let x = hex!("b825a3719147bcbe5fb1d0b0fcb9c09e51948048e2e3283d2ab7b45b5ef38b49");
        let y = hex!("4865a5b7689dafd978f529291c7171bc159be076b92186405d13220b80e2a053");
        let b: StaticSecret = b.into();
        let B: PublicKey = (&b).into();
        let id: Ed25519Identity = id.into();
        let x: StaticSecret = x.into();
        //let X = (&x).into();
        let y: StaticSecret = y.into();

        let client_message = hex!("68656c6c6f20776f726c64");
        let verification = hex!("78797a7a79");
        let server_message = hex!("486f6c61204d756e646f");

        let relay_public = NtorV3PublicKey { pk: B, id };
        let relay_private = NtorV3SecretKey {
            sk: b,
            pk: relay_public.clone(),
        };

        let (state, client_handshake) = client::client_handshake_ntor_v3_no_keygen(
            &relay_public,
            &client_message,
            &verification,
            x,
        )
        .unwrap();

        assert_eq!(client_handshake[..], hex!("9fad2af287ef942632833d21f946c6260c33fae6172b60006e86e4a6911753a2f8307a2bc1870b00b828bb74dbb8fd88e632a6375ab3bcd1ae706aaa8b6cdd1d252fe9ae91264c91d4ecb8501f79d0387e34ad8ca0f7c995184f7d11d5da4f463bebd9151fd3b47c180abc9e044d53565f04d82bbb3bebed3d06cea65db8be9c72b68cd461942088502f67")[..]);

        struct Replier(Vec<u8>, Vec<u8>, bool);
        impl MsgReply for Replier {
            fn reply(&mut self, msg: &[u8]) -> Option<Vec<u8>> {
                assert_eq!(msg, &self.0);
                self.2 = true;
                Some(self.1.clone())
            }
        }
        let mut rep = Replier(client_message.to_vec(), server_message.to_vec(), false);

        let (server_handshake, mut server_keygen) = server::server_handshake_ntor_v3_no_keygen(
            &mut rep,
            &y,
            &client_handshake,
            &[relay_private],
            &verification,
        )
        .unwrap();
        assert!(rep.2);

        assert_eq!(server_handshake[..], hex!("4bf4814326fdab45ad5184f5518bd7fae25dc59374062698201a50a22954246d2fc5f8773ca824542bc6cf6f57c7c29bbf4e5476461ab130c5b18ab0a91276651202c3e1e87c0d32054c")[..]);

        let (server_msg_received, mut client_keygen) =
            client::client_handshake_ntor_v3_part2(&state, &server_handshake, &verification)
                .unwrap();
        assert_eq!(&server_msg_received, &server_message);

        let (c_keys, s_keys) = {
            use digest::XofReader;
            let mut c = [0_u8; 256];
            let mut s = [0_u8; 256];
            client_keygen.read(&mut c);
            server_keygen.read(&mut s);
            (c, s)
        };
        assert_eq!(c_keys, s_keys);
        assert_eq!(c_keys[..], hex!("9c19b631fd94ed86a817e01f6c80b0743a43f5faebd39cfaa8b00fa8bcc65c3bfeaa403d91acbd68a821bf6ee8504602b094a254392a07737d5662768c7a9fb1b2814bb34780eaee6e867c773e28c212ead563e98a1cd5d5b4576f5ee61c59bde025ff2851bb19b721421694f263818e3531e43a9e4e3e2c661e2ad547d8984caa28ebecd3e4525452299be26b9185a20a90ce1eac20a91f2832d731b54502b09749b5a2a2949292f8cfcbeffb790c7790ed935a9d251e7e336148ea83b063a5618fcff674a44581585fd22077ca0e52c59a24347a38d1a1ceebddbf238541f226b8f88d0fb9c07a1bcd2ea764bbbb5dacdaf5312a14c0b9e4f06309b0333b4a")[..]);
    }

    #[test]
    fn mlkem1024_x25519_3way_handshake_flow() {
        let mut rng = rand::thread_rng();
        // long-term server id and keys
        let server_id_keys = StaticSecret::new(&mut rng);
        let _server_id_pub = server_id_keys.public_key();
        // let server_id = ID::new();

        // client open session, generating the associated ephemeral keys
        let client_session = StaticSecret::new(&mut rng);

        // client sends mlkem1024_x25519 session pubkey(s)
        let _cpk = client_session.public_key();

        // server computes mlkem1024_x25519 combined shared secret
        let _server_session = StaticSecret::new(&mut rng);
        // let server_hs_res = server_handshake(&server_session, &cpk, &server_id_keys, &server_id);

        // server sends mlkemx25519 session pubkey(s)
        let _spk = client_session.public_key();

        // // client computes mlkem1024_x25519 combined shared secret
        // let client_hs_res = client_handshake(&client_session, &spk, &server_id_pub, &server_id);

        // assert_ne!(client_hs_res.is_some().unwrap_u8(), 0);
        // assert_ne!(server_hs_res.is_some().unwrap_u8(), 0);

        // let chsres = client_hs_res.unwrap();
        // let shsres = server_hs_res.unwrap();
        // assert_eq!(chsres.key_seed, shsres.key_seed);
        // assert_eq!(&chsres.auth, &shsres.auth);
    }
}