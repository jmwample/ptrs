#![allow(non_snake_case)] // to enable variable names matching the spec.
#![allow(clippy::many_single_char_names)] // ibid

// @@ begin test lint list maintained by maint/add_warning @@
#![allow(clippy::bool_assert_comparison)]
#![allow(clippy::clone_on_copy)]
#![allow(clippy::dbg_macro)]
#![allow(clippy::print_stderr)]
#![allow(clippy::print_stdout)]
#![allow(clippy::single_char_pattern)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::unchecked_duration_subtraction)]
#![allow(clippy::useless_vec)]
#![allow(clippy::needless_pass_by_value)]
//! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

use super::*;
use crate::common::ntor_arti::{ClientHandshake, ServerHandshake};

use hex_literal::hex;
use tor_basic_utils::test_rng::testing_rng;
use digest::XofReader;



#[test]
fn test_obfs4_roundtrip() {
    let mut rng = rand::thread_rng();
    let relay_private = Obfs4NtorSecretKey::generate_for_test(&mut testing_rng());

    let verification = &b"shared secret"[..];
    let client_message = &b"Hello. I am a client. Let's be friends!"[..];
    let relay_message = &b"Greetings, client. I am a robot. Beep boop."[..];

    let (c_state, c_handshake) =
        client_handshake_obfs4(&mut rng, &relay_private.pk, client_message, verification)
            .unwrap();

    struct Rep(Vec<u8>, Vec<u8>);
    impl MsgReply for Rep {
        fn reply(&mut self, msg: &[u8]) -> Option<Vec<u8>> {
            self.0 = msg.to_vec();
            Some(self.1.clone())
        }
    }
    let mut rep = Rep(Vec::new(), relay_message.to_vec());

    let (s_handshake, mut s_keygen) = server_handshake_obfs4(
        &mut rng,
        &mut rep,
        &c_handshake,
        &[relay_private],
        verification,
    )
    .unwrap();

    let (s_msg, mut c_keygen) =
        client_handshake_obfs4_part2(&c_state, &s_handshake, verification).unwrap();

    assert_eq!(rep.0[..], client_message[..]);
    assert_eq!(s_msg[..], relay_message[..]);
    let mut s_keys = [0_u8; 100];
    let mut c_keys = [0_u8; 1000];
    s_keygen.read(&mut s_keys);
    c_keygen.read(&mut c_keys);
    assert_eq!(s_keys[..], c_keys[..100]);
}

// Same as previous test, but use the higher-level APIs instead.
#[test]
fn test_obfs4_roundtrip_highlevel() {
    let mut rng = rand::thread_rng();
    let relay_private = Obfs4NtorSecretKey::generate_for_test(&mut testing_rng());

    let (c_state, c_handshake) =
        Obfs4NtorClient::client1(&mut rng, &relay_private.pk, &[]).unwrap();

    let mut rep = |_: &[NtorV3Extension]| Some(vec![]);

    let (s_keygen, s_handshake) =
        Obfs4NtorServer::server(&mut rng, &mut rep, &[relay_private], &c_handshake).unwrap();

    let (extensions, keygen) = Obfs4NtorClient::client2(c_state, s_handshake).unwrap();

    assert!(extensions.is_empty());
    let c_keys = keygen.expand(1000).unwrap();
    let s_keys = s_keygen.expand(100).unwrap();
    assert_eq!(s_keys[..], c_keys[..100]);
}

// Same as previous test, but encode some congestion control extensions.
#[test]
fn test_obfs4_roundtrip_highlevel_cc() {
    let mut rng = rand::thread_rng();
    let relay_private = Obfs4NtorSecretKey::generate_for_test(&mut testing_rng());

    let client_exts = vec![NtorV3Extension::RequestCongestionControl];
    let reply_exts = vec![NtorV3Extension::AckCongestionControl { sendme_inc: 42 }];

    let (c_state, c_handshake) = Obfs4NtorClient::client1(
        &mut rng,
        &relay_private.pk,
        &[NtorV3Extension::RequestCongestionControl],
    )
    .unwrap();

    let mut rep = |msg: &[NtorV3Extension]| -> Option<Vec<NtorV3Extension>> {
        assert_eq!(msg, client_exts);
        Some(reply_exts.clone())
    };

    let (s_keygen, s_handshake) =
        Obfs4NtorServer::server(&mut rng, &mut rep, &[relay_private], &c_handshake).unwrap();

    let (extensions, keygen) = Obfs4NtorClient::client2(c_state, s_handshake).unwrap();

    assert_eq!(extensions, reply_exts);
    let c_keys = keygen.expand(1000).unwrap();
    let s_keys = s_keygen.expand(100).unwrap();
    assert_eq!(s_keys[..], c_keys[..100]);
}

#[test]
fn test_obfs4_testvec() {
    let id = hex!("9fad2af287ef942632833d21f946c6260c33fae6172b60006e86e4a6911753a2");
    let b = hex!("a8649010896d3c05ab0e2ab75e3e9368695c8f72652e8aa73016756007054e59"); // identity key
    let x = hex!("f886d140047a115b228a8f7f63cbc5a3ad74e9c970ad3cb4a7f7fd8067f0dd68"); // client session key
    let y = hex!("403ec0927a8852bdff12129244fdb03cb3c94b8b8d15c863462fcda52b510d73"); // server session key
    let b: curve25519::StaticSecret = b.into();
    let B: curve25519::PublicKey = (&b).into();
    let id: Ed25519Identity = id.into();
    let x: curve25519::StaticSecret = x.into();
    let y: curve25519::StaticSecret = y.into();

    let client_message = hex!("68656c6c6f20776f726c64");
    let verification = hex!("78797a7a79");
    let server_message = hex!("486f6c61204d756e646f");

    let identity_public = Obfs4NtorPublicKey { pk: B, id, rp: None };
    let identity_private = Obfs4NtorSecretKey {
        sk: b,
        pk: identity_public.clone(),
    };

    let (state, client_handshake) =
        client_handshake_obfs4_no_keygen(&identity_public, &client_message, &verification, x)
            .unwrap();

    // assert_eq!(client_handshake[..], hex!("9fad2af287ef942632833d21f946c6260c33fae6172b60006e86e4a6911753a2f8307a2bc1870b00b828bb74dbb8fd88e632a6375ab3bcd1ae706aaa8b6cdd1d252fe9ae91264c91d4ecb8501f79d0387e34ad8ca0f7c995184f7d11d5da4f463bebd9151fd3b47c180abc9e044d53565f04d82bbb3bebed3d06cea65db8be9c72b68cd461942088502f67")[..]);

    struct Replier(Vec<u8>, Vec<u8>, bool);
    impl MsgReply for Replier {
        fn reply(&mut self, msg: &[u8]) -> Option<Vec<u8>> {
            assert_eq!(msg, &self.0);
            self.2 = true;
            Some(self.1.clone())
        }
    }
    let mut rep = Replier(client_message.to_vec(), server_message.to_vec(), false);

    let (server_handshake, mut server_keygen) = server_handshake_obfs4_no_keygen(
        &mut rep,
        &y,
        &client_handshake,
        &[identity_private],
        &verification,
    )
    .unwrap();
    assert!(rep.2);

    // assert_eq!(server_handshake[..], hex!("4bf4814326fdab45ad5184f5518bd7fae25dc59374062698201a50a22954246d2fc5f8773ca824542bc6cf6f57c7c29bbf4e5476461ab130c5b18ab0a91276651202c3e1e87c0d32054c")[..]);

    let (server_msg_received, mut client_keygen) =
        client_handshake_obfs4_part2(&state, &server_handshake, &verification).unwrap();
    assert_eq!(&server_msg_received, &server_message);

    let (c_keys, s_keys) = {
        let mut c = [0_u8; 256];
        let mut s = [0_u8; 256];
        client_keygen.read(&mut c);
        server_keygen.read(&mut s);
        (c, s)
    };
    assert_eq!(c_keys, s_keys);
    assert_eq!(c_keys[..], hex!("05b858d18df21a01566c74d39a5b091b4415f103c05851e77e79b274132dc5b5")[..]);
    // assert_eq!(c_keys[..], hex!("9c19b631fd94ed86a817e01f6c80b0743a43f5faebd39cfaa8b00fa8bcc65c3bfeaa403d91acbd68a821bf6ee8504602b094a254392a07737d5662768c7a9fb1b2814bb34780eaee6e867c773e28c212ead563e98a1cd5d5b4576f5ee61c59bde025ff2851bb19b721421694f263818e3531e43a9e4e3e2c661e2ad547d8984caa28ebecd3e4525452299be26b9185a20a90ce1eac20a91f2832d731b54502b09749b5a2a2949292f8cfcbeffb790c7790ed935a9d251e7e336148ea83b063a5618fcff674a44581585fd22077ca0e52c59a24347a38d1a1ceebddbf238541f226b8f88d0fb9c07a1bcd2ea764bbbb5dacdaf5312a14c0b9e4f06309b0333b4a")[..]);
}

#[test]
fn about_half() -> Result<()> {
    let mut rng = rand::thread_rng();

    let mut success = 0;
    let mut not_found = 0;
    let mut not_match = 0;
    for _ in 0..1_000 {

        let sk = curve25519::StaticSecret::random_from_rng(&mut rng);
        let rp: Option<curve25519::PublicRepresentative>= (&sk).into();
        let repres = match rp {
            Some(r) => r,
            None => {
                not_found += 1;
                continue;
            }
        };

        let pk = curve25519::PublicKey::from(&sk);


        let decoded_pk = curve25519::PublicKey::from(&repres);
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
fn keypair() -> Result<()> {
    let mut rng = rand::thread_rng();
    for _ in 0..1_000 {
        let kp = Obfs4NtorSecretKey::generate_for_test(&mut rng);

        let pk = kp.pk.pk.to_bytes();
        let repres = kp.pk.rp;

        let pubkey = curve25519::PublicKey::from(&repres.unwrap());
        assert_eq!(hex::encode(pk), hex::encode(pubkey.to_bytes()));
    }
    Ok(())
}


/*
// Benchmark Client/Server handshake.  The actual time taken that will be
// observed on either the Client or Server is half the reported time per
// operation since the benchmark does both sides.
func BenchmarkHandshake(b *testing.B) {
    // Generate the "long lasting" identity key and NodeId.
    idKeypair, err := NewKeypair(false)
    if err != nil || idKeypair == nil {
        b.Fatal("Failed to generate identity keypair")
    }
    nodeID, err := NewNodeID([]byte("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13"))
    if err != nil {
        b.Fatal("Failed to load NodeId:", err)
    }
    b.ResetTimer()

    // Start the actual benchmark.
    for i := 0; i < b.N; i++ {
        // Generate the keypairs.
        serverKeypair, err := NewKeypair(true)
        if err != nil || serverKeypair == nil {
            b.Fatal("Failed to generate server keypair")
        }

        clientKeypair, err := NewKeypair(true)
        if err != nil || clientKeypair == nil {
            b.Fatal("Failed to generate client keypair")
        }

        // Server handshake.
        clientPublic := clientKeypair.Representative().ToPublic()
        ok, serverSeed, serverAuth := ServerHandshake(clientPublic,
            serverKeypair, idKeypair, nodeID)
        if !ok || serverSeed == nil || serverAuth == nil {
            b.Fatal("ServerHandshake failed")
        }

        // Client handshake.
        serverPublic := serverKeypair.Representative().ToPublic()
        ok, clientSeed, clientAuth := ClientHandshake(clientKeypair,
            serverPublic, idKeypair.Public(), nodeID)
        if !ok || clientSeed == nil || clientAuth == nil {
            b.Fatal("ClientHandshake failed")
        }

        // Validate the authenticator.  Real code would pass the AUTH read off
        // the network as a slice to CompareAuth here.
        if !CompareAuth(clientAuth, serverAuth.Bytes()[:]) ||
            !CompareAuth(serverAuth, clientAuth.Bytes()[:]) {
            b.Fatal("AUTH mismatched between client/server")
        }
    }
}
*/
