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
use crate::{
    common::colorize,
    common::x25519_elligator2::*,
    test_utils::{init_subscriber, FakePRNG},
};

use hex_literal::hex;
use tor_basic_utils::test_rng::testing_rng;

fn make_fake_ephem_key(bytes: &[u8]) -> EphemeralSecret {
    assert_eq!(bytes.len(), 32);
    let rng = FakePRNG::new(bytes);
    EphemeralSecret::random_from_rng(rng)
}

#[test]
fn test_obfs4_roundtrip() -> Result<()> {
    let mut rng = rand::thread_rng();

    let relay_private = Obfs4NtorSecretKey::generate_for_test(&mut rng);
    let x_sk = EphemeralSecret::random_from_rng(&mut rng);
    let y = Obfs4NtorSecretKey::generate_for_test(&mut rng);

    let mut sid = [0u8; SESSION_ID_LEN];
    rand::thread_rng().fill_bytes(&mut sid);

    let chs_materials = CHSMaterials::new(relay_private.pk, colorize(sid));

    let server = Server::new_from_key(relay_private);

    let shs_materials = SHSMaterials {
        identity_keys: server.identity_keys.clone(),
        len_seed: [0u8; SEED_LENGTH],
        session_id: "s-yyy".into(),
    };

    let (state, create_msg) = client_handshake_obfs4_no_keygen(x_sk, chs_materials).unwrap();

    let ephem = make_fake_ephem_key(&y.sk.as_bytes()[..]);
    let (s_keygen, created_msg) = server
        .server_handshake_obfs4_no_keygen(ephem, &create_msg[..], shs_materials)
        .unwrap();

    let (c_keygen, _) = client_handshake2_obfs4(created_msg, &state)?;

    let c_keys = c_keygen.expand(72)?;
    let s_keys = s_keygen.expand(72)?;
    assert_eq!(c_keys, s_keys);

    Ok(())
}

// Same as previous test, but use the higher-level APIs instead.
#[test]
fn test_obfs4_roundtrip_highlevel() -> Result<()> {
    let rng = testing_rng();
    let relay_secret = StaticSecret::random_from_rng(rng);
    let relay_public = PublicKey::from(&relay_secret);
    let relay_identity = RsaIdentity::from_bytes(&[12; 20]).unwrap();
    let relay_ntpk = Obfs4NtorPublicKey {
        id: relay_identity,
        pk: relay_public,
    };
    let hs_materials = CHSMaterials::new(relay_ntpk, "c-xxx".into());
    let (state, cmsg) = Obfs4NtorHandshake::client1(&hs_materials, &())?;

    let relay_ntsk = Obfs4NtorSecretKey {
        pk: relay_ntpk,
        sk: relay_secret,
    };
    let server = Server::new_from_key(relay_ntsk.clone());
    let shs_materials = [SHSMaterials::new(
        &relay_ntsk,
        "s-yyy".into(),
        [0u8; SEED_LENGTH],
    )];

    let (skeygen, smsg) = server
        .server(&mut |_: &()| Some(()), &shs_materials, &cmsg)
        .unwrap();

    let (_extensions, ckeygen) = Obfs4NtorHandshake::client2(state, smsg)?;

    let skeys = skeygen.expand(55)?;
    let ckeys = ckeygen.expand(55)?;

    assert_eq!(skeys, ckeys);

    Ok(())
}

#[test]
fn test_obfs4_testvec_compat() -> Result<()> {
    init_subscriber();
    let b_sk = hex!("a83fdd04eb9ed77a2b38d86092a09a1cecfb93a7bdec0da35e542775b2e7af6e");
    let x_sk = hex!("308ff4f3a0ebe8c1a93bcd40d67e3eec6b856aa5c07ef6d5a3d3cedf13dcf150");
    let y_sk = hex!("881f9ad60e0833a627f0c47f5aafbdcb0b5471800eaeaa1e678291b947e4295c");
    let id = hex!("000102030405060708090a0b0c0d0e0f10111213");
    let expected_seed = "05b858d18df21a01566c74d39a5b091b4415f103c05851e77e79b274132dc5b5";
    let expected_auth = "dc71f8ded2e56f829f1b944c1e94357fa8b7987f10211a017e2d1f2455092917";

    let sk: StaticSecret = b_sk.into();
    let pk = Obfs4NtorPublicKey {
        id: RsaIdentity::from_bytes(&id).unwrap(),
        pk: (&sk).into(),
    };
    let relay_sk = Obfs4NtorSecretKey { pk, sk };
    let server = Server::new_from_key(relay_sk.clone());

    let x = EphemeralSecret::from_parts(x_sk.into(), 0u8);

    let chs_materials = CHSMaterials::new(pk, "c-xxx".into());

    let shs_materials =
        SHSMaterials::new(&server.identity_keys, "s-yyy".into(), [0u8; SEED_LENGTH]);

    let (state, create_msg) = client_handshake_obfs4_no_keygen(x, chs_materials).unwrap();

    let (s_keygen, created_msg) = server
        .server_handshake_obfs4_no_keygen(
            make_fake_ephem_key(&y_sk[..]), // convert the StaticSecret to an EphemeralSecret for api to allow from hex
            &create_msg[..],
            shs_materials,
        )
        .unwrap();

    let (c_keygen, auth) = client_handshake2_no_auth_check_obfs4(created_msg, &state)?;
    let seed = c_keygen.seed.clone();

    let c_keys = c_keygen.expand(72)?;
    let s_keys = s_keygen.expand(72)?;

    assert_eq!(&s_keys[..], &c_keys[..]);
    assert_eq!(hex::encode(auth), expected_auth);
    assert_eq!(hex::encode(&seed[..]), expected_seed);

    Ok(())
}

#[cfg(target_feature = "disabled")]
#[test]
fn test_ntor_v1_testvec() -> Result<()> {
    let b_sk = hex!("4820544f4c4420594f5520444f474954204b454550532048415050454e494e47");
    let x_sk = hex!("706f6461792069207075742e2e2e2e2e2e2e2e4a454c4c59206f6e2074686973");
    let y_sk = hex!("70686520737175697272656c2e2e2e2e2e2e2e2e686173206869732067616d65");
    let id = hex!("69546f6c64596f7541626f75745374616972732e");
    let client_handshake = hex!("69546f6c64596f7541626f75745374616972732eccbc8541904d18af08753eae967874749e6149f873de937f57f8fd903a21c471e65dfdbef8b2635837fe2cebc086a8096eae3213e6830dc407516083d412b078");
    let server_handshake = hex!("390480a14362761d6aec1fea840f6e9e928fb2adb7b25c670be1045e35133a371cbdf68b89923e1f85e8e18ee6e805ea333fe4849c790ffd2670bd80fec95cc8");
    let keys = hex!("0c62dee7f48893370d0ef896758d35729867beef1a5121df80e00f79ed349af39b51cae125719182f19d932a667dae1afbf2e336e6910e7822223e763afad0a13342157969dc6b79");

    let sk: StaticSecret = b_sk.into();
    let pk = Obfs4NtorPublicKey {
        id: RsaIdentity::from_bytes(&id).unwrap(),
        pk: (&sk).into(),
        rp: (&sk).into(),
    };
    let relay_sk = Obfs4NtorSecretKey { pk, sk };

    let x: StaticSecret = x_sk.into();
    let y: StaticSecret = y_sk.into();

    let (state, create_msg) =
        client_handshake_obfs4_no_keygen((&x).into(), x, &relay_sk.pk).unwrap();
    assert_eq!(&create_msg[..], &client_handshake[..]);

    let (s_keygen, created_msg) = server_handshake_obfs4_no_keygen(
        (&y).into(),
        make_fake_ephem_key(&y_sk[..]), // convert the StaticSecret to an EphemeralSecret for api to allow from hex
        &create_msg[..],
        &[relay_sk],
    )
    .unwrap();

    assert_eq!(&created_msg[..], &server_handshake[..]);

    let c_keygen = client_handshake2_obfs4(created_msg, &state)?;

    let c_keys = c_keygen.expand(keys.len())?;
    let s_keys = s_keygen.expand(keys.len())?;
    assert_eq!(&c_keys[..], &keys[..]);
    assert_eq!(&s_keys[..], &keys[..]);

    Ok(())
}

#[test]
fn failing_handshakes() {
    let mut rng = testing_rng();

    // Set up keys.
    let relay_secret = StaticSecret::random_from_rng(&mut rng);
    let relay_public = PublicKey::from(&relay_secret);
    let wrong_public = PublicKey::from([16_u8; 32]);
    let relay_identity = RsaIdentity::from_bytes(&[12; 20]).unwrap();
    let wrong_identity = RsaIdentity::from_bytes(&[13; 20]).unwrap();
    let relay_ntpk = Obfs4NtorPublicKey {
        id: relay_identity,
        pk: relay_public,
    };
    let relay_ntsk = Obfs4NtorSecretKey {
        pk: relay_ntpk.clone(),
        sk: relay_secret,
    };

    let wrong_ntpk1 = Obfs4NtorPublicKey {
        id: wrong_identity,
        pk: relay_public,
    };
    let wrong_ntpk2 = Obfs4NtorPublicKey {
        id: relay_identity,
        pk: wrong_public,
    };

    let resources = &Server::new_from_random(&mut rng);

    // If the client uses the wrong keys, the relay should reject the
    // handshake.
    let mut hs_materials = CHSMaterials::new(wrong_ntpk1.clone(), "c-xxx".into());
    let (_, handshake1) = Obfs4NtorHandshake::client1(&hs_materials, &()).unwrap();
    hs_materials.node_pubkey = wrong_ntpk2;
    let (_, handshake2) = Obfs4NtorHandshake::client1(&hs_materials, &()).unwrap();
    hs_materials.node_pubkey = relay_ntpk;
    let (st3, handshake3) = Obfs4NtorHandshake::client1(&hs_materials, &()).unwrap();

    let shs_materials = [SHSMaterials::new(
        &relay_ntsk,
        "s-yyy".into(),
        [0u8; SEED_LENGTH],
    )];
    let ans1 = resources.server(&mut |_: &()| Some(()), &shs_materials, &handshake1);
    let ans2 = resources.server(&mut |_: &()| Some(()), &shs_materials, &handshake2);

    assert!(ans1.is_err());
    assert!(ans2.is_err());

    // If the relay's message is tampered with, the client will
    // reject the handshake.
    let (_, mut smsg) = resources
        .server(&mut |_: &()| Some(()), &shs_materials, &handshake3)
        .unwrap();
    smsg[60] ^= 7;
    let ans3 = Obfs4NtorHandshake::client2(st3, smsg);
    assert!(ans3.is_err());
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
