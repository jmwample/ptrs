use super::*;
use crate::{Error, Result};

use hex::FromHex;
use x25519_dalek::PublicKey;

#[test]
fn demo_handshake() -> Result<()> {
    let a_keys = SessionKeyPair::new(true);
    let b_keys = SessionKeyPair::new(false);

    let a_secret = a_keys.private.diffie_hellman(&b_keys.public);
    let b_secret = b_keys.private.diffie_hellman(&a_keys.public);
    assert_eq!(a_secret.as_bytes(), b_secret.as_bytes());

    let a_keys = SessionKeyPair::new(true);
    let b_keys = SessionKeyPair::new(false);
    let s_keys = IdentityKeyPair::new();

    let as_secret = a_keys.private.diffie_hellman(&s_keys.public);
    let sa_secret = s_keys.private.diffie_hellman(&a_keys.public);
    assert_eq!(as_secret.as_bytes(), sa_secret.as_bytes());

    let bs_secret = b_keys.private.diffie_hellman(&s_keys.public);
    let sb_secret = s_keys.private.diffie_hellman(&b_keys.public);
    assert_eq!(bs_secret.as_bytes(), sb_secret.as_bytes());
    assert_ne!(as_secret.as_bytes(), bs_secret.as_bytes());
    assert_ne!(sa_secret.as_bytes(), sb_secret.as_bytes());

    Ok(())
}

#[test]
fn handshake() -> Result<()> {
    let client_kp = SessionKeyPair::new(true);

    let server_kp = SessionKeyPair::new(false);
    let server_id_kp = IdentityKeyPair::new();

    let node_id = ID::from_hex("0000000000000000000000000000000000000000")?;

    // Server Handshake
    let server_result = process_client_handshake(
        &client_kp.public,
        &server_kp,
        &server_id_kp,
        &node_id.clone(),
    )
    .unwrap();

    // Client Handshake
    let client_result = process_server_handshake(
        &client_kp,
        &server_kp.public,
        &server_id_kp.public,
        &node_id,
    )
    .unwrap();

    println!("\n{}\n{}", client_result, server_result);

    // WARNING: Use a constant time comparison in actual code.
    assert_eq!(client_result.auth.0, server_result.auth.0);
    assert_eq!(client_result.key_seed.0, server_result.key_seed.0);
    Ok(())
}

#[test]
fn about_half() -> Result<()> {
    let mut success = 0;
    let mut not_found = 0;
    let mut not_match = 0;
    for _ in 0..10_000 {
        let kp = SessionKeyPair::new(false);
        let pk = kp.get_public().to_bytes();

        let repres = match kp.get_representative() {
            Some(r) => r,
            None => {
                not_found += 1;
                continue;
            }
        };

        let decoded_pk = PublicKey::from(&repres);
        if hex::encode(pk) != hex::encode(decoded_pk) {
            not_match += 1;
            continue;
        }
        success += 1;
    }

    // println!("{not_found}/{not_match}/{success}/10_000");
    assert_eq!(not_match, 0);
    Ok(())
}

#[test]
fn keypair() -> Result<()> {
    for _ in 0..10_000 {
        let kp = SessionKeyPair::new(true);
        let pk = kp.get_public().to_bytes();
        let repres = kp.get_representative().ok_or(Error::Cancelled)?;

        let pubkey = PublicKey::from(&repres);
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
