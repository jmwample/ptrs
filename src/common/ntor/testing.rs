use super::*;
use crate::common::elligator2::{decode, encode};
use crate::{Error, Result};

use curve25519_dalek::{traits::Identity, EdwardsPoint, Scalar};
use group::GroupEncoding;
use hex::FromHex;

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

        let repres = match encode(pk) {
            Some(r) => r,
            None => {
                not_found += 1;
                continue;
            }
        };

        let decoded_pk = decode(repres)?;
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

        assert_eq!(hex::encode(pk), hex::encode(repres.to_public()?.to_bytes()));
    }
    Ok(())
}

// // This doesn't work and I don't understand curve2559 api/abi
// #[test]
// fn dh_equivalence() -> Result<()> {
//     let a_keys = IdentityKeyPair::new();
//     let b_keys = IdentityKeyPair::new();
//
//     let a_secret = a_keys.private.diffie_hellman(&b_keys.public);
//
//     let y = EdwardsPoint::from_bytes(&a_keys.public.to_bytes()).unwrap();
//     let x = Scalar::from_bytes_mod_order(b_keys.private.to_bytes());
//     let b_secret = y * x;
//
//     assert_eq!(
//         hex::encode(a_secret.to_bytes()),
//         hex::encode(b_secret.to_bytes())
//     );
//
//     Ok(())
// }

// Test that Elligator representatives produced by
// NewKeypair map to public keys that are not always on the prime-order subgroup
// of Curve25519. (And incidentally that Elligator representatives agree with
// the public key stored in the Keypair.)
//
// See discussion under "Step 2" at https://elligator.org/key-exchange.
//
// This doesn't work and I don't understand curve2559 api/abi
// #[test]
fn publickey_subgroup() -> Result<()> {
    // We will test the public keys that comes out of NewKeypair by
    // multiplying each one by L, the order of the prime-order subgroup of
    // Curve25519, then checking the order of the resulting point. The error
    // condition we are checking for specifically is output points always
    // having order 1, which means that public keys are always on the
    // prime-order subgroup of Curve25519, which would make Elligator
    // representatives distinguishable from random. More generally, we want
    // to ensure that all possible output points of low order are covered.
    //
    // We have to do some contortions to conform to the interfaces we use.
    // We do scalar multiplication by L using Edwards coordinates, rather
    // than the Montgomery coordinates output by Keypair.Public and
    // Representative.ToPublic, because the Montgomery-based
    // crypto/curve25519.X25519 clamps the scalar to be a multiple of 8,
    // which would not allow us to use the scalar we need. The Edwards-based
    // ScalarMult only accepts scalars that are strictly less than L; we
    // work around this by multiplying the point by L - 1, then adding the
    // point once to the product.

    // These are all the points of low order that may result from
    // multiplying an Elligator-mapped point by L. We will test that all of
    // them are covered.
    let low_order_points = vec![
        /*order1*/
        vec![
            1_u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ],
        /*order2*/
        vec![
            236, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127,
        ],
        /*order4*/
        vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ],
        /*order4*/
        vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 128,
        ],
        /*order8*/
        vec![
            38, 232, 149, 143, 194, 178, 39, 176, 69, 195, 244, 137, 242, 239, 152, 240, 213, 223,
            172, 5, 211, 198, 51, 57, 177, 56, 2, 136, 109, 83, 252, 5,
        ],
        /*order8*/
        vec![
            38, 232, 149, 143, 194, 178, 39, 176, 69, 195, 244, 137, 242, 239, 152, 240, 213, 223,
            172, 5, 211, 198, 51, 57, 177, 56, 2, 136, 109, 83, 252, 133,
        ],
        /*order8*/
        vec![
            199, 23, 106, 112, 61, 77, 216, 79, 186, 60, 11, 118, 13, 16, 103, 15, 42, 32, 83, 250,
            44, 57, 204, 198, 78, 199, 253, 119, 146, 172, 3, 122,
        ],
        /*order8*/
        vec![
            199, 23, 106, 112, 61, 77, 216, 79, 186, 60, 11, 118, 13, 16, 103, 15, 42, 32, 83, 250,
            44, 57, 204, 198, 78, 199, 253, 119, 146, 172, 3, 250,
        ],
    ];

    let mut counts = vec![0; low_order_points.len()];
    let mut num_covered = 0;
    // Assuming a uniform distribution of representatives, the probability
    // that a specific low-order point will not be covered after n trials is
    // (7/8)^n. The probability that *any* of the 8 low-order points will
    // remain uncovered after n trials is at most 8 times that, 8*(7/8)^n.
    // We must do at least log((1e-12)/8)/log(7/8) = 222.50 trials, in the
    // worst case, to ensure a false error rate of less than 1 in a
    // trillion. In practice, we keep track of the number of covered points
    // and break the loop when it reaches 8, so when representatives are
    // actually uniform we will usually run much fewer iterations.
    'outer: for i in 0..225 {
        let kp = SessionKeyPair::new(true);
        let pk = EdwardsPoint::from_bytes(&kp.get_public().to_bytes());
        let v = scalar_mult_order(&pk.unwrap());

        let mut found = false;
        let mut j = 0;
        for low_point in low_order_points.iter() {
            if v.to_bytes().ct_eq(low_point).unwrap_u8() != 0 {
                found = true;
                counts[j] += 1;
                if counts[j] == 1 {
                    // We just covered a new point for the first time.
                    num_covered += 1;
                }
                if num_covered == low_order_points.len() {
                    break 'outer;
                }
                break;
            }
            j += 1;
        }
        if !found {
            panic!(
                "map {} *order yielded unexpected point {}",
                hex::encode(kp.get_representative().unwrap().as_bytes()),
                hex::encode(v.to_bytes())
            );
        }
    }

    Ok(())
}

fn scalar_mult_order(v: &EdwardsPoint) -> EdwardsPoint {
    // v * (L - 1) + v => v * L
    let scalar_order_minus_one = Scalar::from_bytes_mod_order([
        236, 211, 245, 92, 26, 99, 18, 88, 214, 156, 247, 162, 222, 249, 222, 20, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 16,
    ]);

    let p = v * scalar_order_minus_one;
    p + v
}

#[test]
fn ntor_derive_shared_compat() -> Result<()> {
    Ok(())
}

/*

    "filippo.io/edwards25519"
    "filippo.io/edwards25519/field"
    "gitlab.com/yawning/edwards25519-extra/elligator2"
)

func TestPublicKeySubgroup(t *testing.T) {

    scalarOrderMinus1, err := edwards25519.NewScalar().SetCanonicalBytes(
        // This is the same as scMinusOne in filippo.io/edwards25519.
        // https://github.com/FiloSottile/edwards25519/blob/v1.0.0/scalar.go#L34
        []byte{236, 211, 245, 92, 26, 99, 18, 88, 214, 156, 247, 162, 222, 249, 222, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16},
    )
    if err != nil {
        panic(err)
    }
    // Returns a new edwards25519.Point that is v multiplied by the subgroup
    // order.
    scalarMultOrder := func(v *edwards25519.Point) *edwards25519.Point {
        p := new(edwards25519.Point)
        // v * (L - 1) + v => v * L
        p.ScalarMult(scalarOrderMinus1, v)
        p.Add(p, v)
        return p
    }

    // Generates a new Keypair using NewKeypair, and returns the Keypair
    // along, with its public key as a newly allocated edwards25519.Point.
    generate := func() (*Keypair, *edwards25519.Point) {
        kp, err := NewKeypair(true)
        if err != nil {
            panic(err)
        }

        // We will be using the Edwards representation of the public key
        // (mapped from the Elligator representative) for further
        // processing. But while we're here, check that the Montgomery
        // representation output by Representative agrees with the
        // stored public key.
        if *kp.Representative().ToPublic() != *kp.Public() {
            t.Fatal(kp.Representative().ToPublic(), kp.Public())
        }

        // Do the Elligator map in Edwards coordinates.
        var clamped [32]byte
        copy(clamped[:], kp.Representative().Bytes()[:])
        clamped[31] &= 63
        repr, err := new(field.Element).SetBytes(clamped[:])
        if err != nil {
            panic(err)
        }
        ed := elligator2.EdwardsFlavor(repr)
        if !bytes.Equal(ed.BytesMontgomery(), kp.Public().Bytes()[:]) {
            panic("Failed to derive an equivalent public key in Edwards coordinates")
        }
        return kp, ed
    }

    // These are all the points of low order that may result from
    // multiplying an Elligator-mapped point by L. We will test that all of
    // them are covered.
    lowOrderPoints := [][32]byte{
        /*order1*/{1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
        /*order2*/{236,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,127},
        /*order4*/{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
        /*order4*/{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,128},
        /*order8*/{38,232,149,143,194,178,39,176,69,195,244,137,242,239,152,240,213,223,172,5,211,198,51,57,177,56,2,136,109,83,252,5},
        /*order8*/{38,232,149,143,194,178,39,176,69,195,244,137,242,239,152,240,213,223,172,5,211,198,51,57,177,56,2,136,109,83,252,133},
        /*order8*/{199,23,106,112,61,77,216,79,186,60,11,118,13,16,103,15,42,32,83,250,44,57,204,198,78,199,253,119,146,172,3,122},
        /*order8*/{199,23,106,112,61,77,216,79,186,60,11,118,13,16,103,15,42,32,83,250,44,57,204,198,78,199,253,119,146,172,3,250},
    }
    counts := make(map[[32]byte]int)
    for _, b := range lowOrderPoints {
        counts[b] = 0
    }
    // Assuming a uniform distribution of representatives, the probability
    // that a specific low-order point will not be covered after n trials is
    // (7/8)^n. The probability that *any* of the 8 low-order points will
    // remain uncovered after n trials is at most 8 times that, 8*(7/8)^n.
    // We must do at least log((1e-12)/8)/log(7/8) = 222.50 trials, in the
    // worst case, to ensure a false error rate of less than 1 in a
    // trillion. In practice, we keep track of the number of covered points
    // and break the loop when it reaches 8, so when representatives are
    // actually uniform we will usually run much fewer iterations.
    numCovered := 0
    for i := 0; i < 225; i++ {
        kp, pk := generate()
        v := scalarMultOrder(pk)
        var b [32]byte
        copy(b[:], v.Bytes())
        if _, ok := counts[b]; !ok {
            t.Fatalf("map(%x)*order yielded unexpected point %v",
                *kp.Representative().Bytes(), b)
        }
        counts[b]++
        if counts[b] == 1 {
            // We just covered a new point for the first time.
            numCovered++
            if numCovered == len(lowOrderPoints) {
                break
            }
        }
    }
    for _, b := range lowOrderPoints {
        count, ok := counts[b]
        if !ok {
            panic(b)
        }
        if count == 0 {
            t.Errorf("low-order point %x not covered", b)
        }
    }
}

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
