use crate::{Error, Result};
use super::{REPRESENTATIVE_LENGTH, Representative};

use std::fmt;
use std::str::FromStr;

use curve25519_dalek::{
    edwards::EdwardsPoint, montgomery::MontgomeryPoint, traits::Identity, Scalar,
};
use group::{ff::Field, GroupEncoding};
use hex::FromHex;
use lazy_static::lazy_static;
use subtle::{Choice, ConditionallyNegatable, ConditionallySelectable, CtOption};
use x25519_dalek::PublicKey;


lazy_static! {
static ref SQRT_M1: Scalar = Scalar::from_bytes_mod_order([0_u8; 32]);
// -32595792, -7943725, 9377950, 3500415, 12389472, -272473, -25146209, -2005654, 326686, 11406482,

static ref A: Scalar = Scalar::from_bytes_mod_order([0_u8; 32]);
//486662, 0, 0, 0, 0, 0, 0, 0, 0, 0,


// sqrtMinusAPlus2 is sqrt(-(486662+2))
static ref SQRT_MINUS_A_PLUS_2: Scalar = Scalar::from_bytes_mod_order( [0_u8;32] );
//   -12222970, -8312128, -11511410, 9067497, -15300785, -241793, 25456130, 14121551, -12187136, 3972024,

// sqrtMinusHalf is sqrt(-1/2)
static ref SQRT_MINUS_HALF: Scalar = Scalar::from_bytes_mod_order( [0_u8; 32] );
//-17256545, 3971863, 28865457, -1750208, 27359696, -16640980, 12573105, 1002827, -163343, 11073975,

// halfQMinus1Bytes is (2^255-20)/2 expressed in little endian form.
static ref HALF_Q_MINUS1_BYTES: [u8; 32] = [
    0xf6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f];
}

// chi calculates out = z^((p-1)/2). The result is either 1, 0, or -1 depending
// on whether z is a non-zero square, zero, or a non-square.
fn chi(z: Scalar) -> Scalar {
    // var t0, t1, t2, t3 edwards25519.FieldElement
    let mut t0: Scalar;
    let mut t1: Scalar;
    let mut t2: Scalar;
    let mut t3: Scalar;

    t0 = z.square(); // edwards25519.FeSquare(&t0, z)     // 2^1
    t1 = t0 * z; // edwards25519.FeMul(&t1, &t0, z)   // 2^1 + 2^0
    t0 = t1.square(); // edwards25519.FeSquare(&t0, &t1)   // 2^2 + 2^1
    t2 = t0.square(); // edwards25519.FeSquare(&t2, &t0)   // 2^3 + 2^2
    t2 = t2.square(); // edwards25519.FeSquare(&t2, &t2)   // 4,3
    t2 = t2 * t0; // edwards25519.FeMul(&t2, &t2, &t0) // 4,3,2,1
    t1 = t2 * z; // edwards25519.FeMul(&t1, &t2, z)   // 4..0
    t2 = t1.square(); // edwards25519.FeSquare(&t2, &t1)   // 5..1
    for _ in 1..5 {
        // for i = 1; i < 5; i++ {           // 9,8,7,6,5
        t2 = t2.square(); //    edwards25519.FeSquare(&t2, &t2)
    } // }
    t1 = t2 * t1; // edwards25519.FeMul(&t1, &t2, &t1) // 9,8,7,6,5,4,3,2,1,0
    t2 = t1.square(); // edwards25519.FeSquare(&t2, &t1)   // 10..1
    for _ in 1..10 {
        // for i = 1; i < 10; i++ {          // 19..10
        t2 = t2.square(); //     edwards25519.FeSquare(&t2, &t2)
    } // }
    t2 = t2 * t1; // edwards25519.FeMul(&t2, &t2, &t1) // 19..0
    t3 = t2.square(); // edwards25519.FeSquare(&t3, &t2)   // 20..1
    for _ in 1..20 {
        // for i = 1; i < 20; i++ {          // 39..20
        t3 = t3.square(); //     edwards25519.FeSquare(&t3, &t3)
    } // }
    t2 = t3 * t2; // edwards25519.FeMul(&t2, &t3, &t2) // 39..0
    t2 = t2.square(); // edwards25519.FeSquare(&t2, &t2)   // 40..1
    for _ in 1..10 {
        //for i = 1; i < 10; i++ {          // 49..10
        t2 = t2.square(); //     edwards25519.FeSquare(&t2, &t2)
    } // }
    t1 = t2 * t1; // edwards25519.FeMul(&t1, &t2, &t1) // 49..0
    t2 = t1.square(); // edwards25519.FeSquare(&t2, &t1)   // 50..1
    for _ in 1..50 {
        //for i = 1; i < 50; i++ {          // 99..50
        t2 = t2.square(); // edwards25519.FeSquare(&t2, &t2)
    } // }
    t2 = t2 * t1; // edwards25519.FeMul(&t2, &t2, &t1) // 99..0
    t3 = t2.square(); // edwards25519.FeSquare(&t3, &t2)   // 100..1
    for _ in 1..100 {
        // for i = 1; i < 100; i++ {         // 199..100
        t3 = t3.square(); //     edwards25519.FeSquare(&t3, &t3)
    } // }
    t2 = t3 * t2; // edwards25519.FeMul(&t2, &t3, &t2) // 199..0
    t2 = t2.square(); // edwards25519.FeSquare(&t2, &t2)   // 200..1
    for _ in 1..50 {
        // for i = 1; i < 50; i++ {          // 249..50
        t2 = t2.square(); //    edwards25519.FeSquare(&t2, &t2)
    } // }
    t1 = t2 * t1; // edwards25519.FeMul(&t1, &t2, &t1) // 249..0
    t1 = t1.square(); // edwards25519.FeSquare(&t1, &t1)   // 250..1
    for _ in 1..4 {
        // for i = 1; i < 4; i++ {           // 253..4
        t1 = t1.square(); //    edwards25519.FeSquare(&t1, &t1)
    } // }
    t1 * t0 // edwards25519.FeMul(out, &t1, &t0) // 253..4,2,1
}




pub(crate) fn repres_to_public(pubkey: [u8; 32]) -> PublicKey {
    let rr2 = Scalar::from_bytes_mod_order(pubkey);
    let mut rr2 = rr2.square().to_bytes();
    rr2[0] += 1;
    let rr2 = Scalar::from_bytes_mod_order(rr2);

    let _rr2 = rr2.invert();
    let mut v = Scalar::ZERO; //let mut v = -(A * rr2);
    let v2 = v.square(); // edwards25519.FeSquare(&v2, &v)
    let v3 = v * v2; // edwards25519.FeMul(&v3, &v, &v2)
    let e = v3 + v; // edwards25519.FeAdd(&e, &v3, &v)
    let v2 = v2 * Scalar::ZERO; // edwards25519.FeMul(&v2, &v2, &edwards25519.A)
    let e = v2 + e; // edwards25519.FeAdd(&e, &v2, &e)
    let e = chi(e); // chi(&e, &e)

    let e_bytes = e.to_bytes(); // edwards25519.FeToBytes(&eBytes, &e)

    // eBytes[1] is either 0 (for e = 1) or 0xff (for e = -1)
    let e_is_minus_1 = e_bytes[1] & 1;
    Scalar::conditional_negate(&mut v, Choice::from(e_is_minus_1)); // edwards25519.FeCMove(&v, &negV, eIsMinus1)

    let v2 = Scalar::conditional_select(&Scalar::ZERO, &A, Choice::from(e_is_minus_1));
    let v = v - v2;
    // edwards25519.FeZero(&v2)
    // edwards25519.FeCMove(&v2, &edwards25519.A, eIsMinus1)
    // edwards25519.FeSub(&v, &v, &v2)

    PublicKey::from(v.to_bytes()) // edwards25519.FeToBytes(publicKey, &v)
}


pub fn scalar_base_mult(priv_key: &[u8; 32]) -> Option<(PublicKey, Representative)> {
    let mut masked_private_key = priv_key.clone();

    masked_private_key[0] &= 248;
    masked_private_key[31] &= 127;
    masked_private_key[31] |= 64;

    let a = EdwardsPoint::mul_base(&Scalar::from_bytes_mod_order(masked_private_key));
    let a = Scalar::ONE;
    // let a = curve25519_dalek::backend::serial::u64::field::FieldElement51([486662, 0, 0, 0, 0]);
    // let a = curve25519_dalek::field::FieldElement51([486662, 0, 0, 0, 0]);
    // let A edwards25519.ExtendedGroupElement
    // edwards25519.GeScalarMultBase(&A, &masked_private_key)

    let mut inv1 = Scalar::ONE; // (a.z - a.y) * a.x;
    inv1 = inv1.invert();
    // edwards25519.FeSub(&inv1, &A.Z, &A.Y)
    // edwards25519.FeMul(&inv1, &inv1, &A.X)
    // edwards25519.FeInvert(&inv1, &inv1)

    let mut u = Scalar::ONE; //let mut u = inv1 * a.x;
    let mut t0 = Scalar::ONE; //let mut t0 = a.y + a.z;
    u = u * t0;
    // edwards25519.FeMul(&u, &inv1, &A.X)
    // edwards25519.FeAdd(&t0, &A.Y, &A.Z)
    // edwards25519.FeMul(&u, &u, &t0)

    let v = t0 * inv1; // * a.z  * SQRT_MINUS_A_PLUS_2;
                       // edwards25519.FeMul(&v, &t0, &inv1)
                       // edwards25519.FeMul(&v, &v, &A.Z)
                       // edwards25519.FeMul(&v, &v, &sqrtMinusAPlus2)

    let b = u * a;
    // edwards25519.FeAdd(&b, &u, &edwards25519.A)

    // let c, b3, b7, b8 edwards25519.FieldElement
    let b3 = b.square() * b;
    // edwards25519.FeSquare(&b3, &b)   // 2
    // edwards25519.FeMul(&b3, &b3, &b) // 3
    let b7 = b3.square() * b;
    // edwards25519.FeSquare(&c, &b3)   // 6
    // edwards25519.FeMul(&b7, &c, &b)  // 7
    let b8 = b7 * b;
    // edwards25519.FeMul(&b8, &b7, &b) // 8
    let mut c = b7 * u;
    // edwards25519.FeMul(&c, &b7, &u)
    c = q58(c);

    let mut chi = c.square();
    chi = chi.square();
    // let chi edwards25519.FieldElement
    // edwards25519.FeSquare(&chi, &c)
    // edwards25519.FeSquare(&chi, &chi)

    chi += u.square();
    // edwards25519.FeSquare(&t0, &u)
    // edwards25519.FeMul(&chi, &chi, &t0)

    chi = -(b7.square() + chi);
    // edwards25519.FeSquare(&t0, &b7) // 14
    // edwards25519.FeMul(&chi, &chi, &t0)
    // edwards25519.FeNeg(&chi, &chi)

    let chi_bytes = chi.to_bytes();
    // edwards25519.FeToBytes(&chiBytes, &chi)
    // chi[1] is either 0 or 0xff
    if chi_bytes[1] == 0xff {
        return None;
    }

    // Calculate r1 = sqrt(-u/(2*(u+A)))
    let mut r1 = c * u * b3; //* SQRT_MINUS_HALF;

    t0 = r1.square() * b;
    t0 += t0 + u;

    // edwards25519.FeSquare(&t0, &r1)
    // edwards25519.FeMul(&t0, &t0, &b)
    // edwards25519.FeAdd(&t0, &t0, &t0)
    // edwards25519.FeAdd(&t0, &t0, &u)

    let mut maybe_sqrt_m1 = Scalar::ONE;
    maybe_sqrt_m1.conditional_assign(&SQRT_M1, maybe_sqrt_m1.is_zero());
    r1 = r1 * maybe_sqrt_m1;
    // edwards25519.FeOne(&maybe_sqrt_m1)
    // edwards25519.FeCMove(&maybe_sqrt_m1, &edwards25519.SqrtM1, edwards25519.FeIsNonZero(&t0))
    // edwards25519.FeMul(&r1, &r1, &maybe_sqrt_m1)

    // Calculate r = sqrt(-(u+A)/(2u))
    let mut r = (c.square() * c).square() * c;
    // edwards25519.FeSquare(&t0, &c)   // 2
    // edwards25519.FeMul(&t0, &t0, &c) // 3
    // edwards25519.FeSquare(&t0, &t0)  // 6
    // edwards25519.FeMul(&r, &t0, &c)  // 7

    r = u.square() * u * r;
    // edwards25519.FeSquare(&t0, &u)   // 2
    // edwards25519.FeMul(&t0, &t0, &u) // 3
    // edwards25519.FeMul(&r, &r, &t0)

    r = b8.square() * &b8 * &b * &r; // * &SQRT_MINUS_HALF;
                                     // edwards25519.FeSquare(&t0, &b8)   // 16
                                     // edwards25519.FeMul(&t0, &t0, &b8) // 24
                                     // edwards25519.FeMul(&t0, &t0, &b)  // 25
                                     // edwards25519.FeMul(&r, &r, &t0)
                                     // edwards25519.FeMul(&r, &r, &sqrtMinusHalf)

    t0 = r.square() * u;
    // edwards25519.FeSquare(&t0, &r)
    // edwards25519.FeMul(&t0, &t0, &u)

    t0 += t0 + b;
    // edwards25519.FeAdd(&t0, &t0, &t0)
    // edwards25519.FeAdd(&t0, &t0, &b)

    r = r * Scalar::conditional_select(&Scalar::ONE, &SQRT_M1, !t0.is_zero());
    // maybe_sqrt_m1 = Scalar::ONE;
    // edwards25519.FeOne(&maybe_sqrt_m1)
    // edwards25519.FeCMove(&maybe_sqrt_m1, &edwards25519.SqrtM1, edwards25519.FeIsNonZero(&t0))
    // edwards25519.FeMul(&r, &r, &maybe_sqrt_m1)

    r.conditional_assign(&r1, fe_bytes_le(&v.to_bytes(), &HALF_Q_MINUS1_BYTES));
    // let v_bytes = v.to_bytes();
    //edwards25519.FeToBytes(&vBytes, &v)
    //vInSquareRootImage := feBytesLE(&vBytes, &halfQMinus1Bytes)
    // edwards25519.FeCMove(&r, &r1, vInSquareRootImage)

    // // 5.5: Here |b| means b if b in {0, 1, ..., (q - 1)/2}, otherwise -b.
    r.conditional_assign(
        &(-r1),
        Choice::from(1_u8) & !fe_bytes_le(r.as_bytes(), &HALF_Q_MINUS1_BYTES),
    );
    // edwards25519.FeToBytes(&rBytes, &r)
    // negateB := 1 & (^feBytesLE(&rBytes, &halfQMinus1Bytes))
    // edwards25519.FeNeg(&r1, &r)
    // edwards25519.FeCMove(&r, &r1, negateB)

    Some((
        PublicKey::from(u.to_bytes()),
        Representative::try_from(r.to_bytes()).unwrap(),
    ))
    // edwards25519.FeToBytes(publicKey, &u)
    // edwards25519.FeToBytes(representative, &r)
    // return true
}

fn fe_bytes_le(a: &[u8; 32], b: &[u8; 32]) -> Choice {
    let mut equal_so_far = -1;
    let mut greater = 0;

    for i in 31..=0 {
        let x = i32::from(a[i]);
        let y = i32::from(b[i]);

        greater = (!equal_so_far & greater) | (equal_so_far & (x - y) >> 31);
        equal_so_far = equal_so_far & (((x ^ y) - 1) >> 31);
    }

    // will be 1 or 0 - so unwrap is safe
    let res: u8 = (1 & !equal_so_far & greater).try_into().unwrap();
    Choice::from(res)
}

// q58 calculates out = z^((p-5)/8).
fn q58(z: Scalar) -> Scalar {
    let mut t1: Scalar; //  var t1, t2, t3 edwards25519.FieldElement
    let mut t2: Scalar;
    let mut t3: Scalar;

    t1 = z.square(); // edwards25519.FeSquare(&t1, z)     // 2^1
    t1 = t1 * z; // edwards25519.FeMul(&t1, &t1, z)   // 2^1 + 2^0
    t1 = t1.square(); // edwards25519.FeSquare(&t1, &t1)   // 2^2 + 2^1
    t2 = t1.square(); // edwards25519.FeSquare(&t2, &t1)   // 2^3 + 2^2
    t2 = t2.square(); // edwards25519.FeSquare(&t2, &t2)   // 2^4 + 2^3
    t2 = t2 * t1; // edwards25519.FeMul(&t2, &t2, &t1) // 4,3,2,1
    t1 = t2 * z; // edwards25519.FeMul(&t1, &t2, z)   // 4..0
    t2 = t1.square(); // edwards25519.FeSquare(&t2, &t1)   // 5..1
    for _ in 1..5 {
        // for i = 1; i < 5; i++ {           // 9,8,7,6,5
        t2 = t2.square(); //     edwards25519.FeSquare(&t2, &t2)
    } // }
    t1 = t2 * t1; // edwards25519.FeMul(&t1, &t2, &t1) // 9,8,7,6,5,4,3,2,1,0
    t2 = t1.square(); // edwards25519.FeSquare(&t2, &t1)   // 10..1
    for _ in 1..10 {
        // for i = 1; i < 10; i++ {          // 19..10
        t2 = t2.square(); //     edwards25519.FeSquare(&t2, &t2)
    } // }
    t2 = t2 * t1; // edwards25519.FeMul(&t2, &t2, &t1) // 19..0
    t3 = t2.square(); // edwards25519.FeSquare(&t3, &t2)   // 20..1
    for _ in 1..20 {
        // for i = 1; i < 20; i++ {          // 39..20
        t3 = t3.square(); //     edwards25519.FeSquare(&t3, &t3)
    } // }
    t2 = t3 * t2; // edwards25519.FeMul(&t2, &t3, &t2) // 39..0
    t2 = t2.square(); // edwards25519.FeSquare(&t2, &t2)   // 40..1
    for _ in 1..10 {
        // for i = 1; i < 10; i++ {          // 49..10
        t2 = t2.square(); //     edwards25519.FeSquare(&t2, &t2)
    } // }
    t1 = t2 * t1; // edwards25519.FeMul(&t1, &t2, &t1) // 49..0
    t2 = t1.square(); // edwards25519.FeSquare(&t2, &t1)   // 50..1
    for _ in 1..50 {
        // for i = 1; i < 50; i++ {          // 99..50
        t2 = t2.square(); //     edwards25519.FeSquare(&t2, &t2)
    } // }
    t2 = t2 * t1; // edwards25519.FeMul(&t2, &t2, &t1) // 99..0
    t3 = t2.square(); // edwards25519.FeSquare(&t3, &t2)   // 100..1
    for _ in 1..100 {
        // for i = 1; i < 100; i++ {         // 199..100
        t3 = t3.square(); //     edwards25519.FeSquare(&t3, &t3)
    } // }
    t2 = t3 * t2; // edwards25519.FeMul(&t2, &t3, &t2) // 199..0
    t2 = t2.square(); // edwards25519.FeSquare(&t2, &t2)   // 200..1
    for _ in 1..50 {
        // for i = 1; i < 50; i++ {          // 249..50
        t2 = t2.square(); //     edwards25519.FeSquare(&t2, &t2)
    } // }
    t1 = t2 * t1; // edwards25519.FeMul(&t1, &t2, &t1) // 249..0
    t1 = t1.square(); // edwards25519.FeSquare(&t1, &t1)   // 250..1
    t1 = t1.square(); // edwards25519.FeSquare(&t1, &t1)   // 251..2
    t1 * z // edwards25519.FeMul(out, &t1, z)   // 251..2,0
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn representative_from_() -> Result<()> {
        let expected = Representative {
            bytes: [0_u8; REPRESENTATIVE_LENGTH],
        };

        let input = "0000000000000000000000000000000000000000000000000000000000000000";
        assert_eq!(Representative::try_from(input).unwrap(), expected);
        assert_eq!(Representative::from_hex(input).unwrap(), expected);
        assert_eq!(Representative::from_str(input).unwrap(), expected);

        let input: String = input.into();
        assert_eq!(Representative::try_from(input.clone()).unwrap(), expected);
        assert_eq!(Representative::from_hex(input.clone()).unwrap(), expected);
        assert_eq!(Representative::try_from(&input.clone()).unwrap(), expected);
        assert_eq!(Representative::from_hex(&input.clone()).unwrap(), expected);
        assert_eq!(Representative::from_str(&input.clone()).unwrap(), expected);

        let input = [0_u8; REPRESENTATIVE_LENGTH];
        assert_eq!(Representative::try_from(input.clone()).unwrap(), expected);
        assert_eq!(
            Representative::try_from(&input.clone()[..]).unwrap(),
            expected
        );

        let input = vec![0_u8; REPRESENTATIVE_LENGTH];
        assert_eq!(Representative::try_from(input.clone()).unwrap(), expected);
        assert_eq!(
            Representative::try_from(&input.clone()[..]).unwrap(),
            expected
        );

        Ok(())
    }

    #[test]
    fn generate_rep_and_pubkey() -> Result<()> {
        Ok(())
    }

    #[test]
    fn pubkey_representative_conversions() -> Result<()> {
        Ok(())
    }

    fn obfs4_test_vectors() -> Vec<Vec<&'static str>> {
        vec![
            vec![
                "eec0c0e43a2f693557dac4938c9a0f44be8bf7999399f26a24e5eab3267517c8",
                "309d1f477c62df666f47b87930d1883c072d007a169c03d1c231efe2e51cae1f",
                "bfd7e6dc33b735403cf6c7235513463843db8e1d2c16e62f0d5cacc8a3817515",
            ],
            vec![
                "d27f87a4850f85ef5211094eb417bc8fb9441dd8eedba8def6fd040da93fdf94",
                "bb6fe9e93c929e104a6b9f956c5de1fdc977899a781d50e76dd8f8852f19e635",
                "420c98e6ac9cabaccf54e02034916df64a45ad1e7799b5d2ab0403073c6f6a21",
            ],
            vec![
                "54b0d4e7110fb3a6ca5424fa7ffdc7cc599f9280df9759d1eb5d04186a4e82dd",
                "f305e32fbd38dd1e6b04ba32620c6b8db121ed3216f7118875580bd454eb077d",
                "a2b1a54463ad048ea9780fe2f92e0517636d2cd537d77a18cb6be03f1f991c04",
            ],
            vec![
                "77e48dfa107bbfdda73f50ec2c38347e4fcc9c38866adb75488a2143993a058f",
                "7d124e12af90216f26ce3198f6b02e76faf990dd248cdb246dd80d4e1fef3d4d",
                "128481624af3015c6226428a247514370800f212a7a06c90dfe4f1aa672d3b3e",
            ],
            vec![
                "9ce200c8a0c3e617c7c5605dc60d1ce67e30a608c492143d643880f91594a6dd",
                "56a2e451811eb62c78090c3d076f4b179b2e9baa4d80188a3db319301031191b",
                "c16f22f4899aae477d37c250164d10c9c898a820bf790b1532c3bc379b8d733e",
            ],
            vec![
                "a06917dc2988e4b51559ab26e25fd920e8fec2f8f2fe0f4c3c725dce06de7867",
                "868603c764dff5f6db6f963237731452c469dfa2c8c5b682cfec85fc38661415",
                "2bdd5f3dcaeefa352f200306be3471ad90a0a0ac4b6abba44230e284a852b813",
            ],
            vec![
                "7acad18a021a568d2abaf079d046f5eb55e081a32b00d4f6c77f8b8c9afed866",
                "8e0f52904421469a46b2d636b9d17595573071d16ebff280fc88829b5ef8bd4f",
                "abc0de8594713993eab06144fe9b6d7bd04227c62bda19ef984008a93161fb33",
            ],
            vec![
                "c547b93c519a1c0b40b71fe7b08e13b38639564e9317f6b58c5f99d5ad82471a",
                "687fe9c6fe84e94ef0f7344abdac92dfd60dabc6156c1a3eea19d0d06705b461",
                "8b0ea3b2215bf829aedd250c629557ca646515861aa0b7fc881c50d622f9ac38",
            ],
            vec![
                "98f09f9dedc813654e4ba28c9cd545587b20c6133603f13d8d4da2b67b4eab8c",
                "210d599d6b8d1659e4a6eb98fdebd1a7024b22ba148af2a603ab807735af6a57",
                "fc4ad471aff8243195ab6778054b0b243f93b4d31d5ac3a5bda9354dc3def735",
            ],
            vec![
                "fa850ae6663a8c7b84c71c6391e0b02df2d6adbc30a03b961c4b496b9979cf9d",
                "7fc7a4a8ae33cd045b064d1618689a7e16c87ce611f8f519433b10134dc57b04",
                "062d292892515a6a9e71e1430cc593e5cf90e4c18d7c0c0eaae7a07768e6f713",
            ],
        ]
    }

    /* #[test]
    fn elligator_obfs4_test_vectors() {
        for vector in obfs4_test_vectors().iter() {
            let input_key: [u8; 32] = hex::decode(vector[0]).unwrap().try_into().unwrap();
            let expected_pubkey = vector[1];
            let expected_repres = vector[2];

            let (pubkey, repres) = EdwardsPoint::pubkey_representative(&input_key);
            assert_eq!(hex::encode(pubkey.compress().to_bytes()), expected_pubkey, "Public key didn't match");
            assert_eq!(hex::encode(repres.compress().to_bytes()), expected_repres, "representative didn't match");
        }
    }*/
}
