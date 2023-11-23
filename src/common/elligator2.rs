use crate::{Error, Result};

use std::fmt;
use std::str::FromStr;

use curve25519_dalek::{edwards::EdwardsPoint, montgomery::MontgomeryPoint, traits::Identity, Scalar};
use group::GroupEncoding;
use hex::FromHex;
use x25519_dalek::PublicKey;
use subtle::{CtOption, Choice};

/// The length of an Elligator representative.
const REPRESENTATIVE_LENGTH: usize = 32;

pub fn edwards_flavor(s: Scalar) -> CtOption<EdwardsPoint> {

    let edw = s * EdwardsPoint::identity();
    CtOption::new(edw, Choice::from(1))
}

pub fn scalar_base_mult(priv_key: &[u8;32]) {
	let masked_private_key = priv_key.clone();

	masked_private_key[0] &= 248;
	masked_private_key[31] &= 127;
	masked_private_key[31] |= 64;

    let a = EdwardsPoint::mul_base(&Scalar::from_bytes_mod_order(masked_private_key));
	let A edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&A, &masked_private_key)

	let inv1 edwards25519.FieldElement
	edwards25519.FeSub(&inv1, &A.Z, &A.Y)
	edwards25519.FeMul(&inv1, &inv1, &A.X)
	edwards25519.FeInvert(&inv1, &inv1)

	let t0, u edwards25519.FieldElement
	edwards25519.FeMul(&u, &inv1, &A.X)
	edwards25519.FeAdd(&t0, &A.Y, &A.Z)
	edwards25519.FeMul(&u, &u, &t0)

	let v edwards25519.FieldElement
	edwards25519.FeMul(&v, &t0, &inv1)
	edwards25519.FeMul(&v, &v, &A.Z)
	edwards25519.FeMul(&v, &v, &sqrtMinusAPlus2)

	let b edwards25519.FieldElement
	edwards25519.FeAdd(&b, &u, &edwards25519.A)

	let c, b3, b7, b8 edwards25519.FieldElement
	edwards25519.FeSquare(&b3, &b)   // 2
	edwards25519.FeMul(&b3, &b3, &b) // 3
	edwards25519.FeSquare(&c, &b3)   // 6
	edwards25519.FeMul(&b7, &c, &b)  // 7
	edwards25519.FeMul(&b8, &b7, &b) // 8
	edwards25519.FeMul(&c, &b7, &u)
	q58(&c, &c)

	let chi edwards25519.FieldElement
	edwards25519.FeSquare(&chi, &c)
	edwards25519.FeSquare(&chi, &chi)

	edwards25519.FeSquare(&t0, &u)
	edwards25519.FeMul(&chi, &chi, &t0)

	edwards25519.FeSquare(&t0, &b7) // 14
	edwards25519.FeMul(&chi, &chi, &t0)
	edwards25519.FeNeg(&chi, &chi)

	let chiBytes = [0_u8; 32];
	edwards25519.FeToBytes(&chiBytes, &chi)
	// chi[1] is either 0 or 0xff
	if chiBytes[1] == 0xff {
		return false
	}

	// Calculate r1 = sqrt(-u/(2*(u+A)))
	let r1 edwards25519.FieldElement
	edwards25519.FeMul(&r1, &c, &u)
	edwards25519.FeMul(&r1, &r1, &b3)
	edwards25519.FeMul(&r1, &r1, &sqrtMinusHalf)

	let maybeSqrtM1 edwards25519.FieldElement
	edwards25519.FeSquare(&t0, &r1)
	edwards25519.FeMul(&t0, &t0, &b)
	edwards25519.FeAdd(&t0, &t0, &t0)
	edwards25519.FeAdd(&t0, &t0, &u)

	edwards25519.FeOne(&maybeSqrtM1)
	edwards25519.FeCMove(&maybeSqrtM1, &edwards25519.SqrtM1, edwards25519.FeIsNonZero(&t0))
	edwards25519.FeMul(&r1, &r1, &maybeSqrtM1)

	// Calculate r = sqrt(-(u+A)/(2u))
	let r edwards25519.FieldElement
	edwards25519.FeSquare(&t0, &c)   // 2
	edwards25519.FeMul(&t0, &t0, &c) // 3
	edwards25519.FeSquare(&t0, &t0)  // 6
	edwards25519.FeMul(&r, &t0, &c)  // 7

	edwards25519.FeSquare(&t0, &u)   // 2
	edwards25519.FeMul(&t0, &t0, &u) // 3
	edwards25519.FeMul(&r, &r, &t0)

	edwards25519.FeSquare(&t0, &b8)   // 16
	edwards25519.FeMul(&t0, &t0, &b8) // 24
	edwards25519.FeMul(&t0, &t0, &b)  // 25
	edwards25519.FeMul(&r, &r, &t0)
	edwards25519.FeMul(&r, &r, &sqrtMinusHalf)

	edwards25519.FeSquare(&t0, &r)
	edwards25519.FeMul(&t0, &t0, &u)
	edwards25519.FeAdd(&t0, &t0, &t0)
	edwards25519.FeAdd(&t0, &t0, &b)
	edwards25519.FeOne(&maybeSqrtM1)
	edwards25519.FeCMove(&maybeSqrtM1, &edwards25519.SqrtM1, edwards25519.FeIsNonZero(&t0))
	edwards25519.FeMul(&r, &r, &maybeSqrtM1)

	let vBytes = [0_u8; 32];
	edwards25519.FeToBytes(&vBytes, &v)
	vInSquareRootImage := feBytesLE(&vBytes, &halfQMinus1Bytes)
	edwards25519.FeCMove(&r, &r1, vInSquareRootImage)

	// // 5.5: Here |b| means b if b in {0, 1, ..., (q - 1)/2}, otherwise -b.
	let rBytes = [0_u8; 32];
	edwards25519.FeToBytes(&rBytes, &r)
	negateB := 1 & (^feBytesLE(&rBytes, &halfQMinus1Bytes))
	edwards25519.FeNeg(&r1, &r)
	edwards25519.FeCMove(&r, &r1, negateB)

	edwards25519.FeToBytes(publicKey, &u)
	edwards25519.FeToBytes(representative, &r)
	return true
}

/// Elligator Representative of a public key value
#[derive(Debug, Clone, PartialEq)]
pub struct Representative {
    bytes: [u8; 32],
}

impl Representative {
    // Computes a curve25519 public key from a private key and also
    // a uniform representative for that public key. Note that this function will
    // fail and return false for about half of private keys.
    //
    // See http://elligator.cr.yp.to/elligator-20130828.pdf.
    pub fn from_public(priv_key: &[u8;32]) -> Option<Self> {
        let p = EdwardsPoint::mul_base_clamped(pub_key.to_bytes());
        if p.is_small_order() {
            None
        } else {
            Some(Self {
                bytes: [1_u8; REPRESENTATIVE_LENGTH],
            })
        }
    }

    pub fn edwards_flavor(&self) -> CtOption<EdwardsPoint> {

        <EdwardsPoint as GroupEncoding>::from_bytes(&self.bytes)
    }

    pub fn montgomery_flavor(&self) -> CtOption<MontgomeryPoint> {
        let mut ok: Choice = Choice::from(1_u8);
        let not_ok: Choice = Choice::from(0_u8);
        // This is based off the public domain python implementation by
        // Loup Vaillant, taken from the Monocypher package
        // (tests/gen/elligator.py).
        //
        // The choice of base implementation is primarily because it was
        // convenient, and because they appear to be one of the people
        // that have given the most thought regarding how to implement
        // this correctly, with a readable implementation that I can
        // wrap my brain around.
        let e =  <EdwardsPoint as GroupEncoding>::from_bytes(&self.bytes);
        let edw =  {
            if e.is_some().into() {
                ok &= ok;
                e.unwrap()
            } else {
                ok &= not_ok;
                EdwardsPoint::identity()
            }
        };
        let m = edw.to_montgomery();

        CtOption::new(m, ok)
    }

    pub fn try_from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
        Self::try_from(bytes.as_ref())
    }

    pub fn to_public(&self) -> PublicKey {
        PublicKey::from([0_u8; 32])
    }

    pub fn to_bytes(&self) -> [u8;REPRESENTATIVE_LENGTH] {
         self.bytes.clone()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }


}

impl TryFrom<&PublicKey> for Representative {
    type Error = Error;

    fn try_from(pub_key: &PublicKey) -> Result<Self> {
        let p = EdwardsPoint::mul_base_clamped(pub_key.to_bytes());
        if p.is_small_order() {
            Ok(Self {
                bytes: [0_u8; REPRESENTATIVE_LENGTH],
            })
        } else {
            Ok(Self {
                bytes: [1_u8; REPRESENTATIVE_LENGTH],
            })
        }
    }
}

impl From<&Representative> for PublicKey {
    fn from(representative: &Representative) -> PublicKey {
        PublicKey::from(representative.bytes)
    }
}

impl FromHex for Representative {
    type Error = Error;

    fn from_hex<T: AsRef<[u8]>>(msg: T) -> Result<Self> {
        let buffer = <[u8; REPRESENTATIVE_LENGTH]>::from_hex(msg)?;
        Ok(Representative { bytes: buffer })
    }
}

impl TryFrom<String> for Representative {
    type Error = Error;

    fn try_from(msg: String) -> Result<Self> {
        let buffer = <[u8; REPRESENTATIVE_LENGTH]>::from_hex(msg)?;
        Ok(Representative { bytes: buffer })
    }
}

impl TryFrom<&String> for Representative {
    type Error = Error;

    fn try_from(msg: &String) -> Result<Self> {
        let buffer = <[u8; REPRESENTATIVE_LENGTH]>::from_hex(msg)?;
        Ok(Representative { bytes: buffer })
    }
}

impl TryFrom<&str> for Representative {
    type Error = Error;

    fn try_from(msg: &str) -> Result<Self> {
        let buffer = <[u8; REPRESENTATIVE_LENGTH]>::from_hex(msg)?;
        Ok(Representative { bytes: buffer })
    }
}

impl FromStr for Representative {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Representative::from_hex(s)
    }
}

impl TryFrom<&[u8]> for Representative {
    type Error = Error;

    fn try_from(arr: &[u8]) -> Result<Self> {
        if arr.len() != REPRESENTATIVE_LENGTH {
            let e = format!(
                "incorrect drbg seed length {}!={REPRESENTATIVE_LENGTH}",
                arr.len()
            );
            return Err(Error::Other(e.into()));
        }

        Ok(Representative {
            bytes: (&arr[..])
                .try_into()
                .map_err(|e| Error::Other(format!("{e}").into()))?,
        })
    }
}

impl TryFrom<[u8; REPRESENTATIVE_LENGTH]> for Representative {
    type Error = Error;

    fn try_from(arr: [u8; REPRESENTATIVE_LENGTH]) -> Result<Self> {
        Ok(Representative { bytes: arr })
    }
}

impl TryFrom<Vec<u8>> for Representative {
    type Error = Error;

    fn try_from(arr: Vec<u8>) -> Result<Self> {
        Representative::try_from(arr.as_slice())
    }
}

impl fmt::Display for Representative {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.bytes[..]))
    }
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
    fn pubkey_representative_conversions() -> Result<()> {
        Ok(())
    }
}
