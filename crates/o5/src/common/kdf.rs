//! Key derivation functions
//!
//! Tor has three relevant key derivation functions that it uses for
//! deriving keys used for relay encryption.
//!
//! The *KDF-TOR* KDF (implemented by `LegacyKdf`) is used with the old
//! TAP handshake.  It is ugly, it is based on SHA-1, and it should be
//! avoided for new uses. It is not even linked here as we will not use it in
//! this obfuscated protocol implementation.
//!
//! The *HKDF-SHA256* KDF (implemented by `Ntor1Kdf`) is used with the
//! Ntor handshake.  It is based on RFC5869 and SHA256.
//!
//! The *SHAKE* KDF (implemented by `ShakeKdf` is used with v3 onion
//! services, and is likely to be used by other places in the future.
//! It is based on SHAKE-256.

use crate::{Error, Result};

use digest::{ExtendableOutput, Update, XofReader};
use tor_bytes::SecretBuf;
use tor_llcrypto::d::{Sha256, Shake256};

/// A trait for a key derivation function.
pub(crate) trait Kdf {
    /// Derive `n_bytes` of key data from some secret `seed`.
    fn derive(&self, seed: &[u8], n_bytes: usize) -> Result<SecretBuf>;
}

/// A parameterized KDF, for use with ntor.
///
/// This KDF is based on HKDF-SHA256.
pub(crate) struct Ntor1Kdf<'a, 'b> {
    /// A constant for parameterizing the kdf, during the key extraction
    /// phase.
    t_key: &'a [u8],
    /// Another constant for parameterizing the kdf, during the key
    /// expansion phase.
    m_expand: &'b [u8],
}

/// A modern KDF, for use with v3 onion services.
///
/// This KDF is based on SHAKE256
pub(crate) struct ShakeKdf();

impl<'a, 'b> Ntor1Kdf<'a, 'b> {
    /// Instantiate an Ntor1Kdf, with given values for t_key and m_expand.
    pub(crate) fn new(t_key: &'a [u8], m_expand: &'b [u8]) -> Self {
        Ntor1Kdf { t_key, m_expand }
    }
}

impl Kdf for Ntor1Kdf<'_, '_> {
    fn derive(&self, seed: &[u8], n_bytes: usize) -> Result<SecretBuf> {
        let hkdf = hkdf::Hkdf::<Sha256>::new(Some(self.t_key), seed);

        let mut result: SecretBuf = vec![0; n_bytes].into();
        hkdf.expand(self.m_expand, result.as_mut())
            .map_err(|_| Error::InvalidKDFOutputLength)?;
        Ok(result)
    }
}

impl ShakeKdf {
    /// Instantiate a ShakeKdf.
    pub(crate) fn new() -> Self {
        ShakeKdf()
    }
}
impl Kdf for ShakeKdf {
    fn derive(&self, seed: &[u8], n_bytes: usize) -> Result<SecretBuf> {
        let mut xof = Shake256::default();
        xof.update(seed);
        let mut result: SecretBuf = vec![0; n_bytes].into();
        xof.finalize_xof().read(result.as_mut());
        Ok(result)
    }
}

#[cfg(test)]
// @@ begin test lint list maintained by maint/add_warning @@
#[allow(clippy::bool_assert_comparison)]
#[allow(clippy::clone_on_copy)]
#[allow(clippy::dbg_macro)]
#[allow(clippy::print_stderr)]
#[allow(clippy::print_stdout)]
#[allow(clippy::single_char_pattern)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::unchecked_duration_subtraction)]
#[allow(clippy::useless_vec)]
#[allow(clippy::needless_pass_by_value)]
// <!-- @@ end test lint list maintained by maint/add_warning @@ -->
mod test {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn clearbox_ntor1_kdf() {
        // Calculate Ntor1Kdf, and make sure we get the same result by
        // following the calculation in the spec.
        let input = b"another example key seed that we will expand";
        let result = Ntor1Kdf::new(&b"key"[..], &b"expand"[..])
            .derive(input, 99)
            .unwrap();

        let kdf = hkdf::Hkdf::<Sha256>::new(Some(&b"key"[..]), &input[..]);
        let mut expect_result = vec![0_u8; 99];
        kdf.expand(&b"expand"[..], &mut expect_result[..]).unwrap();

        assert_eq!(&expect_result[..], &result[..]);
    }

    #[test]
    fn testvec_ntor1_kdf() {
        // From Tor's test_crypto.c; generated with ntor_ref.py
        fn expand(b: &[u8]) -> SecretBuf {
            let t_key = b"ntor-curve25519-sha256-1:key_extract";
            let m_expand = b"ntor-curve25519-sha256-1:key_expand";
            Ntor1Kdf::new(&t_key[..], &m_expand[..])
                .derive(b, 100)
                .unwrap()
        }

        let expect = hex!(
            "5521492a85139a8d9107a2d5c0d9c91610d0f95989975ebee6
             c02a4f8d622a6cfdf9b7c7edd3832e2760ded1eac309b76f8d
             66c4a3c4d6225429b3a016e3c3d45911152fc87bc2de9630c3
             961be9fdb9f93197ea8e5977180801926d3321fa21513e59ac"
        );
        assert_eq!(&expand(&b"Tor"[..])[..], &expect[..]);

        let brunner_quote = b"AN ALARMING ITEM TO FIND ON YOUR CREDIT-RATING STATEMENT";
        let expect = hex!(
            "a2aa9b50da7e481d30463adb8f233ff06e9571a0ca6ab6df0f
             b206fa34e5bc78d063fc291501beec53b36e5a0e434561200c
             5f8bd13e0f88b3459600b4dc21d69363e2895321c06184879d
             94b18f078411be70b767c7fc40679a9440a0c95ea83a23efbf"
        );
        assert_eq!(&expand(&brunner_quote[..])[..], &expect[..]);
    }

    #[test]
    fn testvec_shake_kdf() {
        // This is just one of the shake test vectors from tor-llcrypto
        let input = hex!(
            "76891a7bcc6c04490035b743152f64a8dd2ea18ab472b8d36ecf45
             858d0b0046"
        );
        let expected = hex!(
            "e8447df87d01beeb724c9a2a38ab00fcc24e9bd17860e673b02122
             2d621a7810e5d3"
        );

        let result = ShakeKdf::new().derive(&input[..], expected.len());
        assert_eq!(&result.unwrap()[..], &expected[..]);
    }
}
