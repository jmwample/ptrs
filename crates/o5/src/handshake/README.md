
# Obfs4 Ntor Handshake

While exchanging messages during the handshake the client and
server use (a modified version of) the Ntor handshake to
compute a shared seed as well as an authentication value.

The original implementation of the Obfs4 Ntor Handshake has some
small variation from the actual Ntor V1 handshake and as such
requires an alternative implementation to be compatible with
the existing [golang implementation](https://gitlab.com/yawning/obfs4)


## Difference from Ntor V1

* message value used for key seed is different: obfs4 uses a different order and
accidentally writes the server's identity public key bytes twice.
  - Ntor V1 - uses `message = (secret_input) | ID | b | x | y | PROTOID`
  - Obfs4 - uses `message = (secret_input) | b | b | x | y | PROTOID | ID`

* seed for key generator
  * Ntor V1 - uses raw bytes from `message`
  * Obfs4 - uses `HMAC_SHA256(message, T_KEY)` where `T_KEY = "ntor-curve25519-sha256-1:key_extract"`

* The constant string for `T_VERIFY`
  * Ntor V1 - `T_VERIFY = b"ntor-curve25519-sha256-1:verify";`
  * Obfs4 - `T_VERIFY = b"ntor-curve25519-sha256-1:key_verify";`

* message value used for auth is different -- these hash over the same fields,
but result in different hash values. Obfs4 reuses part of the `message` value
so the duplicated server identity public key is included.
  * Ntor V1 - uses input `verify | ID | b | y | x | PROTOID | "Server"`
  * Obfs4 - uses input `verify | b | b | y | x | PROTOID | ID | "Server"`

The rust implementation of the Obfs4 Ntor derivation with diff markup.

```diff

pub(crate) const PROTO_ID: &[u8; 24] = b"ntor-curve25519-sha256-1";
pub(crate) const T_MAC: &[u8; 28] = b"ntor-curve25519-sha256-1:mac";
-pub(crate) const T_VERIFY: &[u8; 31] = b"ntor-curve25519-sha256-1:verify";
+pub(crate) const T_VERIFY: &[u8; 35] = b"ntor-curve25519-sha256-1:key_verify";
pub(crate) const T_KEY: &[u8; 36] = b"ntor-curve25519-sha256-1:key_extract";
pub(crate) const T_EXPAND: &[u8; 35] = b"ntor-curve25519-sha256-1:key_expand";


/// helper: compute a key generator and an authentication code from a set
/// of ntor parameters.
///
/// These parameter names are as described in tor-spec.txt
fn ntor_derive(
    xy: &SharedSecret,
    xb: &SharedSecret,
    server_pk: &Obfs4NtorPublicKey,
    x: &PublicKey,
    y: &PublicKey,
) -> EncodeResult<(NtorHkdfKeyGenerator, Authcode)> {
    let server_string = &b"Server"[..];

    // shared_secret_input = EXP(X,y) | EXP(X,b)   OR    = EXP(Y,x) | EXP(B,x)
-    // message = (shared_secret_input) | ID | X | Y | PROTOID
-    let mut message = SecretBuf::new();
-    message.write(xy.as_bytes())?; // EXP(X,y)
-    message.write(xb.as_bytes())?; // EXP(X,b)
-    message.write(&server_pk.id)?; // ID
-    message.write(&server_pk.pk.as_bytes())?; // b
-    message.write(x.as_bytes())?; // x
-    message.write(y.as_bytes())?; // y
-    message.write(PROTO_ID)?; // PROTOID
+    // obfs4 uses a different order than Ntor V1 and accidentally writes the
+    // server's identity public key bytes twice.
+    let mut suffix = SecretBuf::new();
+    suffix.write(&server_pk.pk.as_bytes())?; // b
+    suffix.write(&server_pk.pk.as_bytes())?; // b
+    suffix.write(x.as_bytes())?; // x
+    suffix.write(y.as_bytes())?; // y
+    suffix.write(PROTO_ID)?; // PROTOID
+    suffix.write(&server_pk.id)?; // ID
+
+    // message = (secret_input) | b | b | x | y | PROTOID | ID
+    let mut message = SecretBuf::new();
+    message.write(xy.as_bytes())?; // EXP(X,y)
+    message.write(xb.as_bytes())?; // EXP(X,b)
+    message.write(&suffix[..])?;   // b | b | x | y | PROTOID | ID

    // verify = HMAC_SHA256(message, T_VERIFY)
    let verify = {
        let mut m =
            Hmac::<Sha256>::new_from_slice(T_VERIFY).expect("Hmac allows keys of any size");
        m.update(&message[..]);
        m.finalize()
    };

-    // auth_input = verify | ID | b | y | x | PROTOID | "Server"
+    // auth_input = verify | (suffix) | "Server"
+    // auth_input = verify | b | b | y | x | PROTOID | ID | "Server"
    let mut auth_input = Vec::new();
    auth_input.write_and_consume(verify)?; // verify
-    auth_input.write(&server_pk.id)?; // ID
-    auth_input.write(&server_pk.pk.as_bytes())?; // B
-    auth_input.write(y.as_bytes())?; // Y
-    auth_input.write(x.as_bytes())?; // X
-    auth_input.write(PROTO_ID)?; // PROTOID
+    auth_input.write(&suffix[..])?; // b | b | x | y | PROTOID | ID
    auth_input.write(server_string)?; // "Server"

    // auth = HMAC_SHA256(auth_input, T_MAC)
    let auth_mac = {
        let mut m =
            Hmac::<Sha256>::new_from_slice(T_MAC).expect("Hmac allows keys of any size");
        m.update(&auth_input[..]);
        m.finalize()
    };

+    let key_seed_bytes = {
+        let mut m = 
+            Hmac::<Sha256>::new_from_slice(T_KEY).expect("Hmac allows keys of any size");
+        m.update(&message[..]);
+        m.finalize()
+    };
+    let mut key_seed = SecretBuf::new();
+    key_seed.write_and_consume(key_seed_bytes)?;
+
+    let keygen = NtorHkdfKeyGenerator::new(key_seed);
-    let keygen = NtorHkdfKeyGenerator::new(message);
    Ok((keygen, auth_mac))
}

```
