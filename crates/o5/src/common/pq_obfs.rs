//! ## KyberX25519 Ntor Handshake
//!
//! ### As Described in draft-tls-westerbaan-xyber768d00-03
//!
//! ```
//! 3.  Construction
//!
//!    We instantiate draft-ietf-tls-hybrid-design-06 with X25519 [rfc7748]
//!    and Kyber768Draft00 [kyber].  The latter is Kyber as submitted to
//!    round 3 of the NIST PQC process [KyberV302].
//!
//!    For the client's share, the key_exchange value contains the
//!    concatenation of the client's X25519 ephemeral share (32 bytes) and
//!    the client's Kyber768Draft00 public key (1184 bytes).  The resulting
//!    key_exchange value is 1216 bytes in length.
//!
//!    For the server's share, the key_exchange value contains the
//!    concatenation of the server's X25519 ephemeral share (32 bytes) and
//!    the Kyber768Draft00 ciphertext (1088 bytes) returned from
//!    encapsulation for the client's public key.  The resulting
//!    key_exchange value is 1120 bytes in length.
//!
//!    The shared secret is calculated as the concatenation of the X25519
//!    shared secret (32 bytes) and the Kyber768Draft00 shared secret (32
//!    bytes).  The resulting shared secret value is 64 bytes in length.
//!
//! 4.  Security Considerations
//!
//!    For TLS 1.3, this concatenation approach provides a secure key
//!    exchange if either component key exchange methods (X25519 or
//!    Kyber768Draft00) are secure [hybrid].
//! ```

mod keys;
mod ntorv3;

pub struct SessionKeyPair(keys::HybridKey);

pub struct IdentityKeyPair(keys::HybridKey);

/*
/// The client side uses the ntor derived shared secret based on the secret
/// input created by appending the shared secret derived between the client's
/// session keys and the server's sessions keys with the shared secret derived
/// between the clients session keys and the server's identity keys.
///
/// secret input = X25519(Y, x) | Kyber(Y, x) | X25519(B, x) | Kyber(B, x)
pub fn client_handshake(
    client_keys: &SessionKeyPair,
    server_public: &PublicKey,
    id_public: &PublicKey,
    id: &ID,
) -> CtOption<HandshakeResult> {
    let mut not_ok = 0;
    let mut secret_input: Vec<u8> = vec![];

    // EXP(Y,x)
    let exp = client_keys
        .x25519
        .private
        .diffie_hellman(&server_public.x25519);

    not_ok |= _ZERO_EXP[..].ct_eq(exp.as_bytes()).unwrap_u8();
    secret_input.append(&mut exp.as_bytes().to_vec());

    // EXP(B,x)
    let exp = client_keys.x25519.private.diffie_hellman(&id_public.x25519);
    not_ok |= _ZERO_EXP[..].ct_eq(exp.as_bytes()).unwrap_u8();
    secret_input.append(&mut exp.as_bytes().to_vec());

    let (key_seed, auth) = derive_ntor_shared(
        secret_input,
        id,
        id_public,
        &client_keys.get_public(),
        server_public,
    );

    // failed if not_ok != 0
    // if not_ok != 0 then scalar operations failed
    subtle::CtOption::new(HandshakeResult { key_seed, auth }, not_ok.ct_eq(&0_u8))
}

/// The server side uses the ntor derived shared secret based on the secret
/// input created by appending the shared secret derived between the server's
/// session keys and the client's sessions keys with the shared secret derived
/// between the server's identity keys and the clients session keys.
///
/// secret input = X25519(X, y) | Kyber(X, y) | X25519(X, b) | Kyber(X, b)
pub fn server_handshake(
    server_keys: &SessionKeyPair,
    client_public: &PublicKey,
    id_keys: &IdentityKeyPair,
    id: &ID,
) -> CtOption<HandshakeResult> {
    let mut not_ok = 0;
    let mut secret_input: Vec<u8> = vec![];

    // EXP(X,y)
    let exp = server_keys
        .x25519
        .private
        .diffie_hellman(&client_public.x25519);
    not_ok |= _ZERO_EXP[..].ct_eq(exp.as_bytes()).unwrap_u8();
    secret_input.append(&mut exp.as_bytes().to_vec());

    // EXP(X,b)
    let exp = id_keys.x25519.private.diffie_hellman(&client_public.x25519);
    not_ok |= _ZERO_EXP[..].ct_eq(exp.as_bytes()).unwrap_u8();
    secret_input.append(&mut exp.as_bytes().to_vec());

    let (key_seed, auth) = derive_ntor_shared(
        secret_input,
        id,
        &id_keys.get_public(),
        client_public,
        &server_keys.get_public(),
    );

    // failed if not_ok != 0
    // if not_ok != 0 then scalar operations failed
    CtOption::new(HandshakeResult { key_seed, auth }, not_ok.ct_eq(&0_u8))
}
*/
