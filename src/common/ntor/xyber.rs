use pqc_kyber::*;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, ReusableSecret, StaticSecret};

const _ZERO_EXP: [u8; 32] = [0_u8; 32];

#[test]
fn kyber1024x25519_handshake_plain() {
    let mut rng = rand::thread_rng();

    // Generate Keypair
    let alice_secret = ReusableSecret::random_from_rng(&mut rng);
    let alice_public = PublicKey::from(&alice_secret);
    let keys_alice = keypair(&mut rng).expect("kyber keypair generation failed");
    // alice -> bob public keys
    let mut kyber1024x_pubkey = alice_public.as_bytes().to_vec();
    kyber1024x_pubkey.extend_from_slice(&keys_alice.public);

    assert_eq!(kyber1024x_pubkey.len(), 1600);

    let bob_secret = ReusableSecret::random_from_rng(&mut rng);
    let bob_public = PublicKey::from(&bob_secret);

    // Bob encapsulates a shared secret using Alice's public key
    let (ciphertext, shared_secret_bob) =
        encapsulate(&keys_alice.public, &mut rng).expect("bob encapsulation failed");
    let bob_shared_secret = bob_secret.diffie_hellman(&alice_public);

    // // Alice decapsulates a shared secret using the ciphertext sent by Bob
    let shared_secret_alice =
        decapsulate(&ciphertext, &keys_alice.secret).expect("alice decapsulation failed");
    let alice_shared_secret = alice_secret.diffie_hellman(&bob_public);

    assert_eq!(alice_shared_secret.as_bytes(), bob_shared_secret.as_bytes());
    assert_eq!(shared_secret_bob, shared_secret_alice);
}

#[test]
fn kyber1024_ake() {
    let mut rng = rand::thread_rng();

    // Server generates its keys
    let mut server = Ake::new();
    let server_kyber_id_keys = keypair(&mut rng).expect("key generation failed");

    // client generates new keys and begins the authenticated key exchange
    let mut client = Ake::new();
    let client_kyber_keys = keypair(&mut rng).expect("key generation failed");
    let client_init = client
        .client_init(&server_kyber_id_keys.public, &mut rng)
        .expect("client handshake failed");

    // client sends the init message, and its public key
    // client_init, client_kyber_keys.public

    // server computes the authenticated key exchange generating the
    // necessary materials for the client to compute a matching
    // authenticated shared secret based on the identity keys
    let server_send = server
        .server_receive(
            client_init,
            &client_kyber_keys.public,
            &server_kyber_id_keys.secret,
            &mut rng,
        )
        .expect("server hands_kyberhake failed");

    // server sends completion materials to client

    // client completes the computation of the authenticated shares secret
    client
        .client_confirm(server_send, &client_kyber_keys.secret)
        .expect("client handshake failed");

    // the shared secrets match
    assert_eq!(client.shared_secret, server.shared_secret);
}

#[test]
fn ntor_shared_secret_x25519() {
    let mut rng = rand::thread_rng();

    // long term server identity keys
    let server_id_keys = StaticSecret::random_from_rng(&mut rng);
    let id_public = PublicKey::from(&server_id_keys);

    // client session keys
    let client_keys = ReusableSecret::random_from_rng(&mut rng);
    let client_public = PublicKey::from(&client_keys);

    // client key exchange value to be sent to the server (elligator2 encoded)
    // i.e.  client_kex = client_x25519_pub.as_bytes();

    // --------------------[ Server Handshake ]--------------------
    let mut server_ok = 1;
    let mut server_secret_input: Vec<u8> = vec![];

    // server session keys
    let server_keys = ReusableSecret::random_from_rng(&mut rng);
    let server_public = PublicKey::from(&server_keys);

    // Server side uses EXP(X,y) | EXP(X,b)
    let exp = server_keys.diffie_hellman(&client_public);
    server_ok &= _ZERO_EXP[..].ct_ne(exp.as_bytes()).unwrap_u8();
    server_secret_input.append(&mut exp.as_bytes().to_vec());

    let exp = server_id_keys.diffie_hellman(&client_public);
    server_ok &= _ZERO_EXP[..].ct_ne(exp.as_bytes()).unwrap_u8();
    server_secret_input.append(&mut exp.as_bytes().to_vec());

    // the server's dh computations worked
    assert_eq!(server_ok, 1);

    // server key exchange value to be sent to the client (elligator2 encoded)
    // i.e.  server_kex = server_x25519_pub.to_bytes() + ciphertext;

    // --------------------[ Client Handshake ]--------------------
    let mut client_ok = 1;
    let mut client_secret_input: Vec<u8> = vec![];

    // Client side uses EXP(Y,x) | EXP(B,x)
    let exp = client_keys.diffie_hellman(&server_public);
    client_ok &= _ZERO_EXP[..].ct_ne(exp.as_bytes()).unwrap_u8();
    client_secret_input.append(&mut exp.as_bytes().to_vec());

    let exp = client_keys.diffie_hellman(&id_public);
    client_ok &= _ZERO_EXP[..].ct_ne(exp.as_bytes()).unwrap_u8();
    client_secret_input.append(&mut exp.as_bytes().to_vec());

    // the client's dh computations worked
    assert_eq!(client_ok, 1);

    // The derived shared secrets SHOULD match
    assert_eq!(server_secret_input, client_secret_input);
}

#[test]
fn draft_tls_westerbaan_xyber768d00_03() {
    // The name of the function says 768 because that is the name of the draft
    // rfc, however this tests using 1024 because that is the value I want to
    // use since my application doesn't have such specific constraints.
    //
    // also this fn should be independent of the kyber key size as that is
    // (currently) selected using a crate feature, without changing the
    // actual interface.

    let mut rng = rand::thread_rng();

    // client session keys
    let client_x25519 = ReusableSecret::random_from_rng(&mut rng);
    let client_x25519_pub = PublicKey::from(&client_x25519);
    let client_kyber = keypair(&mut rng).unwrap();

    // server session keys
    let server_x25519 = ReusableSecret::random_from_rng(&mut rng);
    let server_x25519_pub = PublicKey::from(&server_x25519);
    let server_kyber = keypair(&mut rng).unwrap();

    // For the client's share, the key_exchange value contains the
    // concatenation of the client's X25519 ephemeral share (32 bytes) and
    // the client's Kyber768Draft00 public key (1184 bytes).  The resulting
    // key_exchange value is 1216 bytes in length.
    //
    // i.e.  client_kex = client_x25519_pub.as_bytes() + client_kyber.public;

    // For the server's share, the key_exchange value contains the
    // concatenation of the server's X25519 ephemeral share (32 bytes) and
    // the Kyber768Draft00 ciphertext (1088 bytes) returned from
    // encapsulation for the client's public key.  The resulting
    // key_exchange value is 1120 bytes in length.

    let mut server_shared_secret = vec![];
    let mut server_ok: u8 = 1;
    let exp = server_x25519.diffie_hellman(&client_x25519_pub);
    server_ok &= _ZERO_EXP[..].ct_ne(exp.as_bytes()).unwrap_u8();
    server_shared_secret.append(&mut exp.as_bytes().to_vec());

    let (ciphertext, server_kyber_shared_secret) =
        encapsulate(&client_kyber.public, &mut rng).unwrap();
    server_shared_secret.append(&mut server_kyber_shared_secret.to_vec());

    // server Key exchange value to be sent to the client as described above
    // i.e.  server_kex = server_x25519_pub.to_bytes() + ciphertext;

    assert_eq!(server_ok, 1u8);

    // The shared secret is calculated as the concatenation of the X25519
    // shared secret (32 bytes) and the Kyber768Draft00 shared secret (32
    // bytes).  The resulting shared secret value is 64 bytes in length.
    let mut client_shared_secret = vec![];
    let mut client_ok = 1;
    let exp = client_x25519.diffie_hellman(&server_x25519_pub);
    client_ok &= _ZERO_EXP[..].ct_ne(exp.as_bytes()).unwrap_u8();
    client_shared_secret.append(&mut exp.to_bytes().to_vec());

    let client_kyber_shared_secret = decapsulate(&ciphertext, &client_kyber.secret).unwrap();
    client_shared_secret.append(&mut client_kyber_shared_secret.to_vec());

    assert_eq!(server_ok, 1u8);

    assert_eq!(client_shared_secret, server_shared_secret);
}

#[test]
fn ntor_shared_secret_xyber() {
    let mut rng = rand::thread_rng();

    // long term server identity keys pre-shared, out of band
    let server_id_keys = StaticSecret::random_from_rng(&mut rng);
    let id_public = PublicKey::from(&server_id_keys);
    // let mut server_ake = Ake::new();
    let server_kyber_id_keys = keypair(&mut rng).expect("key generation failed");

    // client generates new session keys and begins the authenticated key
    // exchange using the servers long term xyber identity  public key(s).
    let client_keys = ReusableSecret::random_from_rng(&mut rng);
    let client_public = PublicKey::from(&client_keys);
    let client_kyber_keys = keypair(&mut rng).expect("key generation failed");
    let mut client_ake = Ake::new();

    let client_init = client_ake
        .client_init(&server_kyber_id_keys.public, &mut rng)
        .expect("client kyber ake failed");

    // client key exchange value to be sent to the server (elligator2 encoded),
    // the clientAkeInit message and the clients kyber session key.
    // i.e.  client_kex = client_public.as_bytes() + client_init + client_kyber_keys.public;

    // --------------------[ Server Handshake ]--------------------
    let mut server_ok = 1;
    let mut server_secret_input: Vec<u8> = vec![];

    // server session keys
    let server_keys = ReusableSecret::random_from_rng(&mut rng);
    let server_public = PublicKey::from(&server_keys);
    let server_kyber_keys = keypair(&mut rng).expect("key generation failed");
    let mut server_ake = Ake::new();

    // Server side uses EXP(X,y) | EXP(X,b)
    let exp = server_keys.diffie_hellman(&client_public);
    server_ok &= _ZERO_EXP[..].ct_ne(exp.as_bytes()).unwrap_u8();
    server_secret_input.append(&mut exp.as_bytes().to_vec());

    let (session_ciphertext, server_session_kyber_shared_secret) =
        encapsulate(&client_kyber_keys.public, &mut rng).expect("server session KEx_enc failed");
    server_secret_input.append(&mut server_session_kyber_shared_secret.to_vec());

    let exp = server_id_keys.diffie_hellman(&client_public);
    server_ok &= _ZERO_EXP[..].ct_ne(exp.as_bytes()).unwrap_u8();
    server_secret_input.append(&mut exp.as_bytes().to_vec());

    // the server's dh computations worked
    assert_eq!(server_ok, 1);

    // server computes the authenticated key exchange generating the
    // necessary materials for the client to compute a matching
    // authenticated shared secret based on the identity keys
    let server_send = server_ake
        .server_receive(
            client_init,
            &client_kyber_keys.public,
            &server_kyber_id_keys.secret,
            &mut rng,
        )
        .expect("server kyber handshake failed");
    server_secret_input.append(&mut server_ake.shared_secret.to_vec());

    // server key exchange value to be sent to the client includes the session
    // pubkey (elligator2 encoded), the server's AkeResponse message, the
    // session kyber key exchange ciphertext, and the server's kyber session
    // public key.
    //
    // i.e.  server_kex = server_public.as_bytes() + server_send + ciphertext + server_kyber_keys.public;

    // --------------------[ Client Handshake ]--------------------
    let mut client_ok = 1;
    let mut client_secret_input: Vec<u8> = vec![];

    // Client side uses EXP(Y,x) | EXP(B,x)
    let exp = client_keys.diffie_hellman(&server_public);
    client_ok &= _ZERO_EXP[..].ct_ne(exp.as_bytes()).unwrap_u8();
    client_secret_input.append(&mut exp.as_bytes().to_vec());

    let client_session_kyber_shared_secret =
        decapsulate(&session_ciphertext, &client_kyber_keys.secret)
            .expect("client session KEx_dec failed");
    client_secret_input.append(&mut client_session_kyber_shared_secret.to_vec());

    let exp = client_keys.diffie_hellman(&id_public);
    client_ok &= _ZERO_EXP[..].ct_ne(exp.as_bytes()).unwrap_u8();
    client_secret_input.append(&mut exp.as_bytes().to_vec());

    // the client's dh computations worked
    assert_eq!(client_ok, 1);

    // client completes the computation of the authenticated shares secret
    client_ake
        .client_confirm(server_send, &client_kyber_keys.secret)
        .expect("client handshake failed");
    client_secret_input.append(&mut server_ake.shared_secret.to_vec());

    // ---------------[ The derived shared secrets SHOULD match ]---------------
    assert_eq!(server_secret_input, client_secret_input);
}
