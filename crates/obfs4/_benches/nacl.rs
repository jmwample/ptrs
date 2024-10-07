use criterion::{black_box, criterion_group, criterion_main, Criterion};

use crypto_secretbox::{
    aead::{
        generic_array::GenericArray, heapless::Vec, Aead, AeadCore, AeadInPlace, KeyInit, OsRng,
    },
    XSalsa20Poly1305,
};

fn f() {
    let key = XSalsa20Poly1305::generate_key(&mut OsRng);
    let cipher = XSalsa20Poly1305::new(&key);
    let nonce = XSalsa20Poly1305::generate_nonce(&mut OsRng); // unique per message
    let ciphertext = cipher
        .encrypt(&nonce, black_box("plaintext message".as_ref()))
        .unwrap();
    let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref()).unwrap();
    assert_eq!(&plaintext, b"plaintext message");
}

fn f1() {
    let key = XSalsa20Poly1305::generate_key(&mut OsRng);
    let cipher = XSalsa20Poly1305::new(&key);
    let nonce = XSalsa20Poly1305::generate_nonce(&mut OsRng); // unique per message

    let mut buffer: Vec<u8, 128> = Vec::new(); // Note: buffer needs 16-bytes overhead for auth tag
    buffer
        .extend_from_slice(black_box(b"plaintext message"))
        .unwrap();

    // Encrypt `buffer` in-place, replacing the plaintext contents with ciphertext
    cipher.encrypt_in_place(&nonce, b"", &mut buffer).unwrap();

    // `buffer` now contains the message ciphertext
    assert_ne!(&buffer, b"plaintext message");

    // Decrypt `buffer` in-place, replacing its ciphertext context with the original plaintext
    cipher.decrypt_in_place(&nonce, b"", &mut buffer).unwrap();
    assert_eq!(&buffer, b"plaintext message");
}

fn f2() {
    let key = GenericArray::from_slice(b"an example very very secret key.");
    let cipher = XSalsa20Poly1305::new(key);

    let nonce = GenericArray::from_slice(b"extra long unique nonce!"); // 24-bytes; unique

    let mut buffer: Vec<u8, 128> = Vec::new();
    buffer
        .extend_from_slice(black_box(b"plaintext message"))
        .unwrap();

    // Encrypt `buffer` in-place, replacing the plaintext contents with ciphertext
    cipher
        .encrypt_in_place(nonce, b"", &mut buffer)
        .expect("encryption failure!");

    // `buffer` now contains the message ciphertext
    assert_ne!(&buffer, b"plaintext message");

    // Decrypt `buffer` in-place, replacing its ciphertext context with the original plaintext
    cipher
        .decrypt_in_place(nonce, b"", &mut buffer)
        .expect("decryption failure!");
    assert_eq!(&buffer, b"plaintext message");
}

fn nacl(c: &mut Criterion) {
    c.bench_function("rust-crypto nacl", |b| b.iter(|| f()));
    c.bench_function("rust-crypto nacl-heapless1", |b| b.iter(|| f1()));
    c.bench_function("rust-crypto nacl-heapless2", |b| b.iter(|| f2()));
}

criterion_group!(benches, nacl,);
criterion_main!(benches);
