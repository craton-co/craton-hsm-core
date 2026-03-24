// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
// Known-Answer Tests (KAT) for cryptographic operations
use craton_hsm::crypto::{encrypt, keygen, sign};

#[test]
fn test_aes_256_gcm_roundtrip() {
    let key = keygen::generate_aes_key(32, false).unwrap();
    let plaintext = b"Hello, Craton HSM! This is a test message.";

    let ciphertext = encrypt::aes_256_gcm_encrypt(key.as_bytes(), plaintext).unwrap();
    assert_ne!(&ciphertext[12..], plaintext.as_slice()); // Must be encrypted

    let decrypted = encrypt::aes_256_gcm_decrypt(key.as_bytes(), &ciphertext).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_aes_gcm_different_nonces() {
    let key = keygen::generate_aes_key(32, false).unwrap();
    let plaintext = b"Same plaintext";

    let ct1 = encrypt::aes_256_gcm_encrypt(key.as_bytes(), plaintext).unwrap();
    let ct2 = encrypt::aes_256_gcm_encrypt(key.as_bytes(), plaintext).unwrap();

    // Nonces should be different (first 12 bytes)
    assert_ne!(&ct1[..12], &ct2[..12]);
}

#[test]
fn test_aes_gcm_tamper_detection() {
    let key = keygen::generate_aes_key(32, false).unwrap();
    let plaintext = b"Integrity test";

    let mut ciphertext = encrypt::aes_256_gcm_encrypt(key.as_bytes(), plaintext).unwrap();
    // Tamper with the ciphertext
    if let Some(byte) = ciphertext.last_mut() {
        *byte ^= 0xFF;
    }

    let result = encrypt::aes_256_gcm_decrypt(key.as_bytes(), &ciphertext);
    assert!(
        result.is_err(),
        "Tampered ciphertext should fail decryption"
    );
}

#[test]
fn test_aes_gcm_wrong_key() {
    let key1 = keygen::generate_aes_key(32, false).unwrap();
    let key2 = keygen::generate_aes_key(32, false).unwrap();
    let plaintext = b"Wrong key test";

    let ciphertext = encrypt::aes_256_gcm_encrypt(key1.as_bytes(), plaintext).unwrap();
    let result = encrypt::aes_256_gcm_decrypt(key2.as_bytes(), &ciphertext);
    assert!(result.is_err(), "Decryption with wrong key should fail");
}

#[test]
fn test_aes_key_sizes() {
    assert!(keygen::generate_aes_key(16, false).is_ok());
    assert!(keygen::generate_aes_key(24, false).is_ok());
    assert!(keygen::generate_aes_key(32, false).is_ok());
    assert!(keygen::generate_aes_key(15, false).is_err());
    assert!(keygen::generate_aes_key(64, false).is_err());
}

#[test]
fn test_aes_gcm_empty_plaintext() {
    let key = keygen::generate_aes_key(32, false).unwrap();
    let plaintext = b"";

    let ciphertext = encrypt::aes_256_gcm_encrypt(key.as_bytes(), plaintext).unwrap();
    let decrypted = encrypt::aes_256_gcm_decrypt(key.as_bytes(), &ciphertext).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_rsa_2048_sign_verify_sha256() {
    let (priv_der, modulus, pub_exp) = keygen::generate_rsa_key_pair(2048, false).unwrap();
    let message = b"Test message for RSA PKCS#1 v1.5 SHA-256";

    let signature =
        sign::rsa_pkcs1v15_sign(priv_der.as_bytes(), message, Some(sign::HashAlg::Sha256)).unwrap();

    assert!(!signature.is_empty());
    assert_eq!(signature.len(), 256); // 2048-bit key -> 256-byte signature

    let valid = sign::rsa_pkcs1v15_verify(
        &modulus,
        &pub_exp,
        message,
        &signature,
        Some(sign::HashAlg::Sha256),
    )
    .unwrap();
    assert!(valid, "Signature verification should succeed");
}

#[test]
fn test_rsa_sign_verify_sha384() {
    let (priv_der, modulus, pub_exp) = keygen::generate_rsa_key_pair(2048, false).unwrap();
    let message = b"SHA-384 RSA test";

    let signature =
        sign::rsa_pkcs1v15_sign(priv_der.as_bytes(), message, Some(sign::HashAlg::Sha384)).unwrap();

    let valid = sign::rsa_pkcs1v15_verify(
        &modulus,
        &pub_exp,
        message,
        &signature,
        Some(sign::HashAlg::Sha384),
    )
    .unwrap();
    assert!(valid);
}

#[test]
fn test_rsa_sign_verify_sha512() {
    let (priv_der, modulus, pub_exp) = keygen::generate_rsa_key_pair(2048, false).unwrap();
    let message = b"SHA-512 RSA test";

    let signature =
        sign::rsa_pkcs1v15_sign(priv_der.as_bytes(), message, Some(sign::HashAlg::Sha512)).unwrap();

    let valid = sign::rsa_pkcs1v15_verify(
        &modulus,
        &pub_exp,
        message,
        &signature,
        Some(sign::HashAlg::Sha512),
    )
    .unwrap();
    assert!(valid);
}

#[test]
fn test_rsa_verify_wrong_message() {
    let (priv_der, modulus, pub_exp) = keygen::generate_rsa_key_pair(2048, false).unwrap();

    let signature = sign::rsa_pkcs1v15_sign(
        priv_der.as_bytes(),
        b"original message",
        Some(sign::HashAlg::Sha256),
    )
    .unwrap();

    let valid = sign::rsa_pkcs1v15_verify(
        &modulus,
        &pub_exp,
        b"different message",
        &signature,
        Some(sign::HashAlg::Sha256),
    )
    .unwrap();
    assert!(!valid, "Verification of wrong message should fail");
}

#[test]
fn test_rsa_verify_wrong_key() {
    let (priv_der1, _, _) = keygen::generate_rsa_key_pair(2048, false).unwrap();
    let (_, modulus2, pub_exp2) = keygen::generate_rsa_key_pair(2048, false).unwrap();
    let message = b"Wrong key test";

    let signature =
        sign::rsa_pkcs1v15_sign(priv_der1.as_bytes(), message, Some(sign::HashAlg::Sha256))
            .unwrap();

    let valid = sign::rsa_pkcs1v15_verify(
        &modulus2,
        &pub_exp2,
        message,
        &signature,
        Some(sign::HashAlg::Sha256),
    )
    .unwrap();
    assert!(!valid, "Verification with wrong public key should fail");
}

#[test]
fn test_rsa_key_size_validation() {
    assert!(keygen::generate_rsa_key_pair(2048, false).is_ok());
    assert!(keygen::generate_rsa_key_pair(3072, false).is_ok());
    assert!(keygen::generate_rsa_key_pair(1024, false).is_err());
    assert!(keygen::generate_rsa_key_pair(512, false).is_err());
}

// ============================================================================
// NIST Known-Answer Tests (KAT)
// ============================================================================

/// AES-256-GCM KAT: encrypt with known key, verify decrypt roundtrip.
/// Since our API prepends a random nonce, we can't check exact ciphertext,
/// but we verify the decrypt produces the original plaintext.
#[test]
fn test_aes_256_gcm_kat_roundtrip_integrity() {
    // NIST GCM test key (256-bit)
    let key =
        hex::decode("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308").unwrap();
    let plaintext = hex::decode(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
         1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
    )
    .unwrap();

    let ciphertext = encrypt::aes_256_gcm_encrypt(&key, &plaintext).unwrap();
    let decrypted = encrypt::aes_256_gcm_decrypt(&key, &ciphertext).unwrap();
    assert_eq!(
        decrypted, plaintext,
        "AES-256-GCM KAT: decrypt must match plaintext"
    );
}

/// AES-256-CBC KAT: NIST SP 800-38A F.2.5 — AES-256-CBC encrypt
/// Key: 603deb1015ca71be2b73aef0857d7781 1f352c073b6108d72d9810a30914dff4
/// IV:  000102030405060708090a0b0c0d0e0f
/// PT block 1: 6bc1bee22e409f96e93d7e117393172a
/// CT block 1: f58c4c04d6e5f1ba779eabfb5f7bfbd6
#[test]
fn test_aes_256_cbc_nist_kat() {
    let key =
        hex::decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4").unwrap();
    let iv = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    // Use full 4-block plaintext from NIST SP 800-38A F.2.5
    let plaintext = hex::decode(
        "6bc1bee22e409f96e93d7e117393172a\
         ae2d8a571e03ac9c9eb76fac45af8e51\
         30c81c46a35ce411e5fbc1191a0a52ef\
         f69f2445df4f9b17ad2b417be66c3710",
    )
    .unwrap();

    // Encrypt
    let ciphertext = encrypt::aes_cbc_encrypt(&key, &iv, &plaintext).unwrap();

    // NIST expected ciphertext (4 blocks)
    let expected_ct = hex::decode(
        "f58c4c04d6e5f1ba779eabfb5f7bfbd6\
         9cfc4e967edb808d679f777bc6702c7d\
         39f23369a9d9bacfa530e26304231461\
         b2eb05e2c39be9fcda6c19078c6a9d1b",
    )
    .unwrap();

    // Our CBC adds PKCS#7 padding, so ciphertext will be 64 + 16 = 80 bytes.
    // The first 64 bytes should match the NIST vector exactly.
    assert_eq!(
        &ciphertext[..64],
        &expected_ct[..],
        "AES-256-CBC: first 4 blocks must match NIST SP 800-38A F.2.5"
    );

    // Verify decrypt recovers plaintext
    let decrypted = encrypt::aes_cbc_decrypt(&key, &iv, &ciphertext).unwrap();
    assert_eq!(
        decrypted, plaintext,
        "AES-256-CBC decrypt must match original plaintext"
    );
}

/// AES-256-CTR KAT: NIST SP 800-38A F.5.5 — AES-256-CTR encrypt
/// Key: 603deb1015ca71be2b73aef0857d7781 1f352c073b6108d72d9810a30914dff4
/// IV (Counter): f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
/// PT block 1: 6bc1bee22e409f96e93d7e117393172a
/// CT block 1: 601ec313775789a5b7a7f504bbf3d228
#[test]
fn test_aes_256_ctr_nist_kat() {
    let key =
        hex::decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4").unwrap();
    let iv = hex::decode("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").unwrap();
    let plaintext = hex::decode(
        "6bc1bee22e409f96e93d7e117393172a\
         ae2d8a571e03ac9c9eb76fac45af8e51\
         30c81c46a35ce411e5fbc1191a0a52ef\
         f69f2445df4f9b17ad2b417be66c3710",
    )
    .unwrap();

    let expected_ct = hex::decode(
        "601ec313775789a5b7a7f504bbf3d228\
         f443e3ca4d62b59aca84e990cacaf5c5\
         2b0930daa23de94ce87017ba2d84988d\
         dfc9c58db67aada613c2dd08457941a6",
    )
    .unwrap();

    let ciphertext = encrypt::aes_ctr_crypt(&key, &iv, &plaintext).unwrap();
    assert_eq!(
        ciphertext, expected_ct,
        "AES-256-CTR must match NIST SP 800-38A F.5.5"
    );

    // CTR mode: encrypt again to decrypt
    let decrypted = encrypt::aes_ctr_crypt(&key, &iv, &ciphertext).unwrap();
    assert_eq!(
        decrypted, plaintext,
        "AES-256-CTR decrypt must match original plaintext"
    );
}

/// SHA-256 KAT: NIST FIPS 180-4 example
#[test]
fn test_sha256_nist_kat() {
    use sha2::{Digest, Sha256};
    // "abc" → ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad
    let expected =
        hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad").unwrap();
    let result = Sha256::digest(b"abc");
    assert_eq!(
        result.as_slice(),
        &expected[..],
        "SHA-256 KAT: NIST FIPS 180-4 'abc'"
    );
}

/// SHA-384 KAT: NIST FIPS 180-4 — full 48-byte digest for "abc"
#[test]
fn test_sha384_kat_full_digest() {
    use sha2::{Digest, Sha384};
    let expected = hex::decode(
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
         8086072ba1e7cc2358baeca134c825a7",
    )
    .unwrap();
    let result = Sha384::digest(b"abc");
    assert_eq!(
        result.as_slice(),
        &expected[..],
        "SHA-384 KAT: full 48-byte digest for 'abc'"
    );
}

/// SHA-512 KAT: NIST FIPS 180-4 — full 64-byte digest for "abc"
#[test]
fn test_sha512_kat_full_digest() {
    use sha2::{Digest, Sha512};
    let expected = hex::decode(
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
         2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    )
    .unwrap();
    let result = Sha512::digest(b"abc");
    assert_eq!(
        result.as_slice(),
        &expected[..],
        "SHA-512 KAT: full 64-byte digest for 'abc'"
    );
}

/// HMAC-SHA256 KAT: RFC 4231 Test Case 2
#[test]
fn test_hmac_sha256_rfc4231_tc2() {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let key = b"Jefe";
    let data = b"what do ya want for nothing?";
    let expected =
        hex::decode("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843").unwrap();

    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(data);
    let result = mac.finalize().into_bytes();
    assert_eq!(
        result.as_slice(),
        &expected[..],
        "HMAC-SHA256 KAT: RFC 4231 TC2"
    );
}
