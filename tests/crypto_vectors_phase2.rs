// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
// Phase 2 Known-Answer Tests (KAT) for all new cryptographic operations
use craton_hsm::crypto::{derive, digest, encrypt, keygen, sign, wrap};

// ============================================================================
// ECDSA P-256
// ============================================================================

#[test]
fn test_ecdsa_p256_sign_verify() {
    let (priv_key, pub_key) = keygen::generate_ec_p256_key_pair().unwrap();
    let message = b"ECDSA P-256 test message";

    let signature = sign::ecdsa_p256_sign(priv_key.as_bytes(), message).unwrap();
    assert!(!signature.is_empty());

    let valid = sign::ecdsa_p256_verify(&pub_key, message, &signature).unwrap();
    assert!(valid, "P-256 signature should verify");
}

#[test]
fn test_ecdsa_p256_wrong_message() {
    let (priv_key, pub_key) = keygen::generate_ec_p256_key_pair().unwrap();

    let signature = sign::ecdsa_p256_sign(priv_key.as_bytes(), b"original").unwrap();
    let valid = sign::ecdsa_p256_verify(&pub_key, b"modified", &signature).unwrap();
    assert!(!valid, "P-256 verify with wrong message should fail");
}

#[test]
fn test_ecdsa_p256_wrong_key() {
    let (priv_key1, _) = keygen::generate_ec_p256_key_pair().unwrap();
    let (_, pub_key2) = keygen::generate_ec_p256_key_pair().unwrap();
    let message = b"wrong key test";

    let signature = sign::ecdsa_p256_sign(priv_key1.as_bytes(), message).unwrap();
    let valid = sign::ecdsa_p256_verify(&pub_key2, message, &signature).unwrap();
    assert!(!valid, "P-256 verify with wrong key should fail");
}

// ============================================================================
// ECDSA P-384
// ============================================================================

#[test]
fn test_ecdsa_p384_sign_verify() {
    let (priv_key, pub_key) = keygen::generate_ec_p384_key_pair().unwrap();
    let message = b"ECDSA P-384 test message";

    let signature = sign::ecdsa_p384_sign(priv_key.as_bytes(), message).unwrap();
    assert!(!signature.is_empty());

    let valid = sign::ecdsa_p384_verify(&pub_key, message, &signature).unwrap();
    assert!(valid, "P-384 signature should verify");
}

#[test]
fn test_ecdsa_p384_wrong_message() {
    let (priv_key, pub_key) = keygen::generate_ec_p384_key_pair().unwrap();

    let signature = sign::ecdsa_p384_sign(priv_key.as_bytes(), b"original").unwrap();
    let valid = sign::ecdsa_p384_verify(&pub_key, b"modified", &signature).unwrap();
    assert!(!valid, "P-384 verify with wrong message should fail");
}

// ============================================================================
// Ed25519
// ============================================================================

#[test]
fn test_ed25519_sign_verify() {
    let (priv_key, pub_key) = keygen::generate_ed25519_key_pair().unwrap();
    let message = b"Ed25519 test message";

    let signature = sign::ed25519_sign(priv_key.as_bytes(), message).unwrap();
    assert_eq!(signature.len(), 64, "Ed25519 signature must be 64 bytes");

    let valid = sign::ed25519_verify(&pub_key, message, &signature).unwrap();
    assert!(valid, "Ed25519 signature should verify");
}

#[test]
fn test_ed25519_wrong_message() {
    let (priv_key, pub_key) = keygen::generate_ed25519_key_pair().unwrap();

    let signature = sign::ed25519_sign(priv_key.as_bytes(), b"original").unwrap();
    let valid = sign::ed25519_verify(&pub_key, b"modified", &signature).unwrap();
    assert!(!valid, "Ed25519 verify with wrong message should fail");
}

#[test]
fn test_ed25519_wrong_key() {
    let (priv_key1, _) = keygen::generate_ed25519_key_pair().unwrap();
    let (_, pub_key2) = keygen::generate_ed25519_key_pair().unwrap();
    let message = b"wrong key test";

    let signature = sign::ed25519_sign(priv_key1.as_bytes(), message).unwrap();
    let valid = sign::ed25519_verify(&pub_key2, message, &signature).unwrap();
    assert!(!valid, "Ed25519 verify with wrong key should fail");
}

#[test]
fn test_ed25519_key_sizes() {
    let (priv_key, pub_key) = keygen::generate_ed25519_key_pair().unwrap();
    assert_eq!(
        priv_key.as_bytes().len(),
        32,
        "Ed25519 private key must be 32 bytes"
    );
    assert_eq!(pub_key.len(), 32, "Ed25519 public key must be 32 bytes");
}

// ============================================================================
// RSA-PSS
// ============================================================================

#[test]
fn test_rsa_pss_sign_verify_sha256() {
    let (priv_der, modulus, pub_exp) = keygen::generate_rsa_key_pair(2048, false).unwrap();
    let message = b"RSA-PSS SHA-256 test";

    let signature =
        sign::rsa_pss_sign(priv_der.as_bytes(), message, sign::HashAlg::Sha256).unwrap();
    assert_eq!(signature.len(), 256);

    let valid = sign::rsa_pss_verify(
        &modulus,
        &pub_exp,
        message,
        &signature,
        sign::HashAlg::Sha256,
    )
    .unwrap();
    assert!(valid, "RSA-PSS SHA-256 signature should verify");
}

#[test]
fn test_rsa_pss_sign_verify_sha384() {
    let (priv_der, modulus, pub_exp) = keygen::generate_rsa_key_pair(2048, false).unwrap();
    let message = b"RSA-PSS SHA-384 test";

    let signature =
        sign::rsa_pss_sign(priv_der.as_bytes(), message, sign::HashAlg::Sha384).unwrap();

    let valid = sign::rsa_pss_verify(
        &modulus,
        &pub_exp,
        message,
        &signature,
        sign::HashAlg::Sha384,
    )
    .unwrap();
    assert!(valid, "RSA-PSS SHA-384 signature should verify");
}

#[test]
fn test_rsa_pss_sign_verify_sha512() {
    let (priv_der, modulus, pub_exp) = keygen::generate_rsa_key_pair(2048, false).unwrap();
    let message = b"RSA-PSS SHA-512 test";

    let signature =
        sign::rsa_pss_sign(priv_der.as_bytes(), message, sign::HashAlg::Sha512).unwrap();

    let valid = sign::rsa_pss_verify(
        &modulus,
        &pub_exp,
        message,
        &signature,
        sign::HashAlg::Sha512,
    )
    .unwrap();
    assert!(valid, "RSA-PSS SHA-512 signature should verify");
}

#[test]
fn test_rsa_pss_wrong_message() {
    let (priv_der, modulus, pub_exp) = keygen::generate_rsa_key_pair(2048, false).unwrap();

    let signature =
        sign::rsa_pss_sign(priv_der.as_bytes(), b"original", sign::HashAlg::Sha256).unwrap();

    let valid = sign::rsa_pss_verify(
        &modulus,
        &pub_exp,
        b"different",
        &signature,
        sign::HashAlg::Sha256,
    )
    .unwrap();
    assert!(!valid, "RSA-PSS verify with wrong message should fail");
}

// ============================================================================
// RSA-OAEP
// ============================================================================

#[test]
fn test_rsa_oaep_encrypt_decrypt() {
    let (priv_der, modulus, pub_exp) = keygen::generate_rsa_key_pair(2048, false).unwrap();
    let plaintext = b"RSA-OAEP test plaintext";

    let ciphertext =
        sign::rsa_oaep_encrypt(&modulus, &pub_exp, plaintext, sign::OaepHash::Sha256).unwrap();
    assert_ne!(ciphertext.as_slice(), plaintext.as_slice());

    let decrypted =
        sign::rsa_oaep_decrypt(priv_der.as_bytes(), &ciphertext, sign::OaepHash::Sha256).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_rsa_oaep_wrong_key() {
    let (_, modulus, pub_exp) = keygen::generate_rsa_key_pair(2048, false).unwrap();
    let (priv_der2, _, _) = keygen::generate_rsa_key_pair(2048, false).unwrap();
    let plaintext = b"wrong key test";

    let ciphertext =
        sign::rsa_oaep_encrypt(&modulus, &pub_exp, plaintext, sign::OaepHash::Sha256).unwrap();
    let result = sign::rsa_oaep_decrypt(priv_der2.as_bytes(), &ciphertext, sign::OaepHash::Sha256);
    assert!(
        result.is_err(),
        "RSA-OAEP decrypt with wrong key should fail"
    );
}

// ============================================================================
// AES-CBC
// ============================================================================

#[test]
fn test_aes_cbc_128_roundtrip() {
    let key = keygen::generate_aes_key(16, false).unwrap();
    let iv = [0x11u8; 16]; // Non-zero IV (all-zero IV is rejected)
    let plaintext = b"AES-CBC-128 test message padding!"; // 33 bytes

    let ciphertext = encrypt::aes_cbc_encrypt(key.as_bytes(), &iv, plaintext).unwrap();
    assert_ne!(ciphertext.as_slice(), plaintext.as_slice());

    let decrypted = encrypt::aes_cbc_decrypt(key.as_bytes(), &iv, &ciphertext).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_aes_cbc_192_roundtrip() {
    let key = keygen::generate_aes_key(24, false).unwrap();
    let iv = [0x42u8; 16];
    let plaintext = b"AES-CBC-192 test";

    let ciphertext = encrypt::aes_cbc_encrypt(key.as_bytes(), &iv, plaintext).unwrap();
    let decrypted = encrypt::aes_cbc_decrypt(key.as_bytes(), &iv, &ciphertext).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_aes_cbc_256_roundtrip() {
    let key = keygen::generate_aes_key(32, false).unwrap();
    let iv = [0xFFu8; 16];
    let plaintext = b"AES-CBC-256 test message for roundtrip verification";

    let ciphertext = encrypt::aes_cbc_encrypt(key.as_bytes(), &iv, plaintext).unwrap();
    let decrypted = encrypt::aes_cbc_decrypt(key.as_bytes(), &iv, &ciphertext).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_aes_cbc_wrong_key() {
    let key1 = keygen::generate_aes_key(32, false).unwrap();
    let key2 = keygen::generate_aes_key(32, false).unwrap();
    let iv = [0x22u8; 16];
    let plaintext = b"wrong key test";

    let ciphertext = encrypt::aes_cbc_encrypt(key1.as_bytes(), &iv, plaintext).unwrap();
    let result = encrypt::aes_cbc_decrypt(key2.as_bytes(), &iv, &ciphertext);
    // Wrong key should produce padding error
    assert!(
        result.is_err(),
        "AES-CBC with wrong key should fail (padding error)"
    );
}

#[test]
fn test_aes_cbc_wrong_iv() {
    let key = keygen::generate_aes_key(32, false).unwrap();
    let iv1 = [0x33u8; 16];
    let iv2 = [0x44u8; 16];
    let plaintext = b"This message is exactly 32 bytes"; // 32 bytes

    let ciphertext = encrypt::aes_cbc_encrypt(key.as_bytes(), &iv1, plaintext).unwrap();
    // Wrong IV decrypts but produces garbled first block
    let decrypted = encrypt::aes_cbc_decrypt(key.as_bytes(), &iv2, &ciphertext);
    // May succeed or fail depending on padding — either way, data is wrong
    if let Ok(result) = decrypted {
        assert_ne!(result.as_slice(), plaintext.as_slice());
    }
}

#[test]
fn test_aes_cbc_invalid_iv_length() {
    let key = keygen::generate_aes_key(32, false).unwrap();
    let short_iv = [0u8; 8];
    let plaintext = b"test";

    let result = encrypt::aes_cbc_encrypt(key.as_bytes(), &short_iv, plaintext);
    assert!(result.is_err(), "Short IV should be rejected");
}

#[test]
fn test_aes_cbc_pkcs7_padding() {
    let key = keygen::generate_aes_key(32, false).unwrap();

    // Test various plaintext lengths to exercise padding.
    // Each iteration uses a unique IV to satisfy IV-reuse detection.
    for (idx, len) in [0, 1, 15, 16, 17, 31, 32, 33, 100].iter().enumerate() {
        let mut iv = [0x55u8; 16];
        iv[0] = idx as u8; // unique IV per iteration
        let plaintext = vec![0x42u8; *len];
        let ciphertext = encrypt::aes_cbc_encrypt(key.as_bytes(), &iv, &plaintext).unwrap();
        // Ciphertext should be a multiple of 16 and at least 16 bytes (PKCS7 always pads)
        assert_eq!(ciphertext.len() % 16, 0);
        assert!(ciphertext.len() >= 16);
        let decrypted = encrypt::aes_cbc_decrypt(key.as_bytes(), &iv, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}

// ============================================================================
// AES-CTR
// ============================================================================

#[test]
fn test_aes_ctr_128_roundtrip() {
    let key = keygen::generate_aes_key(16, false).unwrap();
    let iv = [0x66u8; 16];
    let plaintext = b"AES-CTR-128 test message";

    let ciphertext = encrypt::aes_ctr_crypt(key.as_bytes(), &iv, plaintext).unwrap();
    assert_ne!(ciphertext.as_slice(), plaintext.as_slice());
    assert_eq!(ciphertext.len(), plaintext.len()); // CTR is a stream cipher

    let decrypted = encrypt::aes_ctr_crypt(key.as_bytes(), &iv, &ciphertext).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_aes_ctr_256_roundtrip() {
    let key = keygen::generate_aes_key(32, false).unwrap();
    let iv = [0xABu8; 16];
    let plaintext = b"AES-CTR-256 test message for roundtrip";

    let ciphertext = encrypt::aes_ctr_crypt(key.as_bytes(), &iv, plaintext).unwrap();
    let decrypted = encrypt::aes_ctr_crypt(key.as_bytes(), &iv, &ciphertext).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_aes_ctr_no_padding() {
    let key = keygen::generate_aes_key(32, false).unwrap();
    let iv = [0x77u8; 16];

    // CTR mode: ciphertext length == plaintext length (no padding)
    for len in [1, 7, 15, 16, 17, 31, 100] {
        let plaintext = vec![0x55u8; len];
        let ciphertext = encrypt::aes_ctr_crypt(key.as_bytes(), &iv, &plaintext).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len());
        let decrypted = encrypt::aes_ctr_crypt(key.as_bytes(), &iv, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}

#[test]
fn test_aes_ctr_invalid_iv_length() {
    let key = keygen::generate_aes_key(32, false).unwrap();
    let short_iv = [0u8; 12]; // CTR needs 16-byte IV
    let plaintext = b"test";

    let result = encrypt::aes_ctr_crypt(key.as_bytes(), &short_iv, plaintext);
    assert!(result.is_err(), "Short IV should be rejected for CTR mode");
}

// ============================================================================
// Digest (SHA-1, SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512)
// ============================================================================

#[test]
fn test_sha1_digest() {
    use craton_hsm::pkcs11_abi::constants::CKM_SHA_1;
    let data = b"The quick brown fox jumps over the lazy dog";
    let result = digest::compute_digest(CKM_SHA_1, data).unwrap();
    assert_eq!(result.len(), 20);
    // Known SHA-1 hash of this string
    let expected = hex::decode("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12").unwrap();
    assert_eq!(result, expected);
}

#[test]
fn test_sha256_digest() {
    use craton_hsm::pkcs11_abi::constants::CKM_SHA256;
    let data = b"";
    let result = digest::compute_digest(CKM_SHA256, data).unwrap();
    assert_eq!(result.len(), 32);
    // SHA-256 of empty string
    let expected =
        hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").unwrap();
    assert_eq!(result, expected);
}

#[test]
fn test_sha384_digest() {
    use craton_hsm::pkcs11_abi::constants::CKM_SHA384;
    let data = b"abc";
    let result = digest::compute_digest(CKM_SHA384, data).unwrap();
    assert_eq!(result.len(), 48);
    let expected = hex::decode("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7").unwrap();
    assert_eq!(result, expected);
}

#[test]
fn test_sha512_digest() {
    use craton_hsm::pkcs11_abi::constants::CKM_SHA512;
    let data = b"abc";
    let result = digest::compute_digest(CKM_SHA512, data).unwrap();
    assert_eq!(result.len(), 64);
    let expected = hex::decode("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f").unwrap();
    assert_eq!(result, expected);
}

#[test]
fn test_sha3_256_digest() {
    use craton_hsm::pkcs11_abi::constants::CKM_SHA3_256;
    let data = b"";
    let result = digest::compute_digest(CKM_SHA3_256, data).unwrap();
    assert_eq!(result.len(), 32);
    // SHA3-256 of empty string
    let expected =
        hex::decode("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a").unwrap();
    assert_eq!(result, expected);
}

#[test]
fn test_sha3_384_digest() {
    use craton_hsm::pkcs11_abi::constants::CKM_SHA3_384;
    let data = b"";
    let result = digest::compute_digest(CKM_SHA3_384, data).unwrap();
    assert_eq!(result.len(), 48);
    let expected = hex::decode("0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004").unwrap();
    assert_eq!(result, expected);
}

#[test]
fn test_sha3_512_digest() {
    use craton_hsm::pkcs11_abi::constants::CKM_SHA3_512;
    let data = b"";
    let result = digest::compute_digest(CKM_SHA3_512, data).unwrap();
    assert_eq!(result.len(), 64);
    let expected = hex::decode("a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26").unwrap();
    assert_eq!(result, expected);
}

#[test]
fn test_digest_output_lengths() {
    use craton_hsm::pkcs11_abi::constants::*;
    assert_eq!(digest::digest_output_len(CKM_SHA_1).unwrap(), 20);
    assert_eq!(digest::digest_output_len(CKM_SHA256).unwrap(), 32);
    assert_eq!(digest::digest_output_len(CKM_SHA384).unwrap(), 48);
    assert_eq!(digest::digest_output_len(CKM_SHA512).unwrap(), 64);
    assert_eq!(digest::digest_output_len(CKM_SHA3_256).unwrap(), 32);
    assert_eq!(digest::digest_output_len(CKM_SHA3_384).unwrap(), 48);
    assert_eq!(digest::digest_output_len(CKM_SHA3_512).unwrap(), 64);
}

// ============================================================================
// Multi-part digest
// ============================================================================

#[test]
fn test_multipart_sha256_digest() {
    use craton_hsm::pkcs11_abi::constants::CKM_SHA256;

    let data = b"Hello, World!";
    let single_shot = digest::compute_digest(CKM_SHA256, data).unwrap();

    let mut hasher = digest::create_hasher(CKM_SHA256).unwrap();
    hasher.update(b"Hello, ");
    hasher.update(b"World!");
    let multi_part = hasher.finalize();

    assert_eq!(
        single_shot, multi_part,
        "Multi-part and single-shot digest should match"
    );
}

#[test]
fn test_multipart_sha3_256_digest() {
    use craton_hsm::pkcs11_abi::constants::CKM_SHA3_256;

    let data = b"abc";
    let single_shot = digest::compute_digest(CKM_SHA3_256, data).unwrap();

    let mut hasher = digest::create_hasher(CKM_SHA3_256).unwrap();
    hasher.update(b"a");
    hasher.update(b"bc");
    let multi_part = hasher.finalize();

    assert_eq!(single_shot, multi_part);
}

#[test]
fn test_multipart_sha512_digest() {
    use craton_hsm::pkcs11_abi::constants::CKM_SHA512;

    let data = b"The quick brown fox jumps over the lazy dog";
    let single_shot = digest::compute_digest(CKM_SHA512, data).unwrap();

    let mut hasher = digest::create_hasher(CKM_SHA512).unwrap();
    // Feed one byte at a time
    for byte in data.iter() {
        hasher.update(&[*byte]);
    }
    let multi_part = hasher.finalize();

    assert_eq!(single_shot, multi_part);
}

// ============================================================================
// ECDH Key Derivation
// ============================================================================

#[test]
fn test_ecdh_p256() {
    let (priv_a, _pub_a) = keygen::generate_ec_p256_key_pair().unwrap();
    let (_priv_b, pub_b) = keygen::generate_ec_p256_key_pair().unwrap();

    // Derive twice with the same inputs to verify determinism
    let shared1 = derive::ecdh_p256(priv_a.as_bytes(), &pub_b, None).unwrap();
    let shared2 = derive::ecdh_p256(priv_a.as_bytes(), &pub_b, None).unwrap();

    assert_eq!(
        shared1.as_bytes(),
        shared2.as_bytes(),
        "ECDH derivation must be deterministic"
    );
    assert_eq!(
        shared1.as_bytes().len(),
        32,
        "P-256 shared secret is 32 bytes"
    );
    // Verify non-trivial output
    assert!(
        shared1.as_bytes().iter().any(|&b| b != 0),
        "Shared secret must not be all zeros"
    );
}

#[test]
fn test_ecdh_p256_different_pairs() {
    let (priv_a, _pub_a) = keygen::generate_ec_p256_key_pair().unwrap();
    let (_, pub_b) = keygen::generate_ec_p256_key_pair().unwrap();
    let (_, pub_c) = keygen::generate_ec_p256_key_pair().unwrap();

    let shared1 = derive::ecdh_p256(priv_a.as_bytes(), &pub_b, None).unwrap();
    let shared2 = derive::ecdh_p256(priv_a.as_bytes(), &pub_c, None).unwrap();

    assert_ne!(
        shared1.as_bytes(),
        shared2.as_bytes(),
        "Different peers should produce different shared secrets"
    );
}

#[test]
fn test_ecdh_p384() {
    let (priv_a, _pub_a) = keygen::generate_ec_p384_key_pair().unwrap();
    let (_priv_b, pub_b) = keygen::generate_ec_p384_key_pair().unwrap();

    // Derive twice with the same inputs to verify determinism
    let shared1 = derive::ecdh_p384(priv_a.as_bytes(), &pub_b, None).unwrap();
    let shared2 = derive::ecdh_p384(priv_a.as_bytes(), &pub_b, None).unwrap();

    assert_eq!(
        shared1.as_bytes(),
        shared2.as_bytes(),
        "ECDH P-384 derivation must be deterministic"
    );
    assert_eq!(
        shared1.as_bytes().len(),
        48,
        "P-384 shared secret is 48 bytes"
    );
    assert!(
        shared1.as_bytes().iter().any(|&b| b != 0),
        "Shared secret must not be all zeros"
    );
}

// ============================================================================
// AES Key Wrap / Unwrap
// ============================================================================

#[test]
fn test_aes_key_wrap_128_roundtrip() {
    let wrapping_key = keygen::generate_aes_key(16, false).unwrap();
    let key_to_wrap = keygen::generate_aes_key(16, false).unwrap();

    let wrapped =
        wrap::aes_key_wrap(wrapping_key.as_bytes(), key_to_wrap.as_bytes(), false).unwrap();
    assert_eq!(wrapped.len(), 16 + 8); // key + 8-byte overhead

    let unwrapped = wrap::aes_key_unwrap(wrapping_key.as_bytes(), &wrapped, false).unwrap();
    assert_eq!(unwrapped, key_to_wrap.as_bytes());
}

#[test]
fn test_aes_key_wrap_256_roundtrip() {
    let wrapping_key = keygen::generate_aes_key(32, false).unwrap();
    let key_to_wrap = keygen::generate_aes_key(32, false).unwrap();

    let wrapped =
        wrap::aes_key_wrap(wrapping_key.as_bytes(), key_to_wrap.as_bytes(), false).unwrap();
    assert_eq!(wrapped.len(), 32 + 8);

    let unwrapped = wrap::aes_key_unwrap(wrapping_key.as_bytes(), &wrapped, false).unwrap();
    assert_eq!(unwrapped, key_to_wrap.as_bytes());
}

#[test]
fn test_aes_key_wrap_wrong_key() {
    let wrapping_key1 = keygen::generate_aes_key(32, false).unwrap();
    let wrapping_key2 = keygen::generate_aes_key(32, false).unwrap();
    let key_to_wrap = keygen::generate_aes_key(32, false).unwrap();

    let wrapped =
        wrap::aes_key_wrap(wrapping_key1.as_bytes(), key_to_wrap.as_bytes(), false).unwrap();
    let result = wrap::aes_key_unwrap(wrapping_key2.as_bytes(), &wrapped, false);
    assert!(result.is_err(), "Unwrap with wrong key should fail");
}

#[test]
fn test_aes_key_wrap_tamper_detection() {
    let wrapping_key = keygen::generate_aes_key(32, false).unwrap();
    let key_to_wrap = keygen::generate_aes_key(32, false).unwrap();

    let mut wrapped =
        wrap::aes_key_wrap(wrapping_key.as_bytes(), key_to_wrap.as_bytes(), false).unwrap();
    // Tamper
    wrapped[0] ^= 0xFF;
    let result = wrap::aes_key_unwrap(wrapping_key.as_bytes(), &wrapped, false);
    assert!(result.is_err(), "Tampered wrapped key should fail unwrap");
}

#[test]
fn test_aes_key_wrap_invalid_data_length() {
    let wrapping_key = keygen::generate_aes_key(32, false).unwrap();
    // Key to wrap must be at least 16 bytes and a multiple of 8
    let too_short = [0u8; 8];
    let result = wrap::aes_key_wrap(wrapping_key.as_bytes(), &too_short, false);
    assert!(result.is_err(), "Too-short key should be rejected");
}

// ============================================================================
// PBKDF2 PIN hashing
// ============================================================================

#[test]
fn test_pbkdf2_pin_hash_verify() {
    use craton_hsm::store::encrypted_store::{hash_pin_pbkdf2, verify_pin_pbkdf2};

    let pin = b"my-secret-pin";
    let hash = hash_pin_pbkdf2(pin, None);
    assert_eq!(hash.len(), 64, "Hash should be salt(32) + derived_key(32)");

    assert!(
        verify_pin_pbkdf2(&hash, pin, None),
        "Correct PIN should verify"
    );
    assert!(
        !verify_pin_pbkdf2(&hash, b"wrong-pin", None),
        "Wrong PIN should not verify"
    );
}

#[test]
fn test_pbkdf2_different_salts() {
    use craton_hsm::store::encrypted_store::hash_pin_pbkdf2;

    let pin = b"same-pin";
    let hash1 = hash_pin_pbkdf2(pin, None);
    let hash2 = hash_pin_pbkdf2(pin, None);

    // Same PIN should produce different hashes (different random salts)
    assert_ne!(
        *hash1, *hash2,
        "Different salts should produce different hashes"
    );
}

#[test]
fn test_pbkdf2_derive_key() {
    use craton_hsm::store::encrypted_store::derive_key_from_pin;

    let pin = b"test-pin";
    let (key1, salt1) = derive_key_from_pin(pin, None, None);
    let (key2, _) = derive_key_from_pin(pin, Some(&salt1), None);

    assert_eq!(key1, key2, "Same PIN + same salt should produce same key");

    let (key3, _) = derive_key_from_pin(pin, None, None);
    // Different salt -> different key (with overwhelming probability)
    assert_ne!(key1, key3, "Different salts should produce different keys");
}

// ============================================================================
// Encrypted store
// ============================================================================

#[test]
fn test_encrypted_store_roundtrip() {
    use craton_hsm::store::encrypted_store::{derive_key_from_pin, EncryptedStore};

    // Use a temp directory for the redb database file
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.redb");
    let store = EncryptedStore::new(Some(db_path.to_str().unwrap())).unwrap();
    assert!(store.is_available());

    let (key, _) = derive_key_from_pin(b"test-pin", None, None);
    let data = b"sensitive key material";

    store.store_encrypted("test-key", data, &key).unwrap();
    let loaded = store.load_encrypted("test-key", &key).unwrap();
    assert_eq!(loaded.as_ref().map(|v| v.as_slice()), Some(data.as_slice()));
}

#[test]
fn test_encrypted_store_wrong_key() {
    use craton_hsm::store::encrypted_store::{derive_key_from_pin, EncryptedStore};

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.redb");
    let store = EncryptedStore::new(Some(db_path.to_str().unwrap())).unwrap();

    let (key1, _) = derive_key_from_pin(b"pin1", None, None);
    let (key2, _) = derive_key_from_pin(b"pin2", None, None);

    store.store_encrypted("test-key", b"secret", &key1).unwrap();
    let result = store.load_encrypted("test-key", &key2);
    assert!(
        result.is_err(),
        "Wrong encryption key should fail decryption"
    );
}

#[test]
fn test_encrypted_store_delete() {
    use craton_hsm::store::encrypted_store::{derive_key_from_pin, EncryptedStore};

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.redb");
    let store = EncryptedStore::new(Some(db_path.to_str().unwrap())).unwrap();

    let (key, _) = derive_key_from_pin(b"pin", None, None);
    store.store_encrypted("to-delete", b"data", &key).unwrap();
    store.delete("to-delete").unwrap();

    let loaded = store.load_encrypted("to-delete", &key).unwrap();
    assert_eq!(
        loaded.as_ref().map(|v| v.as_slice()),
        None::<&[u8]>,
        "Deleted key should return None"
    );
}

#[test]
fn test_encrypted_store_list_keys() {
    use craton_hsm::store::encrypted_store::{derive_key_from_pin, EncryptedStore};

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.redb");
    let store = EncryptedStore::new(Some(db_path.to_str().unwrap())).unwrap();

    let (key, _) = derive_key_from_pin(b"pin", None, None);
    store.store_encrypted("key-a", b"data-a", &key).unwrap();
    store.store_encrypted("key-b", b"data-b", &key).unwrap();
    store.store_encrypted("key-c", b"data-c", &key).unwrap();

    let mut keys = store.list_keys().unwrap();
    keys.sort();
    assert_eq!(keys, vec!["key-a", "key-b", "key-c"]);
}

#[test]
fn test_encrypted_store_memory_only() {
    use craton_hsm::store::encrypted_store::EncryptedStore;

    let store = EncryptedStore::new(None).unwrap();
    assert!(!store.is_available());
}

// ============================================================================
// EC key generation
// ============================================================================

#[test]
fn test_ec_p256_keygen() {
    let (priv_key, pub_key) = keygen::generate_ec_p256_key_pair().unwrap();
    assert_eq!(
        priv_key.as_bytes().len(),
        32,
        "P-256 private key should be 32 bytes"
    );
    assert_eq!(
        pub_key.len(),
        65,
        "P-256 uncompressed public key should be 65 bytes"
    );
    assert_eq!(
        pub_key[0], 0x04,
        "Uncompressed point should start with 0x04"
    );
}

#[test]
fn test_ec_p384_keygen() {
    let (priv_key, pub_key) = keygen::generate_ec_p384_key_pair().unwrap();
    assert_eq!(
        priv_key.as_bytes().len(),
        48,
        "P-384 private key should be 48 bytes"
    );
    assert_eq!(
        pub_key.len(),
        97,
        "P-384 uncompressed public key should be 97 bytes"
    );
    assert_eq!(
        pub_key[0], 0x04,
        "Uncompressed point should start with 0x04"
    );
}

// ============================================================================
// Config
// ============================================================================

#[test]
fn test_config_defaults() {
    let config = craton_hsm::config::config::HsmConfig::default();
    assert_eq!(config.token.label, "Craton HSM Token 0");
    assert_eq!(config.security.pin_min_length, 8);
    assert_eq!(config.security.pin_max_length, 64);
    assert_eq!(config.security.max_failed_logins, 10);
    // Debug builds use 1 iteration for dev speed; release builds use 600 000.
    if cfg!(debug_assertions) {
        assert_eq!(config.security.pbkdf2_iterations, 1);
    } else {
        assert_eq!(config.security.pbkdf2_iterations, 600_000);
    }
    assert!(!config.algorithms.allow_weak_rsa);
    assert!(!config.algorithms.allow_sha1_signing);
    assert!(config.algorithms.enable_pqc);
}
