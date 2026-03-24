// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Integration tests for crypto/integrity.rs
//!
//! Tests the Ed25519 signature-based integrity check mechanism used for FIPS 140-3 §9.4.

use craton_hsm::crypto::integrity::compute_hash;
use std::path::Path;

fn temp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("craton_hsm_integrity_{}", name));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

#[test]
fn test_integrity_check_with_valid_hash() {
    let dir = temp_dir("valid_hash");
    let binary_path = dir.join("module.bin");

    // Write a test binary
    std::fs::write(&binary_path, b"test module binary content v1").unwrap();

    // Compute correct SHA-256 hash
    let hash_hex = compute_hash(&binary_path).unwrap();
    assert_eq!(hash_hex.len(), 64, "SHA-256 hex should be 64 chars");

    // Verify the hash is deterministic
    let hash_hex2 = compute_hash(&binary_path).unwrap();
    assert_eq!(hash_hex, hash_hex2);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_integrity_check_with_tampered_content() {
    let dir = temp_dir("tampered_hash");
    let binary_path = dir.join("module.bin");

    std::fs::write(&binary_path, b"test module binary content v1").unwrap();
    let hash1 = compute_hash(&binary_path).unwrap();

    // Modify the binary
    std::fs::write(&binary_path, b"TAMPERED module binary content!!").unwrap();
    let hash2 = compute_hash(&binary_path).unwrap();

    // Hash should differ for different content
    assert_ne!(hash1, hash2, "Modified binary must produce different hash");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_integrity_signature_roundtrip() {
    use ed25519_dalek::{Signer, SigningKey, Verifier};
    use sha2::{Digest, Sha256};

    let dir = temp_dir("sig_roundtrip");
    let binary_path = dir.join("module.bin");

    // Write a test binary
    std::fs::write(&binary_path, b"test module binary for signing").unwrap();

    // Compute SHA-256 hash
    let content = std::fs::read(&binary_path).unwrap();
    let hash = Sha256::digest(&content);

    // Generate a test keypair and sign the hash
    let signing_key = SigningKey::from_bytes(&[42u8; 32]);
    let verifying_key = signing_key.verifying_key();
    let signature = signing_key.sign(&hash);

    // Verify passes
    assert!(verifying_key.verify(&hash, &signature).is_ok());

    // Tamper with binary — verification must fail
    std::fs::write(&binary_path, b"TAMPERED binary for signing test").unwrap();
    let tampered_content = std::fs::read(&binary_path).unwrap();
    let tampered_hash = Sha256::digest(&tampered_content);
    assert!(verifying_key.verify(&tampered_hash, &signature).is_err());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_compute_hash_deterministic() {
    let dir = temp_dir("deterministic");
    let test_file = dir.join("test_binary.bin");
    std::fs::write(&test_file, b"deterministic content test").unwrap();

    let hash1 = compute_hash(&test_file).unwrap();
    let hash2 = compute_hash(&test_file).unwrap();
    let hash3 = compute_hash(&test_file).unwrap();

    assert_eq!(hash1, hash2, "SHA-256 hash must be deterministic");
    assert_eq!(
        hash2, hash3,
        "SHA-256 hash must be deterministic across calls"
    );
    assert_eq!(hash1.len(), 64, "SHA-256 hex should be 64 chars");

    // Verify it's a valid hex string
    assert!(hex::decode(&hash1).is_ok(), "Hash output must be valid hex");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_compute_hash_nonexistent_file_fails() {
    let result = compute_hash(Path::new("/nonexistent/path/to/module.bin"));
    assert!(
        result.is_err(),
        "compute_hash on nonexistent file must fail"
    );
}

#[test]
fn test_compute_hash_empty_file() {
    let dir = temp_dir("empty_file");
    let test_file = dir.join("empty.bin");
    std::fs::write(&test_file, b"").unwrap();

    let hash = compute_hash(&test_file).unwrap();
    assert_eq!(
        hash.len(),
        64,
        "SHA-256 hash of empty file should still be 64 hex chars"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
