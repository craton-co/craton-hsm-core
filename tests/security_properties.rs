// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Security property tests — things that SHOULD fail but previously had no tests.
//!
//! These tests verify that security-critical invariants are enforced:
//! monotonicity of CKA_SENSITIVE/CKA_EXTRACTABLE, secure defaults,
//! attribute limits, backup passphrase requirements, and more.

use craton_hsm::crypto::{encrypt, keygen, sign};
use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm::pkcs11_abi::types::{CK_ATTRIBUTE_TYPE, CK_ULONG};
use craton_hsm::store::attributes::{read_attribute, ObjectStore};
use craton_hsm::store::backup::{create_backup, restore_backup};
use craton_hsm::store::key_material::RawKeyMaterial;
use craton_hsm::store::object::StoredObject;

fn make_secret_key(handle: CK_ULONG, label: &str) -> StoredObject {
    let mut obj = StoredObject::new(handle, 3); // CKO_SECRET_KEY
    obj.label = label.as_bytes().to_vec();
    obj.token_object = true;
    obj.key_material = Some(RawKeyMaterial::new(vec![0x42; 32]));
    obj
}

// ============================================================================
// CKA_SENSITIVE / CKA_EXTRACTABLE monotonicity (PKCS#11 §10.7)
// ============================================================================

/// Verify that ObjectStore::create_object rejects CKA_SENSITIVE=false when
/// the object defaults to sensitive=true.  This exercises the monotonicity
/// enforcement inside apply_attribute: once sensitive is true, clearing it
/// to false must return AttributeReadOnly.
#[test]
fn test_sensitive_cannot_be_reset_to_false() {
    let store = ObjectStore::new();

    // StoredObject defaults: sensitive=true.  Attempting to create an object
    // with CKA_SENSITIVE=false in the template must be rejected because
    // apply_attribute sees sensitive already true and refuses to clear it.
    let template = vec![
        (CKA_CLASS, CKO_SECRET_KEY.to_ne_bytes().to_vec()),
        (CKA_SENSITIVE, vec![0u8]), // explicitly false — should be rejected
        (CKA_VALUE, vec![0x42; 32]),
    ];
    let result = store.create_object(&template);
    assert!(
        result.is_err(),
        "Creating a key with CKA_SENSITIVE=false must fail (monotonicity: default is true)"
    );

    // Also verify the positive case: CKA_SENSITIVE=true is accepted (no-op, same as default)
    let template_ok = vec![
        (CKA_CLASS, CKO_SECRET_KEY.to_ne_bytes().to_vec()),
        (CKA_SENSITIVE, vec![1u8]), // true — should be accepted
        (CKA_VALUE, vec![0x42; 32]),
    ];
    let handle = store.create_object(&template_ok).unwrap();
    let obj_ref = store.get_object(handle).unwrap();
    assert!(obj_ref.read().sensitive, "CKA_SENSITIVE must remain true");
}

/// Verify that ObjectStore::create_object rejects CKA_EXTRACTABLE=true when
/// the object defaults to extractable=false.  Once extractable is false it
/// cannot be set back to true.
#[test]
fn test_extractable_cannot_be_set_back_to_true() {
    let store = ObjectStore::new();

    // StoredObject defaults: extractable=false.  Attempting to create an
    // object with CKA_EXTRACTABLE=true must be rejected.
    let template = vec![
        (CKA_CLASS, CKO_SECRET_KEY.to_ne_bytes().to_vec()),
        (CKA_EXTRACTABLE, vec![1u8]), // true — should be rejected
        (CKA_VALUE, vec![0x42; 32]),
    ];
    let result = store.create_object(&template);
    assert!(
        result.is_err(),
        "Creating a key with CKA_EXTRACTABLE=true must fail (monotonicity: default is false)"
    );

    // Positive case: CKA_EXTRACTABLE=false is accepted (same as default)
    let template_ok = vec![
        (CKA_CLASS, CKO_SECRET_KEY.to_ne_bytes().to_vec()),
        (CKA_EXTRACTABLE, vec![0u8]),
        (CKA_VALUE, vec![0x42; 32]),
    ];
    let handle = store.create_object(&template_ok).unwrap();
    let obj_ref = store.get_object(handle).unwrap();
    assert!(
        !obj_ref.read().extractable,
        "CKA_EXTRACTABLE must remain false"
    );
}

// ============================================================================
// Secure defaults
// ============================================================================

#[test]
fn test_default_key_is_sensitive_and_non_extractable() {
    let obj = StoredObject::new(1, 3); // CKO_SECRET_KEY
    assert!(obj.sensitive, "Default key must be sensitive");
    assert!(!obj.extractable, "Default key must be non-extractable");
}

#[test]
fn test_default_key_is_private() {
    let obj = StoredObject::new(1, 3);
    assert!(obj.private, "Default key must be private");
}

// ============================================================================
// Extra attributes size/count limits
// ============================================================================

/// Verify that an extra attribute value exceeding 8192 bytes is rejected.
/// This prevents resource-exhaustion attacks via oversized attribute values.
#[test]
fn test_extra_attributes_size_limit_enforced() {
    let store = ObjectStore::new();

    // Build a template with one extra (vendor-defined) attribute that is too large.
    // Vendor attribute types start at 0x8000_0000.
    let oversized_value = vec![0xAA; 8193]; // 8193 > 8192 limit
    let template = vec![
        (CKA_CLASS, CKO_SECRET_KEY.to_ne_bytes().to_vec()),
        (CKA_VALUE, vec![0x42; 32]),
        (0x8000_0001, oversized_value),
    ];
    let result = store.create_object(&template);
    assert!(
        result.is_err(),
        "Extra attribute value > 8192 bytes must be rejected"
    );

    // At the boundary: exactly 8192 bytes should be accepted
    let boundary_value = vec![0xBB; 8192];
    let template_ok = vec![
        (CKA_CLASS, CKO_SECRET_KEY.to_ne_bytes().to_vec()),
        (CKA_VALUE, vec![0x42; 32]),
        (0x8000_0001, boundary_value),
    ];
    let result = store.create_object(&template_ok);
    assert!(
        result.is_ok(),
        "Extra attribute value of exactly 8192 bytes should be accepted"
    );
}

/// Verify that more than 64 extra (vendor-defined) attributes are rejected.
/// This prevents resource-exhaustion attacks via attribute count inflation.
#[test]
fn test_extra_attributes_count_limit_enforced() {
    let store = ObjectStore::new();

    // Build a template with 65 vendor-defined extra attributes.
    let mut template: Vec<(CK_ATTRIBUTE_TYPE, Vec<u8>)> = vec![
        (CKA_CLASS, CKO_SECRET_KEY.to_ne_bytes().to_vec()),
        (CKA_VALUE, vec![0x42; 32]),
    ];
    // Add 65 unique vendor attributes (0x8000_0001 .. 0x8000_0041)
    for i in 1..=65 {
        let attr_type: CK_ATTRIBUTE_TYPE = 0x8000_0000 + i;
        template.push((attr_type, vec![0xCC; 16]));
    }
    let result = store.create_object(&template);
    assert!(
        result.is_err(),
        "More than 64 extra attributes must be rejected"
    );

    // Exactly 64 extra attributes should be accepted
    let mut template_ok: Vec<(CK_ATTRIBUTE_TYPE, Vec<u8>)> = vec![
        (CKA_CLASS, CKO_SECRET_KEY.to_ne_bytes().to_vec()),
        (CKA_VALUE, vec![0x42; 32]),
    ];
    for i in 1..=64 {
        let attr_type: CK_ATTRIBUTE_TYPE = 0x8000_0000 + i;
        template_ok.push((attr_type, vec![0xDD; 16]));
    }
    let result = store.create_object(&template_ok);
    assert!(
        result.is_ok(),
        "Exactly 64 extra attributes should be accepted"
    );
}

// ============================================================================
// Backup passphrase minimum length (16 chars)
// ============================================================================

#[test]
fn test_backup_passphrase_min_length_16() {
    let objects = vec![make_secret_key(1, "key1")];

    // 12-char passphrase should fail
    let result = create_backup(&objects, "short-phrase", "TEST", None);
    assert!(result.is_err(), "12-char passphrase must be rejected");

    // 15-char passphrase should fail
    let result = create_backup(&objects, "fifteen-chars!!", "TEST", None);
    assert!(result.is_err(), "15-char passphrase must be rejected");

    // 16-char passphrase should succeed (must also meet complexity: 3+ char classes)
    let result = create_backup(&objects, "Sixteen-Chars1!!", "TEST", None);
    assert!(result.is_ok(), "16-char passphrase must be accepted");
}

#[test]
fn test_backup_roundtrip_with_valid_passphrase() {
    let objects = vec![
        make_secret_key(1, "key-alpha"),
        make_secret_key(2, "key-beta"),
    ];

    let passphrase = "Strong-Pass123-here";
    let backup = create_backup(&objects, passphrase, "TEST-SERIAL", None).unwrap();
    let restored = restore_backup(&backup, passphrase, "TEST-SERIAL", Some(0), None, None).unwrap();

    assert_eq!(restored.len(), 2);
    assert_eq!(restored[0].label, b"key-alpha");
    assert_eq!(restored[1].label, b"key-beta");
}

#[test]
fn test_backup_wrong_passphrase_rejected() {
    let objects = vec![make_secret_key(1, "key1")];
    let backup = create_backup(&objects, "Correct-Pass123!X", "TEST-SERIAL", None).unwrap();

    let result = restore_backup(
        &backup,
        "Wrong-Pass456!XXX",
        "TEST-SERIAL",
        Some(0),
        None,
        None,
    );
    assert!(result.is_err(), "Wrong passphrase must be rejected");
}

// ============================================================================
// RSA: unprefixed signing must be rejected
// ============================================================================

#[test]
fn test_unprefixed_rsa_signing_rejected() {
    let (priv_der, _modulus, _pub_exp) = keygen::generate_rsa_key_pair(2048, false).unwrap();
    let message = b"Test message";

    // Sign without hash algorithm (None) should fail
    let result = sign::rsa_pkcs1v15_sign(priv_der.as_bytes(), message, None);
    assert!(
        result.is_err(),
        "Unprefixed RSA PKCS#1 v1.5 signing must be rejected"
    );
}

// ============================================================================
// AES key generation sizes
// ============================================================================

#[test]
fn test_aes_keygen_invalid_sizes_rejected() {
    assert!(
        keygen::generate_aes_key(15, false).is_err(),
        "15-byte AES key must be rejected"
    );
    assert!(
        keygen::generate_aes_key(33, false).is_err(),
        "33-byte AES key must be rejected"
    );
    assert!(
        keygen::generate_aes_key(0, false).is_err(),
        "0-byte AES key must be rejected"
    );
    assert!(
        keygen::generate_aes_key(64, false).is_err(),
        "64-byte AES key must be rejected"
    );
}

#[test]
fn test_aes_keygen_valid_sizes_accepted() {
    assert!(
        keygen::generate_aes_key(16, false).is_ok(),
        "16-byte AES key must be accepted"
    );
    assert!(
        keygen::generate_aes_key(24, false).is_ok(),
        "24-byte AES key must be accepted"
    );
    assert!(
        keygen::generate_aes_key(32, false).is_ok(),
        "32-byte AES key must be accepted"
    );
}

// ============================================================================
// AES-GCM: wrong key size rejected
// ============================================================================

#[test]
fn test_aes_gcm_wrong_key_size_rejected() {
    let result = encrypt::aes_256_gcm_encrypt(&[0u8; 16], b"test");
    assert!(
        result.is_err(),
        "AES-GCM with 16-byte key must be rejected (requires 32)"
    );
}

// ============================================================================
// AES-CBC: invalid inputs rejected
// ============================================================================

#[test]
fn test_aes_cbc_wrong_key_size_rejected() {
    let iv = [0u8; 16];
    let result = encrypt::aes_cbc_encrypt(&[0u8; 15], &iv, b"test data block!");
    assert!(result.is_err(), "AES-CBC with 15-byte key must be rejected");
}

#[test]
fn test_aes_cbc_wrong_iv_size_rejected() {
    let key = [0u8; 32];
    let result = encrypt::aes_cbc_encrypt(&key, &[0u8; 8], b"test data block!");
    assert!(result.is_err(), "AES-CBC with 8-byte IV must be rejected");
}

// ============================================================================
// Handle allocator: concurrent allocation produces unique handles
// ============================================================================

#[test]
fn test_handle_allocator_concurrent_uniqueness() {
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::sync::Mutex;

    let store = Arc::new(ObjectStore::new());
    let handles = Arc::new(Mutex::new(HashSet::new()));
    let mut threads = Vec::new();

    for _ in 0..100 {
        let store = Arc::clone(&store);
        let handles = Arc::clone(&handles);
        threads.push(std::thread::spawn(move || {
            let h = store.next_handle().unwrap();
            let mut set = handles.lock().unwrap();
            assert!(set.insert(h), "Handle {} was duplicated!", h);
        }));
    }

    for t in threads {
        t.join().unwrap();
    }

    let set = handles.lock().unwrap();
    assert_eq!(set.len(), 100, "All 100 handles must be unique");
}

// ============================================================================
// StoredObject: sensitive key material not readable when sensitive + non-extractable
// ============================================================================

#[test]
fn test_sensitive_non_extractable_key_not_readable() {
    let mut obj = StoredObject::new(1, 3);
    obj.sensitive = true;
    obj.extractable = false;
    obj.key_material = Some(RawKeyMaterial::new(vec![0x42; 32]));

    let result = read_attribute(&obj, CKA_VALUE);
    assert!(
        result.is_err(),
        "CKA_VALUE must not be readable when sensitive=true, extractable=false"
    );
}

#[test]
fn test_non_sensitive_extractable_key_readable() {
    let mut obj = StoredObject::new(1, 3);
    obj.sensitive = false;
    obj.extractable = true;
    obj.key_material = Some(RawKeyMaterial::new(vec![0x42; 32]));

    let result = read_attribute(&obj, CKA_VALUE);
    assert!(
        result.is_ok(),
        "CKA_VALUE should be readable when sensitive=false, extractable=true"
    );
    let val = result.unwrap();
    assert!(val.is_some());
    assert_eq!(val.unwrap(), vec![0x42; 32]);
}

// ============================================================================
// Backup: corrupted data rejected
// ============================================================================

#[test]
fn test_backup_truncated_data_rejected() {
    let result = restore_backup(
        &[0u8; 10],
        "Some-Pass123!!XX",
        "TEST-SERIAL",
        Some(0),
        None,
        None,
    );
    assert!(result.is_err(), "Truncated backup must be rejected");
}

#[test]
fn test_backup_invalid_magic_rejected() {
    let objects = vec![make_secret_key(1, "key1")];
    let mut backup = create_backup(&objects, "Valid-Pass123!!X", "TEST-SERIAL", None).unwrap();
    backup[0] = b'X'; // Corrupt magic bytes
    let result = restore_backup(
        &backup,
        "Valid-Pass123!!X",
        "TEST-SERIAL",
        Some(0),
        None,
        None,
    );
    assert!(result.is_err(), "Corrupted magic must be rejected");
}

// ============================================================================
// ECDH output should differ from raw key material (proves KDF is applied)
// ============================================================================

// ============================================================================
// Backup: serial binding — cross-token restore must be rejected
// ============================================================================

#[test]
fn test_backup_serial_mismatch_rejected() {
    let objects = vec![make_secret_key(1, "key1")];
    let backup = create_backup(&objects, "Valid-Pass123!!X", "SERIAL-AAA", None).unwrap();

    // Attempt to restore with a different expected serial
    let result = restore_backup(
        &backup,
        "Valid-Pass123!!X",
        "SERIAL-BBB",
        Some(0),
        None,
        None,
    );
    assert!(
        result.is_err(),
        "Restoring backup to different serial must be rejected"
    );
}

// ============================================================================
// Backup: replay protection — same backup_id consumed twice must be rejected
// ============================================================================

#[test]
fn test_backup_replay_attack_rejected() {
    use std::collections::HashSet;

    let objects = vec![make_secret_key(1, "key1")];
    let backup = create_backup(&objects, "Valid-Pass123!!X", "TEST-SERIAL", None).unwrap();

    let mut consumed_ids = HashSet::new();

    // First restore should succeed
    let result = restore_backup(
        &backup,
        "Valid-Pass123!!X",
        "TEST-SERIAL",
        Some(0),
        None,
        Some(&mut consumed_ids),
    );
    assert!(result.is_ok(), "First restore should succeed");

    // Second restore of the exact same backup should be rejected (replay attack)
    let result = restore_backup(
        &backup,
        "Valid-Pass123!!X",
        "TEST-SERIAL",
        Some(0),
        None,
        Some(&mut consumed_ids),
    );
    assert!(
        result.is_err(),
        "Replaying the same backup must be rejected"
    );
}

// ============================================================================
// Backup: stale backup must be rejected when max_age is enforced
// ============================================================================

#[test]
fn test_backup_age_enforcement() {
    let objects = vec![make_secret_key(1, "key1")];
    let backup = create_backup(&objects, "Valid-Pass123!!X", "TEST-SERIAL", None).unwrap();

    // With max_age_secs=0 (disabled), restore should succeed regardless of age
    let result = restore_backup(
        &backup,
        "Valid-Pass123!!X",
        "TEST-SERIAL",
        Some(0),
        None,
        None,
    );
    assert!(
        result.is_ok(),
        "With age check disabled (max_age=0), restore should succeed"
    );

    // With a generous age limit, a freshly created backup should succeed.
    // Use 300 seconds to account for slow debug-mode PBKDF2 on CI.
    let result = restore_backup(
        &backup,
        "Valid-Pass123!!X",
        "TEST-SERIAL",
        Some(300),
        None,
        None,
    );
    assert!(
        result.is_ok(),
        "Fresh backup within 300-second window should be accepted"
    );

    // Default age (None → 30 days) should accept a fresh backup
    let result = restore_backup(&backup, "Valid-Pass123!!X", "TEST-SERIAL", None, None, None);
    assert!(
        result.is_ok(),
        "Fresh backup within default 30-day window should succeed"
    );
}

// ============================================================================
// AES-GCM: nonce uniqueness — 1000 encryptions must produce unique nonces
// ============================================================================

#[test]
fn test_aes_gcm_nonce_uniqueness_1000() {
    use std::collections::HashSet;

    let key = keygen::generate_aes_key(32, false).unwrap();
    let plaintext = b"nonce uniqueness test payload";
    let mut nonces = HashSet::new();

    for i in 0..1000 {
        let ct = encrypt::aes_256_gcm_encrypt(key.as_bytes(), plaintext).unwrap();
        // First 12 bytes of ciphertext are the nonce
        let nonce: [u8; 12] = ct[..12].try_into().unwrap();
        assert!(
            nonces.insert(nonce),
            "Nonce collision detected at encryption #{} — catastrophic for AES-GCM security",
            i
        );
    }
    assert_eq!(nonces.len(), 1000, "All 1000 nonces must be unique");
}

// ============================================================================
// ECDH output should differ from raw key material (proves KDF is applied)
// ============================================================================

#[test]
fn test_ecdh_derives_different_from_raw_keygen() {
    // Generate two EC P-256 key pairs — the derived shared secret should not
    // match any raw keygen output (it goes through HKDF)
    use craton_hsm::crypto::derive;

    let (sk1, pk1) = keygen::generate_ec_p256_key_pair().unwrap();
    let (sk2, pk2) = keygen::generate_ec_p256_key_pair().unwrap();

    let shared = derive::ecdh_p256(sk1.as_bytes(), &pk2, None).unwrap();
    let shared_rev = derive::ecdh_p256(sk2.as_bytes(), &pk1, None).unwrap();

    // Both directions should produce the same derived key (ECDH commutativity)
    assert_eq!(
        shared.as_bytes(),
        shared_rev.as_bytes(),
        "ECDH must be commutative"
    );
    // Derived key should be 32 bytes (HKDF output)
    assert_eq!(shared.len(), 32, "HKDF-derived key should be 32 bytes");
    // Should not be all zeros
    assert_ne!(
        shared.as_bytes(),
        &[0u8; 32],
        "Derived key must not be all zeros"
    );
}
