// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
// Backup/restore integration tests.
//
// Tests cover:
// - Round-trip: create objects via C ABI → backup → restore → verify
// - Wrong passphrase fails decryption
// - Empty backup produces valid file
// - Truncated/corrupt backup fails
// - Restored objects retain all attributes
// - Library-level backup::create_backup / backup::restore_backup
//
// Must run with --test-threads=1 due to global OnceLock state.

use craton_hsm::pkcs11_abi::types::*;
use craton_hsm::store::backup;
use craton_hsm::store::object::StoredObject;

fn make_test_object(handle: CK_OBJECT_HANDLE, label: &str, class: CK_OBJECT_CLASS) -> StoredObject {
    let mut obj = StoredObject::new(handle, class);
    obj.label = label.as_bytes().to_vec();
    obj.token_object = true;
    obj.private = true;
    obj.sensitive = true;
    obj.extractable = false;
    obj.modifiable = true;
    obj.destroyable = true;
    obj.can_encrypt = true;
    obj.can_decrypt = true;
    obj
}

#[test]
fn test_round_trip_backup_restore() {
    let objects = vec![
        make_test_object(1, "aes-key-1", 3),  // CKO_SECRET_KEY
        make_test_object(2, "rsa-pub-1", 2),  // CKO_PUBLIC_KEY
        make_test_object(3, "rsa-priv-1", 3), // CKO_SECRET_KEY
    ];

    let backup_data =
        backup::create_backup(&objects, "MyPassphrase-123!", "TEST-SERIAL-0001", None).unwrap();
    assert!(
        backup_data.len() > 52,
        "Backup should be larger than header"
    );

    // Verify magic bytes
    assert_eq!(&backup_data[0..4], b"RHBK");

    let restored = backup::restore_backup(
        &backup_data,
        "MyPassphrase-123!",
        "TEST-SERIAL-0001",
        Some(0),
        None,
        None,
    )
    .unwrap();
    assert_eq!(restored.len(), 3);
    assert_eq!(restored[0].label, b"aes-key-1");
    assert_eq!(restored[1].label, b"rsa-pub-1");
    assert_eq!(restored[2].label, b"rsa-priv-1");
}

#[test]
fn test_wrong_passphrase_fails() {
    let objects = vec![make_test_object(1, "key1", 3)];
    let backup_data =
        backup::create_backup(&objects, "Correct-Pass1-long", "TEST-SERIAL-0001", None).unwrap();

    let result = backup::restore_backup(
        &backup_data,
        "Wrong-Pass2-longg",
        "TEST-SERIAL-0001",
        Some(0),
        None,
        None,
    );
    assert!(result.is_err(), "Wrong passphrase should fail");
}

#[test]
fn test_empty_backup_is_valid() {
    let backup_data =
        backup::create_backup(&[], "Pass-Long-Phr4se", "TEST-SERIAL-0001", None).unwrap();
    let restored = backup::restore_backup(
        &backup_data,
        "Pass-Long-Phr4se",
        "TEST-SERIAL-0001",
        Some(0),
        None,
        None,
    )
    .unwrap();
    assert!(restored.is_empty());
}

#[test]
fn test_truncated_backup_fails() {
    let result = backup::restore_backup(
        &[0u8; 10],
        "Pass-Long-Phr4se",
        "TEST-SERIAL-0001",
        Some(0),
        None,
        None,
    );
    assert!(result.is_err(), "Truncated backup should fail");
}

#[test]
fn test_corrupt_magic_fails() {
    let mut backup_data =
        backup::create_backup(&[], "Pass-Long-Phr4se", "TEST-SERIAL-0001", None).unwrap();
    backup_data[0] = b'X'; // corrupt magic
    let result = backup::restore_backup(
        &backup_data,
        "Pass-Long-Phr4se",
        "TEST-SERIAL-0001",
        Some(0),
        None,
        None,
    );
    assert!(result.is_err(), "Corrupt magic should fail");
}

#[test]
fn test_corrupt_ciphertext_fails() {
    let mut backup_data =
        backup::create_backup(&[], "Pass-Long-Phr4se", "TEST-SERIAL-0001", None).unwrap();
    // Corrupt the ciphertext (after header)
    if backup_data.len() > 55 {
        backup_data[55] ^= 0xFF;
    }
    let result = backup::restore_backup(
        &backup_data,
        "Pass-Long-Phr4se",
        "TEST-SERIAL-0001",
        Some(0),
        None,
        None,
    );
    assert!(result.is_err(), "Corrupt ciphertext should fail");
}

#[test]
fn test_restored_objects_retain_attributes() {
    let mut obj = make_test_object(42, "test-key", 3);
    obj.can_sign = true;
    obj.can_verify = true;
    obj.can_wrap = false;
    obj.can_unwrap = false;
    obj.can_derive = false;
    obj.id = b"key-id-42".to_vec();
    obj.value_len = Some(32);

    let backup_data =
        backup::create_backup(&[obj], "Pass-Long-Phr4se", "TEST-SERIAL-0001", None).unwrap();
    let restored = backup::restore_backup(
        &backup_data,
        "Pass-Long-Phr4se",
        "TEST-SERIAL-0001",
        Some(0),
        None,
        None,
    )
    .unwrap();

    assert_eq!(restored.len(), 1);
    let r = &restored[0];
    assert_eq!(r.handle, 42);
    assert_eq!(r.label, b"test-key");
    assert_eq!(r.class, 3);
    assert!(r.token_object);
    assert!(r.private);
    assert!(r.sensitive);
    assert!(!r.extractable);
    assert!(r.can_encrypt);
    assert!(r.can_decrypt);
    assert!(r.can_sign);
    assert!(r.can_verify);
    assert!(!r.can_wrap);
    assert!(!r.can_unwrap);
    assert!(!r.can_derive);
    assert_eq!(r.id, b"key-id-42");
    assert_eq!(r.value_len, Some(32));
}

#[test]
fn test_large_backup() {
    // Create many objects to ensure scaling works
    let objects: Vec<StoredObject> = (0..100)
        .map(|i| make_test_object(i, &format!("key-{}", i), 3))
        .collect();

    let backup_data =
        backup::create_backup(&objects, "Pass-Long-Phr4se", "TEST-SERIAL-0001", None).unwrap();
    let restored = backup::restore_backup(
        &backup_data,
        "Pass-Long-Phr4se",
        "TEST-SERIAL-0001",
        Some(0),
        None,
        None,
    )
    .unwrap();
    assert_eq!(restored.len(), 100);
}

// ============================================================================
// Security: Token serial binding
// ============================================================================

#[test]
fn test_serial_mismatch_rejects_restore() {
    let objects = vec![make_test_object(1, "key1", 3)];
    let backup_data =
        backup::create_backup(&objects, "Pass-Long-Phr4se", "SERIAL-AAA", None).unwrap();

    // Restore with wrong serial should fail
    let result = backup::restore_backup(
        &backup_data,
        "Pass-Long-Phr4se",
        "SERIAL-BBB",
        Some(0),
        None,
        None,
    );
    assert!(
        result.is_err(),
        "Restoring backup to a different token serial must be rejected"
    );
}

// ============================================================================
// Security: Replay protection via consumed backup IDs
// ============================================================================

#[test]
fn test_replay_attack_detection() {
    use std::collections::HashSet;

    let objects = vec![make_test_object(1, "key1", 3)];
    let backup_data =
        backup::create_backup(&objects, "Pass-Long-Phr4se", "TEST-SERIAL-0001", None).unwrap();

    let mut consumed = HashSet::new();

    // First restore succeeds and records the backup ID
    let result = backup::restore_backup(
        &backup_data,
        "Pass-Long-Phr4se",
        "TEST-SERIAL-0001",
        Some(0),
        None,
        Some(&mut consumed),
    );
    assert!(result.is_ok(), "First restore should succeed");
    assert_eq!(consumed.len(), 1, "One backup ID should be recorded");

    // Second restore with same data is a replay and should fail
    let result = backup::restore_backup(
        &backup_data,
        "Pass-Long-Phr4se",
        "TEST-SERIAL-0001",
        Some(0),
        None,
        Some(&mut consumed),
    );
    assert!(result.is_err(), "Replay of same backup must be rejected");
}

// ============================================================================
// Security: Backup age enforcement
// ============================================================================

#[test]
fn test_backup_age_default_accepts_fresh() {
    let objects = vec![make_test_object(1, "key1", 3)];
    let backup_data =
        backup::create_backup(&objects, "Pass-Long-Phr4se", "TEST-SERIAL-0001", None).unwrap();

    // Default max_age (None → 30 days) should accept a fresh backup
    let result = backup::restore_backup(
        &backup_data,
        "Pass-Long-Phr4se",
        "TEST-SERIAL-0001",
        None,
        None,
        None,
    );
    assert!(result.is_ok(), "Fresh backup should pass default age check");
}

#[test]
fn test_backup_age_disabled_accepts_any() {
    let objects = vec![make_test_object(1, "key1", 3)];
    let backup_data =
        backup::create_backup(&objects, "Pass-Long-Phr4se", "TEST-SERIAL-0001", None).unwrap();

    // max_age_secs=0 disables the age check
    let result = backup::restore_backup(
        &backup_data,
        "Pass-Long-Phr4se",
        "TEST-SERIAL-0001",
        Some(0),
        None,
        None,
    );
    assert!(
        result.is_ok(),
        "Age check disabled (max_age=0) should accept any backup"
    );
}

// ============================================================================
// Security: Backup ciphertext bit-flip detection
// ============================================================================

#[test]
fn test_backup_single_bit_flip_detected() {
    let objects = vec![make_test_object(1, "key1", 3)];
    let backup_data =
        backup::create_backup(&objects, "Pass-Long-Phr4se", "TEST-SERIAL-0001", None).unwrap();

    // Flip a single bit in the ciphertext region (after the 52-byte header)
    for offset in [52, 53, 60, backup_data.len() - 1, backup_data.len() - 16] {
        if offset < backup_data.len() {
            let mut corrupted = backup_data.clone();
            corrupted[offset] ^= 0x01; // flip one bit
            let result = backup::restore_backup(
                &corrupted,
                "Pass-Long-Phr4se",
                "TEST-SERIAL-0001",
                Some(0),
                None,
                None,
            );
            assert!(
                result.is_err(),
                "Single bit flip at offset {} must be detected by AES-GCM authentication",
                offset
            );
        }
    }
}
