// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
// Audit log and integrity tests — exercises the audit subsystem and
// crypto self-test/integrity verification through the Rust API.

use craton_hsm::audit::log::{AuditLog, AuditOperation, AuditResult};
use craton_hsm::crypto::self_test;

// ============================================================================
// AuditLog tests
// ============================================================================

#[test]
fn test_audit_log_new_is_empty() {
    let log = AuditLog::new();
    assert_eq!(log.entry_count(), 0, "New audit log should be empty");
}

#[test]
fn test_audit_log_record_increments_count() {
    let log = AuditLog::new();
    log.record(1, AuditOperation::Initialize, AuditResult::Success, None)
        .unwrap();
    log.flush();
    assert_eq!(log.entry_count(), 1);
}

#[test]
fn test_audit_log_multiple_entries() {
    let log = AuditLog::new();
    log.record(1, AuditOperation::Initialize, AuditResult::Success, None)
        .unwrap();
    log.record(
        1,
        AuditOperation::Login { user_type: 1 },
        AuditResult::Success,
        None,
    )
    .unwrap();
    log.record(
        1,
        AuditOperation::GenerateKey {
            mechanism: 0x1080,
            key_length: 256,
            fips_approved: true,
        },
        AuditResult::Success,
        Some("key1".to_string()),
    )
    .unwrap();
    log.flush();
    assert_eq!(log.entry_count(), 3);
}

#[test]
fn test_audit_log_failure_event() {
    let log = AuditLog::new();
    log.record(
        1,
        AuditOperation::Login { user_type: 1 },
        AuditResult::Failure(0xA0),
        None,
    )
    .unwrap();
    log.flush();
    assert_eq!(log.entry_count(), 1);
}

#[test]
fn test_audit_log_all_operation_types() {
    let log = AuditLog::new();
    log.record(1, AuditOperation::Initialize, AuditResult::Success, None)
        .unwrap();
    log.record(1, AuditOperation::Finalize, AuditResult::Success, None)
        .unwrap();
    log.record(
        1,
        AuditOperation::Login { user_type: 0 },
        AuditResult::Success,
        None,
    )
    .unwrap();
    log.record(1, AuditOperation::Logout, AuditResult::Success, None)
        .unwrap();
    log.record(
        1,
        AuditOperation::GenerateKey {
            mechanism: 0x1080,
            key_length: 256,
            fips_approved: true,
        },
        AuditResult::Success,
        Some("k1".into()),
    )
    .unwrap();
    log.record(
        1,
        AuditOperation::GenerateKeyPair {
            mechanism: 0,
            key_length: 2048,
            fips_approved: true,
        },
        AuditResult::Success,
        Some("k2".into()),
    )
    .unwrap();
    log.record(
        1,
        AuditOperation::Sign {
            mechanism: 0x40,
            fips_approved: true,
        },
        AuditResult::Success,
        Some("k3".into()),
    )
    .unwrap();
    log.record(
        1,
        AuditOperation::Verify {
            mechanism: 0x40,
            fips_approved: true,
        },
        AuditResult::Success,
        Some("k4".into()),
    )
    .unwrap();
    log.record(
        1,
        AuditOperation::Encrypt {
            mechanism: 0x1087,
            fips_approved: true,
        },
        AuditResult::Success,
        Some("k5".into()),
    )
    .unwrap();
    log.record(
        1,
        AuditOperation::Decrypt {
            mechanism: 0x1087,
            fips_approved: true,
        },
        AuditResult::Success,
        Some("k6".into()),
    )
    .unwrap();
    log.record(
        1,
        AuditOperation::Digest {
            mechanism: 0x250,
            fips_approved: true,
        },
        AuditResult::Success,
        None,
    )
    .unwrap();
    log.record(1, AuditOperation::CreateObject, AuditResult::Success, None)
        .unwrap();
    log.record(1, AuditOperation::DestroyObject, AuditResult::Success, None)
        .unwrap();
    log.record(
        1,
        AuditOperation::GenerateRandom { length: 32 },
        AuditResult::Success,
        None,
    )
    .unwrap();
    log.record(
        1,
        AuditOperation::WrapKey {
            mechanism: 0x2109,
            fips_approved: true,
        },
        AuditResult::Success,
        Some("k7".into()),
    )
    .unwrap();
    log.record(
        1,
        AuditOperation::UnwrapKey {
            mechanism: 0x2109,
            fips_approved: true,
        },
        AuditResult::Success,
        Some("k8".into()),
    )
    .unwrap();
    log.record(
        1,
        AuditOperation::DeriveKey {
            mechanism: 0x1050,
            fips_approved: true,
        },
        AuditResult::Success,
        Some("k9".into()),
    )
    .unwrap();
    log.flush();
    assert_eq!(
        log.entry_count(),
        17,
        "All 17 operation types should be recorded"
    );
}

#[test]
fn test_audit_log_fips_non_approved() {
    let log = AuditLog::new();
    log.record(
        1,
        AuditOperation::Sign {
            mechanism: 0x80000010,
            fips_approved: false,
        },
        AuditResult::Success,
        Some("pqc".into()),
    )
    .unwrap();
    log.flush();
    assert_eq!(log.entry_count(), 1);
}

#[test]
fn test_audit_log_with_key_id() {
    let log = AuditLog::new();
    log.record(
        1,
        AuditOperation::GenerateKey {
            mechanism: 0x1080,
            key_length: 256,
            fips_approved: true,
        },
        AuditResult::Success,
        Some("my-aes-key-id-123".to_string()),
    );
    log.flush();
    assert_eq!(log.entry_count(), 1);
}

#[test]
fn test_audit_log_different_sessions() {
    let log = AuditLog::new();
    log.record(1, AuditOperation::Initialize, AuditResult::Success, None)
        .unwrap();
    log.record(2, AuditOperation::Initialize, AuditResult::Success, None)
        .unwrap();
    log.record(
        3,
        AuditOperation::Login { user_type: 1 },
        AuditResult::Success,
        None,
    )
    .unwrap();
    log.flush();
    assert_eq!(log.entry_count(), 3);
}

#[test]
fn test_audit_log_rapid_recording() {
    let log = AuditLog::new();
    for i in 0..100 {
        log.record(
            i as u64,
            AuditOperation::GenerateRandom { length: 32 },
            AuditResult::Success,
            None,
        )
        .unwrap();
    }
    log.flush();
    assert_eq!(log.entry_count(), 100, "Should handle 100 rapid entries");
}

// ============================================================================
// Audit export & chain verification tests
// ============================================================================

#[test]
fn test_audit_log_get_entries() {
    let log = AuditLog::new();
    log.record(1, AuditOperation::Initialize, AuditResult::Success, None)
        .unwrap();
    log.record(
        1,
        AuditOperation::Login { user_type: 1 },
        AuditResult::Success,
        None,
    )
    .unwrap();
    log.flush();
    let entries = log.get_entries();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].session_handle, 1);
}

#[test]
fn test_audit_log_get_recent_entries() {
    let log = AuditLog::new();
    for i in 0..10 {
        log.record(
            i,
            AuditOperation::GenerateRandom { length: 32 },
            AuditResult::Success,
            None,
        )
        .unwrap();
    }
    log.flush();
    let recent = log.get_recent_entries(3);
    assert_eq!(recent.len(), 3);
    assert_eq!(recent[0].session_handle, 7);
    assert_eq!(recent[2].session_handle, 9);
}

#[test]
fn test_audit_log_export_json() {
    let log = AuditLog::new();
    log.record(1, AuditOperation::Initialize, AuditResult::Success, None)
        .unwrap();
    log.flush();
    let json = log.export_json();
    assert!(json.starts_with('['));
    assert!(json.ends_with(']'));
    assert!(json.contains("\"Initialize\""));
}

#[test]
fn test_audit_log_export_ndjson() {
    let log = AuditLog::new();
    log.record(1, AuditOperation::Initialize, AuditResult::Success, None)
        .unwrap();
    log.record(
        1,
        AuditOperation::Login { user_type: 1 },
        AuditResult::Success,
        None,
    )
    .unwrap();
    log.flush();
    let ndjson = log.export_ndjson();
    let lines: Vec<&str> = ndjson.lines().collect();
    assert_eq!(lines.len(), 2, "NDJSON should have one line per entry");
    // Each line should be valid JSON
    for line in &lines {
        assert!(
            serde_json::from_str::<serde_json::Value>(line).is_ok(),
            "Each NDJSON line should be valid JSON"
        );
    }
}

#[test]
fn test_audit_log_export_syslog() {
    let log = AuditLog::new();
    log.record(
        42,
        AuditOperation::Sign {
            mechanism: 0x40,
            fips_approved: true,
        },
        AuditResult::Success,
        Some("key-123".to_string()),
    );
    log.record(
        42,
        AuditOperation::Login { user_type: 1 },
        AuditResult::Failure(0xA0),
        None,
    );
    log.flush();
    let syslog = log.export_syslog();
    assert_eq!(syslog.len(), 2);
    // Success = severity 6, facility 10 → priority 86
    assert!(syslog[0].starts_with("<86>1 "));
    assert!(syslog[0].contains("op=Sign"));
    assert!(syslog[0].contains("result=SUCCESS"));
    assert!(syslog[0].contains("key=key-123"));
    // Failure = severity 4, facility 10 → priority 84
    assert!(syslog[1].starts_with("<84>1 "));
    assert!(syslog[1].contains("result=FAILURE(0x000000A0)"));
}

#[test]
fn test_audit_log_verify_chain_empty() {
    let log = AuditLog::new();
    assert_eq!(log.verify_chain(), Ok(0));
}

#[test]
fn test_audit_log_verify_chain_valid() {
    let log = AuditLog::new();
    log.record(1, AuditOperation::Initialize, AuditResult::Success, None)
        .unwrap();
    log.record(
        1,
        AuditOperation::Login { user_type: 1 },
        AuditResult::Success,
        None,
    )
    .unwrap();
    log.record(
        1,
        AuditOperation::GenerateKey {
            mechanism: 0x1080,
            key_length: 256,
            fips_approved: true,
        },
        AuditResult::Success,
        Some("k1".into()),
    );
    log.flush();
    assert_eq!(log.verify_chain(), Ok(3));
}

#[test]
fn test_audit_log_export_json_empty() {
    let log = AuditLog::new();
    let json = log.export_json();
    assert_eq!(json.trim(), "[]");
}

#[test]
fn test_audit_log_export_ndjson_empty() {
    let log = AuditLog::new();
    let ndjson = log.export_ndjson();
    assert_eq!(ndjson, "");
}

// ============================================================================
// FIPS POST / Self-test tests
// ============================================================================

#[test]
fn test_fips_post_passes() {
    // Run all FIPS Power-On Self Tests (KATs)
    let result = self_test::run_post();
    assert!(result.is_ok(), "FIPS POST should pass: {:?}", result.err());
}

#[test]
fn test_fips_post_individual_kats() {
    // Run POST and verify it doesn't panic
    let result = self_test::run_post();
    assert!(result.is_ok());
}

// ============================================================================
// StoredObject unit tests (lifecycle, size, matching)
// ============================================================================

use craton_hsm::store::key_material::RawKeyMaterial;
use craton_hsm::store::object::{KeyLifecycleState, StoredObject};

#[test]
fn test_stored_object_default_lifecycle_active() {
    let obj = StoredObject::new(1, 0x04); // CKO_SECRET_KEY
    assert_eq!(obj.lifecycle_state, KeyLifecycleState::Active);
}

#[test]
fn test_stored_object_check_lifecycle_active() {
    let obj = StoredObject::new(1, 0x04);
    assert!(obj.check_lifecycle("sign").is_ok());
    assert!(obj.check_lifecycle("encrypt").is_ok());
    assert!(obj.check_lifecycle("verify").is_ok());
    assert!(obj.check_lifecycle("decrypt").is_ok());
}

#[test]
fn test_stored_object_compromised_blocks_all() {
    let mut obj = StoredObject::new(1, 0x04);
    obj.lifecycle_state = KeyLifecycleState::Compromised;
    assert!(obj.check_lifecycle("sign").is_err());
    assert!(obj.check_lifecycle("encrypt").is_err());
    assert!(obj.check_lifecycle("verify").is_err());
    assert!(obj.check_lifecycle("decrypt").is_err());
}

#[test]
fn test_stored_object_deactivated_allows_verify() {
    let mut obj = StoredObject::new(1, 0x04);
    obj.lifecycle_state = KeyLifecycleState::Deactivated;
    assert!(
        obj.check_lifecycle("verify").is_ok(),
        "Deactivated should allow verify"
    );
    assert!(
        obj.check_lifecycle("decrypt").is_ok(),
        "Deactivated should allow decrypt"
    );
    assert!(
        obj.check_lifecycle("sign").is_err(),
        "Deactivated should block sign"
    );
    assert!(
        obj.check_lifecycle("encrypt").is_err(),
        "Deactivated should block encrypt"
    );
}

#[test]
fn test_stored_object_destroyed_invalid() {
    let mut obj = StoredObject::new(1, 0x04);
    obj.lifecycle_state = KeyLifecycleState::Destroyed;
    assert!(obj.check_lifecycle("sign").is_err());
    assert!(obj.check_lifecycle("verify").is_err());
}

#[test]
fn test_stored_object_preactivation_blocks_all() {
    let mut obj = StoredObject::new(1, 0x04);
    obj.lifecycle_state = KeyLifecycleState::PreActivation;
    assert!(obj.check_lifecycle("sign").is_err());
    assert!(obj.check_lifecycle("encrypt").is_err());
    assert!(obj.check_lifecycle("verify").is_err());
    assert!(obj.check_lifecycle("decrypt").is_err());
}

#[test]
fn test_stored_object_approximate_size() {
    let obj = StoredObject::new(1, 0x04);
    let size = obj.approximate_size();
    assert!(size > 0, "Object size should be > 0");
}

#[test]
fn test_stored_object_matches_empty_template() {
    let obj = StoredObject::new(1, 0x04);
    assert!(
        obj.matches_template(&[]),
        "Empty template should match anything"
    );
}

#[test]
fn test_stored_object_matches_class_template() {
    use std::ffi::c_ulong;
    let obj = StoredObject::new(1, 0x04); // CKO_SECRET_KEY
    let class_bytes = (0x04 as c_ulong).to_ne_bytes().to_vec();
    assert!(obj.matches_template(&[(0x00, class_bytes)]));
}

#[test]
fn test_stored_object_no_match_wrong_class() {
    use std::ffi::c_ulong;
    let obj = StoredObject::new(1, 0x04); // CKO_SECRET_KEY
    let class_bytes = (0x02 as c_ulong).to_ne_bytes().to_vec(); // CKO_PUBLIC_KEY
    assert!(!obj.matches_template(&[(0x00, class_bytes)]));
}

#[test]
fn test_stored_object_debug_redacts_key() {
    let mut obj = StoredObject::new(1, 0x04);
    obj.key_material = Some(RawKeyMaterial::new(vec![0x42; 32]));
    let debug_output = format!("{:?}", obj);
    assert!(
        debug_output.contains("REDACTED"),
        "Debug should redact key material"
    );
    assert!(
        !debug_output.contains("42"),
        "Debug should not contain key bytes"
    );
}

#[test]
fn test_stored_object_size_with_key_material() {
    let mut obj = StoredObject::new(1, 0x04);
    let size_without = obj.approximate_size();
    obj.key_material = Some(RawKeyMaterial::new(vec![0u8; 32]));
    let size_with = obj.approximate_size();
    assert!(
        size_with > size_without,
        "Size should increase with key material"
    );
}

#[test]
fn test_stored_object_label_matching() {
    let mut obj = StoredObject::new(1, 0x04);
    obj.label = b"mykey".to_vec();
    assert!(obj.matches_template(&[(0x03, b"mykey".to_vec())])); // CKA_LABEL
    assert!(!obj.matches_template(&[(0x03, b"other".to_vec())]));
}
