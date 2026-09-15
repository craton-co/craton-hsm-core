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
    log.flush().unwrap();
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
    log.flush().unwrap();
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
    log.flush().unwrap();
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
    log.flush().unwrap();
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
    log.flush().unwrap();
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
    )
    .unwrap();
    log.flush().unwrap();
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
    log.flush().unwrap();
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
    log.flush().unwrap();
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
    log.flush().unwrap();
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
    log.flush().unwrap();
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
    log.flush().unwrap();
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
    log.flush().unwrap();
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
    )
    .unwrap();
    log.record(
        42,
        AuditOperation::Login { user_type: 1 },
        AuditResult::Failure(0xA0),
        None,
    )
    .unwrap();
    log.flush().unwrap();
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
    )
    .unwrap();
    log.flush().unwrap();
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

// ----------------------------------------------------------------------------
// record_sync durability — the event MUST be on disk before record_sync
// returns. Regression test for the issue where `record()` returned Ok() before
// the background worker had written / fsynced the line, allowing sensitive
// events (login, key destruction, init_token, …) to be lost on SIGKILL / panic
// between enqueue and drain.
// ----------------------------------------------------------------------------

#[test]
fn test_audit_log_record_sync_is_durable_on_disk() {
    use std::io::Read as _;

    // Use a process-unique path so concurrent tests don't collide. We avoid a
    // `tempfile` dependency: the OS temp dir + PID + a counter is sufficient
    // for a single-shot test.
    let dir = std::env::temp_dir();
    let path = dir.join(format!(
        "craton_hsm_audit_record_sync_{}_{}.log",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    // Belt-and-braces cleanup in case a previous run aborted mid-test.
    let _ = std::fs::remove_file(&path);

    let log = AuditLog::new_with_path(path.clone())
        .expect("audit log construction with disk path should succeed");

    // record_sync MUST block until the line is durable on disk. Read the file
    // immediately after — without any explicit flush() — and assert the event
    // is present. With the old fire-and-forget record(), this would flake
    // (the worker may not have drained yet).
    log.record_sync(
        42,
        AuditOperation::Login { user_type: 1 },
        AuditResult::Success,
        Some("durability-test".to_string()),
    )
    .expect("record_sync should succeed for a valid event");

    let mut file =
        std::fs::File::open(&path).expect("audit log file should exist after record_sync");
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .expect("audit log file should be readable");

    assert!(
        contents.contains("\"Login\""),
        "audit file must contain the Login event after record_sync returns, got: {:?}",
        contents,
    );
    assert!(
        contents.contains("durability-test"),
        "audit file must contain the key_id after record_sync returns, got: {:?}",
        contents,
    );
    assert!(
        contents.ends_with('\n'),
        "audit file should end with a newline (NDJSON), got: {:?}",
        contents,
    );

    // Drop the log so the worker exits, then remove the temp file.
    drop(log);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_audit_log_record_sync_in_memory_only() {
    // Without a disk path, record_sync should still block until the in-memory
    // state has been updated — i.e. entry_count() must reflect the new event
    // immediately, without a subsequent flush().
    let log = AuditLog::new();
    log.record_sync(7, AuditOperation::DestroyObject, AuditResult::Success, None)
        .expect("record_sync should succeed on an in-memory audit log");
    assert_eq!(
        log.entry_count(),
        1,
        "record_sync must commit to in-memory state before returning",
    );
}

// ============================================================================
// FIPS POST / Self-test tests
// ============================================================================

#[test]
fn test_fips_post_passes() {
    // Default test builds embed the all-zero placeholder integrity public
    // key, so the §9.4 software-integrity test would now hard-fail.  Opt
    // in to the documented dev bypass so this integration test can still
    // exercise the algorithm KATs.
    // SAFETY: process-global env var, set once for the rest of the test run.
    unsafe { std::env::set_var("CRATON_HSM_INTEGRITY_BYPASS", "unsafe-dev-only") };

    // Run all FIPS Power-On Self Tests (KATs)
    // Whichever backend this build compiled; POST must pass against it, which
    // is the property that matters now that the KATs follow the backend.
    #[cfg(feature = "rustcrypto-backend")]
    let backend = craton_hsm::crypto::rustcrypto_backend::RustCryptoBackend;
    #[cfg(all(feature = "awslc-backend", not(feature = "rustcrypto-backend")))]
    let backend = craton_hsm::crypto::awslc_backend::AwsLcBackend;
    let result = self_test::run_post(&backend);
    assert!(result.is_ok(), "FIPS POST should pass: {:?}", result.err());
}

// test_fips_post_individual_kats removed — identical to test_fips_post_passes
// and run_post() resets global IV trackers, causing races under --test-threads=8.

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

// ===========================================================================
// Audit chain format versioning and group commit
//
// The chain hash input changed from a `serde_json` encoding of the event
// payload to the canonical binary encoding described in `src/audit/log.rs`
// (`AUDIT_LOG_FORMAT_VERSION` 0 -> 1). These tests pin the properties that
// change had to preserve: existing logs keep verifying, upgraded logs verify
// end to end, and tampering is still detected.
// ===========================================================================

/// Build a process-unique temp path for a test audit log.
fn audit_temp_path(tag: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "craton_hsm_audit_{}_{}_{}.log",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    let _ = std::fs::remove_file(&path);
    path
}

#[test]
fn test_audit_records_are_written_at_current_format_version() {
    let path = audit_temp_path("format_version");
    let log = AuditLog::new_with_path(path.clone()).expect("audit log should construct");

    log.record_sync(
        1,
        AuditOperation::Login { user_type: 1 },
        AuditResult::Success,
        None,
    )
    .expect("record_sync should succeed");

    let contents = std::fs::read_to_string(&path).expect("log file should be readable");
    assert!(
        contents.contains("\"format_version\":1"),
        "new records must carry the current format version, got: {:?}",
        contents,
    );

    drop(log);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_audit_chain_verifies_after_reopen() {
    let path = audit_temp_path("reopen");

    {
        let log = AuditLog::new_with_path(path.clone()).expect("audit log should construct");
        for i in 0..8 {
            log.record_sync(
                i,
                AuditOperation::Sign {
                    mechanism: 0x40,
                    fips_approved: true,
                },
                AuditResult::Success,
                Some(format!("key={}", i)),
            )
            .expect("record_sync should succeed");
        }
    }

    // Reopening recovers and verifies the on-disk chain. A verification failure
    // sets the tamper flag permanently, so this asserts the recorded chain and
    // the recomputed chain agree under the new encoding.
    let reopened = AuditLog::new_with_path(path.clone()).expect("audit log should reopen");
    assert!(
        !reopened.is_tamper_detected(),
        "a chain written by this build must verify when reopened",
    );

    // Appending after recovery must keep the chain intact.
    reopened
        .record_sync(99, AuditOperation::Logout, AuditResult::Success, None)
        .expect("append after recovery should succeed");
    drop(reopened);

    let third = AuditLog::new_with_path(path.clone()).expect("audit log should reopen again");
    assert!(
        !third.is_tamper_detected(),
        "appending to a recovered chain must not break it",
    );

    drop(third);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_audit_chain_verifies_legacy_v0_records() {
    // A log written by a build that predates the canonical binary encoding
    // carries `format_version: 0` and was chained over the JSON payload.
    // Verification dispatches on each record's own version, so such a file
    // must still verify rather than being reported as tampered.
    //
    // The fixture below is generated rather than hard-coded: it recomputes the
    // legacy chain the same way the old implementation did, so the test pins
    // the *compatibility rule*, not a byte string that would silently rot.
    use sha2::{Digest, Sha256};

    let path = audit_temp_path("legacy_v0");

    #[derive(serde::Serialize)]
    struct LegacyPayload<'a> {
        format_version: u32,
        timestamp: u64,
        session_handle: u64,
        operation: &'a serde_json::Value,
        key_id: &'a Option<String>,
        result: &'a serde_json::Value,
    }

    let mut prev = [0u8; 32];
    let mut lines = String::new();
    for i in 1u64..=4 {
        let operation = serde_json::json!({ "OpenSession": { "slot_id": i } });
        let result = serde_json::json!("Success");
        let key_id: Option<String> = None;

        let payload = LegacyPayload {
            format_version: 0,
            timestamp: 1_000_000 + i,
            session_handle: i,
            operation: &operation,
            key_id: &key_id,
            result: &result,
        };
        let payload_bytes = serde_json::to_vec(&payload).expect("payload serializes");
        let mut hasher = Sha256::new();
        hasher.update(prev);
        hasher.update(&payload_bytes);
        let next: [u8; 32] = hasher.finalize().into();

        let record = serde_json::json!({
            "format_version": 0,
            "timestamp": 1_000_000 + i,
            "session_handle": i,
            "operation": operation,
            "key_id": key_id,
            "result": result,
            "previous_hash": prev.to_vec(),
        });
        lines.push_str(&serde_json::to_string(&record).expect("record serializes"));
        lines.push('\n');
        prev = next;
    }
    std::fs::write(&path, lines).expect("fixture should be writable");

    let log = AuditLog::new_with_path(path.clone()).expect("audit log should open legacy file");
    assert!(
        !log.is_tamper_detected(),
        "a legacy format_version=0 chain must still verify after the encoding change",
    );

    // An upgraded deployment appends v1 records to a v0 file. The mixed-version
    // file must verify end to end on the next reopen.
    log.record_sync(5, AuditOperation::Logout, AuditResult::Success, None)
        .expect("appending a v1 record to a v0 file should succeed");
    drop(log);

    let mixed = AuditLog::new_with_path(path.clone()).expect("mixed-version file should open");
    assert!(
        !mixed.is_tamper_detected(),
        "a file mixing v0 and v1 records must verify end to end",
    );

    drop(mixed);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_audit_chain_detects_tampering_on_disk() {
    let path = audit_temp_path("tamper");

    {
        let log = AuditLog::new_with_path(path.clone()).expect("audit log should construct");
        for i in 0..4 {
            log.record_sync(
                i,
                AuditOperation::Login { user_type: 1 },
                AuditResult::Success,
                None,
            )
            .expect("record_sync should succeed");
        }
    }

    // Flip a field in the second record. The chain hash covers the payload, so
    // the third record's previous_hash no longer matches.
    let contents = std::fs::read_to_string(&path).expect("log should be readable");
    let mut lines: Vec<String> = contents.lines().map(str::to_string).collect();
    assert!(lines.len() >= 4, "expected 4 records, got {}", lines.len());
    lines[1] = lines[1].replace("\"user_type\":1", "\"user_type\":0");
    assert!(
        lines[1].contains("\"user_type\":0"),
        "tamper fixture must actually modify the record",
    );
    std::fs::write(&path, lines.join("\n") + "\n").expect("log should be writable");

    let reopened = AuditLog::new_with_path(path.clone()).expect("audit log should open");
    assert!(
        reopened.is_tamper_detected(),
        "modifying a record's payload must break chain verification",
    );

    // Once tamper is detected the log must refuse further records.
    let err = reopened.record(0, AuditOperation::Logout, AuditResult::Success, None);
    assert!(
        err.is_err(),
        "record() must refuse to append after tamper detection",
    );

    drop(reopened);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_audit_group_commit_preserves_order_and_chain() {
    // The worker coalesces queued events into one write + fsync. Ordering,
    // timestamp monotonicity, and chain integrity must all survive batching.
    let path = audit_temp_path("group_commit");
    let log = AuditLog::new_with_path(path.clone()).expect("audit log should construct");

    const N: u64 = 500;
    for i in 0..N {
        log.record(
            i,
            AuditOperation::Digest {
                mechanism: 0x250,
                fips_approved: true,
            },
            AuditResult::Success,
            None,
        )
        .expect("record should enqueue");
    }
    log.flush().expect("flush should drain the worker");

    let entries = log.get_entries();
    assert_eq!(
        entries.len() as u64,
        N,
        "every enqueued event must be committed",
    );
    for (i, entry) in entries.iter().enumerate() {
        assert_eq!(
            entry.session_handle, i as u64,
            "batched events must be committed in enqueue order",
        );
    }
    for pair in entries.windows(2) {
        assert!(
            pair[1].timestamp > pair[0].timestamp,
            "timestamps must stay strictly monotonic across a batch",
        );
    }
    assert_eq!(
        log.verify_chain(),
        Ok(entries.len()),
        "the in-memory chain must verify after group commit",
    );

    drop(log);

    // The on-disk chain must verify too, and hold exactly the same events.
    let reopened = AuditLog::new_with_path(path.clone()).expect("audit log should reopen");
    assert!(
        !reopened.is_tamper_detected(),
        "the group-committed on-disk chain must verify",
    );
    let on_disk =
        craton_hsm::audit::log::load_entries_from_file(&path).expect("on-disk entries should load");
    assert_eq!(
        on_disk.len() as u64,
        N,
        "every event must reach disk, not just memory",
    );

    drop(reopened);
    let _ = std::fs::remove_file(&path);
}
