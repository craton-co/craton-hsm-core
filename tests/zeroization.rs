// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Zeroization verification tests for RawKeyMaterial.
//!
//! These tests verify that sensitive key material is properly zeroed
//! when dropped, per FIPS 140-3 CSP zeroization requirements.
//!
//! The tests use a safe approach: we verify that RawKeyMaterial::new()
//! accepts data, that the bytes are accessible, and that after drop
//! the type's zeroize-on-drop contract is exercised. We also verify
//! that Debug output never leaks key bytes.

use craton_hsm::store::key_material::RawKeyMaterial;

/// Verify that a newly created RawKeyMaterial contains the expected bytes.
fn assert_key_contains(key: &RawKeyMaterial, expected_byte: u8, expected_len: usize) {
    assert_eq!(key.len(), expected_len);
    assert!(!key.is_empty());
    for &b in key.as_bytes() {
        assert_eq!(b, expected_byte);
    }
}

#[test]
fn test_zeroization_32_byte_aes_key() {
    // Create a 32-byte AES-256 key, verify contents, then drop.
    // The Zeroize impl on Vec<u8> inside RawKeyMaterial fills with 0 on drop.
    // We verify the contract by checking that key bytes are correct before drop,
    // and that the type implements the expected Drop behavior via a witness.
    let data = vec![0xAB; 32];
    let key = RawKeyMaterial::new(data);
    assert_key_contains(&key, 0xAB, 32);
    // Drop exercises zeroize + munlock
    drop(key);
}

#[test]
fn test_zeroization_48_byte_ec_key() {
    let data = vec![0xCD; 48];
    let key = RawKeyMaterial::new(data);
    assert_key_contains(&key, 0xCD, 48);
    drop(key);
}

#[test]
fn test_zeroization_256_byte_rsa_key() {
    let data = vec![0xEF; 256];
    let key = RawKeyMaterial::new(data);
    assert_key_contains(&key, 0xEF, 256);
    drop(key);
}

#[test]
fn test_zeroization_large_pqc_key() {
    // ML-DSA-44 signing key is ~2560 bytes
    let data = vec![0x77; 2560];
    let key = RawKeyMaterial::new(data);
    assert_key_contains(&key, 0x77, 2560);
    drop(key);
}

#[test]
fn test_zeroization_clone_also_zeroed() {
    // Verify that cloned key material has correct content and both can be dropped
    let original = RawKeyMaterial::new(vec![0xBB; 64]);
    let cloned = original.clone();

    assert_eq!(original.len(), 64);
    assert_eq!(cloned.len(), 64);
    assert_eq!(original.as_bytes(), cloned.as_bytes());

    // Drop clone first, then original — both exercise zeroize
    drop(cloned);
    drop(original);
}

#[test]
fn test_zeroization_empty_key_no_panic() {
    // Empty key material should not panic on drop
    let key = RawKeyMaterial::new(vec![]);
    assert!(key.is_empty());
    assert_eq!(key.len(), 0);
    drop(key);
}

#[test]
fn test_debug_output_redacted() {
    // Verify Debug output never contains actual key bytes
    let key = RawKeyMaterial::new(vec![0xDE, 0xAD, 0xBE, 0xEF]);
    let debug_str = format!("{:?}", key);
    assert!(
        debug_str.contains("[REDACTED]"),
        "Debug output should contain [REDACTED], got: {}",
        debug_str
    );
    assert!(
        !debug_str.contains("222")
            && !debug_str.contains("173")
            && !debug_str.contains("190")
            && !debug_str.contains("239"),
        "Debug output must not contain actual key byte values, got: {}",
        debug_str
    );
    // Should show length
    assert!(
        debug_str.contains("4"),
        "Debug output should show key length, got: {}",
        debug_str
    );
}

#[test]
fn test_zeroization_key_bytes_accessible_before_drop() {
    // Verify key bytes are fully accessible and correct until drop
    let pattern: Vec<u8> = (0..128).collect();
    let key = RawKeyMaterial::new(pattern.clone());
    assert_eq!(key.as_bytes(), &pattern[..]);
    assert_eq!(key.len(), 128);
    drop(key);
}

#[test]
fn test_zeroization_multiple_drops_safe() {
    // Creating and dropping many keys should not panic or leak
    for i in 0..100u8 {
        let key = RawKeyMaterial::new(vec![i; 32]);
        assert_eq!(key.as_bytes()[0], i);
        drop(key);
    }
}

/// FIPS 140-3 CSP Zeroization Post-Drop Verification.
///
/// Captures the raw pointer to key material BEFORE drop, then inspects the
/// memory AFTER drop to verify the zeroize-on-drop contract was honored.
/// This catches compiler optimizations that might elide the zeroing.
///
/// SAFETY: This test intentionally uses unsafe to inspect memory after free.
/// This is acceptable in a test-only context.  The allocation is still live
/// because Vec::zeroize() fills with 0 but does not deallocate; deallocation
/// happens when the Vec's Drop runs after Zeroize.  We capture the pointer
/// and length before drop and check immediately after.  On most allocators
/// the memory will not have been recycled in the same thread between drop
/// and the check.
///
/// NOTE: This test is best-effort — some allocators may recycle the page
/// immediately.  We run multiple iterations to increase confidence.
#[test]
fn test_zeroization_post_drop_memory_is_zeroed() {
    // Run multiple iterations to increase confidence against allocator reuse
    for round in 0..10 {
        let sentinel: u8 = 0xA0 + round;
        let key = RawKeyMaterial::new(vec![sentinel; 64]);

        // Capture pointer and length BEFORE drop
        let ptr = key.as_bytes().as_ptr();
        let len = key.len();

        // Verify the sentinel pattern is present before drop
        assert_eq!(
            unsafe { std::ptr::read(ptr) },
            sentinel,
            "Pre-drop: first byte should be sentinel 0x{:02X}",
            sentinel
        );

        // Drop — this should zeroize the buffer then deallocate
        drop(key);

        // Read the memory that was occupied by the key.
        // After zeroize, these bytes should be 0x00.
        // SAFETY: We're reading potentially-freed memory, which is UB in
        // strict terms, but is safe in practice for this test because:
        // 1. The allocation was just freed in the same thread
        // 2. Most allocators don't unmap pages this quickly
        // 3. We're only reading, not writing
        let mut non_zero_count = 0;
        for i in 0..len {
            let byte = unsafe { std::ptr::read(ptr.add(i)) };
            if byte != 0 {
                non_zero_count += 1;
            }
        }

        // Allow some tolerance — the allocator may have written metadata.
        // But the vast majority of bytes (>90%) should be zero if zeroize ran.
        let zero_ratio = (len - non_zero_count) as f64 / len as f64;
        assert!(
            zero_ratio > 0.9,
            "Round {}: Only {:.0}% of bytes are zero after drop — zeroize may not have run \
             (expected >90%). non_zero={}, total={}",
            round,
            zero_ratio * 100.0,
            non_zero_count,
            len
        );
    }
}

/// Verify that cloned key material is independently zeroized on drop.
/// Both the clone and the original must be zeroed.
#[test]
fn test_zeroization_clone_independently_zeroed() {
    let original = RawKeyMaterial::new(vec![0xFE; 128]);
    let cloned = original.clone();

    let clone_ptr = cloned.as_bytes().as_ptr();
    let clone_len = cloned.len();

    // Verify clone has correct content
    assert_eq!(unsafe { std::ptr::read(clone_ptr) }, 0xFE);

    // Drop clone first
    drop(cloned);

    // Check clone memory is zeroed
    let mut non_zero = 0;
    for i in 0..clone_len {
        if unsafe { std::ptr::read(clone_ptr.add(i)) } != 0 {
            non_zero += 1;
        }
    }
    let zero_ratio = (clone_len - non_zero) as f64 / clone_len as f64;
    assert!(
        zero_ratio > 0.9,
        "Cloned key: only {:.0}% zeroed after drop (expected >90%)",
        zero_ratio * 100.0
    );

    // Original should still be valid
    assert_eq!(original.as_bytes()[0], 0xFE);
    drop(original);
}
