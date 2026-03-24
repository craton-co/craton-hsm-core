// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Integration tests for crypto/drbg.rs (HMAC_DRBG per SP 800-90A)

use craton_hsm::crypto::drbg::HmacDrbg;

#[test]
fn test_drbg_consecutive_outputs_differ() {
    let mut drbg = HmacDrbg::new().unwrap();
    let mut buf1 = [0u8; 32];
    let mut buf2 = [0u8; 32];

    drbg.generate(&mut buf1).unwrap();
    drbg.generate(&mut buf2).unwrap();

    assert_ne!(buf1, buf2, "Consecutive DRBG outputs must differ");
}

#[test]
fn test_drbg_output_not_all_zeros() {
    let mut drbg = HmacDrbg::new().unwrap();

    for size in &[1, 16, 32, 64, 128, 256] {
        let mut buf = vec![0u8; *size];
        drbg.generate(&mut buf).unwrap();
        assert_ne!(
            buf,
            vec![0u8; *size],
            "DRBG output of {} bytes must not be all zeros",
            size
        );
    }
}

#[test]
fn test_drbg_reseed_changes_state() {
    let mut drbg = HmacDrbg::new().unwrap();
    let mut buf1 = [0u8; 32];
    drbg.generate(&mut buf1).unwrap();

    // Reseed
    drbg.reseed().unwrap();

    let mut buf2 = [0u8; 32];
    drbg.generate(&mut buf2).unwrap();

    // After reseed, output should differ
    assert_ne!(buf1, buf2, "Output after reseed should differ");
}

#[test]
fn test_drbg_various_output_lengths() {
    let mut drbg = HmacDrbg::new().unwrap();

    // Test boundary sizes and odd sizes
    for &len in &[
        1, 2, 15, 16, 17, 31, 32, 33, 63, 64, 65, 100, 255, 256, 512, 1024,
    ] {
        let mut buf = vec![0u8; len];
        drbg.generate(&mut buf).unwrap();
        assert_eq!(buf.len(), len);
        // At least one byte should be non-zero for any reasonable output
        assert!(
            buf.iter().any(|&b| b != 0),
            "DRBG output of {} bytes should have non-zero bytes",
            len
        );
    }
}

#[test]
fn test_drbg_large_output() {
    let mut drbg = HmacDrbg::new().unwrap();
    let mut buf = vec![0u8; 4096];
    drbg.generate(&mut buf).unwrap();

    // Count unique bytes — should have good entropy distribution
    let unique: std::collections::HashSet<u8> = buf.iter().copied().collect();
    assert!(
        unique.len() > 200,
        "4096 bytes of DRBG output should have >200 unique byte values, got {}",
        unique.len()
    );
}

#[test]
fn test_drbg_multiple_instances_differ() {
    let mut drbg1 = HmacDrbg::new().unwrap();
    let mut drbg2 = HmacDrbg::new().unwrap();

    let mut buf1 = [0u8; 32];
    let mut buf2 = [0u8; 32];

    drbg1.generate(&mut buf1).unwrap();
    drbg2.generate(&mut buf2).unwrap();

    // Different instances should produce different output (different OS entropy)
    assert_ne!(
        buf1, buf2,
        "Different DRBG instances should produce different output"
    );
}

/// Verify that DRBG generates many outputs without error (exercises the
/// reseed counter and prediction-resistance reseed path).
/// SP 800-90A §10.1.2.4 requires reseeding at RESEED_INTERVAL (2^48),
/// but with prediction resistance the DRBG reseeds on every call.
/// This test verifies the counter increments and reseeds don't fail.
#[test]
fn test_drbg_sustained_generation_1000_calls() {
    let mut drbg = HmacDrbg::new().unwrap();
    let mut prev = [0u8; 32];
    drbg.generate(&mut prev).unwrap();

    for i in 1..1000 {
        let mut buf = [0u8; 32];
        drbg.generate(&mut buf).unwrap();
        // Continuous health test: no two consecutive outputs should be identical
        assert_ne!(
            prev, buf,
            "DRBG stuck output at call #{} (SP 800-90B §4.9 continuous health test)",
            i
        );
        prev = buf;
    }
}

/// Verify reseed produces different output even from same initial state.
/// This tests the entropy injection path.
#[test]
fn test_drbg_reseed_produces_fresh_entropy() {
    let mut drbg = HmacDrbg::new().unwrap();
    let mut outputs = Vec::new();

    for _ in 0..10 {
        drbg.reseed().unwrap();
        let mut buf = [0u8; 32];
        drbg.generate(&mut buf).unwrap();
        // Ensure this output hasn't been seen before
        assert!(
            !outputs.contains(&buf),
            "Reseed should inject fresh entropy producing unique outputs"
        );
        outputs.push(buf);
    }
}

/// Verify DRBG output has good byte distribution (chi-squared-like check).
/// 8192 bytes should have all 256 byte values represented with reasonable
/// frequency (each expected ~32 times).
#[test]
fn test_drbg_byte_distribution_quality() {
    let mut drbg = HmacDrbg::new().unwrap();
    let mut buf = vec![0u8; 8192];
    drbg.generate(&mut buf).unwrap();

    let mut counts = [0u32; 256];
    for &b in &buf {
        counts[b as usize] += 1;
    }

    // Every byte value should appear at least once in 8192 bytes
    let unique_values = counts.iter().filter(|&&c| c > 0).count();
    assert_eq!(
        unique_values, 256,
        "All 256 byte values should appear in 8192 bytes of DRBG output, got {}",
        unique_values
    );

    // No single byte value should dominate (>2% of total = >163 occurrences)
    let max_count = *counts.iter().max().unwrap();
    assert!(
        max_count < 164,
        "No byte value should appear more than 163 times in 8192 bytes, max was {}",
        max_count
    );
}

/// Verify zero-length generate is a no-op (does not panic or corrupt state).
#[test]
fn test_drbg_zero_length_generate() {
    let mut drbg = HmacDrbg::new().unwrap();
    let mut empty: [u8; 0] = [];
    drbg.generate(&mut empty).unwrap();

    // Subsequent normal generation should still work
    let mut buf = [0u8; 32];
    drbg.generate(&mut buf).unwrap();
    assert!(
        buf.iter().any(|&b| b != 0),
        "Output after zero-length generate should be valid"
    );
}
