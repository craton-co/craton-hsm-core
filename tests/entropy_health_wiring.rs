// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Integration tests for the SP 800-90B entropy health monitor wiring.
//!
//! Verifies that the `HealthMonitoredRng` wrapper feeds every consumed byte
//! through the global `EntropyHealthMonitor` and that a known-bad entropy
//! source (all zeros) trips the monitor's continuous health tests.

use craton_hsm::crypto::entropy_health::{
    global_is_error_state, global_reset_for_tests, EntropySource, HealthMonitoredRng,
};
use rand::RngCore;

/// All-zero "entropy" source — used to verify the SP 800-90B repetition-
/// count test (cutoff = 41 identical bytes in a row) trips when the
/// underlying noise source is catastrophically broken.
struct AllZeroSource;

impl EntropySource for AllZeroSource {
    fn fill(&mut self, dest: &mut [u8]) {
        for b in dest.iter_mut() {
            *b = 0;
        }
    }
}

/// A stuck-bit source that returns the same constant byte on every read.
struct ConstantSource(u8);

impl EntropySource for ConstantSource {
    fn fill(&mut self, dest: &mut [u8]) {
        for b in dest.iter_mut() {
            *b = self.0;
        }
    }
}

/// Pseudo-random source for the healthy baseline test. Linear congruential —
/// good enough to satisfy the SP 800-90B health tests, not a CSPRNG.
struct PseudoSource(u32);

impl EntropySource for PseudoSource {
    fn fill(&mut self, dest: &mut [u8]) {
        for b in dest.iter_mut() {
            self.0 = self.0.wrapping_mul(1664525).wrapping_add(1013904223);
            *b = (self.0 >> 24) as u8;
        }
    }
}

/// Baseline: a healthy pseudo-random source should NOT trip the global
/// monitor.
#[test]
fn test_healthy_source_does_not_trip_monitor() {
    global_reset_for_tests();

    let mut rng = HealthMonitoredRng::with_source(Box::new(PseudoSource(0xC0FFEE)));
    let mut buf = [0u8; 256];
    // try_fill_bytes returns Result so we can observe without aborting.
    rng.try_fill_bytes(&mut buf)
        .expect("healthy pseudo-random source must not trip SP 800-90B tests");
    assert!(
        !global_is_error_state(),
        "global monitor must remain healthy with a varied byte stream"
    );

    global_reset_for_tests();
}

/// Bad source: all zeros — the repetition count test must trip (41
/// consecutive identical samples) and the global monitor must latch into
/// the error state.
#[test]
fn test_all_zero_source_trips_repetition_count() {
    global_reset_for_tests();

    let mut rng = HealthMonitoredRng::with_source(Box::new(AllZeroSource));
    let mut buf = [0u8; 256];
    let result = rng.try_fill_bytes(&mut buf);

    assert!(
        result.is_err(),
        "all-zero source must trip the SP 800-90B repetition count test"
    );
    assert!(
        global_is_error_state(),
        "global monitor must latch into error state after a health-test failure"
    );

    // Once latched, subsequent observations must also fail without needing
    // to actually re-trip the underlying counter.
    let mut rng2 = HealthMonitoredRng::with_source(Box::new(PseudoSource(0xABCD)));
    let mut buf2 = [0u8; 32];
    assert!(
        rng2.try_fill_bytes(&mut buf2).is_err(),
        "monitor error state must persist across HealthMonitoredRng instances"
    );

    global_reset_for_tests();
}

/// Constant non-zero source: same as all-zero but with byte 0xAA. Confirms
/// the repetition count test is value-agnostic.
#[test]
fn test_constant_nonzero_source_trips_monitor() {
    global_reset_for_tests();

    let mut rng = HealthMonitoredRng::with_source(Box::new(ConstantSource(0xAA)));
    let mut buf = [0u8; 128];
    assert!(
        rng.try_fill_bytes(&mut buf).is_err(),
        "constant 0xAA source must trip SP 800-90B continuous health tests"
    );
    assert!(global_is_error_state());

    global_reset_for_tests();
}

/// After `global_reset_for_tests`, the monitor must be usable again.
/// This is a guard against the reset helper drifting from production
/// semantics.
#[test]
fn test_reset_clears_error_state() {
    global_reset_for_tests();

    let mut rng = HealthMonitoredRng::with_source(Box::new(AllZeroSource));
    let mut buf = [0u8; 128];
    let _ = rng.try_fill_bytes(&mut buf);
    assert!(global_is_error_state());

    global_reset_for_tests();
    assert!(
        !global_is_error_state(),
        "reset_for_tests must clear the latched error state"
    );

    // And a healthy source should now work.
    let mut rng = HealthMonitoredRng::with_source(Box::new(PseudoSource(42)));
    let mut buf = [0u8; 64];
    assert!(rng.try_fill_bytes(&mut buf).is_ok());

    global_reset_for_tests();
}
