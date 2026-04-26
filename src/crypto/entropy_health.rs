// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! SP 800-90B Entropy Source Health Testing
//!
//! Implements the health tests required by NIST SP 800-90B for entropy sources:
//! - Repetition Count Test (§4.4.1): Detects a noise source that produces
//!   an identical output too many times in a row.
//! - Adaptive Proportion Test (§4.4.2): Detects a noise source that produces
//!   a single value too frequently within a window.
//!
//! These tests monitor the raw entropy source (OsRng) to detect catastrophic
//! failures before the entropy reaches the DRBG.

use crate::error::{HsmError, HsmResult};

/// Cutoff parameter C for the repetition count test.
///
/// For H_min = 1 (conservative estimate for OS entropy), alpha = 2^{-40}:
/// C = 1 + ceil(40 / H_min) = 41
///
/// A noise source producing 41 identical bytes in a row is considered failed.
const REPETITION_COUNT_CUTOFF: u32 = 41;

/// Window size W for the adaptive proportion test (SP 800-90B §4.4.2).
/// For 8-bit samples: W = 1024.
const ADAPTIVE_PROPORTION_WINDOW: usize = 1024;

/// Cutoff for the adaptive proportion test.
///
/// For W=1024, H_min=1, alpha=2^{-40}:
/// Cutoff ≈ 670 (from SP 800-90B Table 2, interpolated for H_min=1)
const ADAPTIVE_PROPORTION_CUTOFF: u32 = 670;

/// Number of samples to collect during startup health test.
const STARTUP_SAMPLES: usize = 1024;

/// Entropy source health monitor per SP 800-90B.
///
/// Maintains running state for both the repetition count test and the
/// adaptive proportion test. Should be called on every byte of entropy
/// consumed from the OS entropy source.
pub struct EntropyHealthMonitor {
    // Repetition count test state
    last_sample: u8,
    repetition_count: u32,
    /// Whether we've seen at least one sample (avoids off-by-one on first byte)
    first_sample_seen: bool,

    // Adaptive proportion test state
    window: [u8; ADAPTIVE_PROPORTION_WINDOW],
    window_pos: usize,
    window_value: u8,  // The value being tracked in the current window
    window_count: u32, // How many times window_value appeared
    window_initialized: bool,

    // Whether the startup test has passed
    startup_passed: bool,
}

impl EntropyHealthMonitor {
    /// Create a new health monitor. Must call `startup_test()` before use.
    pub fn new() -> Self {
        Self {
            // Use a sentinel repetition_count of 0 to indicate no samples seen yet.
            // The first sample will set repetition_count to 1 (see repetition_count_test).
            last_sample: 0,
            repetition_count: 0,
            first_sample_seen: false,
            window: [0u8; ADAPTIVE_PROPORTION_WINDOW],
            window_pos: 0,
            window_value: 0,
            window_count: 0,
            window_initialized: false,
            startup_passed: false,
        }
    }

    /// Run the startup health test (SP 800-90B §4.3).
    ///
    /// Collects `STARTUP_SAMPLES` bytes from the entropy source and runs
    /// both health tests on them. Must pass before any DRBG operations.
    pub fn startup_test(&mut self, entropy_bytes: &[u8]) -> HsmResult<()> {
        if entropy_bytes.len() < STARTUP_SAMPLES {
            tracing::error!(
                "Startup health test: insufficient samples ({} < {})",
                entropy_bytes.len(),
                STARTUP_SAMPLES
            );
            return Err(HsmError::GeneralError);
        }

        // Reset state
        self.repetition_count = 0;
        self.first_sample_seen = false;
        self.window_pos = 0;
        self.window_initialized = false;

        // Feed all startup samples through both tests (unchecked: startup_passed
        // is not yet true, so we use the internal path)
        for &byte in &entropy_bytes[..STARTUP_SAMPLES] {
            self.feed_sample_unchecked(byte)?;
        }

        self.startup_passed = true;
        tracing::debug!("SP 800-90B startup health test passed");
        Ok(())
    }

    /// Feed a single entropy byte through both health tests.
    ///
    /// Call this on every byte consumed from OsRng before using it
    /// for DRBG reseeding. Requires that `startup_test()` has passed;
    /// returns an error if it hasn't (SP 800-90B §4.3 compliance).
    pub fn feed_sample(&mut self, sample: u8) -> HsmResult<()> {
        if !self.startup_passed {
            return Err(HsmError::GeneralError);
        }
        self.feed_sample_unchecked(sample)
    }

    /// Internal: feed a sample without checking startup_passed.
    /// Used by `startup_test()` itself which needs to feed samples
    /// before the flag is set.
    fn feed_sample_unchecked(&mut self, sample: u8) -> HsmResult<()> {
        self.repetition_count_test(sample)?;
        self.adaptive_proportion_test(sample)?;
        Ok(())
    }

    /// Feed a slice of entropy bytes through both health tests.
    /// Requires that `startup_test()` has passed.
    pub fn feed_bytes(&mut self, bytes: &[u8]) -> HsmResult<()> {
        if !self.startup_passed {
            return Err(HsmError::GeneralError);
        }
        for &b in bytes {
            self.feed_sample_unchecked(b)?;
        }
        Ok(())
    }

    /// Whether the startup test has been run and passed.
    pub fn startup_passed(&self) -> bool {
        self.startup_passed
    }

    // ========================================================================
    // SP 800-90B §4.4.1: Repetition Count Test
    // ========================================================================

    fn repetition_count_test(&mut self, sample: u8) -> HsmResult<()> {
        if !self.first_sample_seen {
            // First sample ever: initialize state without comparing to the
            // uninitialized last_sample value (fixes off-by-one if first byte is 0x00).
            self.last_sample = sample;
            self.repetition_count = 1;
            self.first_sample_seen = true;
            return Ok(());
        }

        if sample == self.last_sample {
            self.repetition_count += 1;
            if self.repetition_count >= REPETITION_COUNT_CUTOFF {
                tracing::error!(
                    "SP 800-90B repetition count test FAILED: {} consecutive identical bytes (0x{:02X})",
                    self.repetition_count,
                    sample
                );
                return Err(HsmError::GeneralError);
            }
        } else {
            self.last_sample = sample;
            self.repetition_count = 1;
        }
        Ok(())
    }

    // ========================================================================
    // SP 800-90B §4.4.2: Adaptive Proportion Test
    // ========================================================================

    fn adaptive_proportion_test(&mut self, sample: u8) -> HsmResult<()> {
        if !self.window_initialized {
            // First sample in a new window: set as the tracked value
            self.window_value = sample;
            self.window_count = 1;
            self.window[0] = sample;
            self.window_pos = 1;
            self.window_initialized = true;
            return Ok(());
        }

        // Add sample to window
        self.window[self.window_pos] = sample;
        self.window_pos += 1;

        if sample == self.window_value {
            self.window_count += 1;
        }

        // Check cutoff
        if self.window_count >= ADAPTIVE_PROPORTION_CUTOFF {
            tracing::error!(
                "SP 800-90B adaptive proportion test FAILED: value 0x{:02X} appeared {} times in window of {}",
                self.window_value,
                self.window_count,
                self.window_pos
            );
            return Err(HsmError::GeneralError);
        }

        // Window full: reset for next window
        if self.window_pos >= ADAPTIVE_PROPORTION_WINDOW {
            self.window_pos = 0;
            self.window_initialized = false;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_healthy_entropy() {
        let mut monitor = EntropyHealthMonitor::new();
        // Generate pseudo-random bytes (simulating healthy entropy)
        let mut bytes = vec![0u8; STARTUP_SAMPLES];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i.wrapping_mul(97).wrapping_add(31)) as u8;
        }
        assert!(monitor.startup_test(&bytes).is_ok());
        assert!(monitor.startup_passed());
    }

    /// Helper to create a monitor that has passed startup (for unit testing).
    fn monitor_with_startup_passed() -> EntropyHealthMonitor {
        let mut monitor = EntropyHealthMonitor::new();
        let mut bytes = vec![0u8; STARTUP_SAMPLES];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i.wrapping_mul(97).wrapping_add(31)) as u8;
        }
        monitor.startup_test(&bytes).unwrap();
        monitor
    }

    #[test]
    fn test_feed_sample_fails_before_startup() {
        let mut monitor = EntropyHealthMonitor::new();
        assert!(monitor.feed_sample(0x42).is_err());
        assert!(monitor.feed_bytes(&[1, 2, 3]).is_err());
    }

    #[test]
    fn test_repetition_count_failure() {
        let mut monitor = monitor_with_startup_passed();
        // Feed 41 identical bytes — should fail
        for i in 0..REPETITION_COUNT_CUTOFF {
            let result = monitor.feed_sample(0xAA);
            if i < REPETITION_COUNT_CUTOFF - 1 {
                assert!(result.is_ok());
            } else {
                assert!(result.is_err());
            }
        }
    }

    #[test]
    fn test_repetition_count_reset_on_different_value() {
        let mut monitor = monitor_with_startup_passed();
        // Feed 40 identical bytes, then a different one — should pass
        for _ in 0..40 {
            assert!(monitor.feed_sample(0xBB).is_ok());
        }
        assert!(monitor.feed_sample(0xCC).is_ok()); // Resets counter
    }

    #[test]
    fn test_adaptive_proportion_failure() {
        let mut monitor = monitor_with_startup_passed();
        // Feed a window of identical bytes — should fail when count reaches cutoff
        let mut failed = false;
        for _ in 0..ADAPTIVE_PROPORTION_WINDOW {
            if monitor.feed_sample(0x42).is_err() {
                failed = true;
                break;
            }
        }
        assert!(failed, "Expected adaptive proportion test to fail");
    }

    #[test]
    fn test_insufficient_startup_samples() {
        let mut monitor = EntropyHealthMonitor::new();
        let short = vec![0u8; 100];
        assert!(monitor.startup_test(&short).is_err());
    }

    #[test]
    fn test_first_byte_zero_no_off_by_one() {
        let mut monitor = EntropyHealthMonitor::new();
        // Startup with bytes starting from 0x00
        let mut bytes = vec![0u8; STARTUP_SAMPLES];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i % 256) as u8; // 0x00, 0x01, 0x02, ...
        }
        assert!(monitor.startup_test(&bytes).is_ok());
        // After startup, feed 0x00 — should work normally
        assert!(monitor.feed_sample(0x00).is_ok());
    }
}
