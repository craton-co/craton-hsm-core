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
//!
//! # Wiring into the crypto layer
//!
//! The [`HealthMonitoredRng`] wrapper routes every byte read from
//! [`rand::rngs::OsRng`] through a global [`EntropyHealthMonitor`] singleton.
//! All places that previously called `OsRng.fill_bytes` for crypto entropy
//! (notably the DRBG reseed path) should use `HealthMonitoredRng` instead so
//! that a stuck or biased entropy source is detected before the bytes flow
//! into key material.
//!
//! On a health-test failure the global monitor latches into an error state and
//! all subsequent calls to [`global_observe`] return `HsmError::GeneralError`,
//! which maps to `CKR_DEVICE_ERROR` / `CKR_GENERAL_ERROR` at the C ABI layer.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::LazyLock;

use parking_lot::Mutex;
use rand::RngCore;

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

    /// Observe a slice of entropy bytes. Alias for [`Self::feed_bytes`] —
    /// matches the wiring-spec naming used by [`HealthMonitoredRng`].
    pub fn observe(&mut self, bytes: &[u8]) -> HsmResult<()> {
        self.feed_bytes(bytes)
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

impl Default for EntropyHealthMonitor {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Global monitor singleton + HealthMonitoredRng wrapper
// ===========================================================================

/// Latched error flag for the global monitor. Once set, every subsequent
/// `global_observe` returns `GeneralError`. We use a separate `AtomicBool`
/// in addition to the monitor's own state so the FIPS-style error state
/// survives even if the monitor lock is poisoned by a panicking thread.
static GLOBAL_ENTROPY_ERROR: AtomicBool = AtomicBool::new(false);

/// Global SP 800-90B health monitor. Lazily initialised on first use; the
/// startup test is performed by reading [`STARTUP_SAMPLES`] bytes from
/// `OsRng` directly (the only legitimate raw-`OsRng` consumption in the
/// codebase outside of self-tests).
static GLOBAL_MONITOR: LazyLock<Mutex<EntropyHealthMonitor>> = LazyLock::new(|| {
    use rand::rngs::OsRng;
    let mut monitor = EntropyHealthMonitor::new();
    let mut startup = [0u8; STARTUP_SAMPLES];
    OsRng.fill_bytes(&mut startup);
    if let Err(e) = monitor.startup_test(&startup) {
        tracing::error!(
            "SP 800-90B startup health test FAILED during global monitor init: {:?} \
             — entropy source is unhealthy",
            e
        );
        GLOBAL_ENTROPY_ERROR.store(true, Ordering::Release);
    }
    // Defensive zeroize of the startup buffer.
    use zeroize::Zeroize;
    startup.zeroize();
    Mutex::new(monitor)
});

/// Whether the global entropy health monitor has tripped into error state.
///
/// Returns `true` after either continuous health test (repetition count or
/// adaptive proportion) has failed, or if the startup test failed during
/// monitor initialisation. The flag is sticky: once set it stays set for the
/// lifetime of the process, matching FIPS 140-3 §7.3 "module shall enter an
/// error state".
pub fn global_is_error_state() -> bool {
    GLOBAL_ENTROPY_ERROR.load(Ordering::Acquire)
}

/// Feed a slice of entropy bytes through the global SP 800-90B monitor.
///
/// Returns `Err(HsmError::GeneralError)` if either continuous test fails (or
/// has previously failed). The caller MUST refuse to use the observed bytes
/// when this returns an error.
pub fn global_observe(bytes: &[u8]) -> HsmResult<()> {
    if GLOBAL_ENTROPY_ERROR.load(Ordering::Acquire) {
        return Err(HsmError::GeneralError);
    }
    // Force the lazy init (which performs the startup test) — this also
    // sets GLOBAL_ENTROPY_ERROR if startup fails, so re-check after.
    let monitor = &*GLOBAL_MONITOR;
    if GLOBAL_ENTROPY_ERROR.load(Ordering::Acquire) {
        return Err(HsmError::GeneralError);
    }
    let mut guard = monitor.lock();
    match guard.observe(bytes) {
        Ok(()) => Ok(()),
        Err(e) => {
            tracing::error!(
                "SP 800-90B continuous health test FAILED — global monitor entering error state"
            );
            GLOBAL_ENTROPY_ERROR.store(true, Ordering::Release);
            Err(e)
        }
    }
}

/// Reset the global monitor's error state. **Test-only**: in production the
/// error state is intentionally sticky for the process lifetime.
#[cfg(test)]
pub fn global_reset_for_tests() {
    GLOBAL_ENTROPY_ERROR.store(false, Ordering::Release);
    let mut guard = GLOBAL_MONITOR.lock();
    *guard = EntropyHealthMonitor::new();
    // Re-run startup with fresh OsRng entropy so subsequent observes work.
    use rand::rngs::OsRng;
    let mut startup = [0u8; STARTUP_SAMPLES];
    OsRng.fill_bytes(&mut startup);
    let _ = guard.startup_test(&startup);
    use zeroize::Zeroize;
    startup.zeroize();
}

/// `RngCore` implementation that wraps an underlying entropy source and
/// routes every produced byte through the global [`EntropyHealthMonitor`]
/// BEFORE the bytes leave the wrapper for use.
///
/// In production this wraps `rand::rngs::OsRng`. In tests, the
/// `with_source` constructor can substitute a deterministic / adversarial
/// source to verify that the monitor trips as expected.
///
/// # FIPS 140-3 behaviour on health-test failure
///
/// If `monitor.observe(&buf)` reports a repetition-count or adaptive-
/// proportion failure, the filled buffer is zeroized and the process is
/// aborted via `std::process::abort()`. This matches the existing
/// `DrbgRng::fill_bytes` policy in `crypto/drbg.rs`: a stuck entropy
/// source is a catastrophic failure that must not silently produce weak
/// key material or signatures, and `panic!()` could be caught by the
/// host application across the C ABI boundary.
pub struct HealthMonitoredRng {
    source: Box<dyn EntropySource + Send + Sync>,
}

/// Test-injectable entropy source. Production code uses the
/// `OsEntropySource` blanket implementation over `OsRng`.
pub trait EntropySource {
    fn fill(&mut self, dest: &mut [u8]);
}

/// Production entropy source: thin wrapper around `rand::rngs::OsRng`.
pub struct OsEntropySource;

impl EntropySource for OsEntropySource {
    fn fill(&mut self, dest: &mut [u8]) {
        use rand::rngs::OsRng;
        OsRng.fill_bytes(dest);
    }
}

impl HealthMonitoredRng {
    /// Construct the production health-monitored RNG that draws from `OsRng`.
    pub fn new() -> Self {
        Self {
            source: Box::new(OsEntropySource),
        }
    }

    /// Test-only constructor accepting an arbitrary entropy source so that
    /// integration tests can inject known-bad entropy (e.g. all-zero) and
    /// verify the monitor trips.
    #[cfg(test)]
    pub fn with_source(source: Box<dyn EntropySource + Send + Sync>) -> Self {
        Self { source }
    }
}

impl Default for HealthMonitoredRng {
    fn default() -> Self {
        Self::new()
    }
}

impl RngCore for HealthMonitoredRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.source.fill(dest);
        if let Err(e) = global_observe(dest) {
            // Catastrophic entropy-source failure. Zero the buffer so no
            // observed-bad bytes leak into key material, and abort the
            // process. See module-level FIPS rationale above.
            use zeroize::Zeroize;
            dest.zeroize();
            tracing::error!(
                "HealthMonitoredRng: SP 800-90B health test failed ({:?}) — aborting",
                e
            );
            std::process::abort();
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.source.fill(dest);
        global_observe(dest).map_err(|_| rand::Error::new("SP 800-90B health test failed"))
    }
}

impl rand::CryptoRng for HealthMonitoredRng {}

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

    /// `observe` is a thin alias for `feed_bytes`; verify both paths behave
    /// identically.
    #[test]
    fn test_observe_alias_of_feed_bytes() {
        let mut monitor = monitor_with_startup_passed();
        assert!(monitor.observe(&[1, 2, 3, 4, 5]).is_ok());
        // Before startup the observe path must also fail.
        let mut fresh = EntropyHealthMonitor::new();
        assert!(fresh.observe(&[1, 2, 3]).is_err());
    }

    /// HealthMonitoredRng with a healthy pseudo-random source should not
    /// trip the global monitor (modulo the global-state caveat — we run
    /// this with a reset).
    #[test]
    fn test_health_monitored_rng_healthy_source() {
        global_reset_for_tests();

        struct Pseudo(u32);
        impl EntropySource for Pseudo {
            fn fill(&mut self, dest: &mut [u8]) {
                for b in dest.iter_mut() {
                    // xorshift-ish — produces a varied byte stream
                    self.0 = self.0.wrapping_mul(1664525).wrapping_add(1013904223);
                    *b = (self.0 >> 24) as u8;
                }
            }
        }

        let mut rng = HealthMonitoredRng::with_source(Box::new(Pseudo(0xDEADBEEF)));
        let mut buf = [0u8; 64];
        rng.fill_bytes(&mut buf);
        assert!(!global_is_error_state());
        assert!(buf.iter().any(|&b| b != 0));
    }

    /// `try_fill_bytes` returns Err (rather than aborting) when the source
    /// trips the monitor — useful for unit-testing the failure path without
    /// killing the test runner via `std::process::abort()`.
    #[test]
    fn test_health_monitored_rng_try_fill_detects_bad_source() {
        global_reset_for_tests();

        struct AllZero;
        impl EntropySource for AllZero {
            fn fill(&mut self, dest: &mut [u8]) {
                for b in dest.iter_mut() {
                    *b = 0;
                }
            }
        }

        let mut rng = HealthMonitoredRng::with_source(Box::new(AllZero));
        // Feed enough zero bytes to trip the repetition count test (41
        // identical bytes).
        let mut buf = [0u8; 128];
        let result = rng.try_fill_bytes(&mut buf);
        assert!(
            result.is_err(),
            "all-zero source must trip SP 800-90B repetition count test"
        );
        assert!(
            global_is_error_state(),
            "global monitor should latch into error state after failure"
        );

        // Reset so subsequent tests aren't impacted.
        global_reset_for_tests();
    }
}
