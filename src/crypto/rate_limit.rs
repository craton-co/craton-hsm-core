// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Per-session and global rate limiting for cryptographic operations.
//!
//! Uses a token bucket algorithm with `Instant`-based timing to prevent
//! abuse and denial-of-service attacks against the HSM.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use dashmap::DashMap;
use serde::Deserialize;

use crate::error::HsmError;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Rate-limiting configuration, deserializable from TOML.
///
/// All limits default to `0` (unlimited / disabled).
#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitConfig {
    /// Max operations per session per second. 0 = unlimited.
    #[serde(default)]
    pub max_ops_per_session_per_sec: u64,
    /// Max global operations per second across all sessions. 0 = unlimited.
    #[serde(default)]
    pub max_global_ops_per_sec: u64,
    /// Max concurrent operations across all sessions. 0 = unlimited.
    #[serde(default)]
    pub max_concurrent_ops: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_ops_per_session_per_sec: 0,
            max_global_ops_per_sec: 0,
            max_concurrent_ops: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Per-session token bucket state (integer-based, using microtokens)
// ---------------------------------------------------------------------------

/// 1 token = 1_000_000 microtokens. Using integer arithmetic avoids
/// floating-point drift that would accumulate over many refill cycles.
const MICROTOKENS_PER_OP: u64 = 1_000_000;

/// Maximum number of per-session buckets stored simultaneously.
/// Prevents OOM if an attacker exhausts session IDs.
const MAX_SESSION_BUCKETS: usize = 10_000;

/// Token bucket state for a single session (integer microtokens).
#[derive(Debug)]
struct SessionRateState {
    /// Available microtokens.
    tokens: u64,
    /// Last time the bucket was refilled.
    last_refill: Instant,
    /// Refill rate in microtokens per second.
    rate: u64,
    /// Maximum bucket capacity in microtokens.
    capacity: u64,
}

impl SessionRateState {
    fn new(rate: u64) -> Self {
        let rate_micro = rate.saturating_mul(MICROTOKENS_PER_OP);
        Self {
            tokens: rate_micro, // start with a full bucket
            last_refill: Instant::now(),
            rate: rate_micro,
            capacity: rate_micro,
        }
    }

    /// Refill tokens based on elapsed time, then try to consume one operation.
    /// Returns `true` if the operation is allowed.
    fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed_micros = now.duration_since(self.last_refill).as_micros() as u64;
        // refill = rate (microtokens/sec) * elapsed_micros / 1_000_000
        let refill = (self.rate as u128).saturating_mul(elapsed_micros as u128) / 1_000_000;
        self.tokens = self.tokens.saturating_add(refill as u64).min(self.capacity);
        self.last_refill = now;

        if self.tokens >= MICROTOKENS_PER_OP {
            self.tokens -= MICROTOKENS_PER_OP;
            true
        } else {
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Global token bucket state
// ---------------------------------------------------------------------------

/// Token bucket for the global (cross-session) rate limit (integer microtokens).
#[derive(Debug)]
struct GlobalRateState {
    /// Available microtokens.
    tokens: u64,
    last_refill: Instant,
    /// Refill rate in microtokens per second.
    rate: u64,
    /// Maximum bucket capacity in microtokens.
    capacity: u64,
}

impl GlobalRateState {
    fn new(rate: u64) -> Self {
        let rate_micro = rate.saturating_mul(MICROTOKENS_PER_OP);
        Self {
            tokens: rate_micro,
            last_refill: Instant::now(),
            rate: rate_micro,
            capacity: rate_micro,
        }
    }

    fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed_micros = now.duration_since(self.last_refill).as_micros() as u64;
        let refill = (self.rate as u128).saturating_mul(elapsed_micros as u128) / 1_000_000;
        self.tokens = self.tokens.saturating_add(refill as u64).min(self.capacity);
        self.last_refill = now;

        if self.tokens >= MICROTOKENS_PER_OP {
            self.tokens -= MICROTOKENS_PER_OP;
            true
        } else {
            false
        }
    }
}

// ---------------------------------------------------------------------------
// RateLimiter
// ---------------------------------------------------------------------------

/// Enforces per-session and global rate limits on cryptographic operations.
///
/// Thread-safe: all interior state uses atomics or `DashMap` / `parking_lot`.
pub struct RateLimiter {
    config: RateLimitConfig,
    /// Per-session token buckets keyed by session handle.
    session_buckets: DashMap<u64, SessionRateState>,
    /// Global token bucket (protected by a lightweight mutex).
    global_bucket: parking_lot::Mutex<Option<GlobalRateState>>,
    /// Current number of in-flight concurrent operations.
    concurrent_ops: AtomicU64,
}

impl std::fmt::Debug for RateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimiter")
            .field("config", &self.config)
            .field(
                "concurrent_ops",
                &self.concurrent_ops.load(Ordering::Relaxed),
            )
            .finish()
    }
}

impl RateLimiter {
    /// Create a rate limiter from the given configuration.
    pub fn new(config: &RateLimitConfig) -> Self {
        let global_bucket = if config.max_global_ops_per_sec > 0 {
            Some(GlobalRateState::new(config.max_global_ops_per_sec))
        } else {
            None
        };
        Self {
            config: config.clone(),
            session_buckets: DashMap::new(),
            global_bucket: parking_lot::Mutex::new(global_bucket),
            concurrent_ops: AtomicU64::new(0),
        }
    }

    /// Create a no-op rate limiter where all checks pass (all limits = 0).
    pub fn disabled() -> Self {
        Self::new(&RateLimitConfig::default())
    }

    /// Check whether `session_handle` is allowed to perform an operation
    /// under the per-session and global rate limits.
    ///
    /// Returns `Err(HsmError::GeneralError)` if the rate limit is exceeded.
    pub fn check_rate(&self, session_handle: u64) -> Result<(), HsmError> {
        // --- per-session limit ---
        if self.config.max_ops_per_session_per_sec > 0 {
            // Guard against OOM from unbounded session bucket growth.
            if !self.session_buckets.contains_key(&session_handle)
                && self.session_buckets.len() >= MAX_SESSION_BUCKETS
            {
                return Err(HsmError::GeneralError);
            }

            let mut entry = self
                .session_buckets
                .entry(session_handle)
                .or_insert_with(|| SessionRateState::new(self.config.max_ops_per_session_per_sec));
            if !entry.value_mut().try_consume() {
                return Err(HsmError::GeneralError);
            }
        }

        // --- global limit ---
        if self.config.max_global_ops_per_sec > 0 {
            let mut guard = self.global_bucket.lock();
            if let Some(ref mut bucket) = *guard {
                if !bucket.try_consume() {
                    return Err(HsmError::GeneralError);
                }
            }
        }

        Ok(())
    }

    /// Signal the start of a concurrent operation.
    ///
    /// Returns `Err(HsmError::GeneralError)` if the concurrent-ops limit
    /// would be exceeded.
    pub fn begin_operation(&self) -> Result<(), HsmError> {
        if self.config.max_concurrent_ops == 0 {
            return Ok(());
        }
        // Atomically increment, then check. If over limit, decrement back.
        let prev = self.concurrent_ops.fetch_add(1, Ordering::SeqCst);
        if prev >= self.config.max_concurrent_ops {
            self.concurrent_ops.fetch_sub(1, Ordering::SeqCst);
            return Err(HsmError::GeneralError);
        }
        Ok(())
    }

    /// Signal the end of a concurrent operation (decrement counter).
    pub fn end_operation(&self) {
        if self.config.max_concurrent_ops == 0 {
            return;
        }
        self.concurrent_ops.fetch_sub(1, Ordering::SeqCst);
    }

    /// Remove all rate-limit state for a closed session.
    pub fn remove_session(&self, session_handle: u64) {
        self.session_buckets.remove(&session_handle);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_limiter_always_passes() {
        let rl = RateLimiter::disabled();
        for i in 0..1000 {
            assert!(rl.check_rate(i).is_ok());
            assert!(rl.begin_operation().is_ok());
            rl.end_operation();
        }
    }

    #[test]
    fn per_session_rate_limit_rejects_after_burst() {
        let config = RateLimitConfig {
            max_ops_per_session_per_sec: 5,
            max_global_ops_per_sec: 0,
            max_concurrent_ops: 0,
        };
        let rl = RateLimiter::new(&config);
        let handle = 42u64;

        // First 5 should succeed (bucket starts full with 5 tokens).
        for _ in 0..5 {
            assert!(rl.check_rate(handle).is_ok());
        }
        // 6th should fail — bucket is empty.
        assert!(rl.check_rate(handle).is_err());

        // A different session should still work.
        assert!(rl.check_rate(99).is_ok());
    }

    #[test]
    fn concurrent_ops_limit() {
        let config = RateLimitConfig {
            max_ops_per_session_per_sec: 0,
            max_global_ops_per_sec: 0,
            max_concurrent_ops: 3,
        };
        let rl = RateLimiter::new(&config);

        assert!(rl.begin_operation().is_ok());
        assert!(rl.begin_operation().is_ok());
        assert!(rl.begin_operation().is_ok());
        // 4th should fail.
        assert!(rl.begin_operation().is_err());

        // End one, then the next should succeed.
        rl.end_operation();
        assert!(rl.begin_operation().is_ok());
    }

    #[test]
    fn session_cleanup_removes_state() {
        let config = RateLimitConfig {
            max_ops_per_session_per_sec: 2,
            max_global_ops_per_sec: 0,
            max_concurrent_ops: 0,
        };
        let rl = RateLimiter::new(&config);
        let handle = 7u64;

        // Exhaust the bucket.
        assert!(rl.check_rate(handle).is_ok());
        assert!(rl.check_rate(handle).is_ok());
        assert!(rl.check_rate(handle).is_err());

        // Remove and re-check — should get a fresh bucket.
        rl.remove_session(handle);
        assert!(rl.check_rate(handle).is_ok());
    }

    #[test]
    fn global_rate_limit_rejects_after_burst() {
        let config = RateLimitConfig {
            max_ops_per_session_per_sec: 0,
            max_global_ops_per_sec: 4,
            max_concurrent_ops: 0,
        };
        let rl = RateLimiter::new(&config);

        // Use different sessions — global limit applies across all.
        for i in 0..4 {
            assert!(rl.check_rate(i).is_ok());
        }
        // 5th call (any session) should fail.
        assert!(rl.check_rate(100).is_err());
    }

    #[test]
    fn integer_bucket_does_not_drift_over_many_cycles() {
        // Verify that consuming and fully refilling many times doesn't
        // accumulate floating-point-style drift.  We manipulate `tokens`
        // directly (no wall-clock dependency) so the test is deterministic.
        let rate = 100u64;
        let state_capacity = rate.saturating_mul(MICROTOKENS_PER_OP);

        let mut tokens: u64 = state_capacity; // start full

        for _ in 0..10_000 {
            // Drain the entire bucket.
            let mut consumed = 0u64;
            while tokens >= MICROTOKENS_PER_OP {
                tokens -= MICROTOKENS_PER_OP;
                consumed += 1;
            }
            assert_eq!(
                consumed, rate,
                "bucket should yield exactly `rate` tokens after a full refill"
            );
            assert_eq!(
                tokens, 0,
                "residual microtokens should be exactly 0 after drain"
            );

            // Full refill: add capacity microtokens, cap at capacity.
            tokens = tokens.saturating_add(state_capacity).min(state_capacity);
        }

        // After 10 000 drain/refill cycles the bucket must still be exact.
        assert_eq!(
            tokens, state_capacity,
            "bucket should be at full capacity after final refill"
        );
    }

    #[test]
    fn session_bucket_count_is_bounded() {
        let config = RateLimitConfig {
            max_ops_per_session_per_sec: 10,
            max_global_ops_per_sec: 0,
            max_concurrent_ops: 0,
        };
        let rl = RateLimiter::new(&config);

        // Fill up to the maximum allowed session buckets.
        for i in 0..(MAX_SESSION_BUCKETS as u64) {
            assert!(
                rl.check_rate(i).is_ok(),
                "session {} should succeed while under limit",
                i,
            );
        }

        // The next *new* session must be rejected.
        let overflow_handle = MAX_SESSION_BUCKETS as u64 + 1;
        assert!(
            rl.check_rate(overflow_handle).is_err(),
            "new session beyond MAX_SESSION_BUCKETS must be rejected",
        );

        // An existing session should still work.
        assert!(
            rl.check_rate(0).is_ok(),
            "existing session should still be allowed",
        );
    }
}
