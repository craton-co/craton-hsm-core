// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Lock-free metrics collection for HSM cryptographic operations.
//!
//! Tracks operation counts, latency, and error rates using only `std` atomics —
//! no external observability crates required.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Operation taxonomy
// ---------------------------------------------------------------------------

/// Operation categories for metrics tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MetricOperation {
    Sign,
    Verify,
    Encrypt,
    Decrypt,
    Digest,
    GenerateKey,
    GenerateKeyPair,
    WrapKey,
    UnwrapKey,
    DeriveKey,
    GenerateRandom,
}

impl MetricOperation {
    /// Total number of variants — must stay in sync with the enum definition.
    const COUNT: usize = 11;

    /// Map variant to a fixed index in `[0, COUNT)`.
    #[inline]
    fn index(self) -> usize {
        self as usize
    }

    /// Human-readable label.
    fn name(self) -> &'static str {
        match self {
            Self::Sign => "sign",
            Self::Verify => "verify",
            Self::Encrypt => "encrypt",
            Self::Decrypt => "decrypt",
            Self::Digest => "digest",
            Self::GenerateKey => "generate_key",
            Self::GenerateKeyPair => "generate_key_pair",
            Self::WrapKey => "wrap_key",
            Self::UnwrapKey => "unwrap_key",
            Self::DeriveKey => "derive_key",
            Self::GenerateRandom => "generate_random",
        }
    }

    /// Iterator over all variants (used by `snapshot`).
    fn all() -> &'static [MetricOperation; MetricOperation::COUNT] {
        &[
            Self::Sign,
            Self::Verify,
            Self::Encrypt,
            Self::Decrypt,
            Self::Digest,
            Self::GenerateKey,
            Self::GenerateKeyPair,
            Self::WrapKey,
            Self::UnwrapKey,
            Self::DeriveKey,
            Self::GenerateRandom,
        ]
    }
}

// ---------------------------------------------------------------------------
// Per-operation atomic counters
// ---------------------------------------------------------------------------

struct OperationMetrics {
    total_ops: AtomicU64,
    failed_ops: AtomicU64,
    total_latency_us: AtomicU64,
    max_latency_us: AtomicU64,
}

impl OperationMetrics {
    const fn new() -> Self {
        Self {
            total_ops: AtomicU64::new(0),
            failed_ops: AtomicU64::new(0),
            total_latency_us: AtomicU64::new(0),
            max_latency_us: AtomicU64::new(0),
        }
    }
}

// ---------------------------------------------------------------------------
// Global collector
// ---------------------------------------------------------------------------

/// Lock-free, global metrics collector.
///
/// All mutation methods use `Relaxed` ordering — counters are statistical and
/// do not need sequentially-consistent reads.
pub struct MetricsCollector {
    enabled: bool,
    operations: [OperationMetrics; MetricOperation::COUNT],
    total_sessions_opened: AtomicU64,
    total_sessions_closed: AtomicU64,
    total_logins: AtomicU64,
    total_login_failures: AtomicU64,
    started_at: Instant,
}

impl MetricsCollector {
    /// Create a new collector.  Pass `false` to make every method a no-op.
    pub fn new(enabled: bool) -> Self {
        // Work around the lack of `Copy` on `AtomicU64` — cannot use array
        // repeat syntax, so we initialise each slot manually via a const fn
        // helper.
        #[allow(clippy::declare_interior_mutable_const)]
        const INIT: OperationMetrics = OperationMetrics::new();
        Self {
            enabled,
            operations: [
                INIT, INIT, INIT, INIT, INIT, INIT, INIT, INIT, INIT, INIT, INIT,
            ],
            total_sessions_opened: AtomicU64::new(0),
            total_sessions_closed: AtomicU64::new(0),
            total_logins: AtomicU64::new(0),
            total_login_failures: AtomicU64::new(0),
            started_at: Instant::now(),
        }
    }

    /// Convenience constructor for a disabled (no-op) collector.
    pub fn disabled() -> Self {
        Self::new(false)
    }

    /// Whether metrics collection is active.
    #[inline]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    // -- operation recording -------------------------------------------------

    /// Record a single cryptographic operation.
    ///
    /// `latency` is the wall-clock duration of the operation.
    /// `success` indicates whether it completed without error.
    pub fn record_operation(&self, op: MetricOperation, latency: Duration, success: bool) {
        if !self.enabled {
            return;
        }
        let m = &self.operations[op.index()];
        m.total_ops.fetch_add(1, Ordering::Relaxed);
        if !success {
            m.failed_ops.fetch_add(1, Ordering::Relaxed);
        }
        let us = latency.as_micros() as u64;
        m.total_latency_us.fetch_add(us, Ordering::Relaxed);

        // Update max using a CAS loop.
        let mut cur = m.max_latency_us.load(Ordering::Relaxed);
        while us > cur {
            match m.max_latency_us.compare_exchange_weak(
                cur,
                us,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => cur = actual,
            }
        }
    }

    // -- session recording ---------------------------------------------------

    /// Record a session being opened.
    pub fn record_session_open(&self) {
        if !self.enabled {
            return;
        }
        self.total_sessions_opened.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a session being closed.
    pub fn record_session_close(&self) {
        if !self.enabled {
            return;
        }
        self.total_sessions_closed.fetch_add(1, Ordering::Relaxed);
    }

    // -- login recording -----------------------------------------------------

    /// Record a login attempt.
    pub fn record_login(&self, success: bool) {
        if !self.enabled {
            return;
        }
        self.total_logins.fetch_add(1, Ordering::Relaxed);
        if !success {
            self.total_login_failures.fetch_add(1, Ordering::Relaxed);
        }
    }

    // -- snapshot ------------------------------------------------------------

    /// Capture a point-in-time copy of every metric.
    pub fn snapshot(&self) -> MetricsSnapshot {
        let uptime_secs = self.started_at.elapsed().as_secs();
        let opened = self.total_sessions_opened.load(Ordering::Relaxed);
        let closed = self.total_sessions_closed.load(Ordering::Relaxed);

        let operations = MetricOperation::all()
            .iter()
            .map(|&op| {
                let m = &self.operations[op.index()];
                let total = m.total_ops.load(Ordering::Relaxed);
                let failed = m.failed_ops.load(Ordering::Relaxed);
                let total_lat = m.total_latency_us.load(Ordering::Relaxed);
                let max_lat = m.max_latency_us.load(Ordering::Relaxed);
                let avg = if total > 0 { total_lat / total } else { 0 };
                OperationSnapshot {
                    name: op.name(),
                    total,
                    failed,
                    avg_latency_us: avg,
                    max_latency_us: max_lat,
                }
            })
            .collect();

        MetricsSnapshot {
            uptime_secs,
            operations,
            total_sessions_opened: opened,
            total_sessions_closed: closed,
            active_sessions: opened.saturating_sub(closed),
            total_logins: self.total_logins.load(Ordering::Relaxed),
            total_login_failures: self.total_login_failures.load(Ordering::Relaxed),
        }
    }
}

// ---------------------------------------------------------------------------
// Snapshot types
// ---------------------------------------------------------------------------

/// Point-in-time copy of all metrics.
#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub uptime_secs: u64,
    pub operations: Vec<OperationSnapshot>,
    pub total_sessions_opened: u64,
    pub total_sessions_closed: u64,
    pub active_sessions: u64,
    pub total_logins: u64,
    pub total_login_failures: u64,
}

/// Snapshot of a single operation category.
#[derive(Debug, Clone)]
pub struct OperationSnapshot {
    pub name: &'static str,
    pub total: u64,
    pub failed: u64,
    pub avg_latency_us: u64,
    pub max_latency_us: u64,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn disabled_collector_does_not_panic() {
        let c = MetricsCollector::disabled();
        assert!(!c.is_enabled());
        c.record_operation(MetricOperation::Sign, Duration::from_millis(5), true);
        c.record_operation(MetricOperation::Encrypt, Duration::from_millis(2), false);
        c.record_session_open();
        c.record_session_close();
        c.record_login(true);
        c.record_login(false);

        // Snapshot should return zeroes since collection is disabled.
        let snap = c.snapshot();
        for op in &snap.operations {
            assert_eq!(op.total, 0);
            assert_eq!(op.failed, 0);
        }
        assert_eq!(snap.total_sessions_opened, 0);
        assert_eq!(snap.total_logins, 0);
    }

    #[test]
    fn operation_recording_increments_counters() {
        let c = MetricsCollector::new(true);
        c.record_operation(MetricOperation::Sign, Duration::from_micros(100), true);
        c.record_operation(MetricOperation::Sign, Duration::from_micros(200), true);
        c.record_operation(MetricOperation::Sign, Duration::from_micros(300), false);

        let snap = c.snapshot();
        let sign = snap.operations.iter().find(|o| o.name == "sign").unwrap();
        assert_eq!(sign.total, 3);
        assert_eq!(sign.failed, 1);
    }

    #[test]
    fn snapshot_returns_correct_values() {
        let c = MetricsCollector::new(true);
        c.record_operation(MetricOperation::Encrypt, Duration::from_micros(500), true);
        c.record_session_open();
        c.record_session_open();
        c.record_session_close();
        c.record_login(true);
        c.record_login(false);

        let snap = c.snapshot();
        assert_eq!(snap.total_sessions_opened, 2);
        assert_eq!(snap.total_sessions_closed, 1);
        assert_eq!(snap.active_sessions, 1);
        assert_eq!(snap.total_logins, 2);
        assert_eq!(snap.total_login_failures, 1);

        let enc = snap
            .operations
            .iter()
            .find(|o| o.name == "encrypt")
            .unwrap();
        assert_eq!(enc.total, 1);
        assert_eq!(enc.avg_latency_us, 500);
        assert_eq!(enc.max_latency_us, 500);
    }

    #[test]
    fn concurrent_recording() {
        use std::sync::Arc;
        use std::thread;

        let c = Arc::new(MetricsCollector::new(true));
        let mut handles = Vec::new();

        for _ in 0..8 {
            let c = Arc::clone(&c);
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    c.record_operation(MetricOperation::Verify, Duration::from_micros(10), true);
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        let snap = c.snapshot();
        let verify = snap.operations.iter().find(|o| o.name == "verify").unwrap();
        assert_eq!(verify.total, 8000);
        assert_eq!(verify.failed, 0);
    }

    #[test]
    fn latency_tracking_avg_and_max() {
        let c = MetricsCollector::new(true);
        // 100, 200, 300 => avg 200, max 300
        c.record_operation(MetricOperation::Digest, Duration::from_micros(100), true);
        c.record_operation(MetricOperation::Digest, Duration::from_micros(200), true);
        c.record_operation(MetricOperation::Digest, Duration::from_micros(300), true);

        let snap = c.snapshot();
        let dig = snap.operations.iter().find(|o| o.name == "digest").unwrap();
        assert_eq!(dig.avg_latency_us, 200);
        assert_eq!(dig.max_latency_us, 300);
    }

    #[test]
    fn session_open_close_counting() {
        let c = MetricsCollector::new(true);
        for _ in 0..5 {
            c.record_session_open();
        }
        for _ in 0..3 {
            c.record_session_close();
        }

        let snap = c.snapshot();
        assert_eq!(snap.total_sessions_opened, 5);
        assert_eq!(snap.total_sessions_closed, 3);
        assert_eq!(snap.active_sessions, 2);
    }

    #[test]
    fn login_success_failure_counting() {
        let c = MetricsCollector::new(true);
        c.record_login(true);
        c.record_login(true);
        c.record_login(false);
        c.record_login(true);
        c.record_login(false);

        let snap = c.snapshot();
        assert_eq!(snap.total_logins, 5);
        assert_eq!(snap.total_login_failures, 2);
    }
}
