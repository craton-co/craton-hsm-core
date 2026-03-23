// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
use crate::error::HsmResult;
use crate::pkcs11_abi::types::{CK_OBJECT_HANDLE, CK_SESSION_HANDLE, CK_ULONG};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};

/// Maximum handle value, bounded by the platform's `CK_ULONG` width.
///
/// `CK_ULONG` is `c_ulong` per the PKCS#11 spec — 32 bits on 32-bit
/// platforms, 64 bits on 64-bit platforms.  The internal counter is always
/// `u64`, so on 32-bit targets we must cap at `u32::MAX` to avoid silent
/// truncation when casting `u64 → CK_ULONG`.
const MAX_HANDLE: u64 = CK_ULONG::MAX as u64;

// ── Feistel-based handle scrambling ──────────────────────────────────

/// Round function for a 32-bit Feistel network (16-bit halves).
/// Mixes the half-block with a 64-bit round key using multiply-xorshift.
fn round_fn_16(half: u16, key: u64) -> u16 {
    let x = (half as u64).wrapping_mul(key | 1); // ensure odd multiplier
    ((x >> 16) ^ x) as u16
}

/// Round function for a 64-bit Feistel network (32-bit halves).
fn round_fn_32(half: u32, key: u64) -> u32 {
    let x = (half as u64).wrapping_mul(key | 1);
    ((x >> 32) ^ x) as u32
}

/// Keyed bijective permutation over the handle space.
///
/// Uses a 4-round Feistel cipher so that sequential counter values
/// produce unpredictable handles.  An attacker who observes any number
/// of handles cannot predict future handles without knowing the
/// randomly-generated round keys.
///
/// On platforms where `CK_ULONG` is 32 bits the Feistel operates on
/// 16-bit halves (bijection over `u32`); otherwise on 32-bit halves
/// (bijection over `u64`).
struct HandleScrambler {
    round_keys: [u64; 4],
}

impl HandleScrambler {
    fn new() -> Self {
        use rand::RngCore;
        let mut rng = rand::rngs::OsRng;
        Self {
            round_keys: [
                rng.next_u64(),
                rng.next_u64(),
                rng.next_u64(),
                rng.next_u64(),
            ],
        }
    }

    /// Forward permutation: counter → handle.
    fn scramble(&self, counter: u64) -> u64 {
        if MAX_HANDLE <= u32::MAX as u64 {
            self.feistel32_forward(counter as u32) as u64
        } else {
            self.feistel64_forward(counter)
        }
    }

    /// Inverse permutation: handle → counter.
    fn unscramble(&self, handle: u64) -> u64 {
        if MAX_HANDLE <= u32::MAX as u64 {
            self.feistel32_inverse(handle as u32) as u64
        } else {
            self.feistel64_inverse(handle)
        }
    }

    fn feistel32_forward(&self, input: u32) -> u32 {
        let mut left = (input >> 16) as u16;
        let mut right = input as u16;
        for key in &self.round_keys {
            let f = round_fn_16(right, *key);
            let new_right = left ^ f;
            left = right;
            right = new_right;
        }
        ((left as u32) << 16) | (right as u32)
    }

    fn feistel32_inverse(&self, input: u32) -> u32 {
        let mut left = (input >> 16) as u16;
        let mut right = input as u16;
        for key in self.round_keys.iter().rev() {
            let f = round_fn_16(left, *key);
            let new_left = right ^ f;
            right = left;
            left = new_left;
        }
        ((left as u32) << 16) | (right as u32)
    }

    fn feistel64_forward(&self, input: u64) -> u64 {
        let mut left = (input >> 32) as u32;
        let mut right = input as u32;
        for key in &self.round_keys {
            let f = round_fn_32(right, *key);
            let new_right = left ^ f;
            left = right;
            right = new_right;
        }
        ((left as u64) << 32) | (right as u64)
    }

    fn feistel64_inverse(&self, input: u64) -> u64 {
        let mut left = (input >> 32) as u32;
        let mut right = input as u32;
        for key in self.round_keys.iter().rev() {
            let f = round_fn_32(left, *key);
            let new_left = right ^ f;
            right = left;
            left = new_left;
        }
        ((left as u64) << 32) | (right as u64)
    }
}

// ── Handle allocators ────────────────────────────────────────────────

/// Generates unique, unpredictable session handles.
///
/// Internally a monotonic counter feeds into a keyed Feistel permutation
/// so that output handles are non-sequential and cannot be predicted
/// from observed values.  The counter wraps at `MAX_HANDLE`, making the
/// allocator resilient to long-running processes (no permanent
/// exhaustion).  Handle 0 (`CK_INVALID_HANDLE`) is always skipped.
pub struct SessionHandleAllocator {
    next: AtomicU64,
    scrambler: HandleScrambler,
}

impl SessionHandleAllocator {
    pub fn new() -> Self {
        Self {
            next: AtomicU64::new(0),
            scrambler: HandleScrambler::new(),
        }
    }

    pub fn next(&self) -> HsmResult<CK_SESSION_HANDLE> {
        loop {
            let current = self.next.load(Ordering::Acquire);
            // Wrap around instead of permanently failing on exhaustion.
            let next_val = if current >= MAX_HANDLE {
                0
            } else {
                current + 1
            };
            if self
                .next
                .compare_exchange_weak(current, next_val, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                let handle = self.scrambler.scramble(current);
                // Skip CK_INVALID_HANDLE (0)
                if handle != 0 {
                    return Ok(handle as CK_SESSION_HANDLE);
                }
                // Exactly one counter value maps to 0 per Feistel bijection;
                // claim the next counter value instead.
                continue;
            }
        }
    }
}

/// Generates unique, unpredictable object handles.
///
/// Same Feistel-based design as [`SessionHandleAllocator`], with an
/// additional `ensure_past` method for avoiding collisions with
/// previously persisted object handles.
pub struct ObjectHandleAllocator {
    next: AtomicU64,
    scrambler: HandleScrambler,
    /// Handles that must not be re-issued (e.g., loaded from persistent
    /// storage).  Checked on every allocation; populated via
    /// [`ensure_past`](Self::ensure_past).
    reserved: parking_lot::Mutex<HashSet<u64>>,
}

impl ObjectHandleAllocator {
    pub fn new() -> Self {
        Self {
            next: AtomicU64::new(0),
            scrambler: HandleScrambler::new(),
            reserved: parking_lot::Mutex::new(HashSet::new()),
        }
    }

    pub fn next(&self) -> HsmResult<CK_OBJECT_HANDLE> {
        loop {
            let current = self.next.load(Ordering::Acquire);
            let next_val = if current >= MAX_HANDLE {
                0
            } else {
                current + 1
            };
            if self
                .next
                .compare_exchange_weak(current, next_val, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                let handle = self.scrambler.scramble(current);
                // Skip CK_INVALID_HANDLE (0) and any reserved handles
                if handle == 0 || self.reserved.lock().contains(&handle) {
                    continue;
                }
                return Ok(handle as CK_OBJECT_HANDLE);
            }
        }
    }

    /// Register a persisted handle so that future allocations will never
    /// collide with it.  Call this for every object loaded from storage
    /// before allocating new handles.
    pub fn ensure_past(&self, handle: CK_OBJECT_HANDLE) {
        self.reserved.lock().insert(handle as u64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feistel_is_bijective_32() {
        let s = HandleScrambler::new();
        // Verify inverse(forward(x)) == x for a sample range
        for i in 0u32..1000 {
            let scrambled = s.feistel32_forward(i);
            let recovered = s.feistel32_inverse(scrambled);
            assert_eq!(recovered, i, "Feistel32 round-trip failed for {i}");
        }
    }

    #[test]
    fn feistel_is_bijective_64() {
        let s = HandleScrambler::new();
        for i in 0u64..1000 {
            let scrambled = s.feistel64_forward(i);
            let recovered = s.feistel64_inverse(scrambled);
            assert_eq!(recovered, i, "Feistel64 round-trip failed for {i}");
        }
    }

    #[test]
    fn scramble_produces_no_obvious_pattern() {
        let s = HandleScrambler::new();
        let h1 = s.scramble(0);
        let h2 = s.scramble(1);
        let h3 = s.scramble(2);
        // Consecutive inputs should not produce consecutive outputs
        assert!(
            !(h2 == h1 + 1 && h3 == h2 + 1),
            "Scrambler produced sequential outputs"
        );
    }

    #[test]
    fn session_handle_allocator_skips_zero() {
        let alloc = SessionHandleAllocator::new();
        for _ in 0..10_000 {
            let h = alloc.next().unwrap();
            assert_ne!(h as u64, 0, "Allocator produced CK_INVALID_HANDLE (0)");
        }
    }

    #[test]
    fn object_handle_allocator_respects_reserved() {
        let alloc = ObjectHandleAllocator::new();
        // Allocate a handle, then reserve it and verify it's not reissued
        let first = alloc.next().unwrap();
        alloc.ensure_past(first);
        for _ in 0..10_000 {
            let h = alloc.next().unwrap();
            assert_ne!(h, first, "Allocator reissued reserved handle {first}");
        }
    }
}
