// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
#![forbid(unsafe_code)]

//! Persists lockout counters (failed login counts and locked flags) to disk.
//!
//! Lockout state is NOT secret (it's security metadata, not key material), so
//! it is stored as plain JSON without encryption. This ensures that lockout
//! survives process restarts, preventing an attacker from resetting brute-force
//! counters by crashing or restarting the HSM process.
//!
//! The file is written atomically (write-to-temp + rename) to avoid corruption
//! from power loss mid-write.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Persisted lockout state for a single token.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LockoutData {
    pub failed_user_logins: u32,
    pub failed_so_logins: u32,
    pub failed_init_token_logins: u32,
    pub user_pin_locked: bool,
    pub so_pin_locked: bool,
}

/// File-backed persistence for lockout counters.
pub struct LockoutStore {
    path: PathBuf,
}

impl LockoutStore {
    /// Create a new lockout store. The file is created on first `save()`.
    pub fn new(storage_dir: &std::path::Path) -> Self {
        Self {
            path: storage_dir.join("lockout_state.json"),
        }
    }

    /// Load persisted lockout data, returning defaults if the file doesn't exist
    /// or is unreadable (fail-open on first boot, fail-closed on corruption).
    pub fn load(&self) -> LockoutData {
        match std::fs::read_to_string(&self.path) {
            Ok(content) => match serde_json::from_str::<LockoutData>(&content) {
                Ok(data) => {
                    tracing::info!(
                        "loaded lockout state: user_failures={}, so_failures={}, \
                         user_locked={}, so_locked={}",
                        data.failed_user_logins,
                        data.failed_so_logins,
                        data.user_pin_locked,
                        data.so_pin_locked,
                    );
                    data
                }
                Err(e) => {
                    // Corruption: log a security warning but default to locked-out
                    // state to prevent brute-force bypass via file tampering.
                    tracing::error!(
                        "lockout state file is corrupted ({}), \
                         defaulting to locked state as safety precaution",
                        e
                    );
                    LockoutData {
                        user_pin_locked: true,
                        so_pin_locked: true,
                        failed_user_logins: u32::MAX,
                        failed_so_logins: u32::MAX,
                        failed_init_token_logins: u32::MAX,
                    }
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::debug!("no lockout state file found, starting fresh");
                LockoutData::default()
            }
            Err(e) => {
                // Can't read the file (permission error, etc.) — fail closed.
                tracing::error!(
                    "cannot read lockout state file ({}), \
                     defaulting to locked state as safety precaution",
                    e
                );
                LockoutData {
                    user_pin_locked: true,
                    so_pin_locked: true,
                    failed_user_logins: u32::MAX,
                    failed_so_logins: u32::MAX,
                    failed_init_token_logins: u32::MAX,
                }
            }
        }
    }

    /// Persist lockout data atomically (write-to-temp + rename).
    pub fn save(&self, data: &LockoutData) {
        let json = match serde_json::to_string_pretty(data) {
            Ok(j) => j,
            Err(e) => {
                tracing::error!("failed to serialize lockout state: {}", e);
                return;
            }
        };

        // Ensure parent directory exists
        if let Some(parent) = self.path.parent() {
            if !parent.exists() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    tracing::error!("failed to create lockout state directory: {}", e);
                    return;
                }
            }
        }

        // Atomic write: write to temp file, then rename
        let tmp_path = self.path.with_extension("json.tmp");
        if let Err(e) = std::fs::write(&tmp_path, json.as_bytes()) {
            tracing::error!("failed to write lockout state temp file: {}", e);
            return;
        }
        if let Err(e) = std::fs::rename(&tmp_path, &self.path) {
            tracing::error!("failed to rename lockout state file: {}", e);
            // Clean up temp file on failure
            let _ = std::fs::remove_file(&tmp_path);
        }
    }

    /// Remove the lockout state file (called during token re-initialization).
    pub fn clear(&self) {
        if let Err(e) = std::fs::remove_file(&self.path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!("failed to remove lockout state file: {}", e);
            }
        }
    }
}
