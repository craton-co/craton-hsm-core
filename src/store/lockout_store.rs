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

use crate::error::{HsmError, HsmResult};
use crate::store::encrypted_store::set_restrictive_permissions;

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
    ///
    /// The on-disk file is locked down to owner-only (Unix mode 0o600 / Windows
    /// owner-only DACL) so that a local attacker cannot reset
    /// `user_pin_locked=false` and brute-force PINs. Permission-set failure is
    /// treated as **fatal** — a save that cannot be locked down is worse than
    /// no save at all, because subsequent boots would read attacker-controlled
    /// state. The temp file is also locked down before any data is written so
    /// that a racing attacker cannot observe or rewrite it during the brief
    /// window before `rename`.
    pub fn save(&self, data: &LockoutData) -> HsmResult<()> {
        let json = serde_json::to_string_pretty(data).map_err(|e| {
            tracing::error!("failed to serialize lockout state: {}", e);
            HsmError::GeneralError
        })?;

        // Ensure parent directory exists
        if let Some(parent) = self.path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    tracing::error!("failed to create lockout state directory: {}", e);
                    HsmError::GeneralError
                })?;
            }
        }

        // Atomic write: create temp file with owner-only mode (Unix), then
        // tighten permissions explicitly on both platforms before writing,
        // then rename, then re-tighten the final path.
        let tmp_path = self.path.with_extension("json.tmp");
        {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut file = opts.open(&tmp_path).map_err(|e| {
                tracing::error!("failed to open lockout state temp file: {}", e);
                HsmError::GeneralError
            })?;

            // Belt-and-suspenders: on Unix this is a no-op if `mode(0o600)`
            // already took effect; on Windows it is the only thing that sets
            // a restrictive DACL. Failure here is fatal — we must not write
            // potentially sensitive lockout state to a world-readable file.
            if let Err(e) = set_restrictive_permissions(&tmp_path) {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(e);
            }

            use std::io::Write;
            if let Err(e) = file.write_all(json.as_bytes()) {
                tracing::error!("failed to write lockout state temp file: {}", e);
                let _ = std::fs::remove_file(&tmp_path);
                return Err(HsmError::GeneralError);
            }
            if let Err(e) = file.sync_all() {
                tracing::error!("failed to fsync lockout state temp file: {}", e);
                let _ = std::fs::remove_file(&tmp_path);
                return Err(HsmError::GeneralError);
            }
        }

        if let Err(e) = std::fs::rename(&tmp_path, &self.path) {
            tracing::error!("failed to rename lockout state file: {}", e);
            // Clean up temp file on failure
            let _ = std::fs::remove_file(&tmp_path);
            return Err(HsmError::GeneralError);
        }

        // Re-apply restrictive permissions on the final path. On Unix the
        // rename preserves the source inode's mode (already 0o600). On
        // Windows the new path may inherit DACLs from the parent directory,
        // so we must set them explicitly. Fatal on failure.
        set_restrictive_permissions(&self.path)?;

        Ok(())
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// After `save()`, the lockout state file MUST have mode 0o600 (no group
    /// or world bits). A world- or group-readable lockout file lets a local
    /// attacker reset `user_pin_locked` and brute-force PINs — exactly the
    /// regression this test guards against.
    #[test]
    fn save_writes_owner_only_permissions() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let store = LockoutStore::new(dir.path());
        store
            .save(&LockoutData::default())
            .expect("save must succeed");

        let meta = std::fs::metadata(dir.path().join("lockout_state.json"))
            .expect("stat lockout file");
        let mode = meta.permissions().mode();
        assert_eq!(
            mode & 0o077,
            0,
            "lockout file mode {:o} grants group/world access — must be 0o600",
            mode & 0o777,
        );
    }
}
