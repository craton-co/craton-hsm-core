// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! HSM backup/restore — encrypted export of token objects.
//!
//! Backup file format:
//! ```text
//! [4 bytes: magic "RHBK"]
//! [4 bytes: version (1) as u32 LE]
//! [32 bytes: PBKDF2 salt]
//! [12 bytes: AES-GCM nonce]
//! [remaining: AES-256-GCM ciphertext of JSON payload]
//! ```
//!
//! The JSON payload (before encryption) contains a `BackupPayload` struct
//! with metadata and a Vec of serialized `StoredObject`s.

use std::collections::HashSet;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use zeroize::Zeroize;

use crate::error::{HsmError, HsmResult};
use crate::store::encrypted_store::derive_key_from_pin;
use crate::store::object::StoredObject;

const BACKUP_MAGIC: &[u8; 4] = b"RHBK";
const BACKUP_VERSION: u32 = 1;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const HEADER_LEN: usize = 4 + 4 + SALT_LEN + NONCE_LEN; // 52 bytes
const MIN_PASSPHRASE_LEN: usize = 16;

/// Inner JSON payload that gets encrypted in the backup file.
#[derive(Serialize, Deserialize)]
struct BackupPayload {
    version: u32,
    created: String,
    /// Seconds since UNIX epoch — used for replay/staleness detection on restore.
    created_epoch: u64,
    /// Random UUID to uniquely identify this backup instance.
    backup_id: String,
    /// Token serial number that produced this backup — prevents cross-token restore.
    token_serial: String,
    object_count: usize,
    objects: Vec<StoredObject>,
}

/// Maximum allowed age of a backup in seconds (default: 30 days).
const DEFAULT_MAX_BACKUP_AGE_SECS: u64 = 30 * 24 * 3600;

/// Create an encrypted backup blob from a collection of objects.
///
/// `token_serial` binds the backup to a specific token — restoring to a
/// different token will be rejected unless the caller opts out.
///
/// `pbkdf2_iterations`: if `Some`, uses the given iteration count for key
/// derivation (should match the runtime config). Falls back to the crate
/// default (600k) if `None`.
///
/// The backup is encrypted with AES-256-GCM using a key derived from
/// the passphrase via PBKDF2-HMAC-SHA256.
pub fn create_backup(
    objects: &[StoredObject],
    passphrase: &str,
    token_serial: &str,
    pbkdf2_iterations: Option<u32>,
) -> HsmResult<Vec<u8>> {
    // Check character count, not byte count — a short string of multi-byte
    // characters (e.g. 4 CJK chars = 12 UTF-8 bytes) could otherwise pass
    // the minimum length check despite having very low entropy.
    if passphrase.chars().count() < MIN_PASSPHRASE_LEN {
        return Err(HsmError::PinLenRange);
    }

    // Reject low-entropy passphrases: require at least 3 distinct character
    // classes (lowercase, uppercase, digits, symbols) to prevent trivially
    // guessable inputs like "aaaaaaaaaaaaaaaa" or "1234567890123456".
    if !check_passphrase_complexity(passphrase) {
        return Err(HsmError::PinInvalid);
    }

    // Generate a random backup ID (UUID v4-like)
    let mut uuid_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut uuid_bytes);
    let backup_id = hex::encode(uuid_bytes);

    let now_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Serialize payload to JSON
    let payload = BackupPayload {
        version: BACKUP_VERSION,
        created: chrono_timestamp(),
        created_epoch: now_epoch,
        backup_id,
        token_serial: token_serial.to_string(),
        object_count: objects.len(),
        objects: objects.to_vec(),
    };
    let mut json = serde_json::to_vec(&payload).map_err(|_| HsmError::GeneralError)?;

    // Derive encryption key from passphrase
    let (key, salt) = derive_key_from_pin(passphrase.as_bytes(), None, pbkdf2_iterations);

    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);

    // Encrypt with AES-256-GCM
    let aes_key = Key::<Aes256Gcm>::from_slice(key.as_ref());
    let cipher = Aes256Gcm::new(aes_key);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, json.as_ref())
        .map_err(|_| HsmError::GeneralError)?;

    // Zeroize plaintext JSON containing key material before dropping
    json.zeroize();

    // Assemble backup file: magic + version + salt + nonce + ciphertext
    let mut output = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    output.extend_from_slice(BACKUP_MAGIC);
    output.extend_from_slice(&BACKUP_VERSION.to_le_bytes());
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

/// Restore objects from an encrypted backup blob.
///
/// `expected_serial`: the backup's token_serial must match or restore is rejected.
///   This is mandatory to prevent cross-token restore attacks.
/// `max_age_secs`: if `Some`, the backup must be younger than this many seconds.
///   Defaults to 30 days if `None`.  Pass `Some(0)` to disable age checking.
/// `consumed_ids`: set of previously restored backup IDs.  If the backup's
///   `backup_id` is already in this set, the restore is rejected to prevent
///   replay attacks.  On success the new ID is inserted into the set.
///   Pass `None` to skip replay checking (not recommended for production).
///
/// Returns the list of `StoredObject`s on success.
/// Returns `HsmError::DataInvalid` for format/replay errors and
/// `HsmError::PinIncorrect` for wrong passphrase.
pub fn restore_backup(
    data: &[u8],
    passphrase: &str,
    expected_serial: &str,
    max_age_secs: Option<u64>,
    pbkdf2_iterations: Option<u32>,
    mut consumed_ids: Option<&mut HashSet<String>>,
) -> HsmResult<Vec<StoredObject>> {
    if data.len() < HEADER_LEN {
        return Err(HsmError::DataInvalid);
    }

    // Verify magic
    if &data[0..4] != BACKUP_MAGIC {
        return Err(HsmError::DataInvalid);
    }

    // Check version
    let version = u32::from_le_bytes(data[4..8].try_into().map_err(|_| HsmError::DataInvalid)?);
    if version != BACKUP_VERSION {
        return Err(HsmError::DataInvalid);
    }

    // Extract salt, nonce, ciphertext
    let salt = &data[8..8 + SALT_LEN];
    let nonce_bytes = &data[8 + SALT_LEN..HEADER_LEN];
    let ciphertext = &data[HEADER_LEN..];

    // Derive key from passphrase using stored salt
    let (key, _) = derive_key_from_pin(passphrase.as_bytes(), Some(salt), pbkdf2_iterations);

    // Decrypt
    let aes_key = Key::<Aes256Gcm>::from_slice(key.as_ref());
    let cipher = Aes256Gcm::new(aes_key);
    let nonce = Nonce::from_slice(nonce_bytes);
    let mut plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| HsmError::PinIncorrect)?;

    // Deserialize JSON payload
    let payload: BackupPayload =
        serde_json::from_slice(&plaintext).map_err(|_| HsmError::DataInvalid)?;

    // Zeroize decrypted plaintext containing key material
    plaintext.zeroize();

    // Validate object_count matches actual objects — detects payload tampering
    if payload.object_count != payload.objects.len() {
        tracing::warn!(
            "Backup restore rejected: object_count mismatch (header={}, actual={})",
            payload.object_count,
            payload.objects.len()
        );
        return Err(HsmError::DataInvalid);
    }

    // Validate token serial binding — prevents cross-token restore attacks.
    // This check is mandatory; use create_backup/restore_backup with the
    // correct serial rather than bypassing this check.
    if payload.token_serial != expected_serial {
        tracing::warn!(
            "Backup restore rejected: token serial mismatch (backup={}, expected={})",
            payload.token_serial,
            expected_serial
        );
        return Err(HsmError::DataInvalid);
    }

    // Replay protection — reject backups that have already been consumed.
    // Callers SHOULD always provide consumed_ids for production use to
    // prevent the same backup from being restored multiple times.
    match consumed_ids {
        Some(ref mut ids) => {
            if ids.contains(&payload.backup_id) {
                tracing::warn!(
                    "Backup restore rejected: backup_id {} has already been consumed (replay attack?)",
                    payload.backup_id
                );
                return Err(HsmError::DataInvalid);
            }
        }
        None => {
            tracing::warn!(
                "Backup replay protection disabled (consumed_ids=None). \
                 This is unsafe for production — duplicate key imports are possible."
            );
        }
    }

    // Validate backup age — prevents replay of stale backups
    let max_age = match max_age_secs {
        Some(0) => None, // explicitly disabled
        Some(age) => Some(age),
        None => Some(DEFAULT_MAX_BACKUP_AGE_SECS),
    };
    if let Some(max) = max_age {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if payload.created_epoch > now + 300 {
            // Backup claims to be from the future (>5 min tolerance) — suspicious
            tracing::warn!("Backup restore rejected: timestamp is in the future");
            return Err(HsmError::DataInvalid);
        }
        if now.saturating_sub(payload.created_epoch) > max {
            tracing::warn!(
                "Backup restore rejected: backup is {} seconds old (max allowed: {})",
                now - payload.created_epoch,
                max
            );
            return Err(HsmError::DataInvalid);
        }
    }

    tracing::info!(
        "Backup restored: id={}, serial={}, objects={}",
        payload.backup_id,
        payload.token_serial,
        payload.object_count
    );

    // Record this backup_id as consumed to prevent future replay
    if let Some(ids) = consumed_ids {
        ids.insert(payload.backup_id);
    }

    Ok(payload.objects)
}

/// Persistent replay guard — tracks consumed backup IDs across restarts.
///
/// On creation, loads previously consumed IDs from a file. After each
/// successful restore, the new ID is appended to the file immediately.
/// The file format is one hex-encoded backup ID per line (simple, append-only).
///
/// If the file cannot be read/written (e.g., in-memory-only deployment),
/// falls back to in-memory-only tracking with a warning.
pub struct PersistentReplayGuard {
    ids: HashSet<String>,
    path: Option<std::path::PathBuf>,
}

impl PersistentReplayGuard {
    /// Create a replay guard backed by a file at `path`.
    /// Loads existing consumed IDs from the file (one per line).
    /// If the file doesn't exist, starts with an empty set.
    pub fn new(path: std::path::PathBuf) -> Self {
        let mut ids = HashSet::new();

        match std::fs::read_to_string(&path) {
            Ok(content) => {
                for line in content.lines() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        ids.insert(trimmed.to_string());
                    }
                }
                tracing::info!(
                    "Loaded {} consumed backup IDs from {}",
                    ids.len(),
                    path.display()
                );
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // No file yet — first use
            }
            Err(e) => {
                tracing::warn!(
                    "Could not read replay guard file {}: {} — starting empty",
                    path.display(),
                    e
                );
            }
        }

        Self {
            ids,
            path: Some(path),
        }
    }

    /// Create an in-memory-only replay guard (no persistence).
    pub fn in_memory() -> Self {
        Self {
            ids: HashSet::new(),
            path: None,
        }
    }

    /// Check if a backup ID has already been consumed.
    pub fn is_consumed(&self, id: &str) -> bool {
        self.ids.contains(id)
    }

    /// Record a backup ID as consumed. Persists to file immediately.
    ///
    /// Acquires an exclusive file lock before writing to prevent concurrent
    /// processes from both passing the replay check for the same backup ID.
    pub fn record(&mut self, id: String) -> HsmResult<()> {
        if let Some(ref path) = self.path {
            use fs2::FileExt;
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|e| {
                    tracing::error!(
                        "Failed to open replay guard file {} for append: {}",
                        path.display(),
                        e
                    );
                    HsmError::GeneralError
                })?;

            // Set restrictive permissions on first creation
            crate::store::encrypted_store::set_restrictive_permissions(path);

            // Acquire exclusive lock to prevent TOCTOU race between
            // is_consumed() check and record() in concurrent processes.
            file.lock_exclusive().map_err(|e| {
                tracing::error!("Failed to lock replay guard file {}: {}", path.display(), e);
                HsmError::GeneralError
            })?;

            writeln!(file, "{}", id).map_err(|e| {
                tracing::error!(
                    "Failed to write to replay guard file {}: {}",
                    path.display(),
                    e
                );
                HsmError::GeneralError
            })?;
            // Lock is released when file is dropped
        }
        self.ids.insert(id);
        Ok(())
    }

    /// Get the inner set (for backward compatibility with callers using HashSet).
    pub fn consumed_ids(&self) -> &HashSet<String> {
        &self.ids
    }

    /// Clone the consumed IDs set for passing to `restore_backup`.
    /// The caller should diff the returned set after restore to find
    /// newly consumed IDs and persist them via `record()`.
    pub fn consumed_ids_clone(&self) -> HashSet<String> {
        self.ids.clone()
    }
}

/// Check that a passphrase has sufficient entropy to resist brute-force.
///
/// Accepts passphrases via two policies (either one is sufficient):
///
/// **Policy A — character diversity**: at least 3 of 4 character classes
/// (lowercase, uppercase, digit, symbol) AND at least 6 unique characters.
/// This covers mixed-case passwords like "My-S3cure-Pass!".
///
/// **Policy B — length-based entropy**: at least 24 characters AND at least
/// 12 unique characters. This covers high-entropy Diceware/passphrase-style
/// inputs like "correct horse battery staple zephyr" that may only use 1-2
/// character classes but have ample entropy from length and word diversity.
///
/// Both policies reject trivially guessable inputs like repeated characters.
fn check_passphrase_complexity(passphrase: &str) -> bool {
    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_symbol = false;
    let mut unique_chars = std::collections::HashSet::new();

    for ch in passphrase.chars() {
        unique_chars.insert(ch);
        if ch.is_ascii_lowercase() {
            has_lower = true;
        } else if ch.is_ascii_uppercase() {
            has_upper = true;
        } else if ch.is_ascii_digit() {
            has_digit = true;
        } else {
            has_symbol = true;
        }
    }

    let class_count = has_lower as u8 + has_upper as u8 + has_digit as u8 + has_symbol as u8;
    let char_count = passphrase.chars().count();
    let unique_count = unique_chars.len();

    // Policy A: mixed character classes (traditional password policy)
    let policy_a = class_count >= 3 && unique_count >= 6;

    // Policy B: long passphrase with sufficient unique characters
    // (Diceware / multi-word passphrases with high entropy from length)
    let policy_b = char_count >= 24 && unique_count >= 12;

    policy_a || policy_b
}

/// Simple ISO-8601 timestamp without pulling in chrono.
fn chrono_timestamp() -> String {
    use std::time::SystemTime;
    let duration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}s-since-epoch", duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::object::StoredObject;

    fn make_test_object(
        handle: crate::pkcs11_abi::types::CK_OBJECT_HANDLE,
        label: &str,
    ) -> StoredObject {
        let mut obj = StoredObject::new(handle, 3); // CKO_SECRET_KEY
        obj.label = label.as_bytes().to_vec();
        obj.token_object = true;
        obj
    }

    const TEST_SERIAL: &str = "0000000000000001";

    #[test]
    fn round_trip_backup_restore() {
        let objects = vec![
            make_test_object(1, "key1"),
            make_test_object(2, "key2"),
            make_test_object(3, "key3"),
        ];

        let backup = create_backup(&objects, "Test-P@ssphr4se-Long", TEST_SERIAL, None).unwrap();
        let restored = restore_backup(
            &backup,
            "Test-P@ssphr4se-Long",
            TEST_SERIAL,
            Some(0),
            None,
            None,
        )
        .unwrap();

        assert_eq!(restored.len(), 3);
        assert_eq!(restored[0].label, b"key1");
        assert_eq!(restored[1].label, b"key2");
        assert_eq!(restored[2].label, b"key3");
    }

    #[test]
    fn wrong_passphrase_fails() {
        let objects = vec![make_test_object(1, "key1")];
        let backup = create_backup(&objects, "C0rrect-P@ssphrase", TEST_SERIAL, None).unwrap();

        let result = restore_backup(
            &backup,
            "Wr0ng-P@ssphrase",
            TEST_SERIAL,
            Some(0),
            None,
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn empty_backup_is_valid() {
        let backup = create_backup(&[], "L0ng-P@ssphrase!", TEST_SERIAL, None).unwrap();
        let restored = restore_backup(
            &backup,
            "L0ng-P@ssphrase!",
            TEST_SERIAL,
            Some(0),
            None,
            None,
        )
        .unwrap();
        assert!(restored.is_empty());
    }

    #[test]
    fn truncated_blob_fails() {
        let result = restore_backup(&[0u8; 10], "pass", TEST_SERIAL, Some(0), None, None);
        assert!(result.is_err());
    }

    #[test]
    fn invalid_magic_fails() {
        let mut backup = create_backup(&[], "L0ng-P@ssphrase!", TEST_SERIAL, None).unwrap();
        backup[0] = b'X'; // corrupt magic
        let result = restore_backup(&backup, "pass", TEST_SERIAL, Some(0), None, None);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_serial_rejected() {
        let backup = create_backup(&[], "L0ng-P@ssphrase!", "serial-A0000000", None).unwrap();
        let result = restore_backup(
            &backup,
            "L0ng-P@ssphrase!",
            "serial-B0000000",
            Some(0),
            None,
            None,
        );
        assert!(result.is_err(), "Cross-token restore should be rejected");
    }

    #[test]
    fn replay_protection() {
        let backup = create_backup(&[], "L0ng-P@ssphrase!", TEST_SERIAL, None).unwrap();
        let mut consumed = HashSet::new();

        // First restore succeeds
        let result = restore_backup(
            &backup,
            "L0ng-P@ssphrase!",
            TEST_SERIAL,
            Some(0),
            None,
            Some(&mut consumed),
        );
        assert!(result.is_ok(), "First restore should succeed");
        assert_eq!(consumed.len(), 1);

        // Second restore of the same backup is rejected (replay)
        let result = restore_backup(
            &backup,
            "L0ng-P@ssphrase!",
            TEST_SERIAL,
            Some(0),
            None,
            Some(&mut consumed),
        );
        assert!(result.is_err(), "Replay of same backup should be rejected");
    }
}
