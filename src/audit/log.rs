// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::BufRead;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Every security-relevant operation emits an audit event.
/// The audit log is append-only and tamper-evident (chained SHA-256 hashes).
///
/// Hash chain: `H_n = SHA-256(H_{n-1} || serialize(payload_n))`
/// where `payload_n` is the event data *excluding* `previous_hash`,
/// avoiding circularity in the hash computation.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub timestamp: u64,
    pub session_handle: u64,
    pub operation: AuditOperation,
    pub key_id: Option<String>,
    pub result: AuditResult,
    pub previous_hash: [u8; 32],
}

/// The hashable payload of an audit event — excludes `previous_hash` so that
/// the chain hash `H_n = SHA-256(H_{n-1} || serialize(payload))` is
/// non-circular and cryptographically sound.
#[derive(Serialize)]
struct AuditEventPayload<'a> {
    timestamp: u64,
    session_handle: u64,
    operation: &'a AuditOperation,
    key_id: &'a Option<String>,
    result: &'a AuditResult,
}

impl AuditEvent {
    fn payload(&self) -> AuditEventPayload<'_> {
        AuditEventPayload {
            timestamp: self.timestamp,
            session_handle: self.session_handle,
            operation: &self.operation,
            key_id: &self.key_id,
            result: &self.result,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditOperation {
    Initialize,
    Finalize,
    OpenSession {
        slot_id: u64,
    },
    CloseSession,
    Login {
        user_type: u64,
    },
    Logout,
    InitToken {
        slot_id: u64,
    },
    /// `fips_approved`: FIPS 140-3 IG 2.4.C algorithm indicator.
    /// `true` = approved algorithm, `false` = non-approved.
    GenerateKey {
        mechanism: u64,
        key_length: u32,
        fips_approved: bool,
    },
    GenerateKeyPair {
        mechanism: u64,
        key_length: u32,
        fips_approved: bool,
    },
    Sign {
        mechanism: u64,
        fips_approved: bool,
    },
    Verify {
        mechanism: u64,
        fips_approved: bool,
    },
    Encrypt {
        mechanism: u64,
        fips_approved: bool,
    },
    Decrypt {
        mechanism: u64,
        fips_approved: bool,
    },
    Digest {
        mechanism: u64,
        fips_approved: bool,
    },
    CreateObject,
    DestroyObject,
    GenerateRandom {
        length: u32,
    },
    WrapKey {
        mechanism: u64,
        fips_approved: bool,
    },
    UnwrapKey {
        mechanism: u64,
        fips_approved: bool,
    },
    DeriveKey {
        mechanism: u64,
        fips_approved: bool,
    },
    /// (#7-fix) Audit read operations for FIPS 140-3 compliance.
    FindObjects {
        result_count: u32,
    },
    GetAttributeValue,
    /// FIPS 140-3 zeroization attestation.
    Zeroize {
        /// Number of bytes zeroized.
        key_length: u32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditResult {
    Success,
    Failure(u64),
}

/// Commands sent to the background audit worker thread.
enum AuditCommand {
    Record {
        session_handle: u64,
        operation: AuditOperation,
        result: AuditResult,
        key_id: Option<String>,
    },
    Flush {
        done: std::sync::mpsc::Sender<()>,
    },
}

/// Maximum number of audit events retained in memory.
/// Once exceeded, the oldest entries are discarded (they remain on disk
/// if disk logging is enabled). This prevents unbounded memory growth
/// for long-running HSM processes.
const MAX_IN_MEMORY_ENTRIES: usize = 100_000;

/// Maximum audit log file size in bytes before rotation (100 MB).
const MAX_LOG_FILE_BYTES: u64 = 100 * 1024 * 1024;

/// Maximum number of rotated log file generations to keep.
const MAX_ROTATED_FILES: u32 = 5;

/// Result of attempting to recover the hash chain from an existing log file.
enum ChainRecoveryResult {
    /// No existing log file — start fresh with the zero hash.
    NoFile,
    /// Chain recovered and verified successfully; contains the final hash.
    Verified([u8; 32]),
    /// Chain is broken: the file is corrupt, tampered, or unreadable.
    /// Contains a human-readable reason for the failure.
    Broken(String),
}

/// Internal state protected by a single RwLock to guarantee atomicity
/// between the hash chain and the entry list, while allowing concurrent reads.
struct AuditLogState {
    entries: Vec<AuditEvent>,
    last_hash: [u8; 32],
    /// Set to `true` if the audit log chain was found to be corrupt or tampered
    /// with during recovery. Once set, this flag is permanent for the lifetime
    /// of the `AuditLog` instance and is exposed via `is_tamper_detected()`.
    /// When set, `record()` refuses to append new events to prevent an attacker
    /// from continuing to build a valid chain after tampering.
    tamper_detected: bool,
    /// Monotonic timestamp floor — each event's timestamp is guaranteed to be
    /// strictly greater than the previous one, even if the wall clock jumps
    /// backwards (NTP correction, VM migration, etc.).
    last_timestamp: u64,
}

pub struct AuditLog {
    state: Arc<RwLock<AuditLogState>>,
    /// Optional path for persistent NDJSON audit trail on disk.
    log_path: Option<PathBuf>,
    /// Channel sender for dispatching audit commands to the background worker.
    sender: Option<std::sync::mpsc::Sender<AuditCommand>>,
    /// Shared flag indicating that the audit chain has been tampered with.
    /// Checked in `record()` without acquiring the RwLock for fast-path rejection.
    tamper_flag: Arc<AtomicBool>,
    /// Handle to the background worker thread that processes audit events.
    worker: Option<std::thread::JoinHandle<()>>,
}

/// Global weak reference to the active audit log, allowing `Drop` implementations
/// (like `RawKeyMaterial`) to record zeroization events without holding a direct
/// reference to the HSM core or audit log.
static GLOBAL_AUDIT_LOG: parking_lot::RwLock<Option<std::sync::Weak<AuditLog>>> =
    parking_lot::RwLock::new(None);

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute the chain hash for an event:
/// `SHA-256(previous_hash || serialize(payload))`
///
/// The payload excludes `previous_hash` to avoid circularity.
fn compute_chain_hash(
    previous_hash: &[u8; 32],
    event: &AuditEvent,
) -> Result<[u8; 32], crate::error::HsmError> {
    let payload_bytes = serde_json::to_vec(&event.payload()).map_err(|e| {
        tracing::error!("Audit event payload serialization failed: {}", e);
        crate::error::HsmError::GeneralError
    })?;
    let mut hasher = Sha256::new();
    hasher.update(previous_hash);
    hasher.update(&payload_bytes);
    let hash = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);
    Ok(result)
}

/// Validate and canonicalize the audit log path.
///
/// - Resolves symlinks in the parent directory to prevent path traversal.
/// - Rejects paths where the target file itself is a symlink, preventing
///   an attacker from redirecting audit writes to arbitrary files.
fn validate_log_path(path: &Path) -> Result<PathBuf, crate::error::HsmError> {
    // If the file already exists, ensure it is a regular file (not a symlink,
    // device, pipe, etc.).
    if path.exists() {
        let meta = std::fs::symlink_metadata(path).map_err(|e| {
            tracing::error!(
                "Audit log path validation: cannot stat {}: {}",
                path.display(),
                e,
            );
            crate::error::HsmError::GeneralError
        })?;
        if meta.file_type().is_symlink() {
            tracing::error!("Audit log path is a symlink, refusing: {}", path.display(),);
            return Err(crate::error::HsmError::AuditChainBroken(
                "audit log path is a symlink".to_string(),
            ));
        }
        if !meta.file_type().is_file() {
            tracing::error!("Audit log path is not a regular file: {}", path.display(),);
            return Err(crate::error::HsmError::AuditChainBroken(
                "audit log path is not a regular file".to_string(),
            ));
        }
    }

    // Canonicalize the parent directory to resolve any symlinks in the path
    // components leading to the file. This prevents traversal attacks like
    // `/var/log/../../etc/shadow`.
    if let Some(parent) = path.parent() {
        if parent.as_os_str().is_empty() {
            // Relative filename with no directory — use as-is.
            return Ok(path.to_path_buf());
        }
        let canonical_parent = parent.canonicalize().map_err(|e| {
            tracing::error!(
                "Audit log path validation: cannot canonicalize parent {}: {}",
                parent.display(),
                e,
            );
            crate::error::HsmError::GeneralError
        })?;
        if let Some(file_name) = path.file_name() {
            Ok(canonical_parent.join(file_name))
        } else {
            tracing::error!(
                "Audit log path has no filename component: {}",
                path.display(),
            );
            Err(crate::error::HsmError::GeneralError)
        }
    } else {
        Ok(path.to_path_buf())
    }
}

/// Open (or create) the audit log file with restrictive permissions.
fn open_audit_file(path: &Path) -> Result<std::fs::File, crate::error::HsmError> {
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);

    // On Unix, restrict to owner-only read/write (0o600).
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    let file = opts.open(path).map_err(|e| {
        tracing::error!("Audit log file open failed: {}", e);
        crate::error::HsmError::GeneralError
    })?;

    // On Windows, restrict the file ACL to the current user only (equivalent
    // to Unix 0o600). If ACL setting fails, we log an error (not just a
    // warning) so the failure is visible in monitoring, but continue rather
    // than refusing to audit — a world-readable audit log is better than
    // no audit log at all.
    #[cfg(windows)]
    {
        if let Err(e) = crate::platform_acl::restrict_file_to_owner(path) {
            tracing::error!(
                "Failed to restrict audit log file permissions on {}: {}. \
                 File may be readable by other users.",
                path.display(),
                e,
            );
        }
    }

    Ok(file)
}

impl AuditLog {
    /// Spawn the background worker thread that processes audit commands.
    /// The worker owns the receiver end of the channel and maintains local
    /// copies of `last_hash` and `last_timestamp` for lock-free event building.
    fn spawn_worker(
        state: Arc<RwLock<AuditLogState>>,
        log_path: Option<PathBuf>,
        tamper_flag: Arc<AtomicBool>,
        receiver: std::sync::mpsc::Receiver<AuditCommand>,
        initial_hash: [u8; 32],
        initial_timestamp: u64,
    ) -> std::thread::JoinHandle<()> {
        std::thread::Builder::new()
            .name("audit-worker".to_string())
            .spawn(move || {
                let mut last_hash = initial_hash;
                let mut last_timestamp = initial_timestamp;

                /// Process a single Record command. Returns the updated
                /// (last_hash, last_timestamp) on success.
                fn process_record(
                    state: &Arc<RwLock<AuditLogState>>,
                    log_path: &Option<PathBuf>,
                    tamper_flag: &Arc<AtomicBool>,
                    last_hash: &mut [u8; 32],
                    last_timestamp: &mut u64,
                    session_handle: u64,
                    operation: AuditOperation,
                    result: AuditResult,
                    key_id: Option<String>,
                ) {
                    if tamper_flag.load(Ordering::Acquire) {
                        return;
                    }

                    let duration = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default();
                    let wall_timestamp = u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);

                    // Enforce monotonicity
                    let timestamp = if wall_timestamp <= *last_timestamp {
                        match last_timestamp.checked_add(1) {
                            Some(next) => next,
                            None => {
                                tracing::error!(
                                    "Audit timestamp space exhausted (u64::MAX reached). \
                                     Cannot guarantee monotonicity."
                                );
                                tamper_flag.store(true, Ordering::Release);
                                return;
                            }
                        }
                    } else {
                        wall_timestamp
                    };
                    *last_timestamp = timestamp;

                    let event = AuditEvent {
                        timestamp,
                        session_handle,
                        operation,
                        key_id,
                        result,
                        previous_hash: *last_hash,
                    };

                    // Compute chain hash: SHA-256(previous_hash || payload)
                    let new_hash = match compute_chain_hash(last_hash, &event) {
                        Ok(h) => h,
                        Err(_) => {
                            tracing::error!("Audit worker: chain hash computation failed");
                            return;
                        }
                    };
                    *last_hash = new_hash;

                    // Persist to disk if configured
                    if let Some(path) = log_path {
                        let io_result = (|| -> Result<(), crate::error::HsmError> {
                            let mut file = open_audit_file(path)?;
                            let file_size = file.metadata().map(|m| m.len()).unwrap_or(0);

                            if file_size >= MAX_LOG_FILE_BYTES {
                                drop(file);
                                AuditLog::rotate_log_files(path)?;
                                file = open_audit_file(path)?;
                            }

                            let line = serde_json::to_string(&event).map_err(|e| {
                                tracing::error!("Audit log serialization failed: {}", e);
                                crate::error::HsmError::GeneralError
                            })?;

                            writeln!(file, "{}", line).map_err(|e| {
                                tracing::error!("Audit log write failed: {}", e);
                                crate::error::HsmError::GeneralError
                            })?;
                            file.sync_all().map_err(|e| {
                                tracing::error!("Audit log fsync failed: {}", e);
                                crate::error::HsmError::GeneralError
                            })?;
                            Ok(())
                        })();

                        if let Err(e) = io_result {
                            tracing::error!("Audit worker: disk I/O failed: {}", e);
                        }
                    }

                    // Push to shared state so readers (get_entries, verify_chain, etc.) see it.
                    {
                        let mut s = state.write();
                        s.last_hash = new_hash;
                        s.last_timestamp = *last_timestamp;
                        s.entries.push(event);

                        // Cap in-memory entries to prevent unbounded growth.
                        if s.entries.len() > MAX_IN_MEMORY_ENTRIES {
                            let excess = s.entries.len() - MAX_IN_MEMORY_ENTRIES;
                            s.entries.drain(..excess);
                        }
                    }
                }

                loop {
                    match receiver.recv() {
                        Ok(AuditCommand::Record {
                            session_handle,
                            operation,
                            result,
                            key_id,
                        }) => {
                            process_record(
                                &state,
                                &log_path,
                                &tamper_flag,
                                &mut last_hash,
                                &mut last_timestamp,
                                session_handle,
                                operation,
                                result,
                                key_id,
                            );
                        }
                        Ok(AuditCommand::Flush { done }) => {
                            // Drain any pending records before acknowledging.
                            while let Ok(cmd) = receiver.try_recv() {
                                match cmd {
                                    AuditCommand::Record {
                                        session_handle,
                                        operation,
                                        result,
                                        key_id,
                                    } => {
                                        process_record(
                                            &state,
                                            &log_path,
                                            &tamper_flag,
                                            &mut last_hash,
                                            &mut last_timestamp,
                                            session_handle,
                                            operation,
                                            result,
                                            key_id,
                                        );
                                    }
                                    AuditCommand::Flush { done: inner_done } => {
                                        let _ = inner_done.send(());
                                    }
                                }
                            }
                            let _ = done.send(());
                        }
                        Err(_) => {
                            // Channel closed — sender dropped. Exit the worker.
                            break;
                        }
                    }
                }
            })
            .expect("failed to spawn audit worker thread")
    }

    pub fn new() -> Self {
        let state = Arc::new(RwLock::new(AuditLogState {
            entries: Vec::new(),
            last_hash: [0u8; 32],
            tamper_detected: false,
            last_timestamp: 0,
        }));
        let tamper_flag = Arc::new(AtomicBool::new(false));
        let (sender, receiver) = std::sync::mpsc::channel();

        let worker = Self::spawn_worker(
            Arc::clone(&state),
            None,
            Arc::clone(&tamper_flag),
            receiver,
            [0u8; 32],
            0,
        );

        Self {
            state,
            log_path: None,
            sender: Some(sender),
            tamper_flag,
            worker: Some(worker),
        }
    }

    /// Create an audit log with disk persistence enabled.
    /// Events are appended to the file as NDJSON (one JSON object per line).
    ///
    /// The path is validated and canonicalized to prevent symlink/path traversal
    /// attacks. Returns an error if the path is invalid (symlink, not a regular
    /// file, parent directory unresolvable).
    ///
    /// If an existing log file is found, the hash chain is recovered **and
    /// verified** so that new events are correctly chained to the previous
    /// entries. If the chain is broken or the file is corrupt, the
    /// `tamper_detected` flag is set permanently and `record()` will refuse
    /// to append new events. Callers should check `is_tamper_detected()` after
    /// construction.
    pub fn new_with_path(path: PathBuf) -> Result<Self, crate::error::HsmError> {
        let path = validate_log_path(&path)?;

        let (recovered_hash, tampered) = match Self::recover_chain_from_file(&path) {
            ChainRecoveryResult::NoFile => ([0u8; 32], false),
            ChainRecoveryResult::Verified(hash) => (hash, false),
            ChainRecoveryResult::Broken(reason) => {
                tracing::error!(
                    "Audit chain integrity check FAILED for {}: {}. \
                     Tamper flag set — record() will refuse new events.",
                    path.display(),
                    reason,
                );
                ([0u8; 32], true)
            }
        };

        let state = Arc::new(RwLock::new(AuditLogState {
            entries: Vec::new(),
            last_hash: recovered_hash,
            tamper_detected: tampered,
            last_timestamp: 0,
        }));
        let tamper_flag = Arc::new(AtomicBool::new(tampered));
        let (sender, receiver) = std::sync::mpsc::channel();

        let worker = Self::spawn_worker(
            Arc::clone(&state),
            Some(path.clone()),
            Arc::clone(&tamper_flag),
            receiver,
            recovered_hash,
            0,
        );

        Ok(Self {
            state,
            log_path: Some(path),
            sender: Some(sender),
            tamper_flag,
            worker: Some(worker),
        })
    }

    /// Returns `true` if the audit log chain was found to be corrupt or
    /// tampered with during recovery. Once set, this flag is permanent.
    /// When `true`, `record()` will refuse to append new events.
    pub fn is_tamper_detected(&self) -> bool {
        self.tamper_flag.load(Ordering::Acquire)
    }

    /// Read the existing NDJSON audit log file, recompute the SHA-256
    /// hash chain, and **verify each link** to detect tampering.
    fn recover_chain_from_file(path: &Path) -> ChainRecoveryResult {
        let file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    return ChainRecoveryResult::NoFile;
                }
                return ChainRecoveryResult::Broken(format!(
                    "could not open log file {}: {}",
                    path.display(),
                    e,
                ));
            }
        };

        let reader = std::io::BufReader::new(file);
        let mut running_hash = [0u8; 32];

        for (line_num, line_result) in reader.lines().enumerate() {
            let line = match line_result {
                Ok(l) => l,
                Err(e) => {
                    return ChainRecoveryResult::Broken(format!(
                        "I/O error at line {}: {}",
                        line_num + 1,
                        e,
                    ));
                }
            };

            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            let event: AuditEvent = match serde_json::from_str(trimmed) {
                Ok(ev) => ev,
                Err(e) => {
                    return ChainRecoveryResult::Broken(format!(
                        "failed to deserialize line {}: {}",
                        line_num + 1,
                        e,
                    ));
                }
            };

            // Verify that this event's previous_hash matches our running chain.
            if event.previous_hash != running_hash {
                return ChainRecoveryResult::Broken(format!(
                    "TAMPER DETECTED at line {}: expected previous_hash {:02x?}, found {:02x?}",
                    line_num + 1,
                    &running_hash[..8],
                    &event.previous_hash[..8],
                ));
            }

            // Recompute the chain hash: SHA-256(previous_hash || payload).
            match compute_chain_hash(&running_hash, &event) {
                Ok(h) => running_hash = h,
                Err(_) => {
                    return ChainRecoveryResult::Broken(format!(
                        "serialization failed at line {}",
                        line_num + 1,
                    ));
                }
            }
        }

        if running_hash == [0u8; 32] {
            // File existed but was empty — treat as fresh start.
            ChainRecoveryResult::NoFile
        } else {
            tracing::info!(
                "Audit chain recovery: restored and verified chain from {}",
                path.display(),
            );
            ChainRecoveryResult::Verified(running_hash)
        }
    }

    /// Rotate the log files: shift existing generations downward.
    /// `.4` is deleted, `.3` → `.4`, … `.1` → `.2`, current → `.1`.
    ///
    /// **Chain continuity:** The hash chain is NOT broken by rotation. New events
    /// written after rotation carry `previous_hash` from the last event in the
    /// rotated file (preserved in `AuditLogState::last_hash`). To verify the full
    /// chain across rotations, verify each generation file's internal chain and
    /// ensure the first event of generation N has `previous_hash` equal to the
    /// last chain hash of generation N+1.
    fn rotate_log_files(path: &Path) -> Result<(), crate::error::HsmError> {
        tracing::info!(
            "Audit log rotation: {} exceeds {} bytes, rotating.",
            path.display(),
            MAX_LOG_FILE_BYTES,
        );

        // Shift existing generations downward.
        for gen in (1..MAX_ROTATED_FILES).rev() {
            let from = rotated_path(path, gen);
            let to = rotated_path(path, gen + 1);
            if from.exists() {
                if let Err(e) = std::fs::rename(&from, &to) {
                    tracing::error!(
                        "Audit log rotation: failed to rename {} -> {}: {}",
                        from.display(),
                        to.display(),
                        e,
                    );
                    return Err(crate::error::HsmError::GeneralError);
                }
            }
        }

        // Move current file to generation 1.
        let gen1 = rotated_path(path, 1);
        std::fs::rename(path, &gen1).map_err(|e| {
            tracing::error!("Audit log rotation: rename failed: {}", e);
            crate::error::HsmError::GeneralError
        })?;

        Ok(())
    }

    /// Record an audit event asynchronously by sending it to the background
    /// worker thread. The expensive work (hash chain computation, JSON
    /// serialization, file I/O with fsync) happens off the caller's hot path.
    ///
    /// Returns `Err(AuditChainBroken)` if tamper has been detected — the
    /// HSM must not continue normal operations with a compromised audit trail.
    pub fn record(
        &self,
        session_handle: u64,
        operation: AuditOperation,
        result: AuditResult,
        key_id: Option<String>,
    ) -> crate::error::HsmResult<()> {
        // Fast-path rejection via atomic flag — no lock needed.
        if self.tamper_flag.load(Ordering::Acquire) {
            return Err(crate::error::HsmError::AuditChainBroken(
                "refusing to record: audit chain tamper previously detected".to_string(),
            ));
        }

        // Sanitize key_id to prevent log injection via control characters
        let key_id = key_id.map(|s| sanitize_audit_field(&s));

        if let Some(sender) = &self.sender {
            sender
                .send(AuditCommand::Record {
                    session_handle,
                    operation,
                    result,
                    key_id,
                })
                .map_err(|_| crate::error::HsmError::GeneralError)?;
        }

        Ok(())
    }

    /// Flush all pending audit events synchronously. Blocks until the
    /// background worker has processed every queued command, or until
    /// a 5-second timeout expires.
    pub fn flush(&self) {
        if let Some(sender) = &self.sender {
            let (tx, rx) = std::sync::mpsc::channel();
            let _ = sender.send(AuditCommand::Flush { done: tx });
            let _ = rx.recv_timeout(std::time::Duration::from_secs(5));
        }
    }

    /// # Security
    ///
    /// Callers must verify that the requesting session has Security Officer (SO)
    /// privileges before exposing audit data. This method does not enforce
    /// authorization internally.
    pub fn entry_count(&self) -> usize {
        self.state.read().entries.len()
    }

    /// Get a clone of all audit entries (for export/inspection).
    ///
    /// # Security
    ///
    /// Callers must verify SO authorization. Prefer `get_entries_paginated()`
    /// for large logs to avoid cloning up to 100K entries at once.
    pub fn get_entries(&self) -> Vec<AuditEvent> {
        self.state.read().entries.clone()
    }

    /// Get a clone of the most recent `n` entries.
    ///
    /// # Security
    ///
    /// Callers must verify SO authorization before exposing audit data.
    pub fn get_recent_entries(&self, n: usize) -> Vec<AuditEvent> {
        let state = self.state.read();
        let start = state.entries.len().saturating_sub(n);
        state.entries[start..].to_vec()
    }

    /// Get a paginated window of entries. Returns entries in the range
    /// `[offset .. offset + limit]`, clamped to the available entries.
    /// Useful for UI or API consumers that cannot afford cloning 100K events.
    ///
    /// # Security
    ///
    /// Callers must verify SO authorization before exposing audit data.
    pub fn get_entries_paginated(&self, offset: usize, limit: usize) -> Vec<AuditEvent> {
        let state = self.state.read();
        let end = (offset + limit).min(state.entries.len());
        if offset >= state.entries.len() {
            return Vec::new();
        }
        state.entries[offset..end].to_vec()
    }

    /// Export all entries as a JSON array string.
    /// Snapshots entries under a read lock, then serializes after releasing it
    /// to avoid blocking `record()` during potentially slow serialization.
    ///
    /// # Security
    ///
    /// Callers must verify SO authorization before exposing audit data.
    pub fn export_json(&self) -> String {
        let entries = self.state.read().entries.clone();
        serde_json::to_string_pretty(&entries).unwrap_or_else(|_| "[]".to_string())
    }

    /// Export all entries as newline-delimited JSON (NDJSON/JSON Lines).
    /// Each line is a single JSON object — ideal for log aggregators and SIEM ingestion.
    /// Snapshots entries under a read lock, then serializes after releasing it.
    ///
    /// # Security
    ///
    /// Callers must verify SO authorization before exposing audit data.
    pub fn export_ndjson(&self) -> String {
        let entries = self.state.read().entries.clone();
        entries
            .iter()
            .map(|e| {
                serde_json::to_string(e).unwrap_or_else(|err| {
                    tracing::error!(
                        "Audit export: failed to serialize event (session={}, ts={}): {}",
                        e.session_handle,
                        e.timestamp,
                        err,
                    );
                    // Produce a placeholder so line count is preserved and the
                    // consumer can detect the gap.
                    format!(
                        "{{\"error\":\"serialization_failed\",\"session_handle\":{},\"timestamp\":{}}}",
                        e.session_handle, e.timestamp
                    )
                })
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Export entries in syslog RFC 5424 format with structured data.
    /// Format: `<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG`
    /// Suitable for forwarding to syslog daemons or SIEM systems.
    /// Snapshots entries under a read lock, then formats after releasing it.
    ///
    /// # Security
    ///
    /// Callers must verify SO authorization before exposing audit data.
    pub fn export_syslog(&self) -> Vec<String> {
        let entries = self.state.read().entries.clone();
        entries
            .iter()
            .map(|e| {
                let severity = match &e.result {
                    AuditResult::Success => 6,    // informational
                    AuditResult::Failure(_) => 4, // warning
                };
                let facility = 10; // security/authorization (authpriv)
                let priority = facility * 8 + severity;
                let timestamp = format_rfc3339(e.timestamp);
                let op_name = format_operation_name(&e.operation);
                let result_str = match &e.result {
                    AuditResult::Success => "SUCCESS".to_string(),
                    AuditResult::Failure(rv) => format!("FAILURE(0x{:08X})", rv),
                };
                let key_str = e.key_id.as_deref().unwrap_or("-");

                // RFC 5424 structured data for machine-parseable SIEM ingestion.
                // Values are escaped per RFC 5424 §6.3.3: `"`, `\`, and `]` must
                // be preceded by `\` inside SD param-values.
                let sd = format!(
                    "[hsm@0 session=\"{}\" op=\"{}\" result=\"{}\" key=\"{}\"]",
                    e.session_handle,
                    escape_sd_value(op_name),
                    escape_sd_value(&result_str),
                    escape_sd_value(key_str),
                );

                // (#7-fix) Sanitize msg field values to prevent syslog parser
                // confusion from special characters (e.g., `<` `>` that could
                // be misinterpreted as PRI markers by some syslog implementations).
                let msg = format!(
                    "session={} op={} result={} key={}",
                    e.session_handle,
                    sanitize_syslog_msg_value(op_name),
                    sanitize_syslog_msg_value(&result_str),
                    sanitize_syslog_msg_value(key_str),
                );
                // RFC 5424 PROCID field: use "-" (nil value) instead of the real
                // process ID to avoid leaking container/process topology details
                // in multi-tenant environments.
                format!(
                    "<{}>1 {} craton_hsm craton_hsm - - {} {}",
                    priority, timestamp, sd, msg
                )
            })
            .collect()
    }

    /// Verify the integrity of the in-memory audit log chain.
    /// Returns `Ok(count)` if the chain is valid,
    /// `Err(index)` with the index of the first broken link.
    pub fn verify_chain(&self) -> Result<usize, usize> {
        let state = self.state.read();
        let mut expected_hash = [0u8; 32];
        for (i, entry) in state.entries.iter().enumerate() {
            if entry.previous_hash != expected_hash {
                return Err(i);
            }
            match compute_chain_hash(&expected_hash, entry) {
                Ok(h) => expected_hash = h,
                Err(_) => return Err(i),
            }
        }
        Ok(state.entries.len())
    }

    /// Register this `AuditLog` instance as the global logger for the crate.
    /// Used by `record_zeroization()` and other free functions.
    pub fn register_global_logger(self: &Arc<Self>) {
        *GLOBAL_AUDIT_LOG.write() = Some(Arc::downgrade(self));
    }
}

impl Drop for AuditLog {
    fn drop(&mut self) {
        // Drop sender to signal the worker to exit.
        self.sender.take();
        // Wait for worker to drain remaining events and exit.
        if let Some(handle) = self.worker.take() {
            let _ = handle.join();
        }
    }
}

/// Build a rotated file path: `path.1`, `path.2`, etc.
fn rotated_path(base: &Path, generation: u32) -> PathBuf {
    let mut name = base.as_os_str().to_os_string();
    name.push(format!(".{}", generation));
    PathBuf::from(name)
}

/// Format a nanosecond UNIX timestamp as RFC 3339 (used in syslog).
fn format_rfc3339(nanos: u64) -> String {
    let secs = nanos / 1_000_000_000;
    let subsec = nanos % 1_000_000_000;
    // Simple UTC timestamp without pulling in chrono
    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Approximate date from days since epoch (good enough for audit logs)
    let (year, month, day) = days_to_ymd(days_since_epoch);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}Z",
        year,
        month,
        day,
        hours,
        minutes,
        seconds,
        subsec / 1000
    )
}

/// Convert days since UNIX epoch to (year, month, day).
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Sanitize a string field for audit records: strip control characters and limit length.
/// Prevents log injection attacks where a malicious key_id could contain newlines
/// or other control characters to forge audit log entries.
fn sanitize_audit_field(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(256).collect()
}

/// Escape a value for inclusion in RFC 5424 structured data.
/// Per RFC 5424 §6.3.3, the characters `"`, `\`, and `]` MUST be escaped
/// with a preceding `\` inside SD parameter values.
fn escape_sd_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' | '\\' | ']' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

/// Sanitize a value for the human-readable MSG portion of syslog output.
/// Strips characters that could confuse syslog parsers: `<` and `>` (PRI
/// marker delimiters), control characters, and newlines.
fn sanitize_syslog_msg_value(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() && *c != '<' && *c != '>')
        .collect()
}

/// Format an AuditOperation into a short name for syslog messages.
fn format_operation_name(op: &AuditOperation) -> &'static str {
    match op {
        AuditOperation::Initialize => "Initialize",
        AuditOperation::Finalize => "Finalize",
        AuditOperation::OpenSession { .. } => "OpenSession",
        AuditOperation::CloseSession => "CloseSession",
        AuditOperation::Login { .. } => "Login",
        AuditOperation::Logout => "Logout",
        AuditOperation::InitToken { .. } => "InitToken",
        AuditOperation::GenerateKey { .. } => "GenerateKey",
        AuditOperation::GenerateKeyPair { .. } => "GenerateKeyPair",
        AuditOperation::Sign { .. } => "Sign",
        AuditOperation::Verify { .. } => "Verify",
        AuditOperation::Encrypt { .. } => "Encrypt",
        AuditOperation::Decrypt { .. } => "Decrypt",
        AuditOperation::Digest { .. } => "Digest",
        AuditOperation::CreateObject => "CreateObject",
        AuditOperation::DestroyObject => "DestroyObject",
        AuditOperation::GenerateRandom { .. } => "GenerateRandom",
        AuditOperation::WrapKey { .. } => "WrapKey",
        AuditOperation::UnwrapKey { .. } => "UnwrapKey",
        AuditOperation::DeriveKey { .. } => "DeriveKey",
        AuditOperation::FindObjects { .. } => "FindObjects",
        AuditOperation::GetAttributeValue => "GetAttributeValue",
        AuditOperation::Zeroize { .. } => "Zeroize",
    }
}

/// Free function to record a zeroization event to the global audit log.
/// Used by `RawKeyMaterial::drop()` to satisfy FIPS 140-3 requirements.
pub fn record_zeroization(key_size: usize) {
    if let Some(weak) = &*GLOBAL_AUDIT_LOG.read() {
        if let Some(logger) = weak.upgrade() {
            let _ = logger.record(
                0, // System-level event (no session)
                AuditOperation::Zeroize {
                    key_length: key_size as u32,
                },
                AuditResult::Success,
                None,
            );
        }
    }
}
