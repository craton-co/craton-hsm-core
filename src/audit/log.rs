// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//
// SECURITY WORK-IN-PROGRESS: security/hmac-audit-chain
// ----------------------------------------------------
// This branch begins the migration from the plain SHA-256 audit chain
// (integrity-only, trivially rebuildable by anyone with disk write) to an
// HMAC-SHA-256 chain keyed off an HKDF-derived subkey of the per-instance
// HsmCore::state_hmac_key.
//
// LANDED in this commit:
//   * `AUDIT_LOG_FORMAT_VERSION`, `AUDIT_CHAIN_HKDF_INFO`,
//     `AUDIT_CHAIN_INIT_LABEL` constants.
//   * `derive_audit_chain_key()` -- HKDF(state_hmac_key, "audit-chain")
//     producing a zeroizing 32-byte subkey.
//   * `initial_chain_hash()` -- HMAC(audit_key, "audit-chain-init") for H_0.
//   * `AuditEvent.format_version` field (serde-default 0 for legacy).
//   * `AuditEventPayload.format_version` so downgrade flips the MAC.
//   * `AuditLog.audit_chain_key` field (zero placeholder, see TODOs).
//
// STILL TO DO before this branch is production-ready:
//   1. Thread `state_hmac_key` (or an HKDF-derived subkey) through
//      `AuditLog::new()` / `new_with_path()`. Replace the zero-placeholder
//      `audit_chain_key` assignments marked TODO(security/hmac-audit-chain).
//   2. Rewrite `compute_chain_hash()` to use HMAC keyed by
//      `audit_chain_key` instead of plain `Sha256`. Use `initial_chain_hash`
//      for the H_0 case.
//   3. Bump `AUDIT_LOG_FORMAT_VERSION` to 2 (version 1 is now taken by the
//      canonical binary payload encoding -- see `encode_payload_v1`). The
//      HMAC should be computed over those same canonical bytes, not over
//      JSON: `encode_payload_v1` is already injective and allocation-free,
//      which is exactly what a MAC input wants.
//   4. Update `verify_chain` / recovery to use HMAC for v2 records. Note
//      that `compute_chain_hash_with` already dispatches on each record's
//      own `format_version`, so adding a v2 arm is additive and does not
//      break verification of existing v0/v1 files.
//   5. Update `HsmCore::try_new[_with_backend]` to pass the derived key
//      to the new `AuditLog::new` signature.
//   6. Add tests: valid chain, tampered record, wrong-key verification,
//      legacy-file rejection.
//
// Until those steps land the audit chain still uses plain SHA-256 and the
// new fields are inert. The branch compiles and is safe to merge as a
// stepping stone, but does NOT yet close the original vulnerability.
//
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::BufRead;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// On-disk record format version. Bumped whenever the on-disk schema or the
/// chain construction changes in an incompatible way. Files lacking this field
/// deserialize as `0` and are still verifiable under the legacy rules, so an
/// audit trail written by an older build keeps verifying after an upgrade.
///
/// - `0`: legacy chain — `SHA-256(previous_hash || serde_json(payload))`.
///   Accepted for verification of pre-existing logs; never written.
/// - `1`: current chain — `SHA-256(previous_hash || canonical(payload))`,
///   where `canonical` is the fixed-width binary encoding implemented by
///   [`encode_payload_v1`]. The JSON payload encoding it replaces cost
///   ~2.2 us per event to produce and inflated the hashed input from
///   ~40 to ~148 bytes; the binary encoding roughly halves the audit
///   worker's per-event CPU.
/// - `2`: RESERVED for the in-flight HMAC-SHA-256 chain migration (see the
///   module-level `security/hmac-audit-chain` notes). That migration
///   should MAC over the same [`encode_payload_v1`] canonical bytes
///   rather than over JSON.
///
/// Records are always written at [`AUDIT_LOG_FORMAT_VERSION`]; the verifier
/// dispatches on each record's own `format_version` so mixed-version files
/// (an upgrade appending to an existing log) verify end to end.
pub const AUDIT_LOG_FORMAT_VERSION: u32 = 1;

/// HKDF "info" string used to derive the audit chain subkey from
/// `state_hmac_key`. Domain-separates audit-chain from operation-state HMAC.
const AUDIT_CHAIN_HKDF_INFO: &[u8] = b"audit-chain";

/// Constant fed to HMAC for the initial chain value
/// `H_0 = HMAC(audit_key, "audit-chain-init")`.
const AUDIT_CHAIN_INIT_LABEL: &[u8] = b"audit-chain-init";

/// Derive the audit-chain HMAC subkey from the per-instance `state_hmac_key`
/// using HKDF-SHA-256 with empty salt and a fixed `info` string.
///
/// The derived key is disjoint from `state_hmac_key` so that compromise or
/// misuse of one HMAC domain (audit chain vs. C_GetOperationState blobs) does
/// not affect the other. Returns a `Zeroizing` wrapper so the secret is
/// scrubbed on drop.
pub fn derive_audit_chain_key(state_hmac_key: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, state_hmac_key);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(AUDIT_CHAIN_HKDF_INFO, &mut *okm)
        .expect("HKDF-SHA256 expand(32 bytes) cannot fail");
    okm
}

/// Compute the initial chain value
/// `H_0 = HMAC(audit_key, "audit-chain-init")`.
fn initial_chain_hash(audit_key: &[u8; 32]) -> [u8; 32] {
    let mut mac =
        HmacSha256::new_from_slice(audit_key).expect("HMAC-SHA256 accepts any key length");
    mac.update(AUDIT_CHAIN_INIT_LABEL);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag);
    out
}

/// Every security-relevant operation emits an audit event.
/// The audit log is append-only and tamper-evident: each event is chained to
/// the previous via an HMAC-SHA-256 link keyed off a per-instance subkey
/// derived from `state_hmac_key` via HKDF-SHA-256.
///
/// Chain:
/// ```text
/// H_0     = HMAC(audit_key, "audit-chain-init")
/// H_{n+1} = HMAC(audit_key, H_n || serialize(payload_n))
/// ```
/// where `payload_n` is the event data *excluding* `previous_hash`,
/// avoiding circularity in the MAC computation.
///
/// Without `audit_key` an attacker with disk write access cannot forge a
/// replacement chain — the previous integrity-only SHA-256 chain was trivially
/// reconstructible.

#[derive(Debug, Clone)]
pub struct AuditEvent {
    /// Chain construction used for this record. See
    /// [`AUDIT_LOG_FORMAT_VERSION`]. Records read back from a legacy file
    /// carry `0` and are verified under the legacy JSON rules.
    pub format_version: u32,
    pub timestamp: u64,
    pub session_handle: u64,
    pub operation: AuditOperation,
    pub key_id: Option<String>,
    pub result: AuditResult,
    pub previous_hash: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct AuditEventDisk {
    #[serde(default)]
    format_version: u32,
    timestamp: u64,
    session_handle: u64,
    operation: AuditOperation,
    key_id: Option<String>,
    result: AuditResult,
    previous_hash: [u8; 32],
}

impl Serialize for AuditEvent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("AuditEvent", 7)?;
        state.serialize_field("format_version", &self.format_version)?;
        state.serialize_field("timestamp", &self.timestamp)?;
        state.serialize_field("session_handle", &self.session_handle)?;
        state.serialize_field("operation", &self.operation)?;
        state.serialize_field("key_id", &self.key_id)?;
        state.serialize_field("result", &self.result)?;
        state.serialize_field("previous_hash", &self.previous_hash)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for AuditEvent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let disk = AuditEventDisk::deserialize(deserializer)?;
        Ok(AuditEvent {
            format_version: disk.format_version,
            timestamp: disk.timestamp,
            session_handle: disk.session_handle,
            operation: disk.operation,
            key_id: disk.key_id,
            result: disk.result,
            previous_hash: disk.previous_hash,
        })
    }
}

/// The MAC'd payload of an audit event — excludes `previous_hash` so that the
/// chain link is non-circular. `format_version` IS included so that downgrade
/// attacks (rewriting a v1 event as v0) flip the MAC.
#[derive(Serialize)]
struct AuditEventPayload<'a> {
    format_version: u32,
    timestamp: u64,
    session_handle: u64,
    operation: &'a AuditOperation,
    key_id: &'a Option<String>,
    result: &'a AuditResult,
}

impl AuditEvent {
    fn payload(&self) -> AuditEventPayload<'_> {
        AuditEventPayload {
            format_version: self.format_version,
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
    InitPIN {
        slot_id: u64,
    },
    SetPIN,
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
        /// Optional completion channel. When `Some`, the worker sends the
        /// I/O / chain result *after* the event has been written and fsynced
        /// to disk (or after a non-disk record is committed to in-memory
        /// state). Used by `record_sync()` to provide durable-write
        /// guarantees to sensitive callers.
        done: Option<std::sync::mpsc::SyncSender<Result<(), crate::error::HsmError>>>,
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
    /// HKDF-derived subkey used to key the HMAC-SHA-256 chain. Distinct from
    /// `HsmCore::state_hmac_key`. Kept here (rather than passed per-call) so
    /// that `verify_chain()` and the background worker share a single source
    /// of truth. Zeroized on drop.
    audit_chain_key: Arc<Zeroizing<[u8; 32]>>,
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

/// Canonical binary encoding of an audit event payload (format version 1).
///
/// This replaces `serde_json` as the input to the chain hash. JSON was never a
/// requirement of the chain — only of the on-disk NDJSON line, which is an
/// interop contract with SIEM consumers and is deliberately left unchanged —
/// but it cost ~2.2 us per event to produce and inflated the hashed input from
/// ~40 bytes to ~148, roughly doubling the SHA-256 work on top.
///
/// # Canonicalisation
///
/// The encoding must be *injective*: two distinct payloads must never produce
/// the same bytes, or an attacker could swap one event for another without
/// breaking the chain. Injectivity here comes from three properties:
///
/// * every integer is written little-endian at a fixed width, so field
///   boundaries are unambiguous without separators;
/// * every variable-length field (`key_id`) is length-prefixed with a `u32`
///   before its bytes, so `("ab", "c")` cannot collide with `("a", "bc")`;
/// * every enum is written as a fixed one-byte tag followed by that variant's
///   fixed-width fields, so no two variants share an encoding.
///
/// `format_version` is the first field, which domain-separates this encoding
/// from any future one and makes a downgrade rewrite (re-labelling a v1 record
/// as v0) change the hash.
///
/// # Stability
///
/// The tag values below are part of the on-disk format. They must never be
/// renumbered or reused; new operations append new tags. Renumbering would
/// silently invalidate every existing audit chain.
fn encode_payload_v1(event: &AuditEvent, out: &mut Vec<u8>) {
    out.extend_from_slice(&event.format_version.to_le_bytes());
    out.extend_from_slice(&event.timestamp.to_le_bytes());
    out.extend_from_slice(&event.session_handle.to_le_bytes());

    encode_operation_v1(&event.operation, out);

    match &event.key_id {
        None => out.push(0),
        Some(id) => {
            out.push(1);
            // `sanitize_audit_field` caps key_id at 256 chars, so the cast is
            // lossless; saturate rather than wrap if that ever changes.
            let bytes = id.as_bytes();
            let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&bytes[..len as usize]);
        }
    }

    match &event.result {
        AuditResult::Success => out.push(0),
        AuditResult::Failure(rv) => {
            out.push(1);
            out.extend_from_slice(&rv.to_le_bytes());
        }
    }
}

/// Encode an [`AuditOperation`] as a stable one-byte tag plus fixed-width
/// fields. See [`encode_payload_v1`] for the stability contract on these tags.
fn encode_operation_v1(op: &AuditOperation, out: &mut Vec<u8>) {
    /// Write the `fips_approved` flag shared by the mechanism-bearing variants.
    fn mech(out: &mut Vec<u8>, tag: u8, mechanism: u64, fips_approved: bool) {
        out.push(tag);
        out.extend_from_slice(&mechanism.to_le_bytes());
        out.push(u8::from(fips_approved));
    }

    match op {
        AuditOperation::Initialize => out.push(1),
        AuditOperation::Finalize => out.push(2),
        AuditOperation::OpenSession { slot_id } => {
            out.push(3);
            out.extend_from_slice(&slot_id.to_le_bytes());
        }
        AuditOperation::CloseSession => out.push(4),
        AuditOperation::Login { user_type } => {
            out.push(5);
            out.extend_from_slice(&user_type.to_le_bytes());
        }
        AuditOperation::Logout => out.push(6),
        AuditOperation::InitToken { slot_id } => {
            out.push(7);
            out.extend_from_slice(&slot_id.to_le_bytes());
        }
        AuditOperation::InitPIN { slot_id } => {
            out.push(8);
            out.extend_from_slice(&slot_id.to_le_bytes());
        }
        AuditOperation::SetPIN => out.push(9),
        AuditOperation::GenerateKey {
            mechanism,
            key_length,
            fips_approved,
        } => {
            out.push(10);
            out.extend_from_slice(&mechanism.to_le_bytes());
            out.extend_from_slice(&key_length.to_le_bytes());
            out.push(u8::from(*fips_approved));
        }
        AuditOperation::GenerateKeyPair {
            mechanism,
            key_length,
            fips_approved,
        } => {
            out.push(11);
            out.extend_from_slice(&mechanism.to_le_bytes());
            out.extend_from_slice(&key_length.to_le_bytes());
            out.push(u8::from(*fips_approved));
        }
        AuditOperation::Sign {
            mechanism,
            fips_approved,
        } => mech(out, 12, *mechanism, *fips_approved),
        AuditOperation::Verify {
            mechanism,
            fips_approved,
        } => mech(out, 13, *mechanism, *fips_approved),
        AuditOperation::Encrypt {
            mechanism,
            fips_approved,
        } => mech(out, 14, *mechanism, *fips_approved),
        AuditOperation::Decrypt {
            mechanism,
            fips_approved,
        } => mech(out, 15, *mechanism, *fips_approved),
        AuditOperation::Digest {
            mechanism,
            fips_approved,
        } => mech(out, 16, *mechanism, *fips_approved),
        AuditOperation::CreateObject => out.push(17),
        AuditOperation::DestroyObject => out.push(18),
        AuditOperation::GenerateRandom { length } => {
            out.push(19);
            out.extend_from_slice(&length.to_le_bytes());
        }
        AuditOperation::WrapKey {
            mechanism,
            fips_approved,
        } => mech(out, 20, *mechanism, *fips_approved),
        AuditOperation::UnwrapKey {
            mechanism,
            fips_approved,
        } => mech(out, 21, *mechanism, *fips_approved),
        AuditOperation::DeriveKey {
            mechanism,
            fips_approved,
        } => mech(out, 22, *mechanism, *fips_approved),
        AuditOperation::FindObjects { result_count } => {
            out.push(23);
            out.extend_from_slice(&result_count.to_le_bytes());
        }
        AuditOperation::GetAttributeValue => out.push(24),
        AuditOperation::Zeroize { key_length } => {
            out.push(25);
            out.extend_from_slice(&key_length.to_le_bytes());
        }
    }
}

/// Compute the chain hash for an event:
/// `SHA-256(previous_hash || encode(payload))`
///
/// The payload excludes `previous_hash` to avoid circularity. `encode` is
/// selected by the event's own `format_version` so that a file containing both
/// legacy (`0`, JSON) and current (`1`, canonical binary) records — which is
/// exactly what an in-place upgrade produces — verifies end to end.
///
/// `scratch` is a caller-owned buffer reused across events; it is cleared on
/// entry. [`compute_chain_hash`] wraps this for callers that do not have one.
fn compute_chain_hash_with(
    previous_hash: &[u8; 32],
    event: &AuditEvent,
    scratch: &mut Vec<u8>,
) -> Result<[u8; 32], crate::error::HsmError> {
    scratch.clear();
    match event.format_version {
        // Legacy: the payload was hashed in its `serde_json` encoding.
        0 => {
            serde_json::to_writer(&mut *scratch, &event.payload()).map_err(|e| {
                tracing::error!("Audit event payload serialization failed: {}", e);
                crate::error::HsmError::GeneralError
            })?;
        }
        1 => encode_payload_v1(event, scratch),
        other => {
            tracing::error!(
                "Audit event carries unsupported format_version {} (this build \
                 writes {} and verifies 0..={})",
                other,
                AUDIT_LOG_FORMAT_VERSION,
                AUDIT_LOG_FORMAT_VERSION,
            );
            return Err(crate::error::HsmError::AuditChainBroken(format!(
                "unsupported audit record format_version {}",
                other
            )));
        }
    }

    let mut hasher = Sha256::new();
    hasher.update(previous_hash);
    hasher.update(&*scratch);
    let hash = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);
    Ok(result)
}

/// Allocating convenience wrapper around [`compute_chain_hash_with`] for
/// callers outside the audit worker's hot path.
fn compute_chain_hash(
    previous_hash: &[u8; 32],
    event: &AuditEvent,
) -> Result<[u8; 32], crate::error::HsmError> {
    let mut scratch = Vec::with_capacity(64);
    compute_chain_hash_with(previous_hash, event, &mut scratch)
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

/// Completion channel for a `record_sync` caller waiting on a batched event.
type DoneTx = std::sync::mpsc::SyncSender<Result<(), crate::error::HsmError>>;

/// Background audit worker state.
///
/// Owns the open log file handle and the reusable staging buffers so that the
/// steady-state cost of an audit event is a chain-hash computation, an append
/// into an existing `String`, and a share of one batched `write` + `fsync` —
/// with no per-event `open()`, allocation, or syscall beyond that.
struct AuditWorker {
    state: Arc<RwLock<AuditLogState>>,
    log_path: Option<PathBuf>,
    tamper_flag: Arc<AtomicBool>,
    /// Worker-local chain head. Advanced only once a batch is durable, so a
    /// failed write never leaves the worker chaining from a hash that was
    /// never persisted.
    last_hash: [u8; 32],
    last_timestamp: u64,
    /// Log file, opened once and reused across events. `None` until the first
    /// write, and after a rotation or an I/O error forces a reopen.
    file: Option<std::fs::File>,
    /// Cached size of `file`, maintained incrementally so the rotation check
    /// does not need a `metadata()` syscall per event.
    file_size: u64,
    /// Reusable NDJSON staging buffer for the current batch.
    line_buf: Vec<u8>,
    /// Reusable canonical-payload buffer for chain-hash computation, so the
    /// steady-state event path performs no allocation.
    hash_buf: Vec<u8>,
    /// Events accumulated in the current batch, pending durability.
    batch: Vec<AuditEvent>,
    /// Chain hash of the last event staged in the current batch.
    batch_head: [u8; 32],
    /// `record_sync` waiters for the current batch.
    waiters: Vec<DoneTx>,
}

impl AuditWorker {
    fn run(&mut self, receiver: &std::sync::mpsc::Receiver<AuditCommand>) {
        loop {
            // Block for the first command of a batch.
            let first = match receiver.recv() {
                Ok(cmd) => cmd,
                // Channel closed — sender dropped. Exit the worker.
                Err(_) => break,
            };

            let mut flush_acks: Vec<std::sync::mpsc::Sender<()>> = Vec::new();
            self.stage(first, &mut flush_acks);

            // Opportunistically coalesce everything already queued behind it.
            while self.batch.len() < AuditLog::MAX_BATCH {
                match receiver.try_recv() {
                    Ok(cmd) => self.stage(cmd, &mut flush_acks),
                    Err(_) => break,
                }
            }

            self.commit_batch();

            // Flush acknowledgements are sent after the batch is durable so
            // that `flush()` still means "everything queued before me is on
            // stable storage".
            for ack in flush_acks {
                let _ = ack.send(());
            }
        }
    }

    /// Add one command to the pending batch.
    ///
    /// `Record` commands are chained and serialized here; `Flush` commands are
    /// recorded as acknowledgements to send once the batch is durable.
    fn stage(&mut self, cmd: AuditCommand, flush_acks: &mut Vec<std::sync::mpsc::Sender<()>>) {
        match cmd {
            AuditCommand::Record {
                session_handle,
                operation,
                result,
                key_id,
                done,
            } => match self.chain_event(session_handle, operation, result, key_id) {
                Ok(()) => {
                    if let Some(tx) = done {
                        self.waiters.push(tx);
                    }
                }
                Err(e) => {
                    // Chaining failed before any I/O — reject just this event;
                    // the rest of the batch is unaffected.
                    if let Some(tx) = done {
                        let _ = tx.send(Err(e));
                    }
                }
            },
            AuditCommand::Flush { done } => flush_acks.push(done),
        }
    }

    /// Assign a monotonic timestamp, compute the chain link, and append the
    /// event's NDJSON line to the staging buffer.
    ///
    /// `self.last_hash` is **not** advanced here: the durable chain head is
    /// only moved forward by `commit_batch` once the bytes are on disk.
    fn chain_event(
        &mut self,
        session_handle: u64,
        operation: AuditOperation,
        result: AuditResult,
        key_id: Option<String>,
    ) -> Result<(), crate::error::HsmError> {
        if self.tamper_flag.load(Ordering::Acquire) {
            return Err(crate::error::HsmError::AuditChainBroken(
                "audit chain tamper previously detected".to_string(),
            ));
        }

        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let wall_timestamp = u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);

        // Enforce monotonicity across the whole batch, not just across
        // committed events, so two events staged within the same nanosecond
        // still receive strictly increasing timestamps.
        let timestamp = if wall_timestamp <= self.last_timestamp {
            match self.last_timestamp.checked_add(1) {
                Some(next) => next,
                None => {
                    tracing::error!(
                        "Audit timestamp space exhausted (u64::MAX reached). \
                         Cannot guarantee monotonicity."
                    );
                    self.tamper_flag.store(true, Ordering::Release);
                    return Err(crate::error::HsmError::AuditChainBroken(
                        "timestamp space exhausted".to_string(),
                    ));
                }
            }
        } else {
            wall_timestamp
        };

        // Chain onto the last event staged in this batch, falling back to the
        // durable chain head for the first event of the batch.
        let previous_hash = if self.batch.is_empty() {
            self.last_hash
        } else {
            self.batch_head
        };

        let event = AuditEvent {
            format_version: AUDIT_LOG_FORMAT_VERSION,
            timestamp,
            session_handle,
            operation,
            key_id,
            result,
            previous_hash,
        };

        let new_head = compute_chain_hash_with(&previous_hash, &event, &mut self.hash_buf)?;

        // Serialize into the reusable buffer. A serialization failure must not
        // leave a partial line behind, so truncate back to the mark.
        if self.log_path.is_some() {
            let mark = self.line_buf.len();
            if let Err(e) = serde_json::to_writer(&mut self.line_buf, &event) {
                self.line_buf.truncate(mark);
                tracing::error!("Audit log serialization failed: {}", e);
                return Err(crate::error::HsmError::GeneralError);
            }
            self.line_buf.push(b'\n');
        }

        self.last_timestamp = timestamp;
        self.batch_head = new_head;
        self.batch.push(event);
        Ok(())
    }

    /// Write the staged batch with a single `write_all` + `sync_all`, then
    /// publish it to shared state and release every waiter.
    ///
    /// On I/O failure nothing is committed: the durable chain head stays where
    /// it was, the staged events are dropped, and every waiter receives the
    /// error — so the on-disk and in-memory chains cannot diverge.
    fn commit_batch(&mut self) {
        if self.batch.is_empty() {
            self.line_buf.clear();
            return;
        }

        if self.log_path.is_some() {
            if let Err(e) = self.write_staged() {
                tracing::error!("Audit worker: disk I/O failed: {}", e);
                // Force a reopen on the next batch — the handle may be in an
                // indeterminate state after a partial write.
                self.file = None;
                self.batch.clear();
                self.line_buf.clear();
                self.batch_head = self.last_hash;
                for tx in self.waiters.drain(..) {
                    let _ = tx.send(Err(e.clone()));
                }
                return;
            }
        }

        // The batch is durable: advance the chain head and publish.
        self.last_hash = self.batch_head;

        {
            let mut s = self.state.write();
            s.last_hash = self.last_hash;
            s.last_timestamp = self.last_timestamp;
            s.entries.append(&mut self.batch);

            // Cap in-memory entries to prevent unbounded growth.
            if s.entries.len() > MAX_IN_MEMORY_ENTRIES {
                let excess = s.entries.len() - MAX_IN_MEMORY_ENTRIES;
                s.entries.drain(..excess);
            }
        }

        self.batch.clear();
        self.line_buf.clear();
        for tx in self.waiters.drain(..) {
            let _ = tx.send(Ok(()));
        }
    }

    /// Append the staged buffer to the log file and `fsync` it, rotating first
    /// if the file has reached [`MAX_LOG_FILE_BYTES`].
    fn write_staged(&mut self) -> Result<(), crate::error::HsmError> {
        let path = match &self.log_path {
            Some(p) => p.clone(),
            None => return Ok(()),
        };

        if self.file.is_none() {
            let f = open_audit_file(&path)?;
            self.file_size = f.metadata().map(|m| m.len()).unwrap_or(0);
            self.file = Some(f);
        }

        if self.file_size >= MAX_LOG_FILE_BYTES {
            // Close before renaming — Windows refuses to rename an open file.
            self.file = None;
            AuditLog::rotate_log_files(&path)?;
            let f = open_audit_file(&path)?;
            self.file_size = f.metadata().map(|m| m.len()).unwrap_or(0);
            self.file = Some(f);
        }

        let file = self
            .file
            .as_mut()
            .expect("file handle is opened immediately above");
        let bytes = self.line_buf.as_slice();
        file.write_all(bytes).map_err(|e| {
            tracing::error!("Audit log write failed: {}", e);
            crate::error::HsmError::GeneralError
        })?;
        file.sync_all().map_err(|e| {
            tracing::error!("Audit log fsync failed: {}", e);
            crate::error::HsmError::GeneralError
        })?;
        self.file_size += bytes.len() as u64;
        Ok(())
    }
}

impl AuditLog {
    /// Maximum number of `Record` commands coalesced into a single
    /// write + `fsync` batch. Bounds the worst-case latency that a
    /// `record_sync` caller at the tail of a burst can observe, and bounds
    /// the size of the staging buffer.
    const MAX_BATCH: usize = 1024;

    /// Spawn the background worker thread that processes audit commands.
    /// The worker owns the receiver end of the channel and maintains local
    /// copies of `last_hash` and `last_timestamp` for lock-free event building.
    ///
    /// # Durability model
    ///
    /// The worker performs **group commit**: it blocks for one command, then
    /// drains up to [`AuditLog::MAX_BATCH`] further pending `Record` commands
    /// without blocking, serializes them all into one staging buffer, issues a
    /// single `write_all` + a single `sync_all`, and only then commits the
    /// batch to shared state and releases every `record_sync` waiter in it.
    ///
    /// This preserves the `record_sync` contract exactly — such a caller is
    /// still released only *after* its event is `fsync`-ed — while amortizing
    /// the `fsync` over every event that was already queued behind it. It is
    /// not a durability trade: no event is acknowledged before it is on
    /// stable storage.
    ///
    /// The log file handle is opened once and kept open for the lifetime of
    /// the worker (reopened only across rotation), rather than being opened
    /// per event. On Windows that also removes one ACL-hardening syscall per
    /// event.
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
                let mut worker = AuditWorker {
                    state,
                    log_path,
                    tamper_flag,
                    last_hash: initial_hash,
                    last_timestamp: initial_timestamp,
                    file: None,
                    file_size: 0,
                    line_buf: Vec::new(),
                    hash_buf: Vec::with_capacity(64),
                    batch: Vec::new(),
                    batch_head: initial_hash,
                    waiters: Vec::new(),
                };
                worker.run(&receiver);
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

        // TODO(security/hmac-audit-chain): wire the audit_chain_key through
        // from HsmCore::state_hmac_key so `compute_chain_hash` can switch to
        // HMAC-SHA-256. Today the constructor still uses a zero placeholder
        // and `compute_chain_hash` still emits plain SHA-256 -- the field
        // exists but is dead until that refactor lands. See module-level
        // doc comment for the full migration plan.
        Self {
            state,
            log_path: None,
            sender: Some(sender),
            tamper_flag,
            worker: Some(worker),
            audit_chain_key: Arc::new(Zeroizing::new([0u8; 32])),
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

        // TODO(security/hmac-audit-chain): see Self::new() -- the chain key
        // is still a zero placeholder pending the constructor-signature
        // change that threads HsmCore::state_hmac_key through here.
        Ok(Self {
            state,
            log_path: Some(path),
            sender: Some(sender),
            tamper_flag,
            worker: Some(worker),
            audit_chain_key: Arc::new(Zeroizing::new([0u8; 32])),
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
        let mut scratch = Vec::with_capacity(64);

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

            // Recompute the chain hash: SHA-256(previous_hash || payload),
            // using the encoding this record was written with.
            match compute_chain_hash_with(&running_hash, &event, &mut scratch) {
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
    /// **Durability:** This method returns `Ok(())` as soon as the event has
    /// been enqueued — it does **not** wait for the worker to write or fsync
    /// the event to disk. On `SIGKILL`, panic, or sudden power loss before the
    /// worker drains the queue, an enqueued event may be lost. For
    /// security-relevant operations (login, key destruction, init_token, …)
    /// use [`AuditLog::record_sync`] instead, which blocks until the event is
    /// durably on disk and propagates any write/fsync error.
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
        self.record_internal(session_handle, operation, result, key_id, None)
    }

    /// Record an audit event **synchronously**. Blocks until the background
    /// worker has chained the event, written its NDJSON line, and `fsync`-ed
    /// the audit log file. Propagates write / fsync / serialization failures
    /// as `Err(...)` to the caller so security-relevant call sites can refuse
    /// to proceed when the forensic trail is not durable.
    ///
    /// Use this for sensitive operations where treating `record()` as durable
    /// would be unsafe (login, init_token/init_pin/set_pin, destroy_object,
    /// generate_key/keypair, sign/verify/encrypt/decrypt, session lifecycle,
    /// finalize). Non-sensitive call sites (heartbeats, generate_random
    /// telemetry, …) may continue to use the cheaper [`AuditLog::record`].
    pub fn record_sync(
        &self,
        session_handle: u64,
        operation: AuditOperation,
        result: AuditResult,
        key_id: Option<String>,
    ) -> crate::error::HsmResult<()> {
        // One-shot completion channel (capacity 1 — the worker sends exactly
        // one result per Record command).
        let (tx, rx) = std::sync::mpsc::sync_channel::<Result<(), crate::error::HsmError>>(1);
        self.record_internal(session_handle, operation, result, key_id, Some(tx))?;

        // Wait for the worker to commit the event. We block indefinitely
        // here: an unresponsive audit worker should manifest as a stuck
        // sensitive operation (visible to operators) rather than a silent
        // loss of the forensic record. The caller's request timeout (gRPC
        // deadline, PKCS#11 caller, etc.) provides the upper bound.
        match rx.recv() {
            Ok(result) => result,
            Err(_) => {
                // Worker dropped the sender without responding — typically
                // means the worker thread panicked or exited.
                tracing::error!(
                    "Audit worker disconnected before acknowledging record_sync — \
                     event durability cannot be guaranteed."
                );
                Err(crate::error::HsmError::GeneralError)
            }
        }
    }

    /// Shared implementation for `record` and `record_sync`. Sanitizes the
    /// key_id, rejects on tamper, and dispatches the command to the worker.
    fn record_internal(
        &self,
        session_handle: u64,
        operation: AuditOperation,
        result: AuditResult,
        key_id: Option<String>,
        done: Option<std::sync::mpsc::SyncSender<Result<(), crate::error::HsmError>>>,
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
                    done,
                })
                .map_err(|_| crate::error::HsmError::GeneralError)?;
        }

        Ok(())
    }

    /// Flush all pending audit events synchronously. Blocks until the
    /// background worker has processed every queued command, or until
    /// a 5-second timeout expires.
    ///
    /// Returns `Err(GeneralError)` if the worker is unresponsive (timeout
    /// or disconnect) — previously this silently swallowed the timeout,
    /// hiding worker stalls. Callers that previously relied on
    /// fire-and-forget semantics should ignore the return value.
    pub fn flush(&self) -> crate::error::HsmResult<()> {
        if let Some(sender) = &self.sender {
            let (tx, rx) = std::sync::mpsc::channel();
            sender.send(AuditCommand::Flush { done: tx }).map_err(|_| {
                tracing::error!("Audit flush: worker channel closed");
                crate::error::HsmError::GeneralError
            })?;
            rx.recv_timeout(std::time::Duration::from_secs(5))
                .map_err(|e| {
                    tracing::error!(
                        "Audit flush: worker did not acknowledge within timeout: {}",
                        e
                    );
                    crate::error::HsmError::GeneralError
                })?;
        }
        Ok(())
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
        verify_chain_entries(&self.state.read().entries)
    }
}

/// Load the entire NDJSON audit log at `path` into a vector of [`AuditEvent`]s.
///
/// Each non-empty line is parsed as a single JSON-encoded `AuditEvent`. Blank
/// lines are skipped. This is the canonical loader for off-line consumers
/// (admin CLI, SIEM exporters, forensic tools) that need the on-disk events
/// without spinning up a full [`AuditLog`] instance.
///
/// Returns `Ok(entries)` on success — including an empty `Vec` if the file
/// exists but contains no events. Returns an `HsmError::AuditChainBroken`
/// variant carrying a human-readable reason on I/O or deserialization failure,
/// and propagates `NotFound` as `HsmError::GeneralError` so callers can match
/// on `std::io::ErrorKind` via [`std::fs::File::open`] if they want a more
/// specific message — most callers should check `path.exists()` first.
///
/// # Security
///
/// This function reads the audit log from disk verbatim. Callers must verify
/// that the requesting principal has Security Officer privileges before
/// exposing the returned events.
pub fn load_entries_from_file(path: &Path) -> Result<Vec<AuditEvent>, crate::error::HsmError> {
    let file = std::fs::File::open(path).map_err(|e| {
        tracing::error!("Audit log load: cannot open {}: {}", path.display(), e);
        crate::error::HsmError::AuditChainBroken(format!(
            "could not open log file {}: {}",
            path.display(),
            e,
        ))
    })?;

    let reader = std::io::BufReader::new(file);
    let mut entries = Vec::new();

    for (line_num, line_result) in reader.lines().enumerate() {
        let line = line_result.map_err(|e| {
            crate::error::HsmError::AuditChainBroken(format!(
                "I/O error at line {}: {}",
                line_num + 1,
                e,
            ))
        })?;

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let event: AuditEvent = serde_json::from_str(trimmed).map_err(|e| {
            crate::error::HsmError::AuditChainBroken(format!(
                "failed to deserialize line {}: {}",
                line_num + 1,
                e,
            ))
        })?;

        entries.push(event);
    }

    Ok(entries)
}

/// Verify the SHA-256 hash chain over a slice of [`AuditEvent`]s.
///
/// Returns `Ok(count)` if every event's `previous_hash` matches the running
/// chain and serialization succeeds, `Err(index)` with the zero-based index
/// of the first broken or unserializable link otherwise.
///
/// Used by both the in-memory [`AuditLog::verify_chain`] method and off-line
/// consumers that loaded entries via [`load_entries_from_file`].
pub fn verify_chain_entries(entries: &[AuditEvent]) -> Result<usize, usize> {
    let mut expected_hash = [0u8; 32];
    let mut scratch = Vec::with_capacity(64);
    for (i, entry) in entries.iter().enumerate() {
        if entry.previous_hash != expected_hash {
            return Err(i);
        }
        match compute_chain_hash_with(&expected_hash, entry, &mut scratch) {
            Ok(h) => expected_hash = h,
            Err(_) => return Err(i),
        }
    }
    Ok(entries.len())
}

impl AuditLog {
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
        AuditOperation::InitPIN { .. } => "InitPIN",
        AuditOperation::SetPIN => "SetPIN",
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

#[cfg(test)]
mod codec_tests {
    use super::*;

    /// Build an event that differs from the baseline only where a test varies it.
    fn event(operation: AuditOperation, key_id: Option<&str>, result: AuditResult) -> AuditEvent {
        AuditEvent {
            format_version: AUDIT_LOG_FORMAT_VERSION,
            timestamp: 1_700_000_000_000_000_000,
            session_handle: 7,
            operation,
            key_id: key_id.map(str::to_string),
            result,
            previous_hash: [0xAB; 32],
        }
    }

    fn encode(ev: &AuditEvent) -> Vec<u8> {
        let mut buf = Vec::new();
        encode_payload_v1(ev, &mut buf);
        buf
    }

    /// Every operation variant must encode to a distinct byte string.
    ///
    /// This is the core injectivity property: if two operations collided, an
    /// attacker with disk write access could substitute one audit record for
    /// another without breaking the chain.
    #[test]
    fn every_operation_variant_encodes_distinctly() {
        let variants = vec![
            AuditOperation::Initialize,
            AuditOperation::Finalize,
            AuditOperation::OpenSession { slot_id: 1 },
            AuditOperation::CloseSession,
            AuditOperation::Login { user_type: 1 },
            AuditOperation::Logout,
            AuditOperation::InitToken { slot_id: 1 },
            AuditOperation::InitPIN { slot_id: 1 },
            AuditOperation::SetPIN,
            AuditOperation::GenerateKey {
                mechanism: 1,
                key_length: 1,
                fips_approved: true,
            },
            AuditOperation::GenerateKeyPair {
                mechanism: 1,
                key_length: 1,
                fips_approved: true,
            },
            AuditOperation::Sign {
                mechanism: 1,
                fips_approved: true,
            },
            AuditOperation::Verify {
                mechanism: 1,
                fips_approved: true,
            },
            AuditOperation::Encrypt {
                mechanism: 1,
                fips_approved: true,
            },
            AuditOperation::Decrypt {
                mechanism: 1,
                fips_approved: true,
            },
            AuditOperation::Digest {
                mechanism: 1,
                fips_approved: true,
            },
            AuditOperation::CreateObject,
            AuditOperation::DestroyObject,
            AuditOperation::GenerateRandom { length: 1 },
            AuditOperation::WrapKey {
                mechanism: 1,
                fips_approved: true,
            },
            AuditOperation::UnwrapKey {
                mechanism: 1,
                fips_approved: true,
            },
            AuditOperation::DeriveKey {
                mechanism: 1,
                fips_approved: true,
            },
            AuditOperation::FindObjects { result_count: 1 },
            AuditOperation::GetAttributeValue,
            AuditOperation::Zeroize { key_length: 1 },
        ];

        // Guards against a new variant being added without a tag: if the match
        // in `encode_operation_v1` gains an arm, this list must gain an entry.
        assert_eq!(
            variants.len(),
            25,
            "add the new AuditOperation variant to this list and give it a tag",
        );

        let mut seen: std::collections::HashMap<Vec<u8>, usize> = std::collections::HashMap::new();
        for (i, op) in variants.into_iter().enumerate() {
            let bytes = encode(&event(op, None, AuditResult::Success));
            if let Some(prev) = seen.insert(bytes, i) {
                panic!("operation variants {} and {} encode identically", prev, i);
            }
        }
    }

    /// Fields inside an operation must reach the encoding.
    #[test]
    fn operation_fields_affect_the_encoding() {
        let a = encode(&event(
            AuditOperation::Sign {
                mechanism: 0x40,
                fips_approved: true,
            },
            None,
            AuditResult::Success,
        ));
        let mechanism_changed = encode(&event(
            AuditOperation::Sign {
                mechanism: 0x41,
                fips_approved: true,
            },
            None,
            AuditResult::Success,
        ));
        let flag_changed = encode(&event(
            AuditOperation::Sign {
                mechanism: 0x40,
                fips_approved: false,
            },
            None,
            AuditResult::Success,
        ));

        assert_ne!(a, mechanism_changed, "mechanism must be encoded");
        assert_ne!(a, flag_changed, "fips_approved must be encoded");
    }

    /// `key_id` is length-prefixed, so a split cannot be moved between it and
    /// the fields around it without changing the bytes.
    #[test]
    fn key_id_is_length_prefixed() {
        let short = encode(&event(
            AuditOperation::Logout,
            Some("ab"),
            AuditResult::Success,
        ));
        let long = encode(&event(
            AuditOperation::Logout,
            Some("abc"),
            AuditResult::Success,
        ));
        let none = encode(&event(AuditOperation::Logout, None, AuditResult::Success));

        assert_ne!(short, long, "key_id contents must be encoded");
        assert_ne!(short, none, "presence of key_id must be encoded");
        // The present/absent discriminator is a single byte before the length,
        // so an absent key_id is strictly shorter than any present one.
        assert!(none.len() < short.len());
    }

    /// Success and failure, and distinct failure codes, must not collide.
    #[test]
    fn result_variants_encode_distinctly() {
        let ok = encode(&event(AuditOperation::Logout, None, AuditResult::Success));
        let fail_a = encode(&event(
            AuditOperation::Logout,
            None,
            AuditResult::Failure(0x30),
        ));
        let fail_b = encode(&event(
            AuditOperation::Logout,
            None,
            AuditResult::Failure(0x31),
        ));

        assert_ne!(ok, fail_a, "success and failure must differ");
        assert_ne!(fail_a, fail_b, "the failure code must be encoded");
    }

    /// The header fields must all reach the encoding, including
    /// `format_version` — a downgrade rewrite must change the hash.
    #[test]
    fn header_fields_affect_the_encoding() {
        let base = event(AuditOperation::Logout, None, AuditResult::Success);
        let baseline = encode(&base);

        let mut other = base.clone();
        other.timestamp += 1;
        assert_ne!(baseline, encode(&other), "timestamp must be encoded");

        let mut other = base.clone();
        other.session_handle += 1;
        assert_ne!(baseline, encode(&other), "session_handle must be encoded");

        let mut other = base.clone();
        other.format_version = 0;
        assert_ne!(
            baseline,
            encode(&other),
            "format_version must be encoded so a downgrade rewrite is detected",
        );
    }

    /// The chain hash must dispatch on the record's own version, so the same
    /// event chained as v0 and as v1 produces different links. Otherwise the
    /// version field would be advisory rather than binding.
    #[test]
    fn chain_hash_dispatches_on_format_version() {
        let prev = [0u8; 32];
        let mut v1 = event(AuditOperation::Logout, None, AuditResult::Success);
        v1.format_version = 1;
        let mut v0 = v1.clone();
        v0.format_version = 0;

        let h1 = compute_chain_hash(&prev, &v1).expect("v1 hashes");
        let h0 = compute_chain_hash(&prev, &v0).expect("v0 hashes");
        assert_ne!(h0, h1, "v0 and v1 encodings must produce different links");
    }

    /// An unknown future version must be rejected rather than silently hashed
    /// under the current rules.
    #[test]
    fn unknown_format_version_is_rejected() {
        let mut ev = event(AuditOperation::Logout, None, AuditResult::Success);
        ev.format_version = 99;
        assert!(
            compute_chain_hash(&[0u8; 32], &ev).is_err(),
            "an unrecognised format_version must not verify",
        );
    }

    /// The scratch buffer is reused across events; a stale tail from a longer
    /// previous event must not leak into a shorter one.
    #[test]
    fn scratch_buffer_reuse_does_not_leak_between_events() {
        let long = event(
            AuditOperation::Logout,
            Some("a-considerably-longer-key-identifier"),
            AuditResult::Success,
        );
        let short = event(AuditOperation::Logout, None, AuditResult::Success);
        let prev = [0u8; 32];

        let mut scratch = Vec::new();
        let _ = compute_chain_hash_with(&prev, &long, &mut scratch).expect("long hashes");
        let reused = compute_chain_hash_with(&prev, &short, &mut scratch).expect("short hashes");
        let fresh = compute_chain_hash(&prev, &short).expect("short hashes standalone");

        assert_eq!(
            reused, fresh,
            "a reused scratch buffer must produce the same hash as a fresh one",
        );
    }
}
