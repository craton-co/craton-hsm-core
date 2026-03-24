// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
use serde::Deserialize;
use std::fmt;
use std::path::PathBuf;

use crate::error::HsmError;

/// Minimum acceptable PBKDF2 iteration count to resist brute-force attacks.
const MIN_PBKDF2_ITERATIONS: u32 = 100_000;
/// Maximum acceptable PBKDF2 iteration count to prevent algorithmic DoS via
/// config-planted extreme values.
const MAX_PBKDF2_ITERATIONS: u32 = 10_000_000;
/// Minimum acceptable PIN length (NIST SP 800-63B recommends >= 6; we use 4
/// as an absolute floor so that downstream policy can tighten further).
const MIN_PIN_LENGTH: usize = 4;
/// Bounds for `max_failed_logins` to prevent DoS (too low) or brute-force
/// (too high).
const MIN_FAILED_LOGINS: u32 = 3;
const MAX_FAILED_LOGINS: u32 = 100;
/// Maximum PIN length to prevent memory-exhaustion via PBKDF2 on huge PINs.
const MAX_PIN_LENGTH: usize = 256;
/// Maximum sessions to prevent resource exhaustion.
const MAX_SESSIONS: u64 = 10_000;
/// Maximum slots to prevent OOM on initialization.
const MAX_SLOT_COUNT: usize = 256;
/// Maximum token label length (PKCS#11 CK_TOKEN_INFO.label is 32 bytes).
const MAX_LABEL_LENGTH: usize = 32;
/// Valid crypto backend identifiers.
const VALID_BACKENDS: &[&str] = &["rustcrypto", "awslc"];
/// Valid audit log levels.
const VALID_LOG_LEVELS: &[&str] = &["all", "crypto", "auth", "admin", "none"];
/// Relative path prefixes that could target sensitive directories.
const SENSITIVE_PATH_PREFIXES: &[&str] = &[".git", ".ssh", ".gnupg", ".aws", ".config", ".env"];

#[derive(Debug, Deserialize, Clone)]
pub struct HsmConfig {
    #[serde(default)]
    pub token: TokenConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default)]
    pub algorithms: AlgorithmConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TokenConfig {
    #[serde(default = "default_label")]
    pub label: String,
    #[serde(default = "default_storage_path")]
    pub storage_path: PathBuf,
    #[serde(default = "default_max_sessions")]
    pub max_sessions: u64,
    #[serde(default = "default_max_rw_sessions")]
    pub max_rw_sessions: u64,
    /// If true, token objects (CKA_TOKEN=true) are persisted to disk
    /// via EncryptedStore. Session objects are never persisted.
    /// Default: false (in-memory only, matching legacy behavior).
    #[serde(default)]
    pub persist_objects: bool,
    /// Number of slots to create. Default: 1 (backward compatible).
    /// Each slot gets its own independent token.
    #[serde(default = "default_slot_count")]
    pub slot_count: usize,
    /// Token serial number (16-char string, space-padded).
    /// Should be unique per deployment. Default: "0000000000000001".
    #[serde(default = "default_serial_number")]
    pub serial_number: String,
}

#[derive(Deserialize, Clone)]
pub struct SecurityConfig {
    #[serde(default = "default_pin_min")]
    pub pin_min_length: usize,
    #[serde(default = "default_pin_max")]
    pub pin_max_length: usize,
    #[serde(default = "default_max_failed")]
    pub max_failed_logins: u32,
    #[serde(default = "default_pbkdf2_iterations")]
    pub pbkdf2_iterations: u32,
}

// Custom Debug to avoid leaking security parameters in logs/panics.
impl fmt::Debug for SecurityConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecurityConfig")
            .field("pin_min_length", &"[REDACTED]")
            .field("pin_max_length", &"[REDACTED]")
            .field("max_failed_logins", &"[REDACTED]")
            .field("pbkdf2_iterations", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct AuditConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_audit_path")]
    pub log_path: PathBuf,
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AlgorithmConfig {
    #[serde(default)]
    pub allow_weak_rsa: bool,
    #[serde(default)]
    pub allow_sha1_signing: bool,
    #[serde(default = "default_true")]
    pub enable_pqc: bool,
    /// Crypto backend: "rustcrypto" (default) or "awslc".
    /// Only effective when the corresponding feature is compiled in.
    #[serde(default = "default_crypto_backend")]
    pub crypto_backend: String,
    /// When true, only FIPS 140-3 approved algorithms are permitted.
    /// Non-approved mechanisms (e.g., EdDSA, SHA-1 signing) are blocked.
    /// PQC mechanisms are also blocked (not yet FIPS-approved).
    #[serde(default)]
    pub fips_approved_only: bool,
}

impl Default for HsmConfig {
    fn default() -> Self {
        Self {
            token: TokenConfig::default(),
            security: SecurityConfig::default(),
            audit: AuditConfig::default(),
            algorithms: AlgorithmConfig::default(),
        }
    }
}

impl Default for TokenConfig {
    fn default() -> Self {
        Self {
            label: default_label(),
            storage_path: default_storage_path(),
            max_sessions: default_max_sessions(),
            max_rw_sessions: default_max_rw_sessions(),
            persist_objects: false,
            slot_count: default_slot_count(),
            serial_number: default_serial_number(),
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            pin_min_length: default_pin_min(),
            pin_max_length: default_pin_max(),
            max_failed_logins: default_max_failed(),
            pbkdf2_iterations: default_pbkdf2_iterations(),
        }
    }
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            log_path: default_audit_path(),
            log_level: default_log_level(),
        }
    }
}

impl Default for AlgorithmConfig {
    fn default() -> Self {
        Self {
            allow_weak_rsa: false,
            allow_sha1_signing: false,
            enable_pqc: true,
            crypto_backend: default_crypto_backend(),
            fips_approved_only: false,
        }
    }
}

fn default_label() -> String {
    "Craton HSM Token 0".to_string()
}
fn default_storage_path() -> PathBuf {
    PathBuf::from("craton_hsm_store")
}
fn default_max_sessions() -> u64 {
    100
}
fn default_max_rw_sessions() -> u64 {
    10
}
fn default_pin_min() -> usize {
    8
}
fn default_pin_max() -> usize {
    64
}
fn default_max_failed() -> u32 {
    10
}
fn default_pbkdf2_iterations() -> u32 {
    600_000
}
fn default_true() -> bool {
    true
}
fn default_audit_path() -> PathBuf {
    PathBuf::from("craton_hsm_audit.jsonl")
}
fn default_log_level() -> String {
    "all".to_string()
}
fn default_crypto_backend() -> String {
    "rustcrypto".to_string()
}
fn default_slot_count() -> usize {
    1
}
fn default_serial_number() -> String {
    "0000000000000001".to_string()
}

impl HsmConfig {
    /// Load configuration, returning an error if the config file exists but is
    /// invalid or fails validation. Falls back to defaults only when no config
    /// file is present.
    pub fn load() -> Result<Self, HsmError> {
        // In FIPS mode, use hardcoded secure defaults — never read from filesystem
        // to prevent an attacker from planting a permissive config file.
        #[cfg(feature = "fips")]
        {
            tracing::info!(
                "FIPS mode active (compile-time) — using hardcoded secure defaults, ignoring config files"
            );
            return Ok(Self::fips_defaults());
        }

        #[cfg(not(feature = "fips"))]
        {
            if std::env::var("CRATON_HSM_FIPS").as_deref() == Ok("1") {
                // SECURITY WARNING: Environment-variable FIPS mode is ADVISORY ONLY.
                //
                // An attacker who can modify the process environment (e.g. via
                // /proc/pid/environ, LD_PRELOAD, or parent-process control) can:
                //   1. Unset CRATON_HSM_FIPS to disable FIPS mode entirely.
                //   2. Set CRATON_HSM_CONFIG to load a permissive configuration.
                //
                // For certified FIPS 140-3 compliance, you MUST compile with
                // `--features fips` which hardcodes secure defaults at compile time
                // and cannot be bypassed at runtime.
                //
                // This env-var path exists only as a convenience for development and
                // testing. Do NOT rely on it for production FIPS compliance.
                tracing::warn!(
                    "FIPS mode activated via CRATON_HSM_FIPS env var. \
                     SECURITY: env-var FIPS is ADVISORY ONLY — an attacker who can modify \
                     the process environment can bypass this entirely. For certified FIPS \
                     compliance, compile with `--features fips`."
                );
                if std::path::Path::new("craton_hsm.toml").exists() {
                    tracing::warn!("craton_hsm.toml exists but is being ignored in FIPS mode");
                }
                return Ok(Self::fips_defaults());
            }

            let config_path = std::env::var("CRATON_HSM_CONFIG")
                .unwrap_or_else(|_| "craton_hsm.toml".to_string());

            Self::validate_config_path(&config_path)?;

            let config = Self::load_from_path(&config_path)?;
            config.validate()?;
            Ok(config)
        }
    }

    /// FIPS-hardened defaults: audit enabled, no weak algorithms, approved-only.
    fn fips_defaults() -> Self {
        let mut config = Self::default();
        config.algorithms.fips_approved_only = true;
        config.algorithms.allow_weak_rsa = false;
        config.algorithms.allow_sha1_signing = false;
        config.algorithms.enable_pqc = false;
        config.audit.enabled = true;
        config
    }

    /// Validate that a filesystem path is safe: no absolute paths, no traversal,
    /// no UNC paths, no null bytes, no symlinks, no sensitive directory targets.
    /// `label` is used in error messages (e.g. "config path", "storage_path").
    fn validate_path_safety(path: &std::path::Path, label: &str) -> Result<(), Vec<String>> {
        let mut errors: Vec<String> = Vec::new();
        let path_str = path.to_string_lossy();

        if path.is_absolute() {
            errors.push(format!(
                "{} '{}' is absolute — must be relative to the working directory",
                label, path_str
            ));
        }
        if path_str.starts_with("\\\\") || path_str.starts_with("//") {
            errors.push(format!(
                "{} '{}' is a UNC path — not permitted",
                label, path_str
            ));
        }
        for component in path.components() {
            if let std::path::Component::ParentDir = component {
                errors.push(format!(
                    "{} '{}' contains '..' traversal component",
                    label, path_str
                ));
                break;
            }
        }
        if path_str.contains('\0') {
            errors.push(format!("{} contains null byte", label));
        }

        // Reject paths targeting sensitive directories.
        if let Some(first) = path.components().next() {
            let first_str = first.as_os_str().to_string_lossy();
            for prefix in SENSITIVE_PATH_PREFIXES {
                if first_str.eq_ignore_ascii_case(prefix) {
                    errors.push(format!(
                        "{} '{}' targets sensitive directory '{}'",
                        label, path_str, prefix
                    ));
                    break;
                }
            }
        }

        // Reject symlinks (TOCTOU mitigation — check at validation time).
        if path.exists() {
            match std::fs::symlink_metadata(path) {
                Ok(meta) if meta.file_type().is_symlink() => {
                    errors.push(format!(
                        "{} '{}' is a symlink — not permitted",
                        label, path_str
                    ));
                }
                _ => {}
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Validate the config file path from CRATON_HSM_CONFIG env var.
    fn validate_config_path(path: &str) -> Result<(), HsmError> {
        let p = std::path::Path::new(path);
        if let Err(errs) = Self::validate_path_safety(p, "config path") {
            let msg = errs.join("; ");
            tracing::error!("Config path validation failed: {}", msg);
            return Err(HsmError::ConfigError(msg));
        }
        Ok(())
    }

    /// Check file permissions on the already-opened file to reject insecure
    /// ownership or write permissions, mitigating config-planting attacks.
    ///
    /// On Unix: rejects group-writable or world-writable files.
    /// On Windows: rejects files writable by the Everyone or Users groups.
    fn check_file_permissions(file: &std::fs::File, path: &str) -> Result<(), HsmError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = file.metadata().map_err(|e| {
                HsmError::ConfigError(format!("cannot stat config file '{}': {}", path, e))
            })?;
            let mode = meta.mode();
            // Reject group-writable (0o020) or other-writable (0o002)
            if mode & 0o022 != 0 {
                tracing::error!(
                    "Config file '{}' has insecure permissions {:o} — \
                     must not be group- or world-writable",
                    path,
                    mode & 0o777
                );
                return Err(HsmError::ConfigError(format!(
                    "config file has insecure permissions ({:o}); \
                     must not be group- or world-writable",
                    mode & 0o777
                )));
            }
        }

        #[cfg(windows)]
        {
            Self::check_windows_permissions(file, path)?;
        }

        #[cfg(not(any(unix, windows)))]
        {
            let _ = (file, path);
        }

        Ok(())
    }

    /// Windows-specific permission check: reject files writable by broad groups.
    /// Uses the file's metadata to verify the read-only attribute as a baseline,
    /// and checks NTFS ACLs via icacls on the canonical path.
    #[cfg(windows)]
    fn check_windows_permissions(_file: &std::fs::File, path: &str) -> Result<(), HsmError> {
        // Check NTFS ACLs via icacls for broad write access.
        // Resolve the canonical path from the open handle to avoid TOCTOU on
        // the path string (the handle is already pinned to an inode).
        let canonical = match std::fs::canonicalize(path) {
            Ok(p) => p,
            Err(_) => {
                // If canonicalize fails, fall through — the file is already open.
                return Ok(());
            }
        };
        let output = std::process::Command::new("icacls")
            .arg(&canonical)
            .output();
        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stdout_upper = stdout.to_uppercase();
            // Reject if Everyone, Users, or Authenticated Users have write/full access.
            let dangerous_principals =
                ["EVERYONE", "USERS", "AUTHENTICATED USERS", "BUILTIN\\USERS"];
            let dangerous_perms = ["(F)", "(M)", "(W)"];
            for line in stdout_upper.lines() {
                for principal in &dangerous_principals {
                    if line.contains(principal) {
                        for perm in &dangerous_perms {
                            if line.contains(perm) {
                                tracing::error!(
                                    "Config file '{}' has insecure ACL — {} has write access",
                                    path,
                                    principal
                                );
                                return Err(HsmError::ConfigError(format!(
                                    "config file has insecure permissions; \
                                     {} has write access — restrict to owner only",
                                    principal
                                )));
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Check that an already-opened file is not a symlink, using the file
    /// handle's metadata to avoid TOCTOU races.
    fn check_file_not_symlink(file: &std::fs::File, path: &str) -> Result<(), HsmError> {
        let meta = file.metadata().map_err(|e| {
            HsmError::ConfigError(format!("cannot stat config file '{}': {}", path, e))
        })?;

        // On Unix, also check via symlink_metadata on the path as a defense-in-depth
        // measure (the open fd is authoritative, but this catches broken symlinks).
        #[cfg(unix)]
        {
            if let Ok(link_meta) = std::fs::symlink_metadata(path) {
                if link_meta.file_type().is_symlink() {
                    tracing::error!(
                        "Config file '{}' is a symlink — not permitted for security files",
                        path
                    );
                    return Err(HsmError::ConfigError(
                        "config file is a symlink — not permitted".to_string(),
                    ));
                }
            }
        }

        let _ = meta;
        Ok(())
    }

    /// Load from a specific path. Returns defaults if the file does not exist.
    /// Returns an error if the file exists but cannot be parsed.
    ///
    /// Opens the file first, then performs permission and symlink checks on the
    /// open file descriptor to eliminate TOCTOU race conditions.
    pub fn load_from_path(path: &str) -> Result<Self, HsmError> {
        use std::io::Read;

        let file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::info!("No config file at '{}' — using secure defaults", path);
                return Ok(Self::default());
            }
            Err(e) => {
                tracing::error!("Cannot read config file '{}': {}", path, e);
                return Err(HsmError::ConfigError(
                    "cannot read config file — check logs for details".to_string(),
                ));
            }
        };

        // All checks use the open file descriptor — no TOCTOU window.
        Self::check_file_not_symlink(&file, path)?;
        Self::check_file_permissions(&file, path)?;

        let mut content = String::new();
        let mut reader = std::io::BufReader::new(file);
        reader.read_to_string(&mut content).map_err(|e| {
            tracing::error!("Cannot read config file '{}': {}", path, e);
            HsmError::ConfigError("cannot read config file — check logs for details".to_string())
        })?;

        toml::from_str(&content).map_err(|e| {
            // Log full details internally; return sanitized error to caller
            tracing::error!(
                "Failed to parse config file '{}': {} — refusing to start with potentially \
                 misconfigured security parameters",
                path,
                e
            );
            HsmError::ConfigError(
                "failed to parse config file — check logs for details".to_string(),
            )
        })
    }

    /// Comprehensive validation of all security-critical configuration values.
    /// Called automatically by `load()`.
    pub fn validate(&self) -> Result<(), HsmError> {
        let mut errors: Vec<String> = Vec::new();

        // --- storage_path: reject absolute, traversal, UNC, null bytes, symlinks, sensitive dirs ---
        if let Err(path_errs) = Self::validate_path_safety(&self.token.storage_path, "storage_path")
        {
            errors.extend(path_errs);
        }

        // --- audit log_path: same checks ---
        if let Err(path_errs) = Self::validate_path_safety(&self.audit.log_path, "audit log_path") {
            errors.extend(path_errs);
        }

        // --- token label: PKCS#11 requires <= 32 bytes, printable ASCII only ---
        if self.token.label.is_empty() {
            errors.push("token label must not be empty".to_string());
        }
        if self.token.label.len() > MAX_LABEL_LENGTH {
            errors.push(format!(
                "token label '{}' exceeds {} bytes (PKCS#11 CK_TOKEN_INFO.label limit)",
                self.token.label, MAX_LABEL_LENGTH
            ));
        }
        if !self
            .token
            .label
            .bytes()
            .all(|b| b.is_ascii_graphic() || b == b' ')
        {
            errors.push("token label contains non-printable or non-ASCII characters".to_string());
        }

        // --- PIN length bounds ---
        if self.security.pin_min_length < MIN_PIN_LENGTH {
            errors.push(format!(
                "pin_min_length ({}) is below the minimum of {}",
                self.security.pin_min_length, MIN_PIN_LENGTH
            ));
        }
        if self.security.pin_max_length < self.security.pin_min_length {
            errors.push(format!(
                "pin_max_length ({}) is less than pin_min_length ({})",
                self.security.pin_max_length, self.security.pin_min_length
            ));
        }
        if self.security.pin_max_length > MAX_PIN_LENGTH {
            errors.push(format!(
                "pin_max_length ({}) exceeds the maximum of {} (risk of memory exhaustion during PIN hashing)",
                self.security.pin_max_length, MAX_PIN_LENGTH
            ));
        }

        // --- PBKDF2 iterations bounds ---
        if self.security.pbkdf2_iterations < MIN_PBKDF2_ITERATIONS {
            errors.push(format!(
                "pbkdf2_iterations ({}) is below the minimum of {}",
                self.security.pbkdf2_iterations, MIN_PBKDF2_ITERATIONS
            ));
        }
        if self.security.pbkdf2_iterations > MAX_PBKDF2_ITERATIONS {
            errors.push(format!(
                "pbkdf2_iterations ({}) exceeds the maximum of {} (risk of algorithmic DoS)",
                self.security.pbkdf2_iterations, MAX_PBKDF2_ITERATIONS
            ));
        }

        // --- max_failed_logins bounds ---
        if self.security.max_failed_logins < MIN_FAILED_LOGINS {
            errors.push(format!(
                "max_failed_logins ({}) is below the minimum of {} (risk of accidental lockout)",
                self.security.max_failed_logins, MIN_FAILED_LOGINS
            ));
        }
        if self.security.max_failed_logins > MAX_FAILED_LOGINS {
            errors.push(format!(
                "max_failed_logins ({}) exceeds the maximum of {} (risk of brute-force)",
                self.security.max_failed_logins, MAX_FAILED_LOGINS
            ));
        }

        // --- serial_number format (PKCS#11 requires 16-char space-padded) ---
        if self.token.serial_number.is_empty() {
            errors.push("serial_number must not be empty".to_string());
        }
        if self.token.serial_number.len() > 16 {
            errors.push(format!(
                "serial_number '{}' exceeds 16 characters",
                self.token.serial_number
            ));
        }
        if !self
            .token
            .serial_number
            .bytes()
            .all(|b| b.is_ascii_graphic() || b == b' ')
        {
            errors.push("serial_number contains non-printable or non-ASCII characters".to_string());
        }

        // --- session count bounds ---
        if self.token.max_sessions == 0 {
            errors.push("max_sessions must be at least 1".to_string());
        }
        if self.token.max_sessions > MAX_SESSIONS {
            errors.push(format!(
                "max_sessions ({}) exceeds the maximum of {} (risk of resource exhaustion)",
                self.token.max_sessions, MAX_SESSIONS
            ));
        }
        if self.token.max_rw_sessions == 0 {
            errors.push("max_rw_sessions must be at least 1".to_string());
        }
        if self.token.max_rw_sessions > self.token.max_sessions {
            errors.push(format!(
                "max_rw_sessions ({}) exceeds max_sessions ({})",
                self.token.max_rw_sessions, self.token.max_sessions
            ));
        }

        // --- slot_count sanity ---
        if self.token.slot_count == 0 {
            errors.push("slot_count must be at least 1".to_string());
        }
        if self.token.slot_count > MAX_SLOT_COUNT {
            errors.push(format!(
                "slot_count ({}) exceeds the maximum of {} (risk of resource exhaustion)",
                self.token.slot_count, MAX_SLOT_COUNT
            ));
        }

        // --- crypto_backend must be a known identifier ---
        if !VALID_BACKENDS.contains(&self.algorithms.crypto_backend.as_str()) {
            errors.push(format!(
                "crypto_backend '{}' is not recognized (valid: {:?})",
                self.algorithms.crypto_backend, VALID_BACKENDS
            ));
        }

        // --- log_level must be a known identifier ---
        if !VALID_LOG_LEVELS.contains(&self.audit.log_level.as_str()) {
            errors.push(format!(
                "audit log_level '{}' is not recognized (valid: {:?})",
                self.audit.log_level, VALID_LOG_LEVELS
            ));
        }

        // --- FIPS consistency: reject contradictory weak-algorithm flags ---
        if self.algorithms.fips_approved_only {
            if self.algorithms.allow_weak_rsa {
                errors.push(
                    "allow_weak_rsa cannot be true when fips_approved_only is enabled".to_string(),
                );
            }
            if self.algorithms.allow_sha1_signing {
                errors.push(
                    "allow_sha1_signing cannot be true when fips_approved_only is enabled"
                        .to_string(),
                );
            }
            if !self.audit.enabled {
                errors.push("audit must be enabled when fips_approved_only is active".to_string());
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            let msg = errors.join("; ");
            tracing::error!("Configuration validation failed: {}", msg);
            Err(HsmError::ConfigError(msg))
        }
    }
}
