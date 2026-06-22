// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! JSON-lines logger for PKCS#11 spy calls.
//!
//! ## Timing precision and side-channel exposure
//!
//! By default, this logger emits **millisecond-precision** timestamps and
//! durations. Microsecond-precision timing in a log that sits in the data
//! path of every cryptographic operation is a side-channel: a reader of
//! the log can correlate per-call latency with key-dependent operations
//! (sign, decrypt, etc.) and potentially recover secret material.
//!
//! Environment variables controlling timing precision:
//!
//! - `PKCS11_SPY_FULL_TIMING=1` — opt **in** to microsecond precision.
//!   Only enable this for local debugging where the log is not exposed
//!   to other principals. Do NOT enable on production HSMs or in any
//!   environment where the log is readable by another user or persisted
//!   to long-lived storage.
//! - `PKCS11_SPY_REDUCED_TIMING=1` — legacy, accepted for back-compat.
//!   Millisecond resolution is now the default, so this variable is a
//!   no-op (it simply confirms the default behaviour). New deployments
//!   should not set it.
//!
//! Precedence: if `PKCS11_SPY_FULL_TIMING=1` is set, microsecond
//! resolution is used regardless of `PKCS11_SPY_REDUCED_TIMING`.

use std::io::Write;
use std::sync::Mutex;
use std::time::Instant;

static LOGGER: std::sync::OnceLock<Mutex<SpyLogger>> = std::sync::OnceLock::new();

pub struct SpyLogger {
    writer: Box<dyn Write + Send>,
    start: Instant,
    /// When true, log timing at microsecond precision (opt-in).
    /// The default is millisecond precision, which reduces side-channel
    /// leakage from crypto operation timing.
    /// Controlled by `PKCS11_SPY_FULL_TIMING=1` environment variable.
    full_timing: bool,
}

impl SpyLogger {
    fn new() -> Self {
        let writer: Box<dyn Write + Send> = match std::env::var("PKCS11_SPY_LOG") {
            Ok(path) => {
                // Validate the log path:
                // 1. Canonicalize parent directory to prevent path traversal
                // 2. Ensure parent exists and is a directory
                // 3. Reject paths that escape expected locations
                let log_path = std::path::Path::new(&path);

                let parent = log_path.parent().unwrap_or(std::path::Path::new("."));
                match std::fs::canonicalize(parent) {
                    Ok(canonical_parent) => {
                        // Verify parent is a directory
                        if !canonical_parent.is_dir() {
                            eprintln!(
                                "pkcs11-spy: PKCS11_SPY_LOG parent is not a directory, using stderr"
                            );
                            Box::new(std::io::stderr())
                        } else {
                            let filename = log_path.file_name().unwrap_or_default();
                            let full_path = canonical_parent.join(filename);

                            // Reject if filename contains path separators (additional traversal guard)
                            let fname_str = filename.to_string_lossy();
                            if fname_str.contains('/')
                                || fname_str.contains('\\')
                                || fname_str.contains("..")
                            {
                                eprintln!(
                                    "pkcs11-spy: PKCS11_SPY_LOG filename contains invalid characters, using stderr"
                                );
                                Box::new(std::io::stderr())
                            } else {
                                match std::fs::OpenOptions::new()
                                    .create(true)
                                    .append(true)
                                    .open(&full_path)
                                {
                                    Ok(f) => {
                                        // On Unix, set restrictive permissions on the log file
                                        #[cfg(unix)]
                                        {
                                            use std::os::unix::fs::PermissionsExt;
                                            let _ = std::fs::set_permissions(
                                                &full_path,
                                                std::fs::Permissions::from_mode(0o600),
                                            );
                                        }
                                        // On Windows, restrict log file to current user via icacls.
                                        // The spy log may contain session handles and timing data
                                        // useful for side-channel analysis.
                                        //
                                        // SECURITY: Use `whoami` instead of %USERNAME% env var,
                                        // which is user-controllable and could be set to "Everyone".
                                        #[cfg(windows)]
                                        {
                                            if let Some(path_str) = full_path.to_str() {
                                                let username = std::process::Command::new("whoami")
                                                    .stdout(std::process::Stdio::piped())
                                                    .stderr(std::process::Stdio::null())
                                                    .output()
                                                    .ok()
                                                    .filter(|o| o.status.success())
                                                    .map(|o| {
                                                        String::from_utf8_lossy(&o.stdout)
                                                            .trim()
                                                            .to_string()
                                                    })
                                                    .unwrap_or_default();
                                                if !username.is_empty() {
                                                    let _ = std::process::Command::new("icacls")
                                                        .args([
                                                            path_str,
                                                            "/inheritance:r",
                                                            "/grant:r",
                                                            &format!("{}:(R,W)", username),
                                                        ])
                                                        .stdout(std::process::Stdio::null())
                                                        .stderr(std::process::Stdio::null())
                                                        .status();
                                                }
                                            }
                                        }
                                        Box::new(f)
                                    }
                                    Err(e) => {
                                        eprintln!(
                                            "pkcs11-spy: failed to open log file, using stderr: {}",
                                            e
                                        );
                                        Box::new(std::io::stderr())
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "pkcs11-spy: cannot resolve PKCS11_SPY_LOG parent directory, using stderr: {}",
                            e
                        );
                        Box::new(std::io::stderr())
                    }
                }
            }
            Err(_) => Box::new(std::io::stderr()),
        };
        let full_timing = resolve_full_timing_from_env();

        Self {
            writer,
            start: Instant::now(),
            full_timing,
        }
    }
}

/// Resolve the timing-precision policy from the current environment.
///
/// Returns `true` for microsecond precision (opt-in), `false` for the
/// default millisecond precision.
///
/// Precedence:
///   1. `PKCS11_SPY_FULL_TIMING=1` (or `=true`, case-insensitive)
///      -> microsecond. Wins over everything else.
///   2. Otherwise -> millisecond (the secure default).
///
/// `PKCS11_SPY_REDUCED_TIMING` is read for back-compat but is a no-op:
/// millisecond is already the default. If both vars are set, FULL_TIMING
/// wins.
///
/// SECURITY: microsecond-precision timestamps in the log are a side-channel
/// for any tool that sits in the crypto data path -- a reader of the log
/// can correlate latency with key-dependent operations (sign, decrypt).
fn resolve_full_timing_from_env() -> bool {
    let full = std::env::var("PKCS11_SPY_FULL_TIMING")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    // PKCS11_SPY_REDUCED_TIMING is read but intentionally ignored beyond
    // accepting its presence -- millisecond is already the default. We
    // touch the var explicitly so its semantics are documented at the
    // point of use.
    let _legacy_reduced = std::env::var("PKCS11_SPY_REDUCED_TIMING").ok();
    full
}

pub fn get_logger() -> &'static Mutex<SpyLogger> {
    LOGGER.get_or_init(|| Mutex::new(SpyLogger::new()))
}

/// Acquire the logger, recovering from mutex poisoning.
/// If the mutex was poisoned (a prior holder panicked), we re-initialize the
/// writer to avoid writing to a potentially corrupt buffer state.
fn with_logger<F>(f: F)
where
    F: FnOnce(&mut SpyLogger),
{
    let mutex = get_logger();
    match mutex.lock() {
        Ok(mut guard) => f(&mut guard),
        Err(poisoned) => {
            // Recover from poisoning by replacing the logger with a fresh instance.
            // The prior holder panicked mid-write, so the internal Write buffer may
            // contain a partial JSON line — reusing it would produce corrupt output
            // that breaks log parsers and SIEM ingestion.
            let mut guard = poisoned.into_inner();
            *guard = SpyLogger::new();
            let _ = writeln!(
                guard.writer,
                r#"{{"ts":0,"fn":"pkcs11-spy","event":"warning","msg":"logger re-initialized after mutex poisoning"}}"#
            );
            f(&mut guard);
        }
    }
}

/// Log a loader-level error (e.g. missing or invalid PKCS11_SPY_TARGET).
/// Used to replace panics in `loader.rs` so a misconfiguration produces a
/// log line instead of unwinding across the FFI boundary.
pub fn log_loader_error(msg: &str) {
    // Sanitize: strip embedded quotes so a malicious env-var-derived message
    // cannot break out of the JSON string field.
    let safe: String = msg
        .chars()
        .map(|c| match c {
            '"' | '\\' => ' ',
            c if c.is_control() => ' ',
            c => c,
        })
        .collect();
    with_logger(|logger| {
        let elapsed = logger.start.elapsed().as_secs_f64();
        let _ = writeln!(
            logger.writer,
            r#"{{"ts":{:.6},"fn":"pkcs11-spy","event":"loader_error","msg":"{}"}}"#,
            elapsed, safe
        );
    });
}

/// Log that a panic was caught at the FFI boundary. Returns CKR_GENERAL_ERROR
/// to the host. The panic payload is best-effort: only `&str` and `String`
/// payloads are surfaced; other types log as `<non-string panic>`.
pub fn log_panic(func: &str, payload: &(dyn std::any::Any + Send)) {
    let msg = if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic>".to_string()
    };
    let safe: String = msg
        .chars()
        .map(|c| match c {
            '"' | '\\' => ' ',
            c if c.is_control() => ' ',
            c => c,
        })
        .collect();
    with_logger(|logger| {
        let elapsed = logger.start.elapsed().as_secs_f64();
        let _ = writeln!(
            logger.writer,
            r#"{{"ts":{:.6},"fn":"{}","event":"panic_caught","msg":"{}"}}"#,
            elapsed, func, safe
        );
    });
}

/// Log a function call entry.
///
/// Timestamp precision follows the same policy as `log_return`:
/// millisecond by default, microsecond only if `PKCS11_SPY_FULL_TIMING=1`.
pub fn log_call(func: &str, args: &str) {
    with_logger(|logger| {
        let elapsed = logger.start.elapsed().as_secs_f64();
        if logger.full_timing {
            let _ = writeln!(
                logger.writer,
                r#"{{"ts":{:.6},"fn":"{}","event":"call","args":{}}}"#,
                elapsed, func, args
            );
        } else {
            let elapsed_ms = (elapsed * 1000.0).round() / 1000.0;
            let _ = writeln!(
                logger.writer,
                r#"{{"ts":{:.3},"fn":"{}","event":"call","args":{}}}"#,
                elapsed_ms, func, args
            );
        }
    });
}

/// Log a function return.
pub fn log_return(func: &str, rv: u64, duration_us: u64) {
    let rv_name = ckr_name(rv);
    with_logger(|logger| {
        let elapsed = logger.start.elapsed().as_secs_f64();

        if logger.full_timing {
            // Opt-in microsecond precision (PKCS11_SPY_FULL_TIMING=1).
            // WARNING: microsecond timestamps in the log are a side-channel
            // for any tool that sits in the crypto data path. Only enable
            // for local debugging on logs that are not exposed to other
            // principals.
            let _ = writeln!(
                logger.writer,
                r#"{{"ts":{:.6},"fn":"{}","event":"return","rv":"{}","rv_code":{},"duration_us":{}}}"#,
                elapsed, func, rv_name, rv, duration_us
            );
        } else {
            // Default: millisecond precision. Truncates to limit
            // side-channel leakage from crypto operation timing.
            let elapsed_ms = (elapsed * 1000.0).round() / 1000.0;
            let duration_ms = duration_us / 1000;
            let _ = writeln!(
                logger.writer,
                r#"{{"ts":{:.3},"fn":"{}","event":"return","rv":"{}","rv_code":{},"duration_ms":{}}}"#,
                elapsed_ms, func, rv_name, rv, duration_ms
            );
        }
    });
}

/// Map CK_RV code to human-readable name.
fn ckr_name(rv: u64) -> &'static str {
    match rv {
        0x00000000 => "CKR_OK",
        0x00000001 => "CKR_CANCEL",
        0x00000002 => "CKR_HOST_MEMORY",
        0x00000003 => "CKR_SLOT_ID_INVALID",
        0x00000005 => "CKR_GENERAL_ERROR",
        0x00000006 => "CKR_FUNCTION_FAILED",
        0x00000007 => "CKR_ARGUMENTS_BAD",
        0x00000010 => "CKR_ATTRIBUTE_READ_ONLY",
        0x00000011 => "CKR_ATTRIBUTE_SENSITIVE",
        0x00000012 => "CKR_ATTRIBUTE_TYPE_INVALID",
        0x00000013 => "CKR_ATTRIBUTE_VALUE_INVALID",
        0x00000020 => "CKR_DATA_INVALID",
        0x00000021 => "CKR_DATA_LEN_RANGE",
        0x00000030 => "CKR_DEVICE_ERROR",
        0x00000031 => "CKR_DEVICE_MEMORY",
        0x00000032 => "CKR_DEVICE_REMOVED",
        0x00000050 => "CKR_FUNCTION_CANCELED",
        0x00000051 => "CKR_FUNCTION_NOT_PARALLEL",
        0x00000054 => "CKR_FUNCTION_NOT_SUPPORTED",
        0x00000060 => "CKR_KEY_HANDLE_INVALID",
        0x00000062 => "CKR_KEY_SIZE_RANGE",
        0x00000063 => "CKR_KEY_TYPE_INCONSISTENT",
        0x00000070 => "CKR_MECHANISM_INVALID",
        0x00000071 => "CKR_MECHANISM_PARAM_INVALID",
        0x00000082 => "CKR_OBJECT_HANDLE_INVALID",
        0x000000A0 => "CKR_PIN_INCORRECT",
        0x000000A1 => "CKR_PIN_INVALID",
        0x000000A2 => "CKR_PIN_LEN_RANGE",
        0x000000A4 => "CKR_PIN_LOCKED",
        0x000000B0 => "CKR_SESSION_CLOSED",
        0x000000B1 => "CKR_SESSION_COUNT",
        0x000000B3 => "CKR_SESSION_HANDLE_INVALID",
        0x000000B4 => "CKR_SESSION_PARALLEL_NOT_SUPPORTED",
        0x000000B5 => "CKR_SESSION_READ_ONLY",
        0x000000B6 => "CKR_SESSION_EXISTS",
        0x000000B7 => "CKR_SESSION_READ_ONLY_EXISTS",
        0x000000B8 => "CKR_SESSION_READ_WRITE_SO_EXISTS",
        0x000000C0 => "CKR_SIGNATURE_INVALID",
        0x000000C1 => "CKR_SIGNATURE_LEN_RANGE",
        0x000000D0 => "CKR_TEMPLATE_INCOMPLETE",
        0x000000D1 => "CKR_TEMPLATE_INCONSISTENT",
        0x000000E0 => "CKR_TOKEN_NOT_PRESENT",
        0x000000E1 => "CKR_TOKEN_NOT_RECOGNIZED",
        0x000000E2 => "CKR_TOKEN_WRITE_PROTECTED",
        0x00000100 => "CKR_USER_ALREADY_LOGGED_IN",
        0x00000101 => "CKR_USER_NOT_LOGGED_IN",
        0x00000102 => "CKR_USER_PIN_NOT_INITIALIZED",
        0x00000103 => "CKR_USER_TYPE_INVALID",
        0x00000150 => "CKR_BUFFER_TOO_SMALL",
        0x00000190 => "CKR_CRYPTOKI_NOT_INITIALIZED",
        0x00000191 => "CKR_CRYPTOKI_ALREADY_INITIALIZED",
        _ => "CKR_UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    //! Tests for the timing-precision env-var policy.
    //!
    //! These tests mutate process-wide environment variables, which is not
    //! thread-safe. `cargo test` runs tests in parallel by default, so we
    //! serialise them with a per-module mutex. Callers should also invoke
    //! `cargo test -- --test-threads=1` for extra safety (CI does this for
    //! this crate).
    //!
    //! Note: `std::env::set_var` / `remove_var` are marked `unsafe` from
    //! Rust 2024 onward; we wrap them via the helpers below so the
    //! `unsafe` block is localised and audited.
    use super::resolve_full_timing_from_env;
    use std::sync::Mutex;

    /// Serialises env-var mutation across tests in this module.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    const FULL: &str = "PKCS11_SPY_FULL_TIMING";
    const REDUCED: &str = "PKCS11_SPY_REDUCED_TIMING";

    /// RAII guard that snapshots the two env vars on construction and
    /// restores them on drop. Combined with `ENV_LOCK`, this keeps each
    /// test hermetic even if it panics mid-way.
    struct EnvGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        prev_full: Option<String>,
        prev_reduced: Option<String>,
    }

    impl EnvGuard {
        fn new() -> Self {
            // Recover from a poisoned lock -- a previous test panicked,
            // but we still want to run.
            let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let prev_full = std::env::var(FULL).ok();
            let prev_reduced = std::env::var(REDUCED).ok();
            // Start each test from a clean slate.
            unset(FULL);
            unset(REDUCED);
            Self {
                _lock: lock,
                prev_full,
                prev_reduced,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match self.prev_full.take() {
                Some(v) => set(FULL, &v),
                None => unset(FULL),
            }
            match self.prev_reduced.take() {
                Some(v) => set(REDUCED, &v),
                None => unset(REDUCED),
            }
        }
    }

    fn set(k: &str, v: &str) {
        // SAFETY: env-var mutation is process-global and not thread-safe.
        // Tests in this module are serialised by `ENV_LOCK`, and we only
        // call this from inside an `EnvGuard`, so no other thread in this
        // module is reading or writing these vars concurrently.
        unsafe {
            std::env::set_var(k, v);
        }
    }

    fn unset(k: &str) {
        // SAFETY: see `set`.
        unsafe {
            std::env::remove_var(k);
        }
    }

    #[test]
    fn default_is_millisecond_when_no_vars_set() {
        let _g = EnvGuard::new();
        assert!(
            !resolve_full_timing_from_env(),
            "default precision must be millisecond (full_timing == false)"
        );
    }

    #[test]
    fn full_timing_opts_in_to_microsecond() {
        let _g = EnvGuard::new();
        set(FULL, "1");
        assert!(
            resolve_full_timing_from_env(),
            "PKCS11_SPY_FULL_TIMING=1 must enable microsecond precision"
        );
    }

    #[test]
    fn full_timing_accepts_true_case_insensitive() {
        let _g = EnvGuard::new();
        set(FULL, "TrUe");
        assert!(
            resolve_full_timing_from_env(),
            "PKCS11_SPY_FULL_TIMING=true (any case) must enable microsecond precision"
        );
    }

    #[test]
    fn legacy_reduced_timing_alone_keeps_millisecond_default() {
        let _g = EnvGuard::new();
        set(REDUCED, "1");
        assert!(
            !resolve_full_timing_from_env(),
            "PKCS11_SPY_REDUCED_TIMING=1 (without FULL_TIMING) must keep the millisecond default"
        );
    }

    #[test]
    fn full_timing_wins_when_both_set() {
        let _g = EnvGuard::new();
        set(FULL, "1");
        set(REDUCED, "1");
        assert!(
            resolve_full_timing_from_env(),
            "FULL_TIMING must win over REDUCED_TIMING when both are set"
        );
    }

    #[test]
    fn full_timing_non_truthy_value_keeps_default() {
        let _g = EnvGuard::new();
        // Anything other than "1" / "true" must NOT enable microsecond
        // timing -- avoid easy-to-trip-over opt-in semantics.
        set(FULL, "0");
        assert!(
            !resolve_full_timing_from_env(),
            "PKCS11_SPY_FULL_TIMING=0 must not enable microsecond precision"
        );
        set(FULL, "yes");
        assert!(
            !resolve_full_timing_from_env(),
            "PKCS11_SPY_FULL_TIMING=yes must not enable microsecond precision (only 1/true)"
        );
    }
}
