// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! JSON-lines logger for PKCS#11 spy calls.

use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use std::sync::Mutex;
use std::time::Instant;

static LOGGER: std::sync::OnceLock<Mutex<SpyLogger>> = std::sync::OnceLock::new();

pub struct SpyLogger {
    writer: Box<dyn Write + Send>,
    start: Instant,
    /// When true, log timing at millisecond precision instead of microsecond.
    /// Reduces side-channel leakage from crypto operation timing.
    /// Controlled by PKCS11_SPY_REDUCED_TIMING=1 environment variable.
    reduced_timing: bool,
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
                                match open_log_file(&full_path) {
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
                                        // open_log_file refuses symlink targets and
                                        // uses O_NOFOLLOW / FILE_FLAG_OPEN_REPARSE_POINT
                                        // to defeat symlink-swap attacks on the log path.
                                        tracing::error!(
                                            error = %e,
                                            "pkcs11-spy: failed to open log file (symlink refused or open failed), using stderr"
                                        );
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
        // PKCS11_SPY_REDUCED_TIMING=1 switches from microsecond to millisecond
        // precision, reducing timing side-channel exposure for crypto operations.
        let reduced_timing = std::env::var("PKCS11_SPY_REDUCED_TIMING")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        Self {
            writer,
            start: Instant::now(),
            reduced_timing,
        }
    }
}

/// Open the log file, refusing symlink targets.
///
/// Without `O_NOFOLLOW` (Unix) / `FILE_FLAG_OPEN_REPARSE_POINT` (Windows), an
/// attacker with write access to the log directory can symlink the log path to
/// a sensitive file (e.g. `/etc/shadow`) and cause the spy — potentially
/// running with elevated privilege — to append log lines to that file.
///
/// Strategy:
/// 1. Probe the path with `symlink_metadata`. If it exists and is a symlink,
///    refuse outright with `tracing::error!` and return `io::ErrorKind::InvalidInput`.
/// 2. Try `create_new(true)` first so a brand-new log file is created atomically
///    (`O_EXCL` semantics) and cannot race a symlink in between stat and open.
/// 3. If the file already exists, open it for append with `O_NOFOLLOW` (Unix) or
///    `FILE_FLAG_OPEN_REPARSE_POINT` (Windows) + a post-open symlink_metadata
///    re-check so a TOCTOU symlink swap is still rejected.
fn open_log_file(path: &Path) -> io::Result<File> {
    // Up-front symlink check. If the path resolves to a symlink we refuse
    // before any file handle is created.
    if let Ok(md) = std::fs::symlink_metadata(path) {
        if md.file_type().is_symlink() {
            tracing::error!(
                path = %path.display(),
                "pkcs11-spy: refusing to open log file: path is a symlink"
            );
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "pkcs11-spy: refusing to open symlink as log file",
            ));
        }
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        // First, attempt atomic create with O_EXCL semantics. This races safely:
        // if an attacker pre-creates a symlink at the path, create_new fails with
        // AlreadyExists, and we fall through to the existing-file open below which
        // sets O_NOFOLLOW and refuses the symlink.
        let create_flags = libc::O_NOFOLLOW | libc::O_CLOEXEC;
        match std::fs::OpenOptions::new()
            .create_new(true)
            .append(true)
            .custom_flags(create_flags)
            .open(path)
        {
            Ok(f) => Ok(f),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                // File exists — open without O_CREAT, but keep O_NOFOLLOW so the
                // kernel refuses the open if the path is a symlink.
                std::fs::OpenOptions::new()
                    .append(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(path)
            }
            Err(e) => Err(e),
        }
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_OPEN_REPARSE_POINT (0x00200000) opens the reparse point
        // itself rather than following it; combined with the symlink_metadata
        // re-check below, any symlink target is refused.
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x00200000;

        let f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;

        // Post-open re-check: if the path became a symlink between the up-front
        // probe and the open call, refuse now.
        if let Ok(md) = std::fs::symlink_metadata(path) {
            if md.file_type().is_symlink() {
                tracing::error!(
                    path = %path.display(),
                    "pkcs11-spy: refusing to open log file: path became a symlink during open"
                );
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "pkcs11-spy: refusing to open symlink as log file",
                ));
            }
        }
        Ok(f)
    }

    #[cfg(not(any(unix, windows)))]
    {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
    }
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
pub fn log_call(func: &str, args: &str) {
    with_logger(|logger| {
        let elapsed = logger.start.elapsed().as_secs_f64();
        let _ = writeln!(
            logger.writer,
            r#"{{"ts":{:.6},"fn":"{}","event":"call","args":{}}}"#,
            elapsed, func, args
        );
    });
}

/// Log a function return.
pub fn log_return(func: &str, rv: u64, duration_us: u64) {
    let rv_name = ckr_name(rv);
    with_logger(|logger| {
        let elapsed = logger.start.elapsed().as_secs_f64();

        if logger.reduced_timing {
            // Reduced precision: truncate to milliseconds to limit side-channel
            // leakage from crypto operation timing.
            let elapsed_ms = (elapsed * 1000.0).round() / 1000.0;
            let duration_ms = duration_us / 1000;
            let _ = writeln!(
                logger.writer,
                r#"{{"ts":{:.3},"fn":"{}","event":"return","rv":"{}","rv_code":{},"duration_ms":{}}}"#,
                elapsed_ms, func, rv_name, rv, duration_ms
            );
        } else {
            let _ = writeln!(
                logger.writer,
                r#"{{"ts":{:.6},"fn":"{}","event":"return","rv":"{}","rv_code":{},"duration_us":{}}}"#,
                elapsed, func, rv_name, rv, duration_us
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

#[cfg(all(test, unix))]
mod tests {
    use super::open_log_file;
    use std::os::unix::fs::symlink;

    #[test]
    fn open_log_file_refuses_symlink_targets() {
        let dir = tempfile::tempdir().expect("tempdir");
        // A direct (non-symlink) target should open fine.
        let direct = dir.path().join("direct.log");
        let f = open_log_file(&direct).expect("direct path opens");
        drop(f);
        assert!(direct.exists());

        // Create a real file and a symlink pointing at it.
        let real = dir.path().join("real.log");
        std::fs::write(&real, b"existing\n").expect("write real");
        let link = dir.path().join("link.log");
        symlink(&real, &link).expect("create symlink");

        let err = open_log_file(&link)
            .expect_err("symlinked path must be refused");
        // The real file's contents must be untouched.
        let after = std::fs::read(&real).expect("read real");
        assert_eq!(after, b"existing\n", "symlink target must not be modified");
        // We don't assert on a specific kind across platforms, but on Unix our
        // helper returns InvalidInput (refused up-front) or a kernel ELOOP via
        // O_NOFOLLOW; either is acceptable as long as the open fails.
        let _ = err;
    }

    #[test]
    fn open_log_file_creates_new_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("fresh.log");
        let mut f = open_log_file(&path).expect("create new");
        use std::io::Write;
        writeln!(f, "hello").expect("write");
        drop(f);
        // Reopen and append should also succeed.
        let mut f2 = open_log_file(&path).expect("reopen existing");
        writeln!(f2, "world").expect("append");
        let contents = std::fs::read_to_string(&path).expect("read");
        assert!(contents.contains("hello"));
        assert!(contents.contains("world"));
    }
}
