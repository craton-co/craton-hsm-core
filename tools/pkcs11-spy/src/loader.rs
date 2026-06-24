// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Dynamic loader for the real PKCS#11 library.
#![allow(non_camel_case_types)]

use libloading::{Library, Symbol};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::sync::OnceLock;

/// Opaque PKCS#11 type aliases (platform-independent for the spy wrapper).
pub type CK_ULONG = std::ffi::c_ulong;
pub type CK_RV = CK_ULONG;

static REAL_LIB: OnceLock<Option<Library>> = OnceLock::new();

/// Errors returned by the loader when verifying the target module.
#[derive(Debug)]
pub enum LoaderError {
    /// The expected hex digest was not a 64-character lowercase hex string.
    InvalidExpectedDigest(String),
    /// I/O error while reading the target module for hashing.
    Io(io::Error),
    /// The computed digest did not match the expected digest.
    Mismatch { expected: String, actual: String },
}

impl fmt::Display for LoaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoaderError::InvalidExpectedDigest(s) => write!(
                f,
                "PKCS11_SPY_EXPECTED_SHA256 must be a 64-character hex-encoded SHA-256 digest \
                 (got {:?})",
                s
            ),
            LoaderError::Io(e) => write!(f, "I/O error while hashing PKCS11_SPY_TARGET: {}", e),
            LoaderError::Mismatch { expected, actual } => write!(
                f,
                "PKCS11_SPY_TARGET SHA-256 mismatch: expected {}, got {}",
                expected, actual
            ),
        }
    }
}

impl std::error::Error for LoaderError {}

impl From<io::Error> for LoaderError {
    fn from(e: io::Error) -> Self {
        LoaderError::Io(e)
    }
}

/// Stream the file at `path` through SHA-256 and verify against `expected_hex`.
///
/// The file is read in fixed-size chunks so that arbitrarily large shared
/// objects do not require an in-memory copy. Any I/O error and any malformed
/// `expected_hex` are treated as verification failures (fail-closed).
pub(crate) fn verify_sha256(path: &Path, expected_hex: &str) -> Result<(), LoaderError> {
    // Normalize the expected digest to lowercase for comparison and validate length.
    let expected_norm = expected_hex.trim().to_ascii_lowercase();
    if expected_norm.len() != 64 || !expected_norm.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(LoaderError::InvalidExpectedDigest(expected_hex.to_string()));
    }

    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let actual = hex::encode(hasher.finalize());

    if actual != expected_norm {
        return Err(LoaderError::Mismatch {
            expected: expected_norm,
            actual,
        });
    }
    Ok(())
}

/// Emit a one-shot warning that provenance verification is disabled.
fn warn_provenance_unverified_once() {
    static WARNED: OnceLock<()> = OnceLock::new();
    WARNED.get_or_init(|| {
        tracing::warn!(
            "PKCS11_SPY_EXPECTED_SHA256 is not set \u{2014} module provenance is not verified. \
             Set this to the expected SHA-256 of the PKCS#11 module to harden against substitution."
        );
    });
}

/// Load the target PKCS#11 library from `PKCS11_SPY_TARGET` env var.
/// Returns the loaded library reference, or `None` if the env var is unset,
/// the path cannot be resolved, SHA-256 verification failed, or any other
/// configuration error occurs (all errors are logged and treated as
/// `CKR_FUNCTION_NOT_SUPPORTED`; this function never panics).
///
/// SECURITY: The path is canonicalized to resolve symlinks and relative
/// components, and validated to be a regular file before loading. This
/// mitigates path traversal and symlink-based library injection attacks.
///
/// On Linux, the file is opened first, validated via fstat on the fd, then
/// loaded via `/proc/self/fd/<N>` to eliminate the TOCTOU race between
/// validation and dlopen. On other platforms, a double-check narrows the
/// window but cannot fully eliminate it.
///
/// If `PKCS11_SPY_EXPECTED_SHA256` is set, the canonical target file is
/// streamed through SHA-256 and the digest is compared against the env var.
/// Mismatch, I/O error, or malformed expected digest all cause this function
/// to return `None` (fail-closed). If the env var is unset, a one-shot
/// `tracing::warn!` is emitted noting that provenance is not verified.
fn load_library() -> Option<&'static Library> {
    REAL_LIB
        .get_or_init(|| {
            let raw_path = match std::env::var("PKCS11_SPY_TARGET") {
                Ok(p) => p,
                Err(_) => {
                    tracing::debug!("PKCS11_SPY_TARGET not set; spy passthrough disabled");
                    return None;
                }
            };

            // Canonicalize the path to resolve symlinks and relative components
            let canonical = match std::fs::canonicalize(&raw_path) {
                Ok(p) => p,
                Err(e) => {
                    tracing::error!("PKCS11_SPY_TARGET path cannot be resolved: {}", e);
                    return None;
                }
            };

            // Ensure the target is a regular file (not a directory, device, etc.)
            let metadata = match std::fs::metadata(&canonical) {
                Ok(m) => m,
                Err(e) => {
                    tracing::error!("Cannot read metadata for PKCS11_SPY_TARGET: {}", e);
                    return None;
                }
            };
            if !metadata.is_file() {
                crate::logger::log_loader_error("PKCS11_SPY_TARGET must point to a regular file");
                return None;
            }

            // Validate the file extension looks like a shared library
            let ext = canonical.extension().and_then(|e| e.to_str()).unwrap_or("");
            match ext {
                "so" | "dylib" | "dll" => {}
                _ => {
                    // Allow versioned .so files (e.g., libfoo.so.1.2.3) by checking
                    // if ".so" appears in the filename
                    let name = canonical.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    if !name.contains(".so") {
                        tracing::error!(
                            "PKCS11_SPY_TARGET does not appear to be a shared library \
                             (expected .so, .dylib, or .dll extension)"
                        );
                        return None;
                    }
                }
            }

            // --- Provenance check (fail-closed) ---
            //
            // If PKCS11_SPY_EXPECTED_SHA256 is set, stream the canonical file through
            // SHA-256 and refuse to load on mismatch / I/O error / malformed digest.
            // If it is unset, warn once that provenance is not verified.
            match std::env::var("PKCS11_SPY_EXPECTED_SHA256") {
                Ok(expected) => {
                    if let Err(e) = verify_sha256(&canonical, &expected) {
                        tracing::error!(
                            "Refusing to load PKCS11_SPY_TARGET: {} \
                             (path={})",
                            e,
                            canonical.display()
                        );
                        return None;
                    }
                }
                Err(_) => {
                    warn_provenance_unverified_once();
                }
            }

            // --- TOCTOU-safe loading ---
            //
            // On Linux: open the file, validate via fstat on the fd (not the path),
            // then load via /proc/self/fd/<N>. This eliminates the race between
            // validation and dlopen — the fd pins the inode so the file cannot be
            // swapped between stat and load.
            //
            // On other platforms: fall back to a double-check which narrows but
            // does not eliminate the window.
            #[cfg(target_os = "linux")]
            {
                use std::os::unix::io::AsRawFd;

                let file = match std::fs::File::open(&canonical) {
                    Ok(f) => f,
                    Err(e) => {
                        tracing::error!("Failed to open PKCS11_SPY_TARGET: {}", e);
                        return None;
                    }
                };

                // Validate via fstat on the fd — immune to path-based TOCTOU
                let fd_metadata = match file.metadata() {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::error!("Failed to fstat PKCS11_SPY_TARGET fd: {}", e);
                        return None;
                    }
                };
                if !fd_metadata.is_file() {
                    crate::logger::log_loader_error("PKCS11_SPY_TARGET fd is not a regular file");
                    return None;
                }

                // Load via /proc/self/fd/<N> — dlopen will use the already-opened fd's inode
                let fd_path = format!("/proc/self/fd/{}", file.as_raw_fd());
                let lib = match unsafe { Library::new(&fd_path) } {
                    Ok(l) => l,
                    Err(e) => {
                        tracing::error!("Failed to load PKCS#11 library via fd: {}", e);
                        return None;
                    }
                };

                // The file handle is intentionally kept open (leaked) to prevent the
                // fd from being closed and reused before dlopen completes its own
                // reference. The OS will clean up on process exit.
                std::mem::forget(file);

                Some(lib)
            }

            #[cfg(not(target_os = "linux"))]
            {
                // Re-verify the canonical path is still a regular file immediately before
                // loading to narrow the TOCTOU window (canonicalize → metadata → load).
                // This cannot fully eliminate the race, but makes exploitation harder.
                if !std::fs::metadata(&canonical)
                    .map(|m| m.is_file())
                    .unwrap_or(false)
                {
                    tracing::error!(
                        "PKCS11_SPY_TARGET was replaced between validation and loading"
                    );
                    return None;
                }

                let lib = match unsafe { Library::new(canonical.as_os_str()) } {
                    Ok(l) => l,
                    Err(e) => {
                        tracing::error!("Failed to load PKCS#11 library: {}", e);
                        return None;
                    }
                };
                Some(lib)
            }
        })
        .as_ref()
}

/// Resolve a function symbol from the real library.
///
/// # Safety
/// The caller must ensure the function signature matches the real symbol.
pub unsafe fn resolve<T>(name: &[u8]) -> Option<Symbol<'static, T>> {
    let lib = load_library()?;
    unsafe { lib.get(name).ok() }
}

/// Helper: call a resolved function or return CKR_FUNCTION_NOT_SUPPORTED (0x54).
pub const CKR_FUNCTION_NOT_SUPPORTED: CK_RV = 0x54;
pub const CKR_GENERAL_ERROR: CK_RV = 0x05;

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_tempfile(bytes: &[u8]) -> NamedTempFile {
        let mut f = NamedTempFile::new().expect("create tempfile");
        f.write_all(bytes).expect("write tempfile");
        f.flush().expect("flush tempfile");
        f
    }

    #[test]
    fn verify_sha256_matches_known_digest() {
        let payload = b"craton-hsm pkcs11-spy provenance test vector \xde\xad\xbe\xef";
        let tmp = write_tempfile(payload);

        // Compute the expected digest independently of verify_sha256.
        let mut hasher = Sha256::new();
        hasher.update(payload);
        let expected = hex::encode(hasher.finalize());

        verify_sha256(tmp.path(), &expected).expect("matching digest must verify");
    }

    #[test]
    fn verify_sha256_rejects_wrong_digest() {
        let tmp = write_tempfile(b"some-other-payload");
        // 64 hex zeros — definitely not the SHA-256 of the payload above.
        let wrong = "0".repeat(64);
        let err = verify_sha256(tmp.path(), &wrong).expect_err("wrong digest must fail");
        assert!(matches!(err, LoaderError::Mismatch { .. }), "got {err:?}");
    }

    #[test]
    fn verify_sha256_rejects_malformed_expected() {
        let tmp = write_tempfile(b"any-payload");
        // Too short.
        let err = verify_sha256(tmp.path(), "deadbeef").expect_err("short hex must fail");
        assert!(
            matches!(err, LoaderError::InvalidExpectedDigest(_)),
            "got {err:?}"
        );
        // Non-hex characters.
        let bad = "zz".repeat(32);
        let err = verify_sha256(tmp.path(), &bad).expect_err("non-hex must fail");
        assert!(
            matches!(err, LoaderError::InvalidExpectedDigest(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn verify_sha256_io_error_on_missing_file() {
        let tmp = write_tempfile(b"will-be-deleted");
        let path = tmp.path().to_path_buf();
        drop(tmp); // Closes and removes the file.
        let expected = "0".repeat(64); // valid hex shape, but file is gone
        let err = verify_sha256(&path, &expected).expect_err("missing file must fail");
        assert!(matches!(err, LoaderError::Io(_)), "got {err:?}");
    }
}
