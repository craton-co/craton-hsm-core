// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Dynamic loader for the real PKCS#11 library.
#![allow(non_camel_case_types)]

use libloading::{Library, Symbol};
use std::sync::OnceLock;

/// Opaque PKCS#11 type aliases (platform-independent for the spy wrapper).
pub type CK_ULONG = std::ffi::c_ulong;
pub type CK_RV = CK_ULONG;

// Store an `Option<Library>` so a load failure cached as `None` does not cause
// the next call to retry (and re-log) the same error, but also does not panic
// across the FFI boundary. Spy exports translate `None` into
// CKR_FUNCTION_NOT_SUPPORTED so a misconfigured spy degrades gracefully
// instead of crashing the host process.
static REAL_LIB: OnceLock<Option<Library>> = OnceLock::new();

/// Load the target PKCS#11 library from `PKCS11_SPY_TARGET` env var.
/// Returns `Some(&Library)` on success, or `None` if the env var is missing,
/// the path cannot be resolved, the file is not a regular shared library,
/// or `dlopen` fails. Failures are logged via the spy `logger` module.
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
/// SECURITY: Callers (the spy `extern "C"` exports) are also wrapped in
/// `std::panic::catch_unwind`, so even if a future change reintroduces a
/// panic in this function it cannot unwind across the C ABI boundary.
fn load_library() -> Option<&'static Library> {
    REAL_LIB
        .get_or_init(|| {
            let raw_path = match std::env::var("PKCS11_SPY_TARGET") {
                Ok(p) => p,
                Err(_) => {
                    crate::logger::log_loader_error(
                        "PKCS11_SPY_TARGET environment variable must be set",
                    );
                    return None;
                }
            };

            // Canonicalize the path to resolve symlinks and relative components
            let canonical = match std::fs::canonicalize(&raw_path) {
                Ok(c) => c,
                Err(e) => {
                    crate::logger::log_loader_error(&format!(
                        "PKCS11_SPY_TARGET path cannot be resolved: {}",
                        e
                    ));
                    return None;
                }
            };

            // Ensure the target is a regular file (not a directory, device, etc.)
            let metadata = match std::fs::metadata(&canonical) {
                Ok(m) => m,
                Err(e) => {
                    crate::logger::log_loader_error(&format!(
                        "Cannot read metadata for PKCS11_SPY_TARGET: {}",
                        e
                    ));
                    return None;
                }
            };
            if !metadata.is_file() {
                crate::logger::log_loader_error(
                    "PKCS11_SPY_TARGET must point to a regular file",
                );
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
                        crate::logger::log_loader_error(
                            "PKCS11_SPY_TARGET does not appear to be a shared library \
                             (expected .so, .dylib, or .dll extension)",
                        );
                        return None;
                    }
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
                        crate::logger::log_loader_error(&format!(
                            "Failed to open PKCS11_SPY_TARGET: {}",
                            e
                        ));
                        return None;
                    }
                };

                // Validate via fstat on the fd — immune to path-based TOCTOU
                let fd_metadata = match file.metadata() {
                    Ok(m) => m,
                    Err(e) => {
                        crate::logger::log_loader_error(&format!(
                            "Failed to fstat PKCS11_SPY_TARGET fd: {}",
                            e
                        ));
                        return None;
                    }
                };
                if !fd_metadata.is_file() {
                    crate::logger::log_loader_error(
                        "PKCS11_SPY_TARGET fd is not a regular file",
                    );
                    return None;
                }

                // Load via /proc/self/fd/<N> — dlopen will use the already-opened fd's inode
                let fd_path = format!("/proc/self/fd/{}", file.as_raw_fd());
                let lib = match unsafe { Library::new(&fd_path) } {
                    Ok(l) => l,
                    Err(e) => {
                        crate::logger::log_loader_error(&format!(
                            "Failed to load PKCS#11 library via fd: {}",
                            e
                        ));
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
                    crate::logger::log_loader_error(
                        "PKCS11_SPY_TARGET was replaced between validation and loading",
                    );
                    return None;
                }

                match unsafe { Library::new(canonical.as_os_str()) } {
                    Ok(lib) => Some(lib),
                    Err(e) => {
                        crate::logger::log_loader_error(&format!(
                            "Failed to load PKCS#11 library: {}",
                            e
                        ));
                        None
                    }
                }
            }
        })
        .as_ref()
}

/// Resolve a function symbol from the real library.
///
/// Returns `None` if the library could not be loaded OR if the symbol does
/// not exist in the library. Callers (the spy exports) translate `None`
/// into CKR_FUNCTION_NOT_SUPPORTED.
///
/// # Safety
/// The caller must ensure the function signature matches the real symbol.
pub unsafe fn resolve<T>(name: &[u8]) -> Option<Symbol<'static, T>> {
    let lib = load_library()?;
    unsafe { lib.get(name).ok() }
}

/// Helper: call a resolved function or return CKR_FUNCTION_NOT_SUPPORTED (0x54).
pub const CKR_FUNCTION_NOT_SUPPORTED: CK_RV = 0x54;

/// CKR_GENERAL_ERROR (0x05) — returned by spy exports when a panic is caught
/// in the FFI boundary wrapper. Exposed here so `lib.rs` macros can reference
/// it via the `loader` module without depending on `logger` for constants.
pub const CKR_GENERAL_ERROR: CK_RV = 0x05;
