// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Dynamic loader for the real PKCS#11 library.
#![allow(non_camel_case_types)]

use libloading::{Library, Symbol};
use std::sync::OnceLock;

/// Opaque PKCS#11 type aliases (platform-independent for the spy wrapper).
pub type CK_ULONG = std::ffi::c_ulong;
pub type CK_RV = CK_ULONG;

static REAL_LIB: OnceLock<Library> = OnceLock::new();

/// Load the target PKCS#11 library from `PKCS11_SPY_TARGET` env var.
/// Returns the loaded library reference, or panics if missing/invalid.
///
/// SECURITY: The path is canonicalized to resolve symlinks and relative
/// components, and validated to be a regular file before loading. This
/// mitigates path traversal and symlink-based library injection attacks.
///
/// On Linux, the file is opened first, validated via fstat on the fd, then
/// loaded via `/proc/self/fd/<N>` to eliminate the TOCTOU race between
/// validation and dlopen. On other platforms, a double-check narrows the
/// window but cannot fully eliminate it.
fn load_library() -> &'static Library {
    REAL_LIB.get_or_init(|| {
        let raw_path = std::env::var("PKCS11_SPY_TARGET")
            .expect("PKCS11_SPY_TARGET environment variable must be set");

        // Canonicalize the path to resolve symlinks and relative components
        let canonical = std::fs::canonicalize(&raw_path)
            .unwrap_or_else(|e| panic!("PKCS11_SPY_TARGET path cannot be resolved: {}", e));

        // Ensure the target is a regular file (not a directory, device, etc.)
        let metadata = std::fs::metadata(&canonical)
            .unwrap_or_else(|e| panic!("Cannot read metadata for PKCS11_SPY_TARGET: {}", e));
        if !metadata.is_file() {
            panic!("PKCS11_SPY_TARGET must point to a regular file");
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
                    panic!(
                        "PKCS11_SPY_TARGET does not appear to be a shared library \
                         (expected .so, .dylib, or .dll extension)"
                    );
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

            let file = std::fs::File::open(&canonical)
                .unwrap_or_else(|e| panic!("Failed to open PKCS11_SPY_TARGET: {}", e));

            // Validate via fstat on the fd — immune to path-based TOCTOU
            let fd_metadata = file
                .metadata()
                .unwrap_or_else(|e| panic!("Failed to fstat PKCS11_SPY_TARGET fd: {}", e));
            if !fd_metadata.is_file() {
                panic!("PKCS11_SPY_TARGET fd is not a regular file");
            }

            // Load via /proc/self/fd/<N> — dlopen will use the already-opened fd's inode
            let fd_path = format!("/proc/self/fd/{}", file.as_raw_fd());
            let lib = unsafe {
                Library::new(&fd_path)
                    .unwrap_or_else(|e| panic!("Failed to load PKCS#11 library via fd: {}", e))
            };

            // The file handle is intentionally kept open (leaked) to prevent the
            // fd from being closed and reused before dlopen completes its own
            // reference. The OS will clean up on process exit.
            std::mem::forget(file);

            lib
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
                panic!("PKCS11_SPY_TARGET was replaced between validation and loading");
            }

            unsafe {
                Library::new(canonical.as_os_str())
                    .unwrap_or_else(|e| panic!("Failed to load PKCS#11 library: {}", e))
            }
        }
    })
}

/// Resolve a function symbol from the real library.
///
/// # Safety
/// The caller must ensure the function signature matches the real symbol.
pub unsafe fn resolve<T>(name: &[u8]) -> Option<Symbol<'static, T>> {
    let lib = load_library();
    unsafe { lib.get(name).ok() }
}

/// Helper: call a resolved function or return CKR_FUNCTION_NOT_SUPPORTED (0x54).
pub const CKR_FUNCTION_NOT_SUPPORTED: CK_RV = 0x54;
