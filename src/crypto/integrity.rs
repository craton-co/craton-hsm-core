// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! FIPS 140-3 §9.4 Software/Firmware Integrity Test
//!
//! Verifies an Ed25519 detached signature of the loaded module binary at
//! startup to ensure the code has not been tampered with.
//!
//! The Ed25519 **public key** is embedded as a compile-time constant (safe
//! to expose).  The corresponding **private key** is kept in the build
//! pipeline and never distributed — an attacker who modifies the binary
//! cannot forge a valid signature without it.
//!
//! In development mode (no `.sig` sidecar file present), the check logs a
//! warning and passes.  If the file is present but the signature doesn't
//! verify, the check fails and the module enters error state.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

/// Ed25519 public key for integrity verification.
///
/// Generate a real keypair with `tools/generate-integrity-keypair.sh` and
/// replace this placeholder with the output.  The corresponding private key
/// must be kept secret in the build pipeline.
///
/// # Security Properties
///
/// Unlike the previous HMAC-based approach, the public key is **safe to
/// embed** in the distributed binary.  An attacker with write access to the
/// binary and `.sig` file **cannot** forge a valid Ed25519 signature without
/// the private key (which never leaves the build environment).
///
/// This provides true tamper resistance, not just accidental-corruption
/// detection.
/// Set via the `CRATON_HSM_INTEGRITY_PUBLIC_KEY` env var at build time (64 hex chars).
/// If unset, defaults to all-zeros — the placeholder is detected at runtime and
/// signature verification is skipped with a warning (dev mode). Production builds
/// MUST set this env var; FIPS builds will fail if the key is still all-zeros.
const INTEGRITY_PUBLIC_KEY: [u8; 32] = {
    // Try to read the key from build-time environment variable.
    // Usage: CRATON_HSM_INTEGRITY_PUBLIC_KEY=<64 hex chars> cargo build --release
    const fn hex_nibble(b: u8) -> u8 {
        match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => panic!("CRATON_HSM_INTEGRITY_PUBLIC_KEY contains invalid hex character"),
        }
    }
    match option_env!("CRATON_HSM_INTEGRITY_PUBLIC_KEY") {
        Some(hex) => {
            let bytes = hex.as_bytes();
            assert!(
                bytes.len() == 64,
                "CRATON_HSM_INTEGRITY_PUBLIC_KEY must be exactly 64 hex chars"
            );
            let mut key = [0u8; 32];
            let mut i = 0;
            while i < 32 {
                key[i] = (hex_nibble(bytes[i * 2]) << 4) | hex_nibble(bytes[i * 2 + 1]);
                i += 1;
            }
            key
        }
        None => [0u8; 32], // Placeholder — detected at runtime
    }
};

/// Returns true if the integrity public key is still the all-zeros placeholder.
fn is_placeholder_key() -> bool {
    INTEGRITY_PUBLIC_KEY.iter().all(|&b| b == 0)
}

/// Run the software integrity check (POST §9.4).
///
/// Returns `Ok(())` if:
/// - The `.sig` sidecar file is missing (development mode, logs warning)
/// - The `.sig` file is present and the Ed25519 signature verifies
///
/// Returns `Err(...)` if:
/// - The `.sig` file is present but the signature doesn't verify (tampered binary)
/// - The module binary cannot be read (but `.sig` exists)
pub fn check_integrity() -> Result<(), String> {
    let module_path = match get_module_path() {
        Some(p) => p,
        None => {
            // Cannot determine module path — skip integrity check.
            // This is normal for test binaries, statically linked executables,
            // and some platform configurations.
            tracing::warn!("Software integrity test: could not determine module path — skipping");
            return Ok(());
        }
    };

    let sig_path = module_path.with_extension("sig");

    // Check for legacy .hmac sidecar and warn about migration
    let hmac_path = module_path.with_extension("hmac");
    if hmac_path.exists() && !sig_path.exists() {
        tracing::warn!(
            "Software integrity test: found legacy .hmac file at {} but no .sig file. \
             Migrate to Ed25519 signatures using tools/sign-integrity.sh. \
             The HMAC-based check has been removed.",
            hmac_path.display()
        );
    }

    // If no .sig sidecar file exists, skip the integrity check.
    // The .sig file is the opt-in mechanism: deployments that require FIPS
    // integrity verification generate the .sig file at build/install time.
    // Without it, the check passes — this covers development, testing, and
    // deployments that haven't opted in to integrity verification.
    //
    // When the `fips` feature is enabled, the signature file MUST be present.
    // Reject placeholder key in FIPS mode — production builds MUST set
    // CRATON_HSM_INTEGRITY_PUBLIC_KEY at build time.
    #[cfg(feature = "fips")]
    if is_placeholder_key() {
        return Err(
            "Software integrity test: INTEGRITY_PUBLIC_KEY is still the all-zeros placeholder. \
             Set CRATON_HSM_INTEGRITY_PUBLIC_KEY env var at build time for FIPS builds."
                .to_string(),
        );
    }

    if !sig_path.exists() {
        #[cfg(feature = "fips")]
        {
            return Err(format!(
                "Software integrity test: no .sig file found at {} — required in FIPS mode",
                sig_path.display()
            ));
        }
        #[cfg(not(feature = "fips"))]
        {
            tracing::info!(
                "Software integrity test: no .sig file at {} — skipping (opt-in via .sig sidecar)",
                sig_path.display()
            );
            return Ok(());
        }
    }

    // In non-FIPS mode, warn if placeholder key is used with a .sig file present
    if is_placeholder_key() {
        tracing::warn!(
            "Software integrity test: INTEGRITY_PUBLIC_KEY is the all-zeros placeholder. \
             Signature verification will fail. Set CRATON_HSM_INTEGRITY_PUBLIC_KEY at build time."
        );
    }

    // Read the expected signature from the sidecar file (hex-encoded, 128 chars = 64 bytes)
    let sig_hex = match std::fs::read_to_string(&sig_path) {
        Ok(s) => s.trim().to_lowercase(),
        Err(e) => {
            return Err(format!(
                "Software integrity test: failed to read {}: {}",
                sig_path.display(),
                e
            ));
        }
    };

    if sig_hex.len() != 128 {
        return Err(format!(
            "Software integrity test: .sig file has invalid length {} (expected 128 hex chars / 64 bytes)",
            sig_hex.len()
        ));
    }

    // Read the module binary
    let module_bytes = match std::fs::read(&module_path) {
        Ok(b) => b,
        Err(e) => {
            return Err(format!(
                "Software integrity test: failed to read module binary {}: {}",
                module_path.display(),
                e
            ));
        }
    };

    // Decode signature from hex
    let sig_bytes = hex::decode(&sig_hex).map_err(|e| {
        format!(
            "Software integrity test: .sig file contains invalid hex: {}",
            e
        )
    })?;

    // Compute SHA-256 hash of the module binary.
    // We sign/verify the hash rather than the raw binary — Ed25519 already
    // hashes internally (SHA-512), but pre-hashing allows the signing tool
    // to work with a fixed-size digest rather than streaming the entire binary.
    let hash = Sha256::digest(&module_bytes);

    // Parse the Ed25519 public key
    let verifying_key = VerifyingKey::from_bytes(&INTEGRITY_PUBLIC_KEY).map_err(|e| {
        format!(
            "Software integrity test: invalid embedded public key: {}",
            e
        )
    })?;

    // Parse the signature
    let sig_array: [u8; 64] = sig_bytes.try_into().map_err(|_| {
        "Software integrity test: signature has wrong length (expected 64 bytes)".to_string()
    })?;
    let signature = Signature::from_bytes(&sig_array);

    // Verify the Ed25519 signature over the SHA-256 hash.
    // Ed25519 verification is inherently constant-time.
    if verifying_key.verify(&hash, &signature).is_err() {
        tracing::error!(
            "Software integrity test FAILED: Ed25519 signature verification failed for {}",
            module_path.display()
        );
        // Do NOT log signature or hash values — this is defense in depth.
        tracing::error!("  Re-sign the binary with tools/sign-integrity.sh if this is expected.");
        return Err(
            "Software integrity test: signature verification failed — module may be tampered"
                .to_string(),
        );
    }

    tracing::info!(
        "Software integrity test passed for {}",
        module_path.display()
    );
    Ok(())
}

/// Compute the SHA-256 hash of a file (used by the signing tool).
///
/// Returns the hex-encoded SHA-256 digest of the file contents.
pub fn compute_hash(path: &std::path::Path) -> Result<String, String> {
    let module_bytes =
        std::fs::read(path).map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;

    let hash = Sha256::digest(&module_bytes);
    Ok(hex::encode(hash))
}

/// Determine the path of the currently loaded module.
///
/// On Unix: uses a function pointer address + `dladdr` to find the shared library path.
/// On Windows: uses `GetModuleHandleExW` to find the DLL path.
fn get_module_path() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        get_module_path_unix()
    }

    #[cfg(windows)]
    {
        get_module_path_windows()
    }

    #[cfg(not(any(unix, windows)))]
    {
        None
    }
}

#[cfg(unix)]
fn get_module_path_unix() -> Option<PathBuf> {
    use std::ffi::CStr;

    // Use a function pointer from our module as the address to look up
    let addr = check_integrity as *const () as *mut libc::c_void;

    let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
    let result = unsafe { libc::dladdr(addr, &mut info) };

    if result != 0 && !info.dli_fname.is_null() {
        let path = unsafe { CStr::from_ptr(info.dli_fname) };
        path.to_str().ok().map(PathBuf::from)
    } else {
        None
    }
}

#[cfg(windows)]
fn get_module_path_windows() -> Option<PathBuf> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    // GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS = 0x04
    // GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT = 0x02
    const FLAGS: u32 = 0x04 | 0x02;

    let addr = check_integrity as *const () as *const u8;
    let mut hmodule: windows_sys::Win32::Foundation::HMODULE = std::ptr::null_mut();

    let ok = unsafe {
        windows_sys::Win32::System::LibraryLoader::GetModuleHandleExW(
            FLAGS,
            addr as *const u16,
            &mut hmodule,
        )
    };

    if ok == 0 || hmodule.is_null() {
        return None;
    }

    let mut buf = vec![0u16; 4096];
    let len = unsafe {
        windows_sys::Win32::System::LibraryLoader::GetModuleFileNameW(
            hmodule,
            buf.as_mut_ptr(),
            buf.len() as u32,
        )
    };

    if len == 0 {
        return None;
    }

    let path = OsString::from_wide(&buf[..len as usize]);
    Some(PathBuf::from(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_hash_deterministic() {
        // Write a temp file, compute hash twice, verify same result
        let dir = std::env::temp_dir().join("craton_hsm_integrity_test");
        let _ = std::fs::create_dir_all(&dir);
        let test_file = dir.join("test_binary.bin");
        std::fs::write(&test_file, b"test module content").unwrap();

        let hash1 = compute_hash(&test_file).unwrap();
        let hash2 = compute_hash(&test_file).unwrap();
        assert_eq!(hash1, hash2, "SHA-256 hash should be deterministic");
        assert_eq!(hash1.len(), 64, "SHA-256 hex should be 64 chars");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_integrity_check_no_sig_file_passes() {
        // When no .sig file exists, check should pass (dev mode)
        // This test works because the test binary won't have a .sig sidecar
        assert!(check_integrity().is_ok());
    }

    #[test]
    fn test_different_content_different_hash() {
        let dir = std::env::temp_dir().join("craton_hsm_integrity_test2");
        let _ = std::fs::create_dir_all(&dir);

        let file1 = dir.join("file1.bin");
        let file2 = dir.join("file2.bin");
        std::fs::write(&file1, b"content A").unwrap();
        std::fs::write(&file2, b"content B").unwrap();

        let hash1 = compute_hash(&file1).unwrap();
        let hash2 = compute_hash(&file2).unwrap();
        assert_ne!(
            hash1, hash2,
            "Different content should produce different hash"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_signature_verification_roundtrip() {
        use ed25519_dalek::{Signer, SigningKey};

        // Generate a test keypair
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let verifying_key = signing_key.verifying_key();

        // Simulate: hash some content, sign it, verify it
        let content = b"test module binary content";
        let hash = Sha256::digest(content);
        let signature = signing_key.sign(&hash);

        assert!(
            verifying_key.verify(&hash, &signature).is_ok(),
            "Ed25519 signature should verify"
        );

        // Tampered content should fail
        let tampered = b"tampered module binary content";
        let tampered_hash = Sha256::digest(tampered);
        assert!(
            verifying_key.verify(&tampered_hash, &signature).is_err(),
            "Tampered content should fail verification"
        );
    }
}
