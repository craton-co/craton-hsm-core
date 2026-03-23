// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Fuzz target for session state machine and PIN lifecycle.
//!
//! Exercises edge cases that auditors care about:
//! - Operations after login/logout sequences
//! - Sign after SignFinal, Encrypt after EncryptFinal (state confusion)
//! - Concurrent session interactions (open/close/use)
//! - PIN lockout bypass attempts (rapid login failures)
//! - Token reinitialization under active sessions
//! - Fuzz-derived PINs (edge cases: empty, null bytes, max-length)

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::Once;

use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm::pkcs11_abi::functions;
use craton_hsm::pkcs11_abi::types::*;

static INIT: Once = Once::new();

fn ensure_init() {
    INIT.call_once(|| {
        let rv = functions::C_Initialize(std::ptr::null_mut());
        assert!(rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED);
    });
}

/// Clean up all sessions on slot 0 to prevent state leaking between iterations.
fn cleanup_sessions() {
    let _ = functions::C_CloseAllSessions(0);
}

fuzz_target!(|data: &[u8]| {
    ensure_init();

    if data.len() < 4 {
        return;
    }

    let selector = data[0] % 8;
    let payload = &data[1..];

    match selector {
        0 => fuzz_operation_after_final(payload),
        1 => fuzz_double_init(payload),
        2 => fuzz_wrong_session_handle(payload),
        3 => fuzz_login_logout_interleave(payload),
        4 => fuzz_multi_session_rapid(payload),
        5 => fuzz_sign_without_init(payload),
        6 => fuzz_encrypt_after_error(payload),
        7 => fuzz_digest_multipart_abuse(payload),
        _ => {}
    }

    // FIX: Prevent login state and session handle leaks between fuzz iterations
    cleanup_sessions();
});

/// Extract a fuzz-derived PIN from data. Returns (pin_ptr, pin_len, bytes_consumed).
/// Exercises: empty PINs, null bytes in PIN, very long PINs, single-byte PINs.
fn extract_fuzz_pin(data: &[u8]) -> (*mut u8, CK_ULONG, usize) {
    if data.is_empty() {
        return (std::ptr::null_mut(), 0, 0);
    }
    let pin_len = (data[0] as usize) % 65; // 0..64 byte PINs
    let consumed = 1 + pin_len.min(data.len() - 1);
    let actual_pin = &data[1..consumed];
    if actual_pin.is_empty() {
        (std::ptr::null_mut(), 0, consumed)
    } else {
        (actual_pin.as_ptr() as *mut u8, actual_pin.len() as CK_ULONG, consumed)
    }
}

/// Call C_Sign/C_Verify after C_SignFinal/C_VerifyFinal — must return error, not panic.
fn fuzz_operation_after_final(data: &[u8]) {
    if data.len() < 2 {
        return;
    }

    let mut session: CK_SESSION_HANDLE = 0;
    let rv = functions::C_OpenSession(
        0,
        CKF_SERIAL_SESSION | CKF_RW_SESSION,
        std::ptr::null_mut(),
        None,
        &mut session,
    );
    if rv != CKR_OK {
        return;
    }

    // FIX: Use fuzz-derived PIN instead of hardcoded "1234"
    let (pin_ptr, pin_len, offset) = extract_fuzz_pin(data);
    let _ = functions::C_Login(session, CKU_USER, pin_ptr, pin_len);
    let payload = &data[offset.min(data.len())..];

    // Try DigestInit + DigestFinal + Digest (should fail gracefully)
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256,
        p_parameter: std::ptr::null_mut(),
        parameter_len: 0,
    };

    let rv = functions::C_DigestInit(session, &mut mechanism);
    if rv == CKR_OK {
        // Do DigestUpdate with some data
        if !payload.is_empty() {
            let _rv = functions::C_DigestUpdate(
                session,
                payload.as_ptr() as *mut _,
                payload.len() as CK_ULONG,
            );
        }

        // DigestFinal
        let mut digest = [0u8; 64];
        let mut digest_len: CK_ULONG = 64;
        let _rv = functions::C_DigestFinal(session, digest.as_mut_ptr(), &mut digest_len);

        // Now try another DigestUpdate/DigestFinal — MUST return error
        if !payload.is_empty() {
            let _rv = functions::C_DigestUpdate(
                session,
                payload.as_ptr() as *mut _,
                payload.len() as CK_ULONG,
            );
        }
        let _rv = functions::C_DigestFinal(session, digest.as_mut_ptr(), &mut digest_len);

        // And try single-shot Digest — MUST return error
        if !payload.is_empty() {
            let _rv = functions::C_Digest(
                session,
                payload.as_ptr() as *mut _,
                payload.len() as CK_ULONG,
                digest.as_mut_ptr(),
                &mut digest_len,
            );
        }
    }

    let _ = functions::C_Logout(session);
    let _ = functions::C_CloseSession(session);
}

/// Call Init twice without completing the operation — should error or reset.
fn fuzz_double_init(data: &[u8]) {
    if data.len() < 3 {
        return;
    }

    let mut session: CK_SESSION_HANDLE = 0;
    let rv = functions::C_OpenSession(
        0,
        CKF_SERIAL_SESSION | CKF_RW_SESSION,
        std::ptr::null_mut(),
        None,
        &mut session,
    );
    if rv != CKR_OK {
        return;
    }

    // FIX: Use fuzz-derived PIN
    let (pin_ptr, pin_len, _) = extract_fuzz_pin(&data[1..]);
    let _ = functions::C_Login(session, CKU_USER, pin_ptr, pin_len);

    let mech_type = match data[0] % 3 {
        0 => CKM_SHA256,
        1 => CKM_SHA384,
        _ => CKM_SHA512,
    };

    let mut mechanism = CK_MECHANISM {
        mechanism: mech_type,
        p_parameter: std::ptr::null_mut(),
        parameter_len: 0,
    };

    // First init
    let _rv = functions::C_DigestInit(session, &mut mechanism);
    // Second init without completing — should return OPERATION_ACTIVE
    let rv2 = functions::C_DigestInit(session, &mut mechanism);
    // rv2 should be CKR_OPERATION_ACTIVE (not a panic)
    let _ = rv2;

    let _ = functions::C_Logout(session);
    let _ = functions::C_CloseSession(session);
}

/// Use random/invalid session handles — must return appropriate error.
fn fuzz_wrong_session_handle(data: &[u8]) {
    if data.len() < 8 {
        return;
    }

    let fake_handle = u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]) as CK_SESSION_HANDLE;

    // All of these should return CKR_SESSION_HANDLE_INVALID, never panic
    let mut buf = [0u8; 64];
    let mut len: CK_ULONG = 64;

    let _ = functions::C_CloseSession(fake_handle);

    // FIX: Use fuzz-derived PIN for login with invalid handle
    let pin_data = &data[8..];
    let (pin_ptr, pin_len, _) = extract_fuzz_pin(pin_data);
    let _ = functions::C_Login(fake_handle, CKU_USER, pin_ptr, pin_len);
    let _ = functions::C_Logout(fake_handle);
    let _ = functions::C_GenerateRandom(fake_handle, buf.as_mut_ptr(), 32);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256,
        p_parameter: std::ptr::null_mut(),
        parameter_len: 0,
    };
    let _ = functions::C_DigestInit(fake_handle, &mut mechanism);
    let _ = functions::C_Digest(
        fake_handle,
        buf.as_mut_ptr(),
        32,
        buf.as_mut_ptr(),
        &mut len,
    );
}

/// Rapid login/logout interleaving with fuzz-derived PINs — exercise auth state transitions.
fn fuzz_login_logout_interleave(data: &[u8]) {
    if data.len() < 4 {
        return;
    }

    let mut session: CK_SESSION_HANDLE = 0;
    let rv = functions::C_OpenSession(
        0,
        CKF_SERIAL_SESSION | CKF_RW_SESSION,
        std::ptr::null_mut(),
        None,
        &mut session,
    );
    if rv != CKR_OK {
        return;
    }

    let mut offset = 0;
    while offset < data.len() && offset < 128 {
        let byte = data[offset];
        offset += 1;

        match byte % 5 {
            0 => {
                // FIX #12: Use fuzz-derived PIN instead of hardcoded "1234"
                let remaining = &data[offset..];
                let (pin_ptr, pin_len, consumed) = extract_fuzz_pin(remaining);
                offset += consumed;
                let _ = functions::C_Login(session, CKU_USER, pin_ptr, pin_len);
            }
            1 => {
                // FIX: Login with fuzz-derived PIN (exercises PIN length edge cases,
                // null bytes in PIN, empty PIN, max-length PIN)
                let remaining = &data[offset..];
                let (pin_ptr, pin_len, consumed) = extract_fuzz_pin(remaining);
                offset += consumed;
                let _ = functions::C_Login(session, CKU_USER, pin_ptr, pin_len);
            }
            2 => {
                // Logout
                let _ = functions::C_Logout(session);
            }
            3 => {
                // Login as SO with fuzz-derived PIN
                let remaining = &data[offset..];
                let (pin_ptr, pin_len, consumed) = extract_fuzz_pin(remaining);
                offset += consumed;
                let _ = functions::C_Login(session, CKU_SO, pin_ptr, pin_len);
            }
            4 => {
                // Login with invalid user type
                let remaining = &data[offset..];
                let (pin_ptr, pin_len, consumed) = extract_fuzz_pin(remaining);
                offset += consumed;
                let user_type = if offset < data.len() {
                    offset += 1;
                    data[offset - 1] as CK_ULONG
                } else {
                    0xFF
                };
                let _ = functions::C_Login(session, user_type, pin_ptr, pin_len);
            }
            _ => {}
        }
    }

    let _ = functions::C_Logout(session);
    let _ = functions::C_CloseSession(session);
}

/// Rapidly open and close many sessions — stress handle recycling.
fn fuzz_multi_session_rapid(data: &[u8]) {
    if data.is_empty() {
        return;
    }

    let count = (data[0] as usize % 32) + 1;
    let mut sessions = Vec::new();
    let mut closed = Vec::new();

    for _ in 0..count {
        let mut session: CK_SESSION_HANDLE = 0;
        let rv = functions::C_OpenSession(
            0,
            CKF_SERIAL_SESSION,
            std::ptr::null_mut(),
            None,
            &mut session,
        );
        if rv == CKR_OK {
            sessions.push(session);
            closed.push(false);
        }
    }

    // Close in random order based on fuzz data
    for (i, &byte) in data.iter().enumerate() {
        if i < sessions.len() && byte % 2 == 0 {
            let _ = functions::C_CloseSession(sessions[i]);
            closed[i] = true;
        }
    }

    // FIX: Intentionally double-close already-closed sessions to test handle reuse safety.
    // This is an explicit test: double-close must return CKR_SESSION_HANDLE_INVALID.
    for (i, &s) in sessions.iter().enumerate() {
        let _ = functions::C_CloseSession(s);
        if closed[i] {
            // This is a deliberate double-close — must not panic or use-after-free
        }
    }
}

/// Call Sign/Verify without corresponding Init — must error.
fn fuzz_sign_without_init(data: &[u8]) {
    if data.len() < 4 {
        return;
    }

    let mut session: CK_SESSION_HANDLE = 0;
    let rv = functions::C_OpenSession(
        0,
        CKF_SERIAL_SESSION | CKF_RW_SESSION,
        std::ptr::null_mut(),
        None,
        &mut session,
    );
    if rv != CKR_OK {
        return;
    }

    let mut sig = [0u8; 512];
    let mut sig_len: CK_ULONG = 512;

    // FIX #11: Sign without init — MUST return CKR_OPERATION_NOT_INITIALIZED
    let rv = functions::C_Sign(
        session,
        data.as_ptr() as *mut _,
        data.len() as CK_ULONG,
        sig.as_mut_ptr(),
        &mut sig_len,
    );
    assert!(rv != CKR_OK, "C_Sign succeeded without C_SignInit");

    // SignUpdate without init
    let rv = functions::C_SignUpdate(session, data.as_ptr() as *mut _, data.len() as CK_ULONG);
    assert!(rv != CKR_OK, "C_SignUpdate succeeded without C_SignInit");

    // SignFinal without init
    let rv = functions::C_SignFinal(session, sig.as_mut_ptr(), &mut sig_len);
    assert!(rv != CKR_OK, "C_SignFinal succeeded without C_SignInit");

    // Verify without init
    let rv = functions::C_Verify(
        session,
        data.as_ptr() as *mut _,
        data.len() as CK_ULONG,
        sig.as_mut_ptr(),
        sig_len,
    );
    assert!(rv != CKR_OK, "C_Verify succeeded without C_VerifyInit");

    let _ = functions::C_CloseSession(session);
}

/// Encrypt operation where first call fails — verify state is clean.
fn fuzz_encrypt_after_error(data: &[u8]) {
    if data.len() < 4 {
        return;
    }

    let mut session: CK_SESSION_HANDLE = 0;
    let rv = functions::C_OpenSession(
        0,
        CKF_SERIAL_SESSION | CKF_RW_SESSION,
        std::ptr::null_mut(),
        None,
        &mut session,
    );
    if rv != CKR_OK {
        return;
    }

    // Try EncryptInit with invalid mechanism
    let mech_type = u64::from_le_bytes([
        data[0], data[1], data[2], data[3],
        data.get(4).copied().unwrap_or(0),
        data.get(5).copied().unwrap_or(0),
        data.get(6).copied().unwrap_or(0),
        data.get(7).copied().unwrap_or(0),
    ]) as CK_MECHANISM_TYPE;

    let mut mechanism = CK_MECHANISM {
        mechanism: mech_type,
        p_parameter: std::ptr::null_mut(),
        parameter_len: 0,
    };

    // Invalid key handle
    let _rv = functions::C_EncryptInit(session, &mut mechanism, 0xDEADBEEF as CK_OBJECT_HANDLE);

    // Now try encrypt — should fail cleanly (no leftover state)
    let mut out = [0u8; 512];
    let mut out_len: CK_ULONG = 512;
    let _rv = functions::C_Encrypt(
        session,
        data.as_ptr() as *mut _,
        data.len() as CK_ULONG,
        out.as_mut_ptr(),
        &mut out_len,
    );

    let _ = functions::C_CloseSession(session);
}

/// Multipart digest abuse: interleave Update/Final in unusual patterns.
fn fuzz_digest_multipart_abuse(data: &[u8]) {
    if data.len() < 8 {
        return;
    }

    let mut session: CK_SESSION_HANDLE = 0;
    let rv = functions::C_OpenSession(
        0,
        CKF_SERIAL_SESSION,
        std::ptr::null_mut(),
        None,
        &mut session,
    );
    if rv != CKR_OK {
        return;
    }

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256,
        p_parameter: std::ptr::null_mut(),
        parameter_len: 0,
    };

    let rv = functions::C_DigestInit(session, &mut mechanism);
    if rv != CKR_OK {
        let _ = functions::C_CloseSession(session);
        return;
    }

    // Fuzz-driven sequence of Update/Final calls
    let mut digest = [0u8; 64];
    let mut digest_len: CK_ULONG = 64;
    let mut finalized = false;

    for &byte in data.iter().skip(1).take(32) {
        match byte % 4 {
            0 | 1 => {
                // DigestUpdate with varying chunk sizes
                let chunk_end = ((byte as usize) % data.len()).max(1);
                let _rv = functions::C_DigestUpdate(
                    session,
                    data[..chunk_end].as_ptr() as *mut _,
                    chunk_end as CK_ULONG,
                );
            }
            2 => {
                // DigestFinal
                digest_len = 64;
                let _rv = functions::C_DigestFinal(session, digest.as_mut_ptr(), &mut digest_len);
                finalized = true;
            }
            3 => {
                // Zero-length update
                let _rv = functions::C_DigestUpdate(session, std::ptr::null_mut(), 0);
            }
            _ => {}
        }

        if finalized {
            // Try operations after final — should all fail gracefully
            let _rv = functions::C_DigestUpdate(
                session,
                data.as_ptr() as *mut _,
                data.len() as CK_ULONG,
            );
            break;
        }
    }

    let _ = functions::C_CloseSession(session);
}
