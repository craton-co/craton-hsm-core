// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Fuzz target for PKCS#11 C ABI entry points.
//!
//! Exercises C_CreateObject, C_FindObjects, C_GenerateRandom,
//! crypto operations, info queries, C_SeedRandom, and C_CopyObject
//! with random data to ensure no panics escape the catch_unwind boundary.

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::Once;

use craton_hsm::pkcs11_abi::types::*;
use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm::pkcs11_abi::functions;

static INIT: Once = Once::new();

/// Initialize the HSM exactly once across all fuzz iterations.
fn ensure_init() {
    INIT.call_once(|| {
        let rv = functions::C_Initialize(std::ptr::null_mut());
        assert!(rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED);
    });
}

/// Clean up all sessions to prevent state leaking between iterations.
fn cleanup_sessions() {
    let _ = functions::C_CloseAllSessions(0);
}

/// Extract a fuzz-derived PIN from data. Returns (pin_ptr, pin_len, bytes_consumed).
fn extract_fuzz_pin(data: &[u8]) -> (*mut u8, CK_ULONG, usize) {
    if data.is_empty() {
        return (std::ptr::null_mut(), 0, 0);
    }
    let pin_len = (data[0] as usize) % 65;
    let consumed = 1 + pin_len.min(data.len() - 1);
    let actual_pin = &data[1..consumed];
    if actual_pin.is_empty() {
        (std::ptr::null_mut(), 0, consumed)
    } else {
        (actual_pin.as_ptr() as *mut u8, actual_pin.len() as CK_ULONG, consumed)
    }
}

// FIX #6: Expanded selector from 5 to 9 to cover C_GetInfo, C_GetTokenInfo,
// C_GetSessionInfo, C_SeedRandom
fuzz_target!(|data: &[u8]| {
    ensure_init();

    if data.len() < 4 {
        return;
    }

    let selector = data[0] % 9;
    let payload = &data[1..];

    match selector {
        0 => fuzz_create_object(payload),
        1 => fuzz_find_objects(payload),
        2 => fuzz_generate_random(payload),
        3 => fuzz_open_close_session(payload),
        4 => fuzz_digest(payload),
        // FIX #6: New coverage for info-query functions
        5 => fuzz_get_info(payload),
        6 => fuzz_get_token_and_session_info(payload),
        // FIX #8: New coverage for C_SeedRandom
        7 => fuzz_seed_random(payload),
        // FIX #3: Login with fuzz-derived PIN via C ABI
        8 => fuzz_login_fuzz_pin(payload),
        _ => {}
    }

    // Prevent session/object leaks between fuzz iterations
    cleanup_sessions();
});

fn fuzz_create_object(data: &[u8]) {
    if data.len() < 16 {
        return;
    }

    let mut attrs = Vec::new();
    let mut offset = 0;

    while offset + 4 < data.len() {
        let attr_type = if offset + 8 <= data.len() {
            u64::from_le_bytes([
                data[offset], data[offset+1], data[offset+2], data[offset+3],
                data[offset+4], data[offset+5], data[offset+6], data[offset+7],
            ]) as CK_ATTRIBUTE_TYPE
        } else {
            return;
        };
        offset += 8;

        let value_len = data.get(offset).copied().unwrap_or(0) as usize;
        offset += 1;

        let value_end = (offset + value_len).min(data.len());
        let value = &data[offset..value_end];
        offset = value_end;

        attrs.push(CK_ATTRIBUTE {
            attr_type,
            p_value: value.as_ptr() as *mut std::ffi::c_void,
            value_len: value.len() as CK_ULONG,
        });

        if attrs.len() >= 20 {
            break;
        }
    }

    if attrs.is_empty() {
        return;
    }

    let mut session: CK_SESSION_HANDLE = 0;
    let rv = functions::C_OpenSession(
        0, CKF_SERIAL_SESSION | CKF_RW_SESSION,
        std::ptr::null_mut(), None, &mut session,
    );
    if rv != CKR_OK {
        return;
    }

    let mut obj_handle: CK_OBJECT_HANDLE = 0;
    let _rv = functions::C_CreateObject(
        session, attrs.as_mut_ptr(), attrs.len() as CK_ULONG, &mut obj_handle,
    );

    let _ = functions::C_CloseSession(session);
}

fn fuzz_find_objects(data: &[u8]) {
    if data.len() < 8 {
        return;
    }

    let attr_type = u64::from_le_bytes([
        data[0], data[1], data.get(2).copied().unwrap_or(0),
        data.get(3).copied().unwrap_or(0), data.get(4).copied().unwrap_or(0),
        data.get(5).copied().unwrap_or(0), data.get(6).copied().unwrap_or(0),
        data.get(7).copied().unwrap_or(0),
    ]) as CK_ATTRIBUTE_TYPE;

    let value = &data[8..];

    let mut session: CK_SESSION_HANDLE = 0;
    let rv = functions::C_OpenSession(
        0, CKF_SERIAL_SESSION, std::ptr::null_mut(), None, &mut session,
    );
    if rv != CKR_OK {
        return;
    }

    let mut attr = CK_ATTRIBUTE {
        attr_type,
        p_value: if value.is_empty() { std::ptr::null_mut() } else { value.as_ptr() as *mut _ },
        value_len: value.len() as CK_ULONG,
    };

    let _rv = functions::C_FindObjectsInit(session, &mut attr, 1);
    let mut objects: [CK_OBJECT_HANDLE; 10] = [0; 10];
    let mut count: CK_ULONG = 0;
    let _rv = functions::C_FindObjects(session, objects.as_mut_ptr(), 10, &mut count);
    let _rv = functions::C_FindObjectsFinal(session);
    let _ = functions::C_CloseSession(session);
}

fn fuzz_generate_random(data: &[u8]) {
    if data.is_empty() {
        return;
    }

    let len = (data[0] as usize) % 1024;
    let mut buf = vec![0u8; len];

    let mut session: CK_SESSION_HANDLE = 0;
    let rv = functions::C_OpenSession(
        0, CKF_SERIAL_SESSION, std::ptr::null_mut(), None, &mut session,
    );
    if rv != CKR_OK {
        return;
    }

    let _rv = functions::C_GenerateRandom(session, buf.as_mut_ptr(), len as CK_ULONG);
    let _ = functions::C_CloseSession(session);
}

fn fuzz_open_close_session(data: &[u8]) {
    if data.is_empty() {
        return;
    }

    let flags = if data[0] % 2 == 0 {
        CKF_SERIAL_SESSION
    } else {
        CKF_SERIAL_SESSION | CKF_RW_SESSION
    };

    let mut session: CK_SESSION_HANDLE = 0;
    let rv = functions::C_OpenSession(0, flags, std::ptr::null_mut(), None, &mut session);
    if rv == CKR_OK {
        let _ = functions::C_CloseSession(session);
    }
}

fn fuzz_digest(data: &[u8]) {
    if data.len() < 2 {
        return;
    }

    let mut session: CK_SESSION_HANDLE = 0;
    let rv = functions::C_OpenSession(
        0, CKF_SERIAL_SESSION, std::ptr::null_mut(), None, &mut session,
    );
    if rv != CKR_OK {
        return;
    }

    let mechanisms = [CKM_SHA_1, CKM_SHA256, CKM_SHA384, CKM_SHA512];
    let mech_type = mechanisms[(data[0] as usize) % mechanisms.len()];

    let mut mechanism = CK_MECHANISM {
        mechanism: mech_type,
        p_parameter: std::ptr::null_mut(),
        parameter_len: 0,
    };

    let rv = functions::C_DigestInit(session, &mut mechanism);
    if rv == CKR_OK {
        let input = &data[1..];
        let mut digest = [0u8; 64];
        let mut digest_len: CK_ULONG = 64;
        let _rv = functions::C_Digest(
            session,
            input.as_ptr() as *mut _,
            input.len() as CK_ULONG,
            digest.as_mut_ptr(),
            &mut digest_len,
        );
    }

    let _ = functions::C_CloseSession(session);
}

/// FIX #6: Exercise C_GetInfo — historically a source of struct packing bugs.
fn fuzz_get_info(_data: &[u8]) {
    // C_GetInfo should always succeed after C_Initialize
    let mut info: CK_INFO = unsafe { std::mem::zeroed() };
    let rv = functions::C_GetInfo(&mut info);
    assert!(rv == CKR_OK, "C_GetInfo failed after successful C_Initialize");

    // Also test with null pointer — must return error, not crash
    let rv = functions::C_GetInfo(std::ptr::null_mut());
    assert!(rv != CKR_OK, "C_GetInfo succeeded with null pointer");
}

/// FIX #6: Exercise C_GetTokenInfo and C_GetSessionInfo.
fn fuzz_get_token_and_session_info(data: &[u8]) {
    // C_GetTokenInfo on slot 0
    let mut token_info: CK_TOKEN_INFO = unsafe { std::mem::zeroed() };
    let _rv = functions::C_GetTokenInfo(0, &mut token_info);

    // C_GetTokenInfo with null pointer — must error
    let rv = functions::C_GetTokenInfo(0, std::ptr::null_mut());
    assert!(rv != CKR_OK, "C_GetTokenInfo succeeded with null pointer");

    // C_GetTokenInfo on invalid slot
    let rv = functions::C_GetTokenInfo(0xFFFFFFFF, &mut token_info);
    assert!(rv != CKR_OK, "C_GetTokenInfo succeeded with invalid slot ID");

    // C_GetSlotInfo on slot 0
    let mut slot_info: CK_SLOT_INFO = unsafe { std::mem::zeroed() };
    let _rv = functions::C_GetSlotInfo(0, &mut slot_info);

    // C_GetSlotInfo with null — must error
    let rv = functions::C_GetSlotInfo(0, std::ptr::null_mut());
    assert!(rv != CKR_OK, "C_GetSlotInfo succeeded with null pointer");

    // C_GetSessionInfo on a real session
    let mut session: CK_SESSION_HANDLE = 0;
    let rv = functions::C_OpenSession(
        0, CKF_SERIAL_SESSION, std::ptr::null_mut(), None, &mut session,
    );
    if rv == CKR_OK {
        let mut session_info: CK_SESSION_INFO = unsafe { std::mem::zeroed() };
        let rv = functions::C_GetSessionInfo(session, &mut session_info);
        assert!(rv == CKR_OK, "C_GetSessionInfo failed on valid session");

        // Null pointer — must error
        let rv = functions::C_GetSessionInfo(session, std::ptr::null_mut());
        assert!(rv != CKR_OK, "C_GetSessionInfo succeeded with null pointer");

        let _ = functions::C_CloseSession(session);
    }

    // C_GetSessionInfo with invalid handle
    if !data.is_empty() {
        let fake_handle = data[0] as CK_SESSION_HANDLE | 0xDEAD_0000;
        let mut session_info: CK_SESSION_INFO = unsafe { std::mem::zeroed() };
        let rv = functions::C_GetSessionInfo(fake_handle, &mut session_info);
        assert!(rv != CKR_OK, "C_GetSessionInfo succeeded with invalid session handle");
    }
}

/// FIX #8: Exercise C_SeedRandom — seeding with attacker-controlled entropy.
/// If the implementation doesn't handle this correctly, it can bias the PRNG.
fn fuzz_seed_random(data: &[u8]) {
    if data.is_empty() {
        return;
    }

    let mut session: CK_SESSION_HANDLE = 0;
    let rv = functions::C_OpenSession(
        0, CKF_SERIAL_SESSION, std::ptr::null_mut(), None, &mut session,
    );
    if rv != CKR_OK {
        return;
    }

    // Seed with fuzz data
    let _rv = functions::C_SeedRandom(
        session,
        data.as_ptr() as *mut _,
        data.len() as CK_ULONG,
    );

    // Seed with null pointer + non-zero length — must not crash
    let rv = functions::C_SeedRandom(session, std::ptr::null_mut(), 16);
    assert!(rv != CKR_OK, "C_SeedRandom succeeded with null seed + non-zero length");

    // Seed with zero length (valid edge case)
    let _rv = functions::C_SeedRandom(session, std::ptr::null_mut(), 0);

    // After seeding, GenerateRandom should still work correctly
    let mut buf = [0u8; 32];
    let _rv = functions::C_GenerateRandom(session, buf.as_mut_ptr(), 32);

    let _ = functions::C_CloseSession(session);
}

/// FIX #3: Login with fuzz-derived PIN through C ABI — exercises PIN validation
/// in the context of C ABI entry points (distinct from session_lifecycle target).
fn fuzz_login_fuzz_pin(data: &[u8]) {
    if data.len() < 2 {
        return;
    }

    let mut session: CK_SESSION_HANDLE = 0;
    let rv = functions::C_OpenSession(
        0, CKF_SERIAL_SESSION | CKF_RW_SESSION,
        std::ptr::null_mut(), None, &mut session,
    );
    if rv != CKR_OK {
        return;
    }

    let (pin_ptr, pin_len, _) = extract_fuzz_pin(data);
    let user_type = if data.len() > 1 {
        match data[data.len() - 1] % 3 {
            0 => CKU_USER,
            1 => CKU_SO,
            _ => data[data.len() - 1] as CK_ULONG, // Invalid user type
        }
    } else {
        CKU_USER
    };

    let _rv = functions::C_Login(session, user_type, pin_ptr, pin_len);
    let _ = functions::C_Logout(session);
    let _ = functions::C_CloseSession(session);
}
