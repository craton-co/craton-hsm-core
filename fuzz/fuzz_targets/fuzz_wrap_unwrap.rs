// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Fuzz target for C_WrapKey and C_UnwrapKey.
//!
//! Key wrapping/unwrapping involves complex interactions between:
//! - Key permissions (CKA_WRAP, CKA_UNWRAP, CKA_EXTRACTABLE)
//! - Mechanism parameters (IV, AAD for AES-GCM wrapping)
//! - Buffer management (two-call pattern for wrap size query)
//! - Wrapping with wrong key type or size

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

fn cleanup_sessions() {
    let _ = functions::C_CloseAllSessions(0);
}

/// FIX #3: Extract a fuzz-derived PIN from data.
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

fn open_rw_session() -> Option<CK_SESSION_HANDLE> {
    let mut session: CK_SESSION_HANDLE = 0;
    let rv = functions::C_OpenSession(
        0,
        CKF_SERIAL_SESSION | CKF_RW_SESSION,
        std::ptr::null_mut(),
        None,
        &mut session,
    );
    if rv != CKR_OK {
        return None;
    }
    let pin = b"1234";
    let _ = functions::C_Login(session, CKU_USER, pin.as_ptr() as *mut _, pin.len() as CK_ULONG);
    Some(session)
}

fn close_session(session: CK_SESSION_HANDLE) {
    let _ = functions::C_Logout(session);
    let _ = functions::C_CloseSession(session);
}

/// Generate an AES wrapping key with wrap/unwrap permissions.
fn generate_wrapping_key(session: CK_SESSION_HANDLE) -> Option<CK_OBJECT_HANDLE> {
    let true_val: CK_BBOOL = CK_TRUE;
    let value_len: CK_ULONG = 32;

    let mut template = [
        CK_ATTRIBUTE {
            attr_type: CKA_VALUE_LEN,
            p_value: &value_len as *const _ as *mut _,
            value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_WRAP,
            p_value: &true_val as *const _ as *mut _,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_UNWRAP,
            p_value: &true_val as *const _ as *mut _,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_ENCRYPT,
            p_value: &true_val as *const _ as *mut _,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_DECRYPT,
            p_value: &true_val as *const _ as *mut _,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_TOKEN,
            p_value: &true_val as *const _ as *mut _,
            value_len: 1,
        },
    ];

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        p_parameter: std::ptr::null_mut(),
        parameter_len: 0,
    };

    let mut key: CK_OBJECT_HANDLE = 0;
    let rv = functions::C_GenerateKey(
        session,
        &mut mechanism,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut key,
    );

    if rv == CKR_OK { Some(key) } else { None }
}

/// Generate a target key to be wrapped.
fn generate_target_key(session: CK_SESSION_HANDLE, extractable: bool) -> Option<CK_OBJECT_HANDLE> {
    let true_val: CK_BBOOL = CK_TRUE;
    let extract_val: CK_BBOOL = if extractable { CK_TRUE } else { CK_FALSE };
    let value_len: CK_ULONG = 16;

    let mut template = [
        CK_ATTRIBUTE {
            attr_type: CKA_VALUE_LEN,
            p_value: &value_len as *const _ as *mut _,
            value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_EXTRACTABLE,
            p_value: &extract_val as *const _ as *mut _,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_ENCRYPT,
            p_value: &true_val as *const _ as *mut _,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_TOKEN,
            p_value: &true_val as *const _ as *mut _,
            value_len: 1,
        },
    ];

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        p_parameter: std::ptr::null_mut(),
        parameter_len: 0,
    };

    let mut key: CK_OBJECT_HANDLE = 0;
    let rv = functions::C_GenerateKey(
        session,
        &mut mechanism,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut key,
    );

    if rv == CKR_OK { Some(key) } else { None }
}

fuzz_target!(|data: &[u8]| {
    ensure_init();

    if data.len() < 4 {
        return;
    }

    let selector = data[0] % 5;
    let payload = &data[1..];

    match selector {
        0 => fuzz_wrap_valid_key(payload),
        1 => fuzz_wrap_non_extractable(payload),
        2 => fuzz_wrap_invalid_handles(payload),
        3 => fuzz_unwrap_random_data(payload),
        4 => fuzz_wrap_random_mechanism(payload),
        _ => {}
    }

    cleanup_sessions();
});

/// Wrap an extractable key and unwrap it back.
fn fuzz_wrap_valid_key(data: &[u8]) {
    if data.len() < 2 {
        return;
    }

    let session = match open_rw_session() {
        Some(s) => s,
        None => return,
    };

    let wrapping_key = match generate_wrapping_key(session) {
        Some(k) => k,
        None => { close_session(session); return; }
    };

    let target_key = match generate_target_key(session, true) {
        Some(k) => k,
        None => {
            let _ = functions::C_DestroyObject(session, wrapping_key);
            close_session(session);
            return;
        }
    };

    // Use AES-GCM mechanism with fuzz-controlled parameters
    let param_len = (data[0] as usize % 32).min(data.len() - 1);
    let params = &data[1..1 + param_len];

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: if params.is_empty() {
            std::ptr::null_mut()
        } else {
            params.as_ptr() as *mut _
        },
        parameter_len: params.len() as CK_ULONG,
    };

    // First call: query wrapped size
    let mut wrapped_len: CK_ULONG = 0;
    let rv = functions::C_WrapKey(
        session,
        &mut mechanism,
        wrapping_key,
        target_key,
        std::ptr::null_mut(),
        &mut wrapped_len,
    );

    if rv == CKR_OK && wrapped_len > 0 && wrapped_len < 4096 {
        // Second call: actually wrap
        let mut wrapped = vec![0u8; wrapped_len as usize];
        let rv = functions::C_WrapKey(
            session,
            &mut mechanism,
            wrapping_key,
            target_key,
            wrapped.as_mut_ptr(),
            &mut wrapped_len,
        );

        if rv == CKR_OK {
            // Unwrap back
            let true_val: CK_BBOOL = CK_TRUE;
            let value_len: CK_ULONG = 16;
            let mut unwrap_template = [
                CK_ATTRIBUTE {
                    attr_type: CKA_VALUE_LEN,
                    p_value: &value_len as *const _ as *mut _,
                    value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
                },
                CK_ATTRIBUTE {
                    attr_type: CKA_ENCRYPT,
                    p_value: &true_val as *const _ as *mut _,
                    value_len: 1,
                },
                CK_ATTRIBUTE {
                    attr_type: CKA_TOKEN,
                    p_value: &true_val as *const _ as *mut _,
                    value_len: 1,
                },
            ];

            let mut unwrapped_key: CK_OBJECT_HANDLE = 0;
            let _rv = functions::C_UnwrapKey(
                session,
                &mut mechanism,
                wrapping_key,
                wrapped.as_mut_ptr(),
                wrapped_len,
                unwrap_template.as_mut_ptr(),
                unwrap_template.len() as CK_ULONG,
                &mut unwrapped_key,
            );

            if _rv == CKR_OK {
                let _ = functions::C_DestroyObject(session, unwrapped_key);
            }
        }
    }

    let _ = functions::C_DestroyObject(session, target_key);
    let _ = functions::C_DestroyObject(session, wrapping_key);
    close_session(session);
}

/// Attempt to wrap a non-extractable key — must fail.
/// FIX #13: Use fuzz data to vary the mechanism parameters instead of ignoring it.
/// FIX #11: Assert that wrapping a non-extractable key actually fails.
fn fuzz_wrap_non_extractable(data: &[u8]) {
    let session = match open_rw_session() {
        Some(s) => s,
        None => return,
    };

    let wrapping_key = match generate_wrapping_key(session) {
        Some(k) => k,
        None => { close_session(session); return; }
    };

    let target_key = match generate_target_key(session, false) {
        Some(k) => k,
        None => {
            let _ = functions::C_DestroyObject(session, wrapping_key);
            close_session(session);
            return;
        }
    };

    // FIX #13: Use fuzz data for mechanism parameters instead of ignoring it
    let param_len = if data.is_empty() { 0 } else { (data[0] as usize % 32).min(data.len().saturating_sub(1)) };
    let params = if param_len > 0 { &data[1..1 + param_len] } else { &[] as &[u8] };

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: if params.is_empty() {
            std::ptr::null_mut()
        } else {
            params.as_ptr() as *mut _
        },
        parameter_len: params.len() as CK_ULONG,
    };

    let mut wrapped = [0u8; 512];
    let mut wrapped_len: CK_ULONG = 512;

    // This MUST fail — wrapping a non-extractable key is prohibited
    let rv = functions::C_WrapKey(
        session,
        &mut mechanism,
        wrapping_key,
        target_key,
        wrapped.as_mut_ptr(),
        &mut wrapped_len,
    );

    // FIX #11: Assert that wrapping non-extractable key does NOT succeed
    assert!(rv != CKR_OK, "C_WrapKey succeeded on non-extractable key — CKA_EXTRACTABLE bypass!");

    let _ = functions::C_DestroyObject(session, target_key);
    let _ = functions::C_DestroyObject(session, wrapping_key);
    close_session(session);
}

/// Wrap/unwrap with invalid key handles.
fn fuzz_wrap_invalid_handles(data: &[u8]) {
    if data.len() < 16 {
        return;
    }

    let session = match open_rw_session() {
        Some(s) => s,
        None => return,
    };

    let fake_wrapping = u64::from_le_bytes([
        data[0], data[1], data[2], data[3],
        data[4], data[5], data[6], data[7],
    ]) as CK_OBJECT_HANDLE;

    let fake_target = u64::from_le_bytes([
        data[8], data[9], data[10], data[11],
        data[12], data[13], data[14], data[15],
    ]) as CK_OBJECT_HANDLE;

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: std::ptr::null_mut(),
        parameter_len: 0,
    };

    let mut wrapped = [0u8; 512];
    let mut wrapped_len: CK_ULONG = 512;

    // Both handles invalid
    let _rv = functions::C_WrapKey(
        session,
        &mut mechanism,
        fake_wrapping,
        fake_target,
        wrapped.as_mut_ptr(),
        &mut wrapped_len,
    );

    // Unwrap with invalid handle and random wrapped data
    let mut unwrapped_key: CK_OBJECT_HANDLE = 0;
    let wrapped_data = &data[16..];
    let _rv = functions::C_UnwrapKey(
        session,
        &mut mechanism,
        fake_wrapping,
        wrapped_data.as_ptr() as *mut _,
        wrapped_data.len() as CK_ULONG,
        std::ptr::null_mut(),
        0,
        &mut unwrapped_key,
    );

    close_session(session);
}

/// Unwrap random bytes — must fail gracefully.
fn fuzz_unwrap_random_data(data: &[u8]) {
    if data.len() < 4 {
        return;
    }

    let session = match open_rw_session() {
        Some(s) => s,
        None => return,
    };

    let wrapping_key = match generate_wrapping_key(session) {
        Some(k) => k,
        None => { close_session(session); return; }
    };

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: std::ptr::null_mut(),
        parameter_len: 0,
    };

    let true_val: CK_BBOOL = CK_TRUE;
    let value_len: CK_ULONG = 16;
    let mut unwrap_template = [
        CK_ATTRIBUTE {
            attr_type: CKA_VALUE_LEN,
            p_value: &value_len as *const _ as *mut _,
            value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_TOKEN,
            p_value: &true_val as *const _ as *mut _,
            value_len: 1,
        },
    ];

    let mut unwrapped_key: CK_OBJECT_HANDLE = 0;

    // Random bytes as wrapped key data — must error, not panic
    let _rv = functions::C_UnwrapKey(
        session,
        &mut mechanism,
        wrapping_key,
        data.as_ptr() as *mut _,
        data.len() as CK_ULONG,
        unwrap_template.as_mut_ptr(),
        unwrap_template.len() as CK_ULONG,
        &mut unwrapped_key,
    );

    let _ = functions::C_DestroyObject(session, wrapping_key);
    close_session(session);
}

/// Wrap with random mechanism type.
fn fuzz_wrap_random_mechanism(data: &[u8]) {
    if data.len() < 8 {
        return;
    }

    let session = match open_rw_session() {
        Some(s) => s,
        None => return,
    };

    let wrapping_key = match generate_wrapping_key(session) {
        Some(k) => k,
        None => { close_session(session); return; }
    };

    let target_key = match generate_target_key(session, true) {
        Some(k) => k,
        None => {
            let _ = functions::C_DestroyObject(session, wrapping_key);
            close_session(session);
            return;
        }
    };

    let mech_type = u64::from_le_bytes([
        data[0], data[1], data[2], data[3],
        data[4], data[5], data[6], data[7],
    ]) as CK_MECHANISM_TYPE;

    let mut mechanism = CK_MECHANISM {
        mechanism: mech_type,
        p_parameter: std::ptr::null_mut(),
        parameter_len: 0,
    };

    let mut wrapped = [0u8; 512];
    let mut wrapped_len: CK_ULONG = 512;

    // Random mechanism — should error for unsupported mechanisms
    let _rv = functions::C_WrapKey(
        session,
        &mut mechanism,
        wrapping_key,
        target_key,
        wrapped.as_mut_ptr(),
        &mut wrapped_len,
    );

    let _ = functions::C_DestroyObject(session, target_key);
    let _ = functions::C_DestroyObject(session, wrapping_key);
    close_session(session);
}
