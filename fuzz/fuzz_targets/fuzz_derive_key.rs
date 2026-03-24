// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Fuzz target for C_DeriveKey.
//!
//! Key derivation involves complex mechanism parameter parsing:
//! - ECDH1_DERIVE with shared info / public key data
//! - Random mechanism types
//! - Invalid base key handles
//! - Malformed parameter structs
//! - Null pointers in parameters

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

fuzz_target!(|data: &[u8]| {
    ensure_init();

    if data.len() < 4 {
        return;
    }

    let selector = data[0] % 4;
    let payload = &data[1..];

    match selector {
        0 => fuzz_derive_ecdh_random_params(payload),
        1 => fuzz_derive_random_mechanism(payload),
        2 => fuzz_derive_invalid_base_key(payload),
        3 => fuzz_derive_null_pointers(payload),
        _ => {}
    }

    cleanup_sessions();
});

/// ECDH key derivation with fuzz-controlled parameters.
fn fuzz_derive_ecdh_random_params(data: &[u8]) {
    if data.len() < 16 {
        return;
    }

    let session = match open_rw_session() {
        Some(s) => s,
        None => return,
    };

    // Generate an EC key pair for derivation
    let true_val: CK_BBOOL = CK_TRUE;
    // P-256 OID: 06 08 2A 86 48 CE 3D 03 01 07
    let p256_oid: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

    let mut pub_template = [
        CK_ATTRIBUTE {
            attr_type: CKA_EC_PARAMS,
            p_value: p256_oid.as_ptr() as *mut _,
            value_len: p256_oid.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_VERIFY,
            p_value: &true_val as *const _ as *mut _,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_TOKEN,
            p_value: &true_val as *const _ as *mut _,
            value_len: 1,
        },
    ];

    let mut priv_template = [
        CK_ATTRIBUTE {
            attr_type: CKA_SIGN,
            p_value: &true_val as *const _ as *mut _,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_DERIVE,
            p_value: &true_val as *const _ as *mut _,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_TOKEN,
            p_value: &true_val as *const _ as *mut _,
            value_len: 1,
        },
    ];

    let mut keygen_mechanism = CK_MECHANISM {
        mechanism: CKM_EC_KEY_PAIR_GEN,
        p_parameter: std::ptr::null_mut(),
        parameter_len: 0,
    };

    let mut pub_key: CK_OBJECT_HANDLE = 0;
    let mut priv_key: CK_OBJECT_HANDLE = 0;

    let rv = functions::C_GenerateKeyPair(
        session,
        &mut keygen_mechanism,
        pub_template.as_mut_ptr(),
        pub_template.len() as CK_ULONG,
        priv_template.as_mut_ptr(),
        priv_template.len() as CK_ULONG,
        &mut pub_key,
        &mut priv_key,
    );

    if rv != CKR_OK {
        close_session(session);
        return;
    }

    // ECDH derive with fuzz-controlled "peer public key" parameter
    let param_len = (data[0] as usize % 128).min(data.len() - 1);
    let params = &data[1..1 + param_len];

    let mut derive_mechanism = CK_MECHANISM {
        mechanism: CKM_ECDH1_DERIVE,
        p_parameter: if params.is_empty() {
            std::ptr::null_mut()
        } else {
            params.as_ptr() as *mut _
        },
        parameter_len: params.len() as CK_ULONG,
    };

    let value_len: CK_ULONG = 32;
    let mut derive_template = [
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

    let mut derived_key: CK_OBJECT_HANDLE = 0;

    // Should error for random peer key bytes, not panic
    let rv = functions::C_DeriveKey(
        session,
        &mut derive_mechanism,
        priv_key,
        derive_template.as_mut_ptr(),
        derive_template.len() as CK_ULONG,
        &mut derived_key,
    );

    if rv == CKR_OK {
        let _ = functions::C_DestroyObject(session, derived_key);
    }

    let _ = functions::C_DestroyObject(session, pub_key);
    let _ = functions::C_DestroyObject(session, priv_key);
    close_session(session);
}

/// DeriveKey with random mechanism type.
fn fuzz_derive_random_mechanism(data: &[u8]) {
    if data.len() < 8 {
        return;
    }

    let session = match open_rw_session() {
        Some(s) => s,
        None => return,
    };

    let mech_type = u64::from_le_bytes([
        data[0], data[1], data[2], data[3],
        data[4], data[5], data[6], data[7],
    ]) as CK_MECHANISM_TYPE;

    let param_data = &data[8..];

    let mut mechanism = CK_MECHANISM {
        mechanism: mech_type,
        p_parameter: if param_data.is_empty() {
            std::ptr::null_mut()
        } else {
            param_data.as_ptr() as *mut _
        },
        parameter_len: param_data.len() as CK_ULONG,
    };

    let true_val: CK_BBOOL = CK_TRUE;
    let value_len: CK_ULONG = 32;
    let mut template = [
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

    let mut derived_key: CK_OBJECT_HANDLE = 0;

    // Random mechanism + random base key handle = should error
    let _rv = functions::C_DeriveKey(
        session,
        &mut mechanism,
        0xDEADBEEF as CK_OBJECT_HANDLE,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut derived_key,
    );

    close_session(session);
}

/// DeriveKey with invalid base key handle.
fn fuzz_derive_invalid_base_key(data: &[u8]) {
    if data.len() < 8 {
        return;
    }

    let session = match open_rw_session() {
        Some(s) => s,
        None => return,
    };

    let fake_key = u64::from_le_bytes([
        data[0], data[1], data[2], data[3],
        data[4], data[5], data[6], data[7],
    ]) as CK_OBJECT_HANDLE;

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_ECDH1_DERIVE,
        p_parameter: std::ptr::null_mut(),
        parameter_len: 0,
    };

    let true_val: CK_BBOOL = CK_TRUE;
    let value_len: CK_ULONG = 32;
    let mut template = [
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

    let mut derived_key: CK_OBJECT_HANDLE = 0;

    let _rv = functions::C_DeriveKey(
        session,
        &mut mechanism,
        fake_key,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut derived_key,
    );

    close_session(session);
}

/// DeriveKey with null pointers.
fn fuzz_derive_null_pointers(data: &[u8]) {
    if data.len() < 2 {
        return;
    }

    let session = match open_rw_session() {
        Some(s) => s,
        None => return,
    };

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_ECDH1_DERIVE,
        p_parameter: std::ptr::null_mut(),
        parameter_len: 0,
    };

    // FIX #11: Assert that null pointer cases return errors
    match data[0] % 3 {
        0 => {
            // Null mechanism
            let mut derived: CK_OBJECT_HANDLE = 0;
            let rv = functions::C_DeriveKey(
                session,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
                &mut derived,
            );
            assert!(rv != CKR_OK, "C_DeriveKey succeeded with null mechanism");
        }
        1 => {
            // Null output handle
            let rv = functions::C_DeriveKey(
                session,
                &mut mechanism,
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
            );
            assert!(rv != CKR_OK, "C_DeriveKey succeeded with null output handle");
        }
        2 => {
            // Null template with non-zero count
            let mut derived: CK_OBJECT_HANDLE = 0;
            let rv = functions::C_DeriveKey(
                session,
                &mut mechanism,
                0,
                std::ptr::null_mut(),
                5,
                &mut derived,
            );
            assert!(rv != CKR_OK, "C_DeriveKey succeeded with null template + non-zero count");
        }
        _ => {}
    }

    close_session(session);
}
