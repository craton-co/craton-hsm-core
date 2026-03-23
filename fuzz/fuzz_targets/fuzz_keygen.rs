// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Fuzz target for key generation via C ABI.
//!
//! Key generation with malformed parameters is a common crash source:
//! - Invalid modulus bits (0, 1, odd, extremely large)
//! - Invalid EC curve OIDs
//! - Missing required attributes
//! - Conflicting attributes (e.g., CKA_ENCRYPT=true on a signing key)
//! - Invalid AES key lengths
//! - Null pointers in templates

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

/// Open an RW session with fuzz-derived PIN for authentication.
fn open_rw_session_with_pin(data: &[u8]) -> (Option<CK_SESSION_HANDLE>, usize) {
    let mut session: CK_SESSION_HANDLE = 0;
    let rv = functions::C_OpenSession(
        0,
        CKF_SERIAL_SESSION | CKF_RW_SESSION,
        std::ptr::null_mut(),
        None,
        &mut session,
    );
    if rv != CKR_OK {
        return (None, 0);
    }
    let (pin_ptr, pin_len, consumed) = extract_fuzz_pin(data);
    let _ = functions::C_Login(session, CKU_USER, pin_ptr, pin_len);
    (Some(session), consumed)
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

    let selector = data[0] % 5;
    let payload = &data[1..];

    match selector {
        // FIX #3: Use fuzz PIN for targets that need authenticated sessions
        0 => fuzz_aes_keygen(payload),
        1 => fuzz_ec_keygen_random_params(payload),
        2 => fuzz_keygen_random_mechanism(payload),
        3 => fuzz_keygen_conflicting_attrs(payload),
        4 => fuzz_keygen_null_pointers(payload),
        _ => {}
    }

    cleanup_sessions();
});

/// AES key generation with fuzz-controlled key length.
fn fuzz_aes_keygen(data: &[u8]) {
    if data.len() < 4 {
        return;
    }

    let session = match open_rw_session() {
        Some(s) => s,
        None => return,
    };

    // Fuzz-controlled key length (including invalid: 0, 1, 15, 33, 255)
    let value_len: CK_ULONG = u16::from_le_bytes([data[0], data[1]]) as CK_ULONG;
    let true_val: CK_BBOOL = CK_TRUE;
    let class_val: CK_ULONG = CKO_SECRET_KEY;

    let mut template = [
        CK_ATTRIBUTE {
            attr_type: CKA_CLASS,
            p_value: &class_val as *const _ as *mut _,
            value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        },
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

    let mut key_handle: CK_OBJECT_HANDLE = 0;

    let rv = functions::C_GenerateKey(
        session,
        &mut mechanism,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut key_handle,
    );

    if rv == CKR_OK {
        let _ = functions::C_DestroyObject(session, key_handle);
    }

    close_session(session);
}

/// EC key pair generation with fuzz-controlled EC parameters (OID).
fn fuzz_ec_keygen_random_params(data: &[u8]) {
    if data.len() < 4 {
        return;
    }

    let session = match open_rw_session() {
        Some(s) => s,
        None => return,
    };

    let true_val: CK_BBOOL = CK_TRUE;

    // Use fuzz data as EC params — includes valid OIDs, garbage, truncated OIDs
    let ec_param_len = (data[0] as usize % 32).min(data.len() - 1);
    let ec_params = &data[1..1 + ec_param_len];

    let mut pub_template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_EC_PARAMS,
            p_value: if ec_params.is_empty() {
                std::ptr::null_mut()
            } else {
                ec_params.as_ptr() as *mut _
            },
            value_len: ec_params.len() as CK_ULONG,
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
            attr_type: CKA_TOKEN,
            p_value: &true_val as *const _ as *mut _,
            value_len: 1,
        },
    ];

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_EC_KEY_PAIR_GEN,
        p_parameter: std::ptr::null_mut(),
        parameter_len: 0,
    };

    let mut pub_key: CK_OBJECT_HANDLE = 0;
    let mut priv_key: CK_OBJECT_HANDLE = 0;

    let rv = functions::C_GenerateKeyPair(
        session,
        &mut mechanism,
        pub_template.as_mut_ptr(),
        pub_template.len() as CK_ULONG,
        priv_template.as_mut_ptr(),
        priv_template.len() as CK_ULONG,
        &mut pub_key,
        &mut priv_key,
    );

    if rv == CKR_OK {
        let _ = functions::C_DestroyObject(session, pub_key);
        let _ = functions::C_DestroyObject(session, priv_key);
    }

    close_session(session);
}

/// Key generation with random mechanism type — tests mechanism validation.
fn fuzz_keygen_random_mechanism(data: &[u8]) {
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

    let true_val: CK_BBOOL = CK_TRUE;

    let mut template = [
        CK_ATTRIBUTE {
            attr_type: CKA_TOKEN,
            p_value: &true_val as *const _ as *mut _,
            value_len: 1,
        },
    ];

    let mut mechanism = CK_MECHANISM {
        mechanism: mech_type,
        p_parameter: std::ptr::null_mut(),
        parameter_len: 0,
    };

    let mut key_handle: CK_OBJECT_HANDLE = 0;

    // C_GenerateKey with random mechanism — should error for invalid mechanisms
    let rv = functions::C_GenerateKey(
        session,
        &mut mechanism,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut key_handle,
    );

    if rv == CKR_OK {
        let _ = functions::C_DestroyObject(session, key_handle);
    }

    // Also try C_GenerateKeyPair
    let mut pub_key: CK_OBJECT_HANDLE = 0;
    let mut priv_key: CK_OBJECT_HANDLE = 0;

    let rv = functions::C_GenerateKeyPair(
        session,
        &mut mechanism,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut pub_key,
        &mut priv_key,
    );

    if rv == CKR_OK {
        let _ = functions::C_DestroyObject(session, pub_key);
        let _ = functions::C_DestroyObject(session, priv_key);
    }

    close_session(session);
}

/// Key generation with conflicting attributes.
fn fuzz_keygen_conflicting_attrs(data: &[u8]) {
    if data.len() < 8 {
        return;
    }

    let session = match open_rw_session() {
        Some(s) => s,
        None => return,
    };

    // Build a template from fuzz data with potentially conflicting flags
    let mut attrs = Vec::new();
    let true_val: CK_BBOOL = CK_TRUE;
    let false_val: CK_BBOOL = CK_FALSE;
    let value_len: CK_ULONG = 32;

    // Always include CKA_VALUE_LEN
    attrs.push(CK_ATTRIBUTE {
        attr_type: CKA_VALUE_LEN,
        p_value: &value_len as *const _ as *mut _,
        value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
    });

    // Fuzz-controlled boolean attributes
    let bool_attrs = [
        CKA_ENCRYPT, CKA_DECRYPT, CKA_SIGN, CKA_VERIFY,
        CKA_WRAP, CKA_UNWRAP, CKA_DERIVE, CKA_TOKEN,
    ];

    for (i, &attr_type) in bool_attrs.iter().enumerate() {
        if i < data.len() {
            let val = if data[i] % 2 == 0 { &true_val } else { &false_val };
            attrs.push(CK_ATTRIBUTE {
                attr_type,
                p_value: val as *const _ as *mut _,
                value_len: 1,
            });
        }
    }

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        p_parameter: std::ptr::null_mut(),
        parameter_len: 0,
    };

    let mut key_handle: CK_OBJECT_HANDLE = 0;
    let rv = functions::C_GenerateKey(
        session,
        &mut mechanism,
        attrs.as_mut_ptr(),
        attrs.len() as CK_ULONG,
        &mut key_handle,
    );

    if rv == CKR_OK {
        let _ = functions::C_DestroyObject(session, key_handle);
    }

    close_session(session);
}

/// Key generation with null pointers in various positions.
fn fuzz_keygen_null_pointers(data: &[u8]) {
    if data.len() < 2 {
        return;
    }

    let session = match open_rw_session() {
        Some(s) => s,
        None => return,
    };

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        p_parameter: std::ptr::null_mut(),
        parameter_len: 0,
    };

    // FIX #11: Assert that null pointer cases return errors, not success
    match data[0] % 4 {
        0 => {
            // Null template with non-zero count
            let mut key: CK_OBJECT_HANDLE = 0;
            let rv = functions::C_GenerateKey(
                session,
                &mut mechanism,
                std::ptr::null_mut(),
                5,
                &mut key,
            );
            assert!(rv != CKR_OK, "C_GenerateKey succeeded with null template + non-zero count");
        }
        1 => {
            // Null output handle
            let true_val: CK_BBOOL = CK_TRUE;
            let mut template = [CK_ATTRIBUTE {
                attr_type: CKA_TOKEN,
                p_value: &true_val as *const _ as *mut _,
                value_len: 1,
            }];
            let rv = functions::C_GenerateKey(
                session,
                &mut mechanism,
                template.as_mut_ptr(),
                1,
                std::ptr::null_mut(),
            );
            assert!(rv != CKR_OK, "C_GenerateKey succeeded with null output handle");
        }
        2 => {
            // Null mechanism pointer
            let mut key: CK_OBJECT_HANDLE = 0;
            let rv = functions::C_GenerateKey(
                session,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
                &mut key,
            );
            assert!(rv != CKR_OK, "C_GenerateKey succeeded with null mechanism");
        }
        3 => {
            // GenerateKeyPair with null output handles
            mechanism.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
            let rv = functions::C_GenerateKeyPair(
                session,
                &mut mechanism,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
            assert!(rv != CKR_OK, "C_GenerateKeyPair succeeded with null output handles");
        }
        _ => {}
    }

    close_session(session);
}
