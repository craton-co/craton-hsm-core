// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Fuzz target for C_SetAttributeValue.
//!
//! Mutation of existing objects with conflicting or prohibited attributes
//! is a distinct code path from creation. Tests:
//! - Setting read-only attributes (CKA_CLASS, CKA_KEY_TYPE)
//! - Setting conflicting boolean attributes
//! - Setting attributes on non-existent objects
//! - Buffer/length mismatches in attribute values
//! - Setting sensitive attributes on non-sensitive objects

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

/// Generate an AES key to use as the target for attribute mutation.
fn generate_test_key(session: CK_SESSION_HANDLE) -> Option<CK_OBJECT_HANDLE> {
    let true_val: CK_BBOOL = CK_TRUE;
    let value_len: CK_ULONG = 32;

    let mut template = [
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
            attr_type: CKA_MODIFIABLE,
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

// FIX #7: Expanded selector from 5 to 7 to include C_CopyObject coverage
fuzz_target!(|data: &[u8]| {
    ensure_init();

    if data.len() < 4 {
        return;
    }

    let selector = data[0] % 7;
    let payload = &data[1..];

    match selector {
        0 => fuzz_set_random_attributes(payload),
        1 => fuzz_set_readonly_attributes(payload),
        2 => fuzz_set_on_invalid_handle(payload),
        3 => fuzz_set_conflicting_booleans(payload),
        4 => fuzz_set_mismatched_lengths(payload),
        // FIX #7: C_CopyObject — classic PKCS#11 attack vector
        5 => fuzz_copy_object_extractable_bypass(payload),
        6 => fuzz_copy_object_invalid_handles(payload),
        _ => {}
    }

    cleanup_sessions();
});

/// Set random attribute types with random values on a real key.
fn fuzz_set_random_attributes(data: &[u8]) {
    if data.len() < 12 {
        return;
    }

    let session = match open_rw_session() {
        Some(s) => s,
        None => return,
    };

    let key = match generate_test_key(session) {
        Some(k) => k,
        None => { close_session(session); return; }
    };

    let mut attrs = Vec::new();
    let mut offset = 0;

    while offset + 9 < data.len() && attrs.len() < 10 {
        let attr_type = u64::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
            data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
        ]) as CK_ATTRIBUTE_TYPE;
        offset += 8;

        let value_len = (data[offset] as usize % 64).min(data.len() - offset - 1);
        offset += 1;

        let value = &data[offset..offset + value_len];
        offset += value_len;

        attrs.push(CK_ATTRIBUTE {
            attr_type,
            p_value: if value.is_empty() {
                std::ptr::null_mut()
            } else {
                value.as_ptr() as *mut _
            },
            value_len: value.len() as CK_ULONG,
        });
    }

    if !attrs.is_empty() {
        let _rv = functions::C_SetAttributeValue(
            session,
            key,
            attrs.as_mut_ptr(),
            attrs.len() as CK_ULONG,
        );
    }

    let _ = functions::C_DestroyObject(session, key);
    close_session(session);
}

/// Attempt to set read-only attributes (CKA_CLASS, CKA_KEY_TYPE, etc.) — must fail.
fn fuzz_set_readonly_attributes(data: &[u8]) {
    if data.len() < 8 {
        return;
    }

    let session = match open_rw_session() {
        Some(s) => s,
        None => return,
    };

    let key = match generate_test_key(session) {
        Some(k) => k,
        None => { close_session(session); return; }
    };

    // FIX #11: Assert that setting read-only attributes fails
    // Try to change the object class (read-only)
    let new_class: CK_ULONG = CKO_PUBLIC_KEY;
    let mut class_attr = CK_ATTRIBUTE {
        attr_type: CKA_CLASS,
        p_value: &new_class as *const _ as *mut _,
        value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
    };
    let rv = functions::C_SetAttributeValue(session, key, &mut class_attr, 1);
    assert!(rv != CKR_OK, "C_SetAttributeValue allowed changing CKA_CLASS (read-only)");

    // Try to change key type (read-only)
    let new_key_type: CK_ULONG = CKK_RSA;
    let mut kt_attr = CK_ATTRIBUTE {
        attr_type: CKA_KEY_TYPE,
        p_value: &new_key_type as *const _ as *mut _,
        value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
    };
    let rv = functions::C_SetAttributeValue(session, key, &mut kt_attr, 1);
    assert!(rv != CKR_OK, "C_SetAttributeValue allowed changing CKA_KEY_TYPE (read-only)");

    // Try to set CKA_SENSITIVE from false to true (one-way transition in PKCS#11)
    let true_val: CK_BBOOL = CK_TRUE;
    let mut sensitive_attr = CK_ATTRIBUTE {
        attr_type: CKA_SENSITIVE,
        p_value: &true_val as *const _ as *mut _,
        value_len: 1,
    };
    let _rv = functions::C_SetAttributeValue(session, key, &mut sensitive_attr, 1);

    // Try to set CKA_EXTRACTABLE from true to false (one-way transition)
    let false_val: CK_BBOOL = CK_FALSE;
    let mut extract_attr = CK_ATTRIBUTE {
        attr_type: CKA_EXTRACTABLE,
        p_value: &false_val as *const _ as *mut _,
        value_len: 1,
    };
    let _rv = functions::C_SetAttributeValue(session, key, &mut extract_attr, 1);

    // Try to change the label with fuzz data
    let label = &data[..data.len().min(64)];
    let mut label_attr = CK_ATTRIBUTE {
        attr_type: CKA_LABEL,
        p_value: label.as_ptr() as *mut _,
        value_len: label.len() as CK_ULONG,
    };
    let _rv = functions::C_SetAttributeValue(session, key, &mut label_attr, 1);

    let _ = functions::C_DestroyObject(session, key);
    close_session(session);
}

/// Set attributes on an invalid/non-existent object handle.
fn fuzz_set_on_invalid_handle(data: &[u8]) {
    if data.len() < 8 {
        return;
    }

    let session = match open_rw_session() {
        Some(s) => s,
        None => return,
    };

    let fake_handle = u64::from_le_bytes([
        data[0], data[1], data[2], data[3],
        data[4], data[5], data[6], data[7],
    ]) as CK_OBJECT_HANDLE;

    let true_val: CK_BBOOL = CK_TRUE;
    let mut attr = CK_ATTRIBUTE {
        attr_type: CKA_ENCRYPT,
        p_value: &true_val as *const _ as *mut _,
        value_len: 1,
    };

    // FIX #11: Must return error, not succeed
    let rv = functions::C_SetAttributeValue(session, fake_handle, &mut attr, 1);
    assert!(rv != CKR_OK, "C_SetAttributeValue succeeded with invalid object handle");

    // Also try with null template
    let _rv = functions::C_SetAttributeValue(session, fake_handle, std::ptr::null_mut(), 0);
    let rv = functions::C_SetAttributeValue(session, fake_handle, std::ptr::null_mut(), 5);
    assert!(rv != CKR_OK, "C_SetAttributeValue succeeded with null template + non-zero count");

    close_session(session);
}

/// Set multiple conflicting boolean attributes simultaneously.
fn fuzz_set_conflicting_booleans(data: &[u8]) {
    if data.len() < 8 {
        return;
    }

    let session = match open_rw_session() {
        Some(s) => s,
        None => return,
    };

    let key = match generate_test_key(session) {
        Some(k) => k,
        None => { close_session(session); return; }
    };

    let true_val: CK_BBOOL = CK_TRUE;
    let false_val: CK_BBOOL = CK_FALSE;

    // Fuzz-controlled mix of true/false for various attributes
    let bool_attrs = [
        CKA_ENCRYPT, CKA_DECRYPT, CKA_SIGN, CKA_VERIFY,
        CKA_WRAP, CKA_UNWRAP, CKA_DERIVE, CKA_TOKEN,
    ];

    let mut attrs: Vec<CK_ATTRIBUTE> = Vec::new();
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

    if !attrs.is_empty() {
        let _rv = functions::C_SetAttributeValue(
            session,
            key,
            attrs.as_mut_ptr(),
            attrs.len() as CK_ULONG,
        );
    }

    let _ = functions::C_DestroyObject(session, key);
    close_session(session);
}

/// Set attributes with mismatched value_len.
fn fuzz_set_mismatched_lengths(data: &[u8]) {
    if data.len() < 4 {
        return;
    }

    let session = match open_rw_session() {
        Some(s) => s,
        None => return,
    };

    let key = match generate_test_key(session) {
        Some(k) => k,
        None => { close_session(session); return; }
    };

    let true_val: CK_BBOOL = CK_TRUE;

    // Boolean attribute with wrong value_len
    let mut attr = CK_ATTRIBUTE {
        attr_type: CKA_ENCRYPT,
        p_value: &true_val as *const _ as *mut _,
        value_len: data[0] as CK_ULONG, // Fuzzed: could be 0, 255, etc.
    };
    let _rv = functions::C_SetAttributeValue(session, key, &mut attr, 1);

    // FIX #11: Null value pointer with non-zero length — must not succeed
    let mut null_attr = CK_ATTRIBUTE {
        attr_type: CKA_LABEL,
        p_value: std::ptr::null_mut(),
        value_len: data[1] as CK_ULONG,
    };
    if data[1] > 0 {
        let rv = functions::C_SetAttributeValue(session, key, &mut null_attr, 1);
        assert!(rv != CKR_OK, "C_SetAttributeValue succeeded with null p_value + non-zero value_len");
    } else {
        let _rv = functions::C_SetAttributeValue(session, key, &mut null_attr, 1);
    }

    // Extreme count
    let _rv = functions::C_SetAttributeValue(session, key, &mut attr, CK_ULONG::MAX);

    let _ = functions::C_DestroyObject(session, key);
    close_session(session);
}

/// FIX #7: C_CopyObject with CKA_EXTRACTABLE bypass attempt.
/// Classic PKCS#11 attack: copy a non-extractable key and set CKA_EXTRACTABLE=true
/// on the copy. The library MUST reject this.
fn fuzz_copy_object_extractable_bypass(data: &[u8]) {
    if data.len() < 4 {
        return;
    }

    let session = match open_rw_session() {
        Some(s) => s,
        None => return,
    };

    // Create a non-extractable AES key
    let true_val: CK_BBOOL = CK_TRUE;
    let false_val: CK_BBOOL = CK_FALSE;
    let value_len: CK_ULONG = 32;

    let mut gen_template = [
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
            attr_type: CKA_EXTRACTABLE,
            p_value: &false_val as *const _ as *mut _,
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
        gen_template.as_mut_ptr(),
        gen_template.len() as CK_ULONG,
        &mut key,
    );
    if rv != CKR_OK {
        close_session(session);
        return;
    }

    // Attempt to copy with CKA_EXTRACTABLE=true — MUST fail
    let mut copy_template = [CK_ATTRIBUTE {
        attr_type: CKA_EXTRACTABLE,
        p_value: &true_val as *const _ as *mut _,
        value_len: 1,
    }];

    let mut copy_handle: CK_OBJECT_HANDLE = 0;
    let rv = functions::C_CopyObject(
        session,
        key,
        copy_template.as_mut_ptr(),
        copy_template.len() as CK_ULONG,
        &mut copy_handle,
    );

    // Security-critical assertion — extractable bypass is a CVE-class bug
    assert!(
        rv != CKR_OK,
        "C_CopyObject allowed CKA_EXTRACTABLE=true on non-extractable key — security bypass!"
    );

    // Also attempt to copy with CKA_SENSITIVE=false (another bypass vector)
    let mut sensitive_template = [CK_ATTRIBUTE {
        attr_type: CKA_SENSITIVE,
        p_value: &false_val as *const _ as *mut _,
        value_len: 1,
    }];

    let rv_sens = functions::C_CopyObject(
        session,
        key,
        sensitive_template.as_mut_ptr(),
        sensitive_template.len() as CK_ULONG,
        &mut copy_handle,
    );
    if rv_sens == CKR_OK {
        let _ = functions::C_DestroyObject(session, copy_handle);
    }

    // Copy with fuzz-controlled attributes
    let mut fuzz_attrs = Vec::new();
    let mut offset = 0;
    while offset + 9 < data.len() && fuzz_attrs.len() < 5 {
        let attr_type = u64::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
            data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
        ]) as CK_ATTRIBUTE_TYPE;
        offset += 8;

        let val_len = (data[offset] as usize % 16).min(data.len() - offset - 1);
        offset += 1;

        let value = &data[offset..offset + val_len];
        offset += val_len;

        fuzz_attrs.push(CK_ATTRIBUTE {
            attr_type,
            p_value: if value.is_empty() {
                std::ptr::null_mut()
            } else {
                value.as_ptr() as *mut _
            },
            value_len: value.len() as CK_ULONG,
        });
    }

    if !fuzz_attrs.is_empty() {
        let rv_fuzz = functions::C_CopyObject(
            session,
            key,
            fuzz_attrs.as_mut_ptr(),
            fuzz_attrs.len() as CK_ULONG,
            &mut copy_handle,
        );
        if rv_fuzz == CKR_OK {
            let _ = functions::C_DestroyObject(session, copy_handle);
        }
    }

    let _ = functions::C_DestroyObject(session, key);
    close_session(session);
}

/// FIX #7: C_CopyObject with invalid handles and null pointers.
fn fuzz_copy_object_invalid_handles(data: &[u8]) {
    if data.len() < 8 {
        return;
    }

    let session = match open_rw_session() {
        Some(s) => s,
        None => return,
    };

    let fake_handle = u64::from_le_bytes([
        data[0], data[1], data[2], data[3],
        data[4], data[5], data[6], data[7],
    ]) as CK_OBJECT_HANDLE;

    let true_val: CK_BBOOL = CK_TRUE;
    let mut attr = CK_ATTRIBUTE {
        attr_type: CKA_TOKEN,
        p_value: &true_val as *const _ as *mut _,
        value_len: 1,
    };

    // Copy with invalid source handle — must fail
    let mut copy_handle: CK_OBJECT_HANDLE = 0;
    let rv = functions::C_CopyObject(session, fake_handle, &mut attr, 1, &mut copy_handle);
    assert!(rv != CKR_OK, "C_CopyObject succeeded with invalid source handle");

    // Copy with null output handle — must fail
    let rv = functions::C_CopyObject(session, fake_handle, &mut attr, 1, std::ptr::null_mut());
    assert!(rv != CKR_OK, "C_CopyObject succeeded with null output handle");

    // Copy with null template + non-zero count — must fail
    let rv = functions::C_CopyObject(session, fake_handle, std::ptr::null_mut(), 5, &mut copy_handle);
    assert!(rv != CKR_OK, "C_CopyObject succeeded with null template + non-zero count");

    close_session(session);
}
