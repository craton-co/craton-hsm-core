// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Session objects die with their session (PKCS#11 v3.2 §5.6.2, §5.6.3).
//!
//! Must run with --test-threads=1 due to global PKCS#11 state.

use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm::pkcs11_abi::functions::*;
use craton_hsm::pkcs11_abi::types::*;
use std::ptr;

mod common;

const USER_PIN: &[u8] = b"userpin1234";

fn open(rw: bool) -> CK_SESSION_HANDLE {
    let flags = CKF_SERIAL_SESSION | if rw { CKF_RW_SESSION } else { 0 };
    let mut s: CK_SESSION_HANDLE = 0;
    assert_eq!(
        C_OpenSession(0, flags, ptr::null_mut(), None, &mut s),
        CKR_OK
    );
    s
}

fn login(s: CK_SESSION_HANDLE, user_type: CK_USER_TYPE, pin: &[u8]) -> CK_RV {
    C_Login(s, user_type, pin.as_ptr() as *mut _, pin.len() as CK_ULONG)
}

/// Fresh token with the user logged in through a "keeper" session.
fn setup() -> CK_SESSION_HANDLE {
    let rv = C_Initialize(ptr::null_mut());
    assert!(rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED);
    let so_pin = b"sopin123";
    let mut label = [b' '; 32];
    label[..9].copy_from_slice(b"TestToken");
    assert_eq!(
        C_InitToken(
            0,
            so_pin.as_ptr() as *mut _,
            so_pin.len() as CK_ULONG,
            label.as_ptr() as *mut _
        ),
        CKR_OK
    );
    let keeper = open(true);
    assert_eq!(login(keeper, CKU_SO, so_pin), CKR_OK);
    assert_eq!(
        C_InitPIN(
            keeper,
            USER_PIN.as_ptr() as *mut _,
            USER_PIN.len() as CK_ULONG
        ),
        CKR_OK
    );
    assert_eq!(C_Logout(keeper), CKR_OK);
    assert_eq!(login(keeper, CKU_USER, USER_PIN), CKR_OK);
    keeper
}

fn gen_session_aes(s: CK_SESSION_HANDLE, label: &[u8]) -> CK_OBJECT_HANDLE {
    let f: CK_BBOOL = CK_FALSE;
    let t: CK_BBOOL = CK_TRUE;
    let len: CK_ULONG = 32;
    let mut tmpl = [
        CK_ATTRIBUTE {
            attr_type: CKA_TOKEN,
            p_value: &f as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_ENCRYPT,
            p_value: &t as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_VALUE_LEN,
            p_value: &len as *const _ as CK_VOID_PTR,
            value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_LABEL,
            p_value: label.as_ptr() as CK_VOID_PTR,
            value_len: label.len() as CK_ULONG,
        },
    ];
    let mut mech = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let mut h = 0;
    assert_eq!(
        C_GenerateKey(
            s,
            &mut mech,
            tmpl.as_mut_ptr(),
            tmpl.len() as CK_ULONG,
            &mut h
        ),
        CKR_OK
    );
    h
}

fn count_by_label(s: CK_SESSION_HANDLE, label: &[u8]) -> CK_ULONG {
    let mut tmpl = [CK_ATTRIBUTE {
        attr_type: CKA_LABEL,
        p_value: label.as_ptr() as CK_VOID_PTR,
        value_len: label.len() as CK_ULONG,
    }];
    assert_eq!(C_FindObjectsInit(s, tmpl.as_mut_ptr(), 1), CKR_OK);
    let mut found = [0 as CK_OBJECT_HANDLE; 8];
    let mut n: CK_ULONG = 0;
    assert_eq!(C_FindObjects(s, found.as_mut_ptr(), 8, &mut n), CKR_OK);
    assert_eq!(C_FindObjectsFinal(s), CKR_OK);
    n
}

fn value_len_rv(s: CK_SESSION_HANDLE, h: CK_OBJECT_HANDLE) -> CK_RV {
    let mut v: CK_ULONG = 0;
    let mut a = [CK_ATTRIBUTE {
        attr_type: CKA_VALUE_LEN,
        p_value: &mut v as *mut _ as CK_VOID_PTR,
        value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
    }];
    C_GetAttributeValue(s, h, a.as_mut_ptr(), 1)
}

#[test]
fn close_session_destroys_its_session_objects() {
    let keeper = setup();
    let keeper_key = gen_session_aes(keeper, b"keeper");

    let a = open(true);
    let key = gen_session_aes(a, b"ephemeral");
    assert_eq!(count_by_label(keeper, b"ephemeral"), 1);
    assert_eq!(C_CloseSession(a), CKR_OK);

    let b = open(false);
    assert_eq!(count_by_label(b, b"ephemeral"), 0);
    assert_eq!(value_len_rv(b, key), CKR_OBJECT_HANDLE_INVALID);
    // Other sessions' objects are untouched.
    assert_eq!(value_len_rv(b, keeper_key), CKR_OK);

    C_Finalize(ptr::null_mut());
}

#[test]
fn close_all_sessions_destroys_session_objects() {
    let keeper = setup();
    let key = gen_session_aes(keeper, b"ephemeral");
    assert_eq!(C_CloseAllSessions(0), CKR_OK);

    let b = open(true);
    assert_eq!(login(b, CKU_USER, USER_PIN), CKR_OK);
    assert_eq!(count_by_label(b, b"ephemeral"), 0);
    assert_eq!(value_len_rv(b, key), CKR_OBJECT_HANDLE_INVALID);

    C_Finalize(ptr::null_mut());
}
