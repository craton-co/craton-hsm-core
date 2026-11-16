// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! CKA_ALWAYS_AUTHENTICATE / CKU_CONTEXT_SPECIFIC (PKCS#11 v3.2 §4.10, §5.6.8).
//!
//! Must run with --test-threads=1 due to global PKCS#11 state.

use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm::pkcs11_abi::functions::*;
use craton_hsm::pkcs11_abi::types::*;
use std::ptr;

mod common;

const USER_PIN: &[u8] = b"userpin1234";

fn setup_session() -> CK_SESSION_HANDLE {
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
    let mut s: CK_SESSION_HANDLE = 0;
    assert_eq!(
        C_OpenSession(
            0,
            CKF_RW_SESSION | CKF_SERIAL_SESSION,
            ptr::null_mut(),
            None,
            &mut s
        ),
        CKR_OK
    );
    assert_eq!(
        C_Login(
            s,
            CKU_SO,
            so_pin.as_ptr() as *mut _,
            so_pin.len() as CK_ULONG
        ),
        CKR_OK
    );
    assert_eq!(
        C_InitPIN(s, USER_PIN.as_ptr() as *mut _, USER_PIN.len() as CK_ULONG),
        CKR_OK
    );
    assert_eq!(C_Logout(s), CKR_OK);
    assert_eq!(login(s, CKU_USER, USER_PIN), CKR_OK);
    s
}

fn login(s: CK_SESSION_HANDLE, user_type: CK_USER_TYPE, pin: &[u8]) -> CK_RV {
    C_Login(s, user_type, pin.as_ptr() as *mut _, pin.len() as CK_ULONG)
}

fn attr(t: CK_ATTRIBUTE_TYPE, v: &CK_BBOOL) -> CK_ATTRIBUTE {
    CK_ATTRIBUTE {
        attr_type: t,
        p_value: v as *const _ as CK_VOID_PTR,
        value_len: 1,
    }
}

/// P-256 key pair; the private key gets CKA_ALWAYS_AUTHENTICATE = `always`.
fn gen_p256(s: CK_SESSION_HANDLE, always: CK_BBOOL) -> CK_OBJECT_HANDLE {
    let t: CK_BBOOL = CK_TRUE;
    let f: CK_BBOOL = CK_FALSE;
    let p256: [u8; 10] = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    let mut pub_t = [
        CK_ATTRIBUTE {
            attr_type: CKA_EC_PARAMS,
            p_value: p256.as_ptr() as CK_VOID_PTR,
            value_len: p256.len() as CK_ULONG,
        },
        attr(CKA_VERIFY, &t),
        attr(CKA_TOKEN, &f),
    ];
    let mut priv_t = [
        attr(CKA_SIGN, &t),
        attr(CKA_PRIVATE, &t),
        attr(CKA_SENSITIVE, &t),
        attr(CKA_TOKEN, &f),
        attr(CKA_ALWAYS_AUTHENTICATE, &always),
    ];
    let mut mech = CK_MECHANISM {
        mechanism: CKM_EC_KEY_PAIR_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let (mut h_pub, mut h_priv) = (0, 0);
    let rv = C_GenerateKeyPair(
        s,
        &mut mech,
        pub_t.as_mut_ptr(),
        pub_t.len() as CK_ULONG,
        priv_t.as_mut_ptr(),
        priv_t.len() as CK_ULONG,
        &mut h_pub,
        &mut h_priv,
    );
    assert_eq!(rv, CKR_OK);
    h_priv
}

fn sign_init(s: CK_SESSION_HANDLE, key: CK_OBJECT_HANDLE) -> CK_RV {
    let mut mech = CK_MECHANISM {
        mechanism: CKM_ECDSA,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    C_SignInit(s, &mut mech, key)
}

fn sign(s: CK_SESSION_HANDLE) -> CK_RV {
    let digest = [0x11u8; 32];
    let mut sig = [0u8; 128];
    let mut sig_len = sig.len() as CK_ULONG;
    C_Sign(
        s,
        digest.as_ptr() as *mut _,
        digest.len() as CK_ULONG,
        sig.as_mut_ptr(),
        &mut sig_len,
    )
}

fn read_always_auth(s: CK_SESSION_HANDLE, key: CK_OBJECT_HANDLE) -> (CK_RV, CK_BBOOL) {
    let mut v: CK_BBOOL = 0xff;
    let mut a = [CK_ATTRIBUTE {
        attr_type: CKA_ALWAYS_AUTHENTICATE,
        p_value: &mut v as *mut _ as CK_VOID_PTR,
        value_len: 1,
    }];
    let rv = C_GetAttributeValue(s, key, a.as_mut_ptr(), 1);
    (rv, v)
}

#[test]
fn always_authenticate_requires_context_login_per_operation() {
    let s = setup_session();
    let key = gen_p256(s, CK_TRUE);
    assert_eq!(read_always_auth(s, key), (CKR_OK, CK_TRUE));

    // Context login after SignInit authorizes this one operation.
    assert_eq!(sign_init(s, key), CKR_OK);
    assert_eq!(login(s, CKU_CONTEXT_SPECIFIC, USER_PIN), CKR_OK);
    assert_eq!(sign(s), CKR_OK);

    // Omitting it on the next operation fails and ends the operation.
    assert_eq!(sign_init(s, key), CKR_OK);
    assert_eq!(sign(s), CKR_USER_NOT_LOGGED_IN);
    assert_eq!(sign(s), CKR_OPERATION_NOT_INITIALIZED);

    // A wrong PIN does not authorize the operation.
    assert_eq!(sign_init(s, key), CKR_OK);
    assert_eq!(
        login(s, CKU_CONTEXT_SPECIFIC, b"wrongpin99"),
        CKR_PIN_INCORRECT
    );
    assert_eq!(sign(s), CKR_USER_NOT_LOGGED_IN);

    C_Finalize(ptr::null_mut());
}

#[test]
fn context_login_without_always_authenticate_operation_is_rejected() {
    let s = setup_session();
    let key = gen_p256(s, CK_FALSE);
    assert_eq!(read_always_auth(s, key), (CKR_OK, CK_FALSE));

    // No operation at all.
    assert_eq!(
        login(s, CKU_CONTEXT_SPECIFIC, USER_PIN),
        CKR_OPERATION_NOT_INITIALIZED
    );
    // Operation on a key without the attribute: no context login needed.
    assert_eq!(sign_init(s, key), CKR_OK);
    assert_eq!(
        login(s, CKU_CONTEXT_SPECIFIC, USER_PIN),
        CKR_OPERATION_NOT_INITIALIZED
    );
    assert_eq!(sign(s), CKR_OK);

    C_Finalize(ptr::null_mut());
}
