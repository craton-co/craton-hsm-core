// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
// CKM_AES_GCM with CK_GCM_PARAMS — the standard PKCS#11 form in which the
// caller supplies the IV and AAD and the ciphertext is `ciphertext || tag`.
//
// Regression tests for OpenBao's PKCS#11 auto-unseal, which encrypts with a
// caller-chosen IV, stores (ciphertext, IV) and decrypts with that IV. Craton
// used to ignore CK_GCM_PARAMS and prepend its own nonce, so the decrypt
// failed with CKR_ENCRYPTED_DATA_INVALID.
//
// Must run with --test-threads=1 due to global OnceLock state.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm::pkcs11_abi::functions::*;
use craton_hsm::pkcs11_abi::types::*;
use std::ptr;

mod common;

fn ck_ulong_bytes(val: CK_ULONG) -> Vec<u8> {
    val.to_ne_bytes().to_vec()
}

fn setup_session() -> CK_SESSION_HANDLE {
    let rv = C_Initialize(ptr::null_mut());
    assert!(rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED);

    let so_pin = b"sopin123";
    let mut label = [b' '; 32];
    label[..9].copy_from_slice(b"TestToken");
    let rv = C_InitToken(
        0,
        so_pin.as_ptr() as *mut _,
        so_pin.len() as CK_ULONG,
        label.as_ptr() as *mut _,
    );
    assert_eq!(rv, CKR_OK);

    let mut session: CK_SESSION_HANDLE = 0;
    let rv = C_OpenSession(
        0,
        CKF_RW_SESSION | CKF_SERIAL_SESSION,
        ptr::null_mut(),
        None,
        &mut session,
    );
    assert_eq!(rv, CKR_OK);
    let rv = C_Login(
        session,
        CKU_SO,
        so_pin.as_ptr() as *mut _,
        so_pin.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_OK);
    let user_pin = b"userpin1234";
    let rv = C_InitPIN(
        session,
        user_pin.as_ptr() as *mut _,
        user_pin.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_OK);
    assert_eq!(C_Logout(session), CKR_OK);
    let rv = C_Login(
        session,
        CKU_USER,
        user_pin.as_ptr() as *mut _,
        user_pin.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_OK);
    session
}

/// Create an AES-256 key with known value so the ciphertext can
/// be checked against an independent AES-GCM implementation.
fn create_aes_key(session: CK_SESSION_HANDLE, value: &[u8; 32]) -> CK_OBJECT_HANDLE {
    let class = ck_ulong_bytes(CKO_SECRET_KEY);
    let key_type = ck_ulong_bytes(CKK_AES);
    let yes: CK_BBOOL = CK_TRUE;
    let mut template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_CLASS,
            p_value: class.as_ptr() as CK_VOID_PTR,
            value_len: class.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_KEY_TYPE,
            p_value: key_type.as_ptr() as CK_VOID_PTR,
            value_len: key_type.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_VALUE,
            p_value: value.as_ptr() as CK_VOID_PTR,
            value_len: value.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_ENCRYPT,
            p_value: &yes as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_DECRYPT,
            p_value: &yes as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
    ];
    let mut handle: CK_OBJECT_HANDLE = 0;
    let rv = C_CreateObject(
        session,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut handle,
    );
    assert_eq!(rv, CKR_OK);
    handle
}

fn random_iv(session: CK_SESSION_HANDLE) -> [u8; 12] {
    let mut iv = [0u8; 12];
    assert_eq!(C_GenerateRandom(session, iv.as_mut_ptr(), 12), CKR_OK);
    iv
}

fn gcm_params(iv: &[u8], aad: &[u8], tag_bits: CK_ULONG) -> CK_GCM_PARAMS {
    CK_GCM_PARAMS {
        p_iv: iv.as_ptr() as CK_BYTE_PTR,
        iv_len: iv.len() as CK_ULONG,
        iv_bits: (iv.len() * 8) as CK_ULONG,
        p_aad: if aad.is_empty() {
            ptr::null_mut()
        } else {
            aad.as_ptr() as CK_BYTE_PTR
        },
        aad_len: aad.len() as CK_ULONG,
        tag_bits,
    }
}

fn gcm_mechanism(params: &mut CK_GCM_PARAMS) -> CK_MECHANISM {
    CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: params as *mut _ as CK_VOID_PTR,
        parameter_len: std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
    }
}

fn encrypt(
    session: CK_SESSION_HANDLE,
    mech: &mut CK_MECHANISM,
    key: CK_OBJECT_HANDLE,
    data: &[u8],
) -> Result<Vec<u8>, CK_RV> {
    let rv = C_EncryptInit(session, mech, key);
    if rv != CKR_OK {
        return Err(rv);
    }
    let mut len: CK_ULONG = 0;
    let rv = C_Encrypt(
        session,
        data.as_ptr() as *mut _,
        data.len() as CK_ULONG,
        ptr::null_mut(),
        &mut len,
    );
    assert_eq!(rv, CKR_OK);
    let mut out = vec![0u8; len as usize];
    let rv = C_Encrypt(
        session,
        data.as_ptr() as *mut _,
        data.len() as CK_ULONG,
        out.as_mut_ptr(),
        &mut len,
    );
    if rv != CKR_OK {
        return Err(rv);
    }
    out.truncate(len as usize);
    Ok(out)
}

fn decrypt(
    session: CK_SESSION_HANDLE,
    mech: &mut CK_MECHANISM,
    key: CK_OBJECT_HANDLE,
    data: &[u8],
) -> Result<Vec<u8>, CK_RV> {
    let rv = C_DecryptInit(session, mech, key);
    if rv != CKR_OK {
        return Err(rv);
    }
    let mut out = vec![0u8; data.len()];
    let mut len = out.len() as CK_ULONG;
    let rv = C_Decrypt(
        session,
        data.as_ptr() as *mut _,
        data.len() as CK_ULONG,
        out.as_mut_ptr(),
        &mut len,
    );
    if rv != CKR_OK {
        return Err(rv);
    }
    out.truncate(len as usize);
    Ok(out)
}

#[test]
fn test_gcm_params_openbao_roundtrip() {
    let session = setup_session();
    let key_value = [0x42u8; 32];
    let key = create_aes_key(session, &key_value);
    let plaintext = b"openbao-root-key-material-33bytes";
    assert_eq!(plaintext.len(), 33);

    let iv = random_iv(session);
    let mut params = gcm_params(&iv, &[], 128);
    let mut mech = gcm_mechanism(&mut params);
    let ciphertext = encrypt(session, &mut mech, key, plaintext).unwrap();

    // ciphertext || 128-bit tag — no IV prefix.
    assert_eq!(ciphertext.len(), plaintext.len() + 16);

    // Interoperable with any AES-GCM implementation given the same IV.
    let reference = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_value))
        .encrypt(Nonce::from_slice(&iv), &plaintext[..])
        .unwrap();
    assert_eq!(ciphertext, reference);

    // OpenBao decrypts with a fresh CK_GCM_PARAMS carrying the stored IV.
    let mut params = gcm_params(&iv, &[], 128);
    let mut mech = gcm_mechanism(&mut params);
    let decrypted = decrypt(session, &mut mech, key, &ciphertext).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_gcm_params_aad() {
    let session = setup_session();
    let key_value = [0x17u8; 32];
    let key = create_aes_key(session, &key_value);
    let plaintext = b"payload with associated data";
    let aad = b"context-binding";

    let iv = random_iv(session);
    let mut params = gcm_params(&iv, aad, 128);
    let mut mech = gcm_mechanism(&mut params);
    let ciphertext = encrypt(session, &mut mech, key, plaintext).unwrap();

    let reference = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_value))
        .encrypt(
            Nonce::from_slice(&iv),
            Payload {
                msg: &plaintext[..],
                aad: &aad[..],
            },
        )
        .unwrap();
    assert_eq!(ciphertext, reference);

    let mut params = gcm_params(&iv, aad, 128);
    let mut mech = gcm_mechanism(&mut params);
    assert_eq!(
        decrypt(session, &mut mech, key, &ciphertext).unwrap(),
        plaintext
    );

    // Wrong AAD must fail authentication.
    let mut params = gcm_params(&iv, b"other-context", 128);
    let mut mech = gcm_mechanism(&mut params);
    assert_eq!(
        decrypt(session, &mut mech, key, &ciphertext),
        Err(CKR_ENCRYPTED_DATA_INVALID)
    );
}

#[test]
fn test_gcm_params_rejects_iv_reuse() {
    let session = setup_session();
    let key = create_aes_key(session, &[0x33u8; 32]);
    let iv = random_iv(session);

    let mut params = gcm_params(&iv, &[], 128);
    let mut mech = gcm_mechanism(&mut params);
    encrypt(session, &mut mech, key, b"first").unwrap();

    let mut params = gcm_params(&iv, &[], 128);
    let mut mech = gcm_mechanism(&mut params);
    assert_eq!(
        encrypt(session, &mut mech, key, b"second"),
        Err(CKR_MECHANISM_PARAM_INVALID)
    );
}

#[test]
fn test_gcm_params_rejects_unsupported_params() {
    let session = setup_session();
    let key = create_aes_key(session, &[0x55u8; 32]);

    // Truncated tag.
    let iv = random_iv(session);
    let mut params = gcm_params(&iv, &[], 96);
    let mut mech = gcm_mechanism(&mut params);
    assert_eq!(
        C_EncryptInit(session, &mut mech, key),
        CKR_MECHANISM_PARAM_INVALID
    );

    // Non-96-bit IV.
    let iv16 = [0x01u8; 16];
    let mut params = gcm_params(&iv16, &[], 128);
    let mut mech = gcm_mechanism(&mut params);
    assert_eq!(
        C_EncryptInit(session, &mut mech, key),
        CKR_MECHANISM_PARAM_INVALID
    );

    // All-zero IV.
    let zero = [0u8; 12];
    let mut params = gcm_params(&zero, &[], 128);
    let mut mech = gcm_mechanism(&mut params);
    assert_eq!(
        C_EncryptInit(session, &mut mech, key),
        CKR_MECHANISM_PARAM_INVALID
    );
}

#[test]
fn test_gcm_without_params_keeps_legacy_layout() {
    let session = setup_session();
    let key = create_aes_key(session, &[0x66u8; 32]);
    let plaintext = b"legacy craton layout";

    let mut mech = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let ciphertext = encrypt(session, &mut mech, key, plaintext).unwrap();
    // nonce (12) || ciphertext || tag (16)
    assert_eq!(ciphertext.len(), plaintext.len() + 28);

    let mut mech = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    assert_eq!(
        decrypt(session, &mut mech, key, &ciphertext).unwrap(),
        plaintext
    );
}
