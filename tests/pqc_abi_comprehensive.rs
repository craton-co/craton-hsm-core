// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Comprehensive PQC (Post-Quantum Cryptography) tests through the PKCS#11 C ABI layer.
//! Covers ML-DSA (FIPS 204), ML-KEM (FIPS 203), SLH-DSA (FIPS 205), and hybrid mechanisms.
//!
//! NOTE: These tests MUST be run with --test-threads=1 because the PKCS#11 C ABI uses
//! a shared global OnceLock state.

use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm::pkcs11_abi::functions::*;
use craton_hsm::pkcs11_abi::types::*;
use std::ptr;

fn ck_ulong_bytes(val: CK_ULONG) -> Vec<u8> {
    val.to_ne_bytes().to_vec()
}

fn ensure_init() {
    let rv = C_Initialize(ptr::null_mut());
    assert!(
        rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED,
        "C_Initialize failed: 0x{:08X}",
        rv
    );
}

/// Set up a fully authenticated RW user session: init token, open RW session,
/// login as SO, init user PIN, logout SO, login as user.
fn setup_user_session() -> CK_SESSION_HANDLE {
    ensure_init();
    let so_pin = b"sopin123";
    let mut label = [b' '; 32];
    label[..7].copy_from_slice(b"PQCTest");
    let rv = C_InitToken(
        0,
        so_pin.as_ptr() as *mut _,
        so_pin.len() as CK_ULONG,
        label.as_ptr() as *mut _,
    );
    assert_eq!(rv, CKR_OK, "C_InitToken failed: 0x{:08X}", rv);

    let mut session: CK_SESSION_HANDLE = 0;
    let rv = C_OpenSession(
        0,
        CKF_RW_SESSION | CKF_SERIAL_SESSION,
        ptr::null_mut(),
        None,
        &mut session,
    );
    assert_eq!(rv, CKR_OK, "C_OpenSession failed: 0x{:08X}", rv);

    let rv = C_Login(
        session,
        CKU_SO,
        so_pin.as_ptr() as *mut _,
        so_pin.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_OK, "C_Login SO failed: 0x{:08X}", rv);
    let user_pin = b"userpin1";
    let rv = C_InitPIN(
        session,
        user_pin.as_ptr() as *mut _,
        user_pin.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_OK, "C_InitPIN failed: 0x{:08X}", rv);
    let rv = C_Logout(session);
    assert_eq!(rv, CKR_OK, "C_Logout SO failed: 0x{:08X}", rv);
    let rv = C_Login(
        session,
        CKU_USER,
        user_pin.as_ptr() as *mut _,
        user_pin.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_OK, "C_Login USER failed: 0x{:08X}", rv);
    session
}

// ---------------------------------------------------------------------------
// PQC key generation helpers
// ---------------------------------------------------------------------------

fn generate_ml_dsa_keypair(
    session: CK_SESSION_HANDLE,
    mechanism_type: CK_MECHANISM_TYPE,
) -> (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) {
    let mut mechanism = CK_MECHANISM {
        mechanism: mechanism_type,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let ck_true: CK_BBOOL = CK_TRUE;

    let mut pub_template = vec![CK_ATTRIBUTE {
        attr_type: CKA_VERIFY,
        p_value: &ck_true as *const _ as CK_VOID_PTR,
        value_len: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
    }];
    let mut priv_template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_SIGN,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_SENSITIVE,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ];

    let mut pub_key: CK_OBJECT_HANDLE = 0;
    let mut priv_key: CK_OBJECT_HANDLE = 0;
    let rv = C_GenerateKeyPair(
        session,
        &mut mechanism,
        pub_template.as_mut_ptr(),
        pub_template.len() as CK_ULONG,
        priv_template.as_mut_ptr(),
        priv_template.len() as CK_ULONG,
        &mut pub_key,
        &mut priv_key,
    );
    assert_eq!(rv, CKR_OK, "ML-DSA keygen failed: 0x{:08X}", rv);
    (pub_key, priv_key)
}

fn generate_ml_kem_keypair(
    session: CK_SESSION_HANDLE,
    mechanism_type: CK_MECHANISM_TYPE,
) -> (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) {
    let mut mechanism = CK_MECHANISM {
        mechanism: mechanism_type,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let ck_true: CK_BBOOL = CK_TRUE;

    let mut pub_template = vec![CK_ATTRIBUTE {
        attr_type: CKA_DERIVE,
        p_value: &ck_true as *const _ as CK_VOID_PTR,
        value_len: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
    }];
    let mut priv_template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_DERIVE,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_SENSITIVE,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ];

    let mut pub_key: CK_OBJECT_HANDLE = 0;
    let mut priv_key: CK_OBJECT_HANDLE = 0;
    let rv = C_GenerateKeyPair(
        session,
        &mut mechanism,
        pub_template.as_mut_ptr(),
        pub_template.len() as CK_ULONG,
        priv_template.as_mut_ptr(),
        priv_template.len() as CK_ULONG,
        &mut pub_key,
        &mut priv_key,
    );
    assert_eq!(rv, CKR_OK, "ML-KEM keygen failed: 0x{:08X}", rv);
    (pub_key, priv_key)
}

fn generate_slh_dsa_keypair(
    session: CK_SESSION_HANDLE,
    mechanism_type: CK_MECHANISM_TYPE,
) -> (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) {
    let mut mechanism = CK_MECHANISM {
        mechanism: mechanism_type,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let ck_true: CK_BBOOL = CK_TRUE;

    let mut pub_template = vec![CK_ATTRIBUTE {
        attr_type: CKA_VERIFY,
        p_value: &ck_true as *const _ as CK_VOID_PTR,
        value_len: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
    }];
    let mut priv_template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_SIGN,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_SENSITIVE,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ];

    let mut pub_key: CK_OBJECT_HANDLE = 0;
    let mut priv_key: CK_OBJECT_HANDLE = 0;
    let rv = C_GenerateKeyPair(
        session,
        &mut mechanism,
        pub_template.as_mut_ptr(),
        pub_template.len() as CK_ULONG,
        priv_template.as_mut_ptr(),
        priv_template.len() as CK_ULONG,
        &mut pub_key,
        &mut priv_key,
    );
    assert_eq!(rv, CKR_OK, "SLH-DSA keygen failed: 0x{:08X}", rv);
    (pub_key, priv_key)
}

/// Helper: sign data using the given session, mechanism, and private key handle.
/// Returns the signature bytes.
///
/// Uses a generously-sized output buffer to avoid needing a separate size query.
/// PQC signature sizes: ML-DSA-44=2420, ML-DSA-65=3309, ML-DSA-87=4627,
/// SLH-DSA-SHA2-128s=7856, SLH-DSA-SHA2-256s=29792, hybrid>3400.
fn sign_data(
    session: CK_SESSION_HANDLE,
    mechanism_type: CK_MECHANISM_TYPE,
    priv_key: CK_OBJECT_HANDLE,
    data: &[u8],
) -> Vec<u8> {
    let mut mechanism = CK_MECHANISM {
        mechanism: mechanism_type,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_SignInit(session, &mut mechanism, priv_key);
    assert_eq!(rv, CKR_OK, "C_SignInit failed: 0x{:08X}", rv);

    // Allocate a generous buffer — PQC signatures can be up to ~30KB
    let mut sig_buf = vec![0u8; 32768];
    let mut sig_len: CK_ULONG = sig_buf.len() as CK_ULONG;
    let rv = C_Sign(
        session,
        data.as_ptr() as CK_BYTE_PTR,
        data.len() as CK_ULONG,
        sig_buf.as_mut_ptr(),
        &mut sig_len,
    );
    assert_eq!(rv, CKR_OK, "C_Sign failed: 0x{:08X}", rv);
    sig_buf.truncate(sig_len as usize);
    sig_buf
}

/// Helper: verify a signature.
fn verify_data(
    session: CK_SESSION_HANDLE,
    mechanism_type: CK_MECHANISM_TYPE,
    pub_key: CK_OBJECT_HANDLE,
    data: &[u8],
    signature: &[u8],
) -> CK_RV {
    let mut mechanism = CK_MECHANISM {
        mechanism: mechanism_type,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_VerifyInit(session, &mut mechanism, pub_key);
    assert_eq!(rv, CKR_OK, "C_VerifyInit failed: 0x{:08X}", rv);

    C_Verify(
        session,
        data.as_ptr() as CK_BYTE_PTR,
        data.len() as CK_ULONG,
        signature.as_ptr() as CK_BYTE_PTR,
        signature.len() as CK_ULONG,
    )
}

/// Helper: read a CK_ULONG attribute from an object.
fn read_ulong_attribute(
    session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    attr_type: CK_ATTRIBUTE_TYPE,
) -> CK_ULONG {
    let mut buf = [0u8; std::mem::size_of::<CK_ULONG>()];
    let mut template = [CK_ATTRIBUTE {
        attr_type,
        p_value: buf.as_mut_ptr() as CK_VOID_PTR,
        value_len: buf.len() as CK_ULONG,
    }];
    let rv = C_GetAttributeValue(session, object, template.as_mut_ptr(), 1);
    assert_eq!(rv, CKR_OK, "C_GetAttributeValue failed: 0x{:08X}", rv);
    CK_ULONG::from_ne_bytes(buf)
}

/// Helper: read a CK_BBOOL attribute from an object.
fn read_bbool_attribute(
    session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    attr_type: CK_ATTRIBUTE_TYPE,
) -> CK_BBOOL {
    let mut buf = [0u8; 1];
    let mut template = [CK_ATTRIBUTE {
        attr_type,
        p_value: buf.as_mut_ptr() as CK_VOID_PTR,
        value_len: 1,
    }];
    let rv = C_GetAttributeValue(session, object, template.as_mut_ptr(), 1);
    assert_eq!(rv, CKR_OK, "C_GetAttributeValue failed: 0x{:08X}", rv);
    buf[0]
}

/// Helper: read a variable-length attribute from an object (e.g., CKA_VALUE, public key data).
/// First queries the size with p_value=null, then allocates and reads.
fn read_variable_attribute(
    session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    attr_type: CK_ATTRIBUTE_TYPE,
) -> Vec<u8> {
    // First: query size
    let mut template = [CK_ATTRIBUTE {
        attr_type,
        p_value: ptr::null_mut(),
        value_len: 0,
    }];
    let rv = C_GetAttributeValue(session, object, template.as_mut_ptr(), 1);
    assert_eq!(
        rv, CKR_OK,
        "C_GetAttributeValue size query failed: 0x{:08X}",
        rv
    );
    let size = template[0].value_len as usize;
    assert!(size > 0, "Attribute size should be > 0");

    // Second: read value
    let mut buf = vec![0u8; size];
    template[0].p_value = buf.as_mut_ptr() as CK_VOID_PTR;
    template[0].value_len = size as CK_ULONG;
    let rv = C_GetAttributeValue(session, object, template.as_mut_ptr(), 1);
    assert_eq!(rv, CKR_OK, "C_GetAttributeValue read failed: 0x{:08X}", rv);
    buf
}

// ===========================================================================
// Test 1: ML-DSA-44 keygen + sign + verify
// ===========================================================================
#[test]
fn test_ml_dsa_44_keygen_sign_verify() {
    let session = setup_user_session();
    let (pub_key, priv_key) = generate_ml_dsa_keypair(session, CKM_ML_DSA_44);

    let data = b"test data for ML-DSA-44";
    let signature = sign_data(session, CKM_ML_DSA_44, priv_key, data);

    let rv = verify_data(session, CKM_ML_DSA_44, pub_key, data, &signature);
    assert_eq!(rv, CKR_OK, "ML-DSA-44 verify failed: 0x{:08X}", rv);
}

// ===========================================================================
// Test 2: ML-DSA-65 keygen + sign + verify
// ===========================================================================
#[test]
fn test_ml_dsa_65_keygen_sign_verify() {
    let session = setup_user_session();
    let (pub_key, priv_key) = generate_ml_dsa_keypair(session, CKM_ML_DSA_65);

    let data = b"test data for ML-DSA-65";
    let signature = sign_data(session, CKM_ML_DSA_65, priv_key, data);

    let rv = verify_data(session, CKM_ML_DSA_65, pub_key, data, &signature);
    assert_eq!(rv, CKR_OK, "ML-DSA-65 verify failed: 0x{:08X}", rv);
}

// ===========================================================================
// Test 3: ML-DSA-87 keygen + sign + verify
// ===========================================================================
#[test]
fn test_ml_dsa_87_keygen_sign_verify() {
    let session = setup_user_session();
    let (pub_key, priv_key) = generate_ml_dsa_keypair(session, CKM_ML_DSA_87);

    let data = b"test data for ML-DSA-87";
    let signature = sign_data(session, CKM_ML_DSA_87, priv_key, data);

    let rv = verify_data(session, CKM_ML_DSA_87, pub_key, data, &signature);
    assert_eq!(rv, CKR_OK, "ML-DSA-87 verify failed: 0x{:08X}", rv);
}

// ===========================================================================
// Test 4: ML-KEM-768 keygen succeeds and returns valid handles
// ===========================================================================
#[test]
fn test_ml_kem_768_keygen() {
    let session = setup_user_session();
    let (pub_key, priv_key) = generate_ml_kem_keypair(session, CKM_ML_KEM_768);
    assert_ne!(
        pub_key, 0,
        "ML-KEM-768 public key handle should be non-zero"
    );
    assert_ne!(
        priv_key, 0,
        "ML-KEM-768 private key handle should be non-zero"
    );
    assert_ne!(
        pub_key, priv_key,
        "Public and private handles should differ"
    );
}

// ===========================================================================
// Test 5: ML-DSA sign with key A, verify with key B -> CKR_SIGNATURE_INVALID
// ===========================================================================
#[test]
fn test_ml_dsa_sign_wrong_key_fails() {
    let session = setup_user_session();
    let (_pub_a, priv_a) = generate_ml_dsa_keypair(session, CKM_ML_DSA_44);
    let (pub_b, _priv_b) = generate_ml_dsa_keypair(session, CKM_ML_DSA_44);

    let data = b"signed with key A";
    let signature = sign_data(session, CKM_ML_DSA_44, priv_a, data);

    // Verify with key B should fail
    let rv = verify_data(session, CKM_ML_DSA_44, pub_b, data, &signature);
    assert_eq!(
        rv, CKR_SIGNATURE_INVALID,
        "Verifying with wrong key should return CKR_SIGNATURE_INVALID, got 0x{:08X}",
        rv
    );
}

// ===========================================================================
// Test 6: ML-DSA sign "hello", verify with "world" -> CKR_SIGNATURE_INVALID
// ===========================================================================
#[test]
fn test_ml_dsa_sign_tampered_data_fails() {
    let session = setup_user_session();
    let (pub_key, priv_key) = generate_ml_dsa_keypair(session, CKM_ML_DSA_44);

    let signature = sign_data(session, CKM_ML_DSA_44, priv_key, b"hello");

    let rv = verify_data(session, CKM_ML_DSA_44, pub_key, b"world", &signature);
    assert_eq!(
        rv, CKR_SIGNATURE_INVALID,
        "Verifying tampered data should return CKR_SIGNATURE_INVALID, got 0x{:08X}",
        rv
    );
}

// ===========================================================================
// Test 7: ML-DSA-44 signature size is 2420 bytes
// ===========================================================================
#[test]
fn test_ml_dsa_44_signature_size() {
    let session = setup_user_session();
    let (_pub_key, priv_key) = generate_ml_dsa_keypair(session, CKM_ML_DSA_44);

    let signature = sign_data(session, CKM_ML_DSA_44, priv_key, b"size check");
    assert_eq!(
        signature.len(),
        2420,
        "ML-DSA-44 signature should be exactly 2420 bytes, got {}",
        signature.len()
    );
}

// ===========================================================================
// Test 8: ML-DSA-65 signature size is 3309 bytes
// ===========================================================================
#[test]
fn test_ml_dsa_65_signature_size() {
    let session = setup_user_session();
    let (_pub_key, priv_key) = generate_ml_dsa_keypair(session, CKM_ML_DSA_65);

    let signature = sign_data(session, CKM_ML_DSA_65, priv_key, b"size check 65");
    assert_eq!(
        signature.len(),
        3309,
        "ML-DSA-65 signature should be exactly 3309 bytes, got {}",
        signature.len()
    );
}

// ===========================================================================
// Test 9: ML-DSA C_Sign with null output returns required size
// ===========================================================================
#[test]
fn test_ml_dsa_null_output_gets_size() {
    let session = setup_user_session();
    let (_pub_key, priv_key) = generate_ml_dsa_keypair(session, CKM_ML_DSA_44);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_ML_DSA_44,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_SignInit(session, &mut mechanism, priv_key);
    assert_eq!(rv, CKR_OK);

    let data = b"query size test";
    let mut sig_len: CK_ULONG = 0;
    let rv = C_Sign(
        session,
        data.as_ptr() as CK_BYTE_PTR,
        data.len() as CK_ULONG,
        ptr::null_mut(),
        &mut sig_len,
    );
    assert_eq!(rv, CKR_OK, "Size query should succeed");
    assert_eq!(
        sig_len, 2420,
        "ML-DSA-44 reported size should be 2420, got {}",
        sig_len
    );
}

// ===========================================================================
// Test 10: ML-DSA keygen attributes — CKA_KEY_TYPE and CKA_CLASS
// ===========================================================================
#[test]
fn test_ml_dsa_keygen_attributes() {
    let session = setup_user_session();
    let (pub_key, priv_key) = generate_ml_dsa_keypair(session, CKM_ML_DSA_44);

    // Public key: CKA_KEY_TYPE should be CKK_ML_DSA
    let kt = read_ulong_attribute(session, pub_key, CKA_KEY_TYPE);
    assert_eq!(kt, CKK_ML_DSA, "Public key type should be CKK_ML_DSA");

    // Public key: CKA_CLASS should be CKO_PUBLIC_KEY
    let cls = read_ulong_attribute(session, pub_key, CKA_CLASS);
    assert_eq!(
        cls, CKO_PUBLIC_KEY,
        "Public key class should be CKO_PUBLIC_KEY"
    );

    // Private key: CKA_KEY_TYPE should be CKK_ML_DSA
    let kt = read_ulong_attribute(session, priv_key, CKA_KEY_TYPE);
    assert_eq!(kt, CKK_ML_DSA, "Private key type should be CKK_ML_DSA");

    // Private key: CKA_CLASS should be CKO_PRIVATE_KEY
    let cls = read_ulong_attribute(session, priv_key, CKA_CLASS);
    assert_eq!(
        cls, CKO_PRIVATE_KEY,
        "Private key class should be CKO_PRIVATE_KEY"
    );
}

// ===========================================================================
// Test 11: ML-DSA private key CKA_SENSITIVE is CK_TRUE
// ===========================================================================
#[test]
fn test_ml_dsa_private_key_sensitive() {
    let session = setup_user_session();
    let (_pub_key, priv_key) = generate_ml_dsa_keypair(session, CKM_ML_DSA_44);

    let sensitive = read_bbool_attribute(session, priv_key, CKA_SENSITIVE);
    assert_eq!(
        sensitive, CK_TRUE,
        "ML-DSA private key CKA_SENSITIVE should be CK_TRUE"
    );
}

// ===========================================================================
// Test 12: ML-DSA sign without login -> CKR_USER_NOT_LOGGED_IN
// ===========================================================================
#[test]
fn test_ml_dsa_sign_without_login() {
    ensure_init();

    // Init token so we have a clean state
    let so_pin = b"sopin123";
    let mut label = [b' '; 32];
    label[..9].copy_from_slice(b"NoLoginTk");
    let rv = C_InitToken(
        0,
        so_pin.as_ptr() as *mut _,
        so_pin.len() as CK_ULONG,
        label.as_ptr() as *mut _,
    );
    assert_eq!(rv, CKR_OK);

    // Open session but do NOT login
    let mut session: CK_SESSION_HANDLE = 0;
    let rv = C_OpenSession(
        0,
        CKF_RW_SESSION | CKF_SERIAL_SESSION,
        ptr::null_mut(),
        None,
        &mut session,
    );
    assert_eq!(rv, CKR_OK);

    // Attempt C_SignInit without logging in — should fail
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_ML_DSA_44,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    // We use handle 1 as a dummy; the login check should come first
    let rv = C_SignInit(session, &mut mechanism, 1);
    assert_eq!(
        rv, CKR_USER_NOT_LOGGED_IN,
        "SignInit without login should return CKR_USER_NOT_LOGGED_IN, got 0x{:08X}",
        rv
    );

    let rv = C_CloseSession(session);
    assert_eq!(rv, CKR_OK);
}

// ===========================================================================
// Test 13: ML-KEM-768 encapsulation + decapsulation via C_DeriveKey
// ===========================================================================
#[test]
fn test_ml_kem_768_encap_decap() {
    // ML-KEM uses C_DeriveKey (not C_Encrypt/C_Decrypt) in this implementation.
    // The public key data (ek_bytes) is stored in `public_key_data` which is not
    // directly readable through a standard CKA_ attribute. So we generate keys at
    // the Rust level for encapsulation, and verify decapsulation via C_DeriveKey
    // by creating the private key object through C_CreateObject.
    use craton_hsm::crypto::pqc::{ml_kem_encapsulate, ml_kem_keygen, MlKemVariant};

    let session = setup_user_session();

    // Generate ML-KEM-768 keypair at the Rust level
    let (dk_seed, ek_bytes) = ml_kem_keygen(MlKemVariant::MlKem768).expect("ML-KEM keygen failed");

    // Encapsulate using the public key
    let (ciphertext, shared_secret_enc) =
        ml_kem_encapsulate(&ek_bytes, MlKemVariant::MlKem768).expect("ML-KEM encapsulation failed");
    assert!(!ciphertext.is_empty(), "KEM ciphertext should not be empty");
    assert_eq!(
        shared_secret_enc.len(),
        32,
        "Shared secret should be 32 bytes"
    );

    // Now create a private key object in the PKCS#11 store so we can use C_DeriveKey
    let key_type_bytes = ck_ulong_bytes(CKK_ML_KEM);
    let class_bytes = ck_ulong_bytes(CKO_PRIVATE_KEY);
    let ck_true: CK_BBOOL = CK_TRUE;
    let dk_bytes = dk_seed.as_bytes();

    let mut template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_CLASS,
            p_value: class_bytes.as_ptr() as CK_VOID_PTR,
            value_len: class_bytes.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_KEY_TYPE,
            p_value: key_type_bytes.as_ptr() as CK_VOID_PTR,
            value_len: key_type_bytes.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_VALUE,
            p_value: dk_bytes.as_ptr() as CK_VOID_PTR,
            value_len: dk_bytes.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_DERIVE,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
    ];

    let mut priv_handle: CK_OBJECT_HANDLE = 0;
    let rv = C_CreateObject(
        session,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut priv_handle,
    );
    assert_eq!(
        rv, CKR_OK,
        "C_CreateObject for ML-KEM private key failed: 0x{:08X}",
        rv
    );

    // Decapsulate via C_DeriveKey: base key = private key, mechanism param = ciphertext
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_ML_KEM_768,
        p_parameter: ciphertext.as_ptr() as CK_VOID_PTR,
        parameter_len: ciphertext.len() as CK_ULONG,
    };
    let mut derived_key: CK_OBJECT_HANDLE = 0;
    let rv = C_DeriveKey(
        session,
        &mut mechanism,
        priv_handle,
        ptr::null_mut(),
        0,
        &mut derived_key,
    );
    assert_eq!(
        rv, CKR_OK,
        "C_DeriveKey (ML-KEM decapsulation) failed: 0x{:08X}",
        rv
    );
    assert_ne!(derived_key, 0, "Derived key handle should be non-zero");
}

// ===========================================================================
// Test 14: SLH-DSA-SHA2-128s keygen succeeds
// ===========================================================================
#[test]
fn test_slh_dsa_sha2_128s_keygen() {
    let session = setup_user_session();
    let (pub_key, priv_key) = generate_slh_dsa_keypair(session, CKM_SLH_DSA_SHA2_128S);
    assert_ne!(pub_key, 0, "SLH-DSA public key handle should be non-zero");
    assert_ne!(priv_key, 0, "SLH-DSA private key handle should be non-zero");
}

// ===========================================================================
// Test 15: SLH-DSA-SHA2-128s sign + verify (slow ~60s in debug)
// ===========================================================================
#[test]
fn test_slh_dsa_sha2_128s_sign_verify() {
    let session = setup_user_session();
    let (pub_key, priv_key) = generate_slh_dsa_keypair(session, CKM_SLH_DSA_SHA2_128S);

    // Use minimal data — SLH-DSA is extremely slow in debug mode
    let data = b"x";
    let signature = sign_data(session, CKM_SLH_DSA_SHA2_128S, priv_key, data);
    assert!(
        !signature.is_empty(),
        "SLH-DSA signature should not be empty"
    );

    let rv = verify_data(session, CKM_SLH_DSA_SHA2_128S, pub_key, data, &signature);
    assert_eq!(rv, CKR_OK, "SLH-DSA verify failed: 0x{:08X}", rv);
}

// ===========================================================================
// Test 16: ML-DSA-44 sign 3 different messages, all verify
// ===========================================================================
#[test]
fn test_ml_dsa_44_multiple_signs() {
    let session = setup_user_session();
    let (pub_key, priv_key) = generate_ml_dsa_keypair(session, CKM_ML_DSA_44);

    let messages: [&[u8]; 3] = [b"message one", b"message two", b"message three"];
    for msg in &messages {
        let sig = sign_data(session, CKM_ML_DSA_44, priv_key, msg);
        let rv = verify_data(session, CKM_ML_DSA_44, pub_key, msg, &sig);
        assert_eq!(
            rv,
            CKR_OK,
            "Verification of '{}' failed: 0x{:08X}",
            String::from_utf8_lossy(msg),
            rv
        );
    }
}

// ===========================================================================
// Test 17: ML-DSA keygen on RO session -> CKR_SESSION_READ_ONLY
// ===========================================================================
#[test]
fn test_ml_dsa_keygen_on_ro_session() {
    ensure_init();

    let so_pin = b"sopin123";
    let mut label = [b' '; 32];
    label[..6].copy_from_slice(b"ROTest");
    let rv = C_InitToken(
        0,
        so_pin.as_ptr() as *mut _,
        so_pin.len() as CK_ULONG,
        label.as_ptr() as *mut _,
    );
    assert_eq!(rv, CKR_OK);

    // Open a read-only session (no CKF_RW_SESSION)
    let mut session: CK_SESSION_HANDLE = 0;
    let rv = C_OpenSession(0, CKF_SERIAL_SESSION, ptr::null_mut(), None, &mut session);
    assert_eq!(rv, CKR_OK);

    let ck_true: CK_BBOOL = CK_TRUE;
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_ML_DSA_44,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let mut pub_template = vec![CK_ATTRIBUTE {
        attr_type: CKA_VERIFY,
        p_value: &ck_true as *const _ as CK_VOID_PTR,
        value_len: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
    }];
    let mut priv_template = vec![CK_ATTRIBUTE {
        attr_type: CKA_SIGN,
        p_value: &ck_true as *const _ as CK_VOID_PTR,
        value_len: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
    }];
    let mut pub_key: CK_OBJECT_HANDLE = 0;
    let mut priv_key: CK_OBJECT_HANDLE = 0;

    let rv = C_GenerateKeyPair(
        session,
        &mut mechanism,
        pub_template.as_mut_ptr(),
        pub_template.len() as CK_ULONG,
        priv_template.as_mut_ptr(),
        priv_template.len() as CK_ULONG,
        &mut pub_key,
        &mut priv_key,
    );
    assert_eq!(
        rv, CKR_SESSION_READ_ONLY,
        "Keygen on RO session should return CKR_SESSION_READ_ONLY, got 0x{:08X}",
        rv
    );

    let rv = C_CloseSession(session);
    assert_eq!(rv, CKR_OK);
}

// ===========================================================================
// Test 18: ML-DSA sign empty data (b"") succeeds
// ===========================================================================
#[test]
fn test_ml_dsa_sign_empty_data() {
    let session = setup_user_session();
    let (pub_key, priv_key) = generate_ml_dsa_keypair(session, CKM_ML_DSA_44);

    let data: &[u8] = b"";
    let signature = sign_data(session, CKM_ML_DSA_44, priv_key, data);
    assert_eq!(
        signature.len(),
        2420,
        "Empty-data signature should still be 2420 bytes"
    );

    let rv = verify_data(session, CKM_ML_DSA_44, pub_key, data, &signature);
    assert_eq!(
        rv, CKR_OK,
        "Verify of empty-data signature failed: 0x{:08X}",
        rv
    );
}

// ===========================================================================
// Test 19: ML-DSA sign 4KB data succeeds
// ===========================================================================
#[test]
fn test_ml_dsa_sign_large_data() {
    let session = setup_user_session();
    let (pub_key, priv_key) = generate_ml_dsa_keypair(session, CKM_ML_DSA_44);

    let data = vec![0xABu8; 4096];
    let signature = sign_data(session, CKM_ML_DSA_44, priv_key, &data);
    assert_eq!(signature.len(), 2420);

    let rv = verify_data(session, CKM_ML_DSA_44, pub_key, &data, &signature);
    assert_eq!(rv, CKR_OK, "Verify of 4KB data failed: 0x{:08X}", rv);
}

// ===========================================================================
// Test 20: Sign with DSA-44 key, verify with DSA-65 key -> error
// ===========================================================================
#[test]
fn test_ml_dsa_44_verify_wrong_variant_key() {
    let session = setup_user_session();
    let (_pub_44, priv_44) = generate_ml_dsa_keypair(session, CKM_ML_DSA_44);
    let (pub_65, _priv_65) = generate_ml_dsa_keypair(session, CKM_ML_DSA_65);

    let data = b"cross-variant test";
    let signature = sign_data(session, CKM_ML_DSA_44, priv_44, data);

    // Try to verify an ML-DSA-44 signature using an ML-DSA-65 key.
    // The mechanism is ML-DSA-65, but the signature was produced by ML-DSA-44.
    // This should produce an error — either CKR_SIGNATURE_INVALID or CKR_KEY_HANDLE_INVALID
    // depending on how the implementation validates the key/sig mismatch.
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_ML_DSA_65,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_VerifyInit(session, &mut mechanism, pub_65);
    assert_eq!(rv, CKR_OK, "VerifyInit should succeed");

    let rv = C_Verify(
        session,
        data.as_ptr() as CK_BYTE_PTR,
        data.len() as CK_ULONG,
        signature.as_ptr() as CK_BYTE_PTR,
        signature.len() as CK_ULONG,
    );
    assert!(
        rv == CKR_SIGNATURE_INVALID || rv == CKR_SIGNATURE_LEN_RANGE || rv == CKR_GENERAL_ERROR,
        "Cross-variant verify should fail, got 0x{:08X}",
        rv
    );
}

// ===========================================================================
// Test 21: Two ML-DSA-44 keygens produce different key handles and different keys
// ===========================================================================
#[test]
fn test_pqc_keygen_generates_unique_keys() {
    let session = setup_user_session();
    let (pub_a, priv_a) = generate_ml_dsa_keypair(session, CKM_ML_DSA_44);
    let (pub_b, priv_b) = generate_ml_dsa_keypair(session, CKM_ML_DSA_44);

    // Handles should differ
    assert_ne!(
        pub_a, pub_b,
        "Two keygens should produce different public key handles"
    );
    assert_ne!(
        priv_a, priv_b,
        "Two keygens should produce different private key handles"
    );

    // Sign the same message with both keys — signatures should differ because the keys differ
    let data = b"uniqueness test message";
    let sig_a = sign_data(session, CKM_ML_DSA_44, priv_a, data);
    let sig_b = sign_data(session, CKM_ML_DSA_44, priv_b, data);
    assert_ne!(sig_a, sig_b, "Signatures from different keys should differ");

    // Cross-verify should fail (sig_a was made by key_a, verify with key_b)
    let rv = verify_data(session, CKM_ML_DSA_44, pub_b, data, &sig_a);
    assert_eq!(
        rv, CKR_SIGNATURE_INVALID,
        "Cross-key verify should fail, got 0x{:08X}",
        rv
    );
}

// ===========================================================================
// Test 22: ML-DSA-44 sign with 1-byte buffer -> CKR_BUFFER_TOO_SMALL
// ===========================================================================
#[test]
fn test_ml_dsa_44_sign_buffer_too_small() {
    let session = setup_user_session();
    let (_pub_key, priv_key) = generate_ml_dsa_keypair(session, CKM_ML_DSA_44);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_ML_DSA_44,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_SignInit(session, &mut mechanism, priv_key);
    assert_eq!(rv, CKR_OK);

    let data = b"buffer test";
    let mut tiny_buf = [0u8; 1];
    let mut sig_len: CK_ULONG = tiny_buf.len() as CK_ULONG;
    let rv = C_Sign(
        session,
        data.as_ptr() as CK_BYTE_PTR,
        data.len() as CK_ULONG,
        tiny_buf.as_mut_ptr(),
        &mut sig_len,
    );
    assert_eq!(
        rv, CKR_BUFFER_TOO_SMALL,
        "Sign with 1-byte buffer should return CKR_BUFFER_TOO_SMALL, got 0x{:08X}",
        rv
    );
    // sig_len should report the required size
    assert_eq!(
        sig_len, 2420,
        "Reported required size should be 2420, got {}",
        sig_len
    );
}

// ===========================================================================
// Test 23: Hybrid ML-DSA + ECDSA sign + verify through ABI
// ===========================================================================
#[test]
fn test_hybrid_ml_dsa_ecdsa_sign_verify() {
    // The hybrid mechanism CKM_HYBRID_ML_DSA_ECDSA does not support keygen via
    // C_GenerateKeyPair. Instead, we generate ML-DSA-65 and EC-P256 keys separately,
    // then attach the ECDSA key data to the ML-DSA objects via C_SetAttributeValue,
    // and use the hybrid mechanism for sign/verify.
    let session = setup_user_session();

    // Step 1: Generate ML-DSA-65 keypair (for ML-DSA component)
    let (ml_pub, ml_priv) = generate_ml_dsa_keypair(session, CKM_ML_DSA_65);

    // Step 2: Generate EC-P256 keypair (for ECDSA component)
    let mut ec_mechanism = CK_MECHANISM {
        mechanism: CKM_EC_KEY_PAIR_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let ck_true: CK_BBOOL = CK_TRUE;
    // P-256 OID: 1.2.840.10045.3.1.7 (DER-encoded)
    let ec_params: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    let mut ec_pub_template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_EC_PARAMS,
            p_value: ec_params.as_ptr() as CK_VOID_PTR,
            value_len: ec_params.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_VERIFY,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ];
    let ck_false: CK_BBOOL = CK_FALSE;
    let mut ec_priv_template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_SIGN,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        // Mark as non-sensitive and extractable so we can read CKA_VALUE
        CK_ATTRIBUTE {
            attr_type: CKA_SENSITIVE,
            p_value: &ck_false as *const _ as CK_VOID_PTR,
            value_len: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_EXTRACTABLE,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ];
    let mut ec_pub: CK_OBJECT_HANDLE = 0;
    let mut ec_priv: CK_OBJECT_HANDLE = 0;
    let rv = C_GenerateKeyPair(
        session,
        &mut ec_mechanism,
        ec_pub_template.as_mut_ptr(),
        ec_pub_template.len() as CK_ULONG,
        ec_priv_template.as_mut_ptr(),
        ec_priv_template.len() as CK_ULONG,
        &mut ec_pub,
        &mut ec_priv,
    );
    assert_eq!(rv, CKR_OK, "EC-P256 keygen failed: 0x{:08X}", rv);

    // Step 3: Read ECDSA private key bytes (non-sensitive, so CKA_VALUE is readable)
    let ecdsa_priv_bytes = read_variable_attribute(session, ec_priv, CKA_VALUE);

    // Step 4: Read ECDSA public key point
    let ecdsa_pub_bytes = read_variable_attribute(session, ec_pub, CKA_EC_POINT);

    // Step 5: Attach ECDSA keys to ML-DSA objects via C_SetAttributeValue
    // Set CKA_EC_POINT on the ML-DSA private key (ECDSA private key for signing)
    let mut set_template_priv = [CK_ATTRIBUTE {
        attr_type: CKA_EC_POINT,
        p_value: ecdsa_priv_bytes.as_ptr() as CK_VOID_PTR,
        value_len: ecdsa_priv_bytes.len() as CK_ULONG,
    }];
    let rv = C_SetAttributeValue(session, ml_priv, set_template_priv.as_mut_ptr(), 1);
    assert_eq!(
        rv, CKR_OK,
        "Setting ECDSA key on ML-DSA priv failed: 0x{:08X}",
        rv
    );

    // Set CKA_EC_POINT on the ML-DSA public key (ECDSA public key for verification)
    let mut set_template_pub = [CK_ATTRIBUTE {
        attr_type: CKA_EC_POINT,
        p_value: ecdsa_pub_bytes.as_ptr() as CK_VOID_PTR,
        value_len: ecdsa_pub_bytes.len() as CK_ULONG,
    }];
    let rv = C_SetAttributeValue(session, ml_pub, set_template_pub.as_mut_ptr(), 1);
    assert_eq!(
        rv, CKR_OK,
        "Setting ECDSA key on ML-DSA pub failed: 0x{:08X}",
        rv
    );

    // Step 6: Sign with hybrid mechanism
    let data = b"hybrid PQC + classical test";
    let signature = sign_data(session, CKM_HYBRID_ML_DSA_ECDSA, ml_priv, data);
    assert!(
        signature.len() > 3309,
        "Hybrid signature should be larger than bare ML-DSA-65 (3309), got {}",
        signature.len()
    );

    // Step 7: Verify with hybrid mechanism
    let rv = verify_data(session, CKM_HYBRID_ML_DSA_ECDSA, ml_pub, data, &signature);
    assert_eq!(rv, CKR_OK, "Hybrid verify failed: 0x{:08X}", rv);
}

// ===========================================================================
// Test 24: ML-KEM key attributes — CKA_KEY_TYPE = CKK_ML_KEM, CKA_CLASS correct
// ===========================================================================
#[test]
fn test_ml_kem_keygen_attributes() {
    let session = setup_user_session();
    let (pub_key, priv_key) = generate_ml_kem_keypair(session, CKM_ML_KEM_768);

    // Public key
    let kt = read_ulong_attribute(session, pub_key, CKA_KEY_TYPE);
    assert_eq!(
        kt, CKK_ML_KEM,
        "ML-KEM public key type should be CKK_ML_KEM"
    );

    let cls = read_ulong_attribute(session, pub_key, CKA_CLASS);
    assert_eq!(
        cls, CKO_PUBLIC_KEY,
        "ML-KEM public key class should be CKO_PUBLIC_KEY"
    );

    // Private key
    let kt = read_ulong_attribute(session, priv_key, CKA_KEY_TYPE);
    assert_eq!(
        kt, CKK_ML_KEM,
        "ML-KEM private key type should be CKK_ML_KEM"
    );

    let cls = read_ulong_attribute(session, priv_key, CKA_CLASS);
    assert_eq!(
        cls, CKO_PRIVATE_KEY,
        "ML-KEM private key class should be CKO_PRIVATE_KEY"
    );
}

// ===========================================================================
// Test 25: Destroy private key, then C_SignInit -> CKR_KEY_HANDLE_INVALID
// ===========================================================================
#[test]
fn test_ml_dsa_destroy_key_then_sign() {
    let session = setup_user_session();
    let (_pub_key, priv_key) = generate_ml_dsa_keypair(session, CKM_ML_DSA_44);

    // Destroy the private key
    let rv = C_DestroyObject(session, priv_key);
    assert_eq!(rv, CKR_OK, "C_DestroyObject failed: 0x{:08X}", rv);

    // Try to sign with the destroyed key
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_ML_DSA_44,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_SignInit(session, &mut mechanism, priv_key);
    assert_eq!(
        rv, CKR_KEY_HANDLE_INVALID,
        "SignInit with destroyed key should return CKR_KEY_HANDLE_INVALID, got 0x{:08X}",
        rv
    );
}

// ===========================================================================
// Test 26: C_GetMechanismList includes PQC mechanisms
// ===========================================================================
#[test]
fn test_pqc_mechanism_in_mechanism_list() {
    ensure_init();

    let so_pin = b"sopin123";
    let mut label = [b' '; 32];
    label[..8].copy_from_slice(b"MechList");
    let rv = C_InitToken(
        0,
        so_pin.as_ptr() as *mut _,
        so_pin.len() as CK_ULONG,
        label.as_ptr() as *mut _,
    );
    assert_eq!(rv, CKR_OK);

    // Get mechanism count
    let mut count: CK_ULONG = 0;
    let rv = C_GetMechanismList(0, ptr::null_mut(), &mut count);
    assert_eq!(rv, CKR_OK);
    assert!(count > 0, "Mechanism count should be > 0");

    // Get mechanism list
    let mut mechs = vec![0 as CK_MECHANISM_TYPE; count as usize];
    let rv = C_GetMechanismList(0, mechs.as_mut_ptr(), &mut count);
    assert_eq!(rv, CKR_OK);

    // Verify PQC mechanisms are present
    assert!(
        mechs.contains(&CKM_ML_DSA_44),
        "Mechanism list should include CKM_ML_DSA_44"
    );
    assert!(
        mechs.contains(&CKM_ML_DSA_65),
        "Mechanism list should include CKM_ML_DSA_65"
    );
    assert!(
        mechs.contains(&CKM_ML_DSA_87),
        "Mechanism list should include CKM_ML_DSA_87"
    );
    assert!(
        mechs.contains(&CKM_ML_KEM_768),
        "Mechanism list should include CKM_ML_KEM_768"
    );
    assert!(
        mechs.contains(&CKM_ML_KEM_512),
        "Mechanism list should include CKM_ML_KEM_512"
    );
    assert!(
        mechs.contains(&CKM_ML_KEM_1024),
        "Mechanism list should include CKM_ML_KEM_1024"
    );
    assert!(
        mechs.contains(&CKM_SLH_DSA_SHA2_128S),
        "Mechanism list should include CKM_SLH_DSA_SHA2_128S"
    );
    assert!(
        mechs.contains(&CKM_SLH_DSA_SHA2_256S),
        "Mechanism list should include CKM_SLH_DSA_SHA2_256S"
    );
    assert!(
        mechs.contains(&CKM_HYBRID_ML_DSA_ECDSA),
        "Mechanism list should include CKM_HYBRID_ML_DSA_ECDSA"
    );
}

// ===========================================================================
// Test 27: ML-DSA sign with AES key -> wrong key type error
// ===========================================================================
#[test]
fn test_ml_dsa_sign_with_aes_key_fails() {
    let session = setup_user_session();

    // Generate an AES key
    let mut aes_mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let value_len_bytes = ck_ulong_bytes(32);
    let ck_true: CK_BBOOL = CK_TRUE;
    let mut aes_template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_VALUE_LEN,
            p_value: value_len_bytes.as_ptr() as CK_VOID_PTR,
            value_len: value_len_bytes.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_ENCRYPT,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_DECRYPT,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ];

    let mut aes_key: CK_OBJECT_HANDLE = 0;
    let rv = C_GenerateKey(
        session,
        &mut aes_mechanism,
        aes_template.as_mut_ptr(),
        aes_template.len() as CK_ULONG,
        &mut aes_key,
    );
    assert_eq!(rv, CKR_OK, "AES keygen failed: 0x{:08X}", rv);

    // Try to use ML-DSA sign with the AES key
    let mut ml_mechanism = CK_MECHANISM {
        mechanism: CKM_ML_DSA_44,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_SignInit(session, &mut ml_mechanism, aes_key);
    // The AES key doesn't have CKA_SIGN=true, so it should fail with
    // CKR_KEY_FUNCTION_NOT_PERMITTED or CKR_KEY_TYPE_INCONSISTENT or CKR_KEY_HANDLE_INVALID
    assert!(
        rv == CKR_KEY_FUNCTION_NOT_PERMITTED
            || rv == CKR_KEY_TYPE_INCONSISTENT
            || rv == CKR_KEY_HANDLE_INVALID,
        "ML-DSA sign with AES key should fail, got 0x{:08X}",
        rv
    );
}

// ===========================================================================
// Test 28: SLH-DSA-SHA2-128s signature size is 7856 bytes
// ===========================================================================
#[test]
fn test_slh_dsa_signature_size() {
    let session = setup_user_session();
    let (_pub_key, priv_key) = generate_slh_dsa_keypair(session, CKM_SLH_DSA_SHA2_128S);

    // Use minimal data to keep SLH-DSA fast
    let data = b"s";
    let signature = sign_data(session, CKM_SLH_DSA_SHA2_128S, priv_key, data);
    assert_eq!(
        signature.len(),
        7856,
        "SLH-DSA-SHA2-128s signature should be exactly 7856 bytes, got {}",
        signature.len()
    );
}
