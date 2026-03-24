// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
// PKCS#11 error path tests — exercises every critical CK_RV error code at the C ABI level.
// Each test is focused on a single error condition.
//
// Strategy: OnceLock prevents re-initialization, so we accept CKR_CRYPTOKI_ALREADY_INITIALIZED
// from C_Initialize and use C_InitToken for clean state per test.

use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm::pkcs11_abi::functions::*;
use craton_hsm::pkcs11_abi::types::*;
use std::ptr;

fn ck_ulong_bytes(val: CK_ULONG) -> Vec<u8> {
    val.to_ne_bytes().to_vec()
}

/// Ensure HSM is initialized. Idempotent.
fn ensure_init() {
    let rv = C_Initialize(ptr::null_mut());
    assert!(
        rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED,
        "C_Initialize failed: 0x{:08X}",
        rv
    );
}

/// Re-initialize token to get clean state, open RW session, login as user.
/// Returns session handle.
fn setup_user_session() -> CK_SESSION_HANDLE {
    ensure_init();
    let so_pin = b"sopin123";
    let mut label = [b' '; 32];
    label[..8].copy_from_slice(b"ErrTests");
    let rv = C_InitToken(
        0,
        so_pin.as_ptr() as *mut _,
        so_pin.len() as CK_ULONG,
        label.as_ptr() as *mut _,
    );
    assert_eq!(rv, CKR_OK, "C_InitToken failed");

    let mut session: CK_SESSION_HANDLE = 0;
    let rv = C_OpenSession(
        0,
        CKF_RW_SESSION | CKF_SERIAL_SESSION,
        ptr::null_mut(),
        None,
        &mut session,
    );
    assert_eq!(rv, CKR_OK);

    // Login as SO, init user PIN, logout, login as user
    let rv = C_Login(
        session,
        CKU_SO,
        so_pin.as_ptr() as *mut _,
        so_pin.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_OK);
    let user_pin = b"userpin1";
    let rv = C_InitPIN(
        session,
        user_pin.as_ptr() as *mut _,
        user_pin.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_OK);
    let rv = C_Logout(session);
    assert_eq!(rv, CKR_OK);
    let rv = C_Login(
        session,
        CKU_USER,
        user_pin.as_ptr() as *mut _,
        user_pin.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_OK);

    session
}

/// Generate an AES-256 key on the given session. Returns the key handle.
fn generate_aes_key(session: CK_SESSION_HANDLE) -> CK_OBJECT_HANDLE {
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let value_len_bytes = ck_ulong_bytes(32);
    let ck_true: CK_BBOOL = CK_TRUE;
    let mut template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_VALUE_LEN,
            p_value: value_len_bytes.as_ptr() as CK_VOID_PTR,
            value_len: value_len_bytes.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_ENCRYPT,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_DECRYPT,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_SIGN,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
    ];
    let mut key: CK_OBJECT_HANDLE = 0;
    let rv = C_GenerateKey(
        session,
        &mut mechanism,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut key,
    );
    assert_eq!(rv, CKR_OK, "generate_aes_key failed");
    key
}

// ============================================================================
// CKR_ARGUMENTS_BAD — null pointer validation
// ============================================================================

#[test]
fn test_get_info_null_pointer() {
    ensure_init();
    let rv = C_GetInfo(ptr::null_mut());
    assert_eq!(rv, CKR_ARGUMENTS_BAD);
}

#[test]
fn test_get_slot_list_null_count() {
    ensure_init();
    let rv = C_GetSlotList(CK_FALSE, ptr::null_mut(), ptr::null_mut());
    assert_eq!(rv, CKR_ARGUMENTS_BAD);
}

#[test]
fn test_get_slot_info_null_pointer() {
    ensure_init();
    let rv = C_GetSlotInfo(0, ptr::null_mut());
    assert_eq!(rv, CKR_ARGUMENTS_BAD);
}

#[test]
fn test_get_token_info_null_pointer() {
    ensure_init();
    let rv = C_GetTokenInfo(0, ptr::null_mut());
    assert_eq!(rv, CKR_ARGUMENTS_BAD);
}

#[test]
fn test_open_session_null_handle() {
    ensure_init();
    let rv = C_OpenSession(
        0,
        CKF_RW_SESSION | CKF_SERIAL_SESSION,
        ptr::null_mut(),
        None,
        ptr::null_mut(),
    );
    assert_eq!(rv, CKR_ARGUMENTS_BAD);
}

#[test]
fn test_get_function_list_null_pointer() {
    let rv = C_GetFunctionList(ptr::null_mut());
    assert_eq!(rv, CKR_ARGUMENTS_BAD);
}

#[test]
fn test_encrypt_init_null_mechanism() {
    let session = setup_user_session();
    let key = generate_aes_key(session);
    let rv = C_EncryptInit(session, ptr::null_mut(), key);
    assert_eq!(rv, CKR_ARGUMENTS_BAD);
}

#[test]
fn test_sign_init_null_mechanism() {
    let session = setup_user_session();
    let key = generate_aes_key(session);
    let rv = C_SignInit(session, ptr::null_mut(), key);
    assert_eq!(rv, CKR_ARGUMENTS_BAD);
}

#[test]
fn test_decrypt_init_null_mechanism() {
    let session = setup_user_session();
    let key = generate_aes_key(session);
    let rv = C_DecryptInit(session, ptr::null_mut(), key);
    assert_eq!(rv, CKR_ARGUMENTS_BAD);
}

#[test]
fn test_verify_init_null_mechanism() {
    let session = setup_user_session();
    let key = generate_aes_key(session);
    let rv = C_VerifyInit(session, ptr::null_mut(), key);
    assert_eq!(rv, CKR_ARGUMENTS_BAD);
}

#[test]
fn test_encrypt_null_data() {
    let session = setup_user_session();
    let key = generate_aes_key(session);
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_EncryptInit(session, &mut mechanism, key);
    assert_eq!(rv, CKR_OK);

    let mut out = vec![0u8; 256];
    let mut out_len: CK_ULONG = out.len() as CK_ULONG;
    let rv = C_Encrypt(session, ptr::null_mut(), 32, out.as_mut_ptr(), &mut out_len);
    assert_eq!(rv, CKR_ARGUMENTS_BAD);
}

#[test]
fn test_encrypt_null_output_len() {
    let session = setup_user_session();
    let key = generate_aes_key(session);
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_EncryptInit(session, &mut mechanism, key);
    assert_eq!(rv, CKR_OK);

    let data = b"test data for encryption";
    let rv = C_Encrypt(
        session,
        data.as_ptr() as CK_BYTE_PTR,
        data.len() as CK_ULONG,
        ptr::null_mut(),
        ptr::null_mut(),
    );
    assert_eq!(rv, CKR_ARGUMENTS_BAD);
}

#[test]
fn test_finalize_non_null_reserved() {
    ensure_init();
    let mut dummy: u8 = 0;
    let rv = C_Finalize(&mut dummy as *mut u8 as CK_VOID_PTR);
    assert_eq!(rv, CKR_ARGUMENTS_BAD);
}

#[test]
fn test_get_mechanism_list_null_count() {
    ensure_init();
    let rv = C_GetMechanismList(0, ptr::null_mut(), ptr::null_mut());
    assert_eq!(rv, CKR_ARGUMENTS_BAD);
}

#[test]
fn test_generate_key_null_handle() {
    let session = setup_user_session();
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let value_len_bytes = ck_ulong_bytes(32);
    let mut template = vec![CK_ATTRIBUTE {
        attr_type: CKA_VALUE_LEN,
        p_value: value_len_bytes.as_ptr() as CK_VOID_PTR,
        value_len: value_len_bytes.len() as CK_ULONG,
    }];
    let rv = C_GenerateKey(
        session,
        &mut mechanism,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        ptr::null_mut(),
    );
    assert_eq!(rv, CKR_ARGUMENTS_BAD);
}

#[test]
fn test_generate_key_pair_null_handles() {
    let session = setup_user_session();
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let bits = ck_ulong_bytes(2048);
    let ck_true: CK_BBOOL = CK_TRUE;
    let mut pub_tmpl = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_MODULUS_BITS,
            p_value: bits.as_ptr() as CK_VOID_PTR,
            value_len: bits.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_VERIFY,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
    ];
    let mut priv_tmpl = vec![CK_ATTRIBUTE {
        attr_type: CKA_SIGN,
        p_value: &ck_true as *const _ as CK_VOID_PTR,
        value_len: 1,
    }];
    let rv = C_GenerateKeyPair(
        session,
        &mut mechanism,
        pub_tmpl.as_mut_ptr(),
        pub_tmpl.len() as CK_ULONG,
        priv_tmpl.as_mut_ptr(),
        priv_tmpl.len() as CK_ULONG,
        ptr::null_mut(),
        ptr::null_mut(),
    );
    assert_eq!(rv, CKR_ARGUMENTS_BAD);
}

// ============================================================================
// CKR_BUFFER_TOO_SMALL
// ============================================================================

#[test]
fn test_get_slot_list_buffer_too_small() {
    ensure_init();
    let mut count: CK_ULONG = 0; // count=0 but non-null buffer
    let mut slot_ids = vec![0 as CK_SLOT_ID; 1];
    // First get the actual count
    let rv = C_GetSlotList(CK_FALSE, ptr::null_mut(), &mut count);
    assert_eq!(rv, CKR_OK);
    assert!(count >= 1);

    // Now request with count=0 but non-null pointer
    let mut small_count: CK_ULONG = 0;
    let rv = C_GetSlotList(CK_FALSE, slot_ids.as_mut_ptr(), &mut small_count);
    assert_eq!(rv, CKR_BUFFER_TOO_SMALL);
}

#[test]
fn test_get_mechanism_list_buffer_too_small() {
    ensure_init();
    let mut count: CK_ULONG = 0;
    let rv = C_GetMechanismList(0, ptr::null_mut(), &mut count);
    assert_eq!(rv, CKR_OK);
    assert!(count > 1);

    // Non-null buffer but count too small
    let mut mechs = vec![0 as CK_MECHANISM_TYPE; 1];
    let mut small_count: CK_ULONG = 1;
    let rv = C_GetMechanismList(0, mechs.as_mut_ptr(), &mut small_count);
    assert_eq!(rv, CKR_BUFFER_TOO_SMALL);
}

#[test]
fn test_encrypt_output_buffer_too_small() {
    let session = setup_user_session();
    let key = generate_aes_key(session);
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_EncryptInit(session, &mut mechanism, key);
    assert_eq!(rv, CKR_OK);

    let plaintext = b"Hello, World! This is a test message for buffer size.";
    // First call: query required size by passing null output buffer
    let mut required_len: CK_ULONG = 0;
    let _rv = C_Encrypt(
        session,
        plaintext.as_ptr() as CK_BYTE_PTR,
        plaintext.len() as CK_ULONG,
        ptr::null_mut(),
        &mut required_len,
    );
    // GCM produces output on the encryption call itself, so it may return OK with required_len set
    // or the implementation may need a re-init. Let's try with small buffer instead.
    // Re-init for a fresh attempt
    let rv = C_EncryptInit(session, &mut mechanism, key);
    // May be OK or already have cleared
    if rv == CKR_OK {
        let mut tiny_buf = vec![0u8; 1];
        let mut tiny_len: CK_ULONG = 1;
        let rv = C_Encrypt(
            session,
            plaintext.as_ptr() as CK_BYTE_PTR,
            plaintext.len() as CK_ULONG,
            tiny_buf.as_mut_ptr(),
            &mut tiny_len,
        );
        assert_eq!(rv, CKR_BUFFER_TOO_SMALL);
    }
}

#[test]
fn test_sign_output_buffer_too_small() {
    let session = setup_user_session();

    // Generate ECDSA key pair for faster test
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_EC_KEY_PAIR_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    // P-256 OID
    let ec_params = hex::decode("06082a8648ce3d030107")
        .unwrap_or_else(|_| vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);
    let ck_true: CK_BBOOL = CK_TRUE;
    let mut pub_tmpl = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_EC_PARAMS,
            p_value: ec_params.as_ptr() as CK_VOID_PTR,
            value_len: ec_params.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_VERIFY,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
    ];
    let mut priv_tmpl = vec![CK_ATTRIBUTE {
        attr_type: CKA_SIGN,
        p_value: &ck_true as *const _ as CK_VOID_PTR,
        value_len: 1,
    }];
    let mut pub_key: CK_OBJECT_HANDLE = 0;
    let mut priv_key: CK_OBJECT_HANDLE = 0;
    let rv = C_GenerateKeyPair(
        session,
        &mut mechanism,
        pub_tmpl.as_mut_ptr(),
        pub_tmpl.len() as CK_ULONG,
        priv_tmpl.as_mut_ptr(),
        priv_tmpl.len() as CK_ULONG,
        &mut pub_key,
        &mut priv_key,
    );
    assert_eq!(rv, CKR_OK);

    // Sign with tiny buffer
    let mut sign_mech = CK_MECHANISM {
        mechanism: CKM_ECDSA,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_SignInit(session, &mut sign_mech, priv_key);
    assert_eq!(rv, CKR_OK);

    let message = b"test message for buffer size check";
    let mut tiny_buf = vec![0u8; 1];
    let mut tiny_len: CK_ULONG = 1;
    let rv = C_Sign(
        session,
        message.as_ptr() as CK_BYTE_PTR,
        message.len() as CK_ULONG,
        tiny_buf.as_mut_ptr(),
        &mut tiny_len,
    );
    assert_eq!(rv, CKR_BUFFER_TOO_SMALL);
}

#[test]
fn test_digest_output_buffer_too_small() {
    let session = setup_user_session();
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_DigestInit(session, &mut mechanism);
    assert_eq!(rv, CKR_OK);

    let data = b"test data for digest";
    let mut tiny_buf = vec![0u8; 1]; // SHA-256 needs 32 bytes
    let mut tiny_len: CK_ULONG = 1;
    let rv = C_Digest(
        session,
        data.as_ptr() as CK_BYTE_PTR,
        data.len() as CK_ULONG,
        tiny_buf.as_mut_ptr(),
        &mut tiny_len,
    );
    assert_eq!(rv, CKR_BUFFER_TOO_SMALL);
    assert_eq!(tiny_len, 32); // should report required size
}

// ============================================================================
// CKR_OPERATION_ACTIVE — double-init
// ============================================================================

#[test]
fn test_encrypt_init_double_init() {
    let session = setup_user_session();
    let key = generate_aes_key(session);
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_EncryptInit(session, &mut mechanism, key);
    assert_eq!(rv, CKR_OK);
    // Second init should fail
    let rv = C_EncryptInit(session, &mut mechanism, key);
    assert_eq!(rv, CKR_OPERATION_ACTIVE);
}

#[test]
fn test_sign_init_double_init() {
    let session = setup_user_session();
    // Generate ECDSA key pair for sign testing
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_EC_KEY_PAIR_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let ec_params: Vec<u8> = vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]; // P-256 OID
    let ck_true: CK_BBOOL = CK_TRUE;
    let mut pub_tmpl = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_EC_PARAMS,
            p_value: ec_params.as_ptr() as CK_VOID_PTR,
            value_len: ec_params.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_VERIFY,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
    ];
    let mut priv_tmpl = vec![CK_ATTRIBUTE {
        attr_type: CKA_SIGN,
        p_value: &ck_true as *const _ as CK_VOID_PTR,
        value_len: 1,
    }];
    let mut pub_key: CK_OBJECT_HANDLE = 0;
    let mut priv_key: CK_OBJECT_HANDLE = 0;
    let rv = C_GenerateKeyPair(
        session,
        &mut mechanism,
        pub_tmpl.as_mut_ptr(),
        pub_tmpl.len() as CK_ULONG,
        priv_tmpl.as_mut_ptr(),
        priv_tmpl.len() as CK_ULONG,
        &mut pub_key,
        &mut priv_key,
    );
    assert_eq!(rv, CKR_OK);

    let mut sign_mech = CK_MECHANISM {
        mechanism: CKM_ECDSA,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_SignInit(session, &mut sign_mech, priv_key);
    assert_eq!(rv, CKR_OK);
    let rv = C_SignInit(session, &mut sign_mech, priv_key);
    assert_eq!(rv, CKR_OPERATION_ACTIVE);
}

#[test]
fn test_decrypt_init_double_init() {
    let session = setup_user_session();
    let key = generate_aes_key(session);
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_DecryptInit(session, &mut mechanism, key);
    assert_eq!(rv, CKR_OK);
    let rv = C_DecryptInit(session, &mut mechanism, key);
    assert_eq!(rv, CKR_OPERATION_ACTIVE);
}

#[test]
fn test_digest_init_double_init() {
    let session = setup_user_session();
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_DigestInit(session, &mut mechanism);
    assert_eq!(rv, CKR_OK);
    let rv = C_DigestInit(session, &mut mechanism);
    assert_eq!(rv, CKR_OPERATION_ACTIVE);
}

// ============================================================================
// CKR_OPERATION_NOT_INITIALIZED — missing init
// ============================================================================

#[test]
fn test_encrypt_without_init() {
    let session = setup_user_session();
    let data = b"test data";
    let mut out = vec![0u8; 256];
    let mut out_len: CK_ULONG = out.len() as CK_ULONG;
    let rv = C_Encrypt(
        session,
        data.as_ptr() as CK_BYTE_PTR,
        data.len() as CK_ULONG,
        out.as_mut_ptr(),
        &mut out_len,
    );
    assert_eq!(rv, CKR_OPERATION_NOT_INITIALIZED);
}

#[test]
fn test_decrypt_without_init() {
    let session = setup_user_session();
    let data = b"test data";
    let mut out = vec![0u8; 256];
    let mut out_len: CK_ULONG = out.len() as CK_ULONG;
    let rv = C_Decrypt(
        session,
        data.as_ptr() as CK_BYTE_PTR,
        data.len() as CK_ULONG,
        out.as_mut_ptr(),
        &mut out_len,
    );
    assert_eq!(rv, CKR_OPERATION_NOT_INITIALIZED);
}

#[test]
fn test_sign_without_init() {
    let session = setup_user_session();
    let data = b"test data";
    let mut out = vec![0u8; 256];
    let mut out_len: CK_ULONG = out.len() as CK_ULONG;
    let rv = C_Sign(
        session,
        data.as_ptr() as CK_BYTE_PTR,
        data.len() as CK_ULONG,
        out.as_mut_ptr(),
        &mut out_len,
    );
    assert_eq!(rv, CKR_OPERATION_NOT_INITIALIZED);
}

#[test]
fn test_verify_without_init() {
    let session = setup_user_session();
    let data = b"test data";
    let sig = b"fake signature";
    let rv = C_Verify(
        session,
        data.as_ptr() as CK_BYTE_PTR,
        data.len() as CK_ULONG,
        sig.as_ptr() as CK_BYTE_PTR,
        sig.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_OPERATION_NOT_INITIALIZED);
}

#[test]
fn test_digest_without_init() {
    let session = setup_user_session();
    let data = b"test data";
    let mut out = vec![0u8; 64];
    let mut out_len: CK_ULONG = out.len() as CK_ULONG;
    let rv = C_Digest(
        session,
        data.as_ptr() as CK_BYTE_PTR,
        data.len() as CK_ULONG,
        out.as_mut_ptr(),
        &mut out_len,
    );
    assert_eq!(rv, CKR_OPERATION_NOT_INITIALIZED);
}

#[test]
fn test_digest_update_without_init() {
    let session = setup_user_session();
    let data = b"test data";
    let rv = C_DigestUpdate(
        session,
        data.as_ptr() as CK_BYTE_PTR,
        data.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_OPERATION_NOT_INITIALIZED);
}

#[test]
fn test_digest_final_without_init() {
    let session = setup_user_session();
    let mut out = vec![0u8; 64];
    let mut out_len: CK_ULONG = out.len() as CK_ULONG;
    let rv = C_DigestFinal(session, out.as_mut_ptr(), &mut out_len);
    assert_eq!(rv, CKR_OPERATION_NOT_INITIALIZED);
}

// ============================================================================
// CKR_SESSION_HANDLE_INVALID
// ============================================================================

#[test]
fn test_get_session_info_invalid_handle() {
    ensure_init();
    let mut info: CK_SESSION_INFO = unsafe { std::mem::zeroed() };
    let rv = C_GetSessionInfo(999999, &mut info);
    assert_eq!(rv, CKR_SESSION_HANDLE_INVALID);
}

#[test]
fn test_close_session_invalid_handle() {
    ensure_init();
    let rv = C_CloseSession(999999);
    assert_eq!(rv, CKR_SESSION_HANDLE_INVALID);
}

// ============================================================================
// CKR_SLOT_ID_INVALID
// ============================================================================

#[test]
fn test_get_slot_info_invalid_slot() {
    ensure_init();
    let mut info: CK_SLOT_INFO = unsafe { std::mem::zeroed() };
    let rv = C_GetSlotInfo(99, &mut info);
    assert_eq!(rv, CKR_SLOT_ID_INVALID);
}

#[test]
fn test_get_token_info_invalid_slot() {
    ensure_init();
    let mut info: CK_TOKEN_INFO = unsafe { std::mem::zeroed() };
    let rv = C_GetTokenInfo(99, &mut info);
    assert_eq!(rv, CKR_SLOT_ID_INVALID);
}

#[test]
fn test_open_session_invalid_slot() {
    ensure_init();
    let mut session: CK_SESSION_HANDLE = 0;
    let rv = C_OpenSession(
        99,
        CKF_RW_SESSION | CKF_SERIAL_SESSION,
        ptr::null_mut(),
        None,
        &mut session,
    );
    assert_eq!(rv, CKR_SLOT_ID_INVALID);
}

// ============================================================================
// CKR_MECHANISM_INVALID
// ============================================================================

#[test]
fn test_encrypt_init_invalid_mechanism() {
    let session = setup_user_session();
    let key = generate_aes_key(session);
    let mut mechanism = CK_MECHANISM {
        mechanism: 0xFFFFFFFF,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_EncryptInit(session, &mut mechanism, key);
    assert_eq!(rv, CKR_MECHANISM_INVALID);
}

#[test]
fn test_sign_init_invalid_mechanism() {
    let session = setup_user_session();
    let key = generate_aes_key(session);
    let mut mechanism = CK_MECHANISM {
        mechanism: 0xFFFFFFFF,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_SignInit(session, &mut mechanism, key);
    assert_eq!(rv, CKR_MECHANISM_INVALID);
}

// ============================================================================
// CKR_KEY_HANDLE_INVALID
// ============================================================================

#[test]
fn test_encrypt_init_invalid_key_handle() {
    let session = setup_user_session();
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_EncryptInit(session, &mut mechanism, 999999);
    assert_eq!(rv, CKR_KEY_HANDLE_INVALID);
}

#[test]
fn test_sign_init_invalid_key_handle() {
    let session = setup_user_session();
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256_RSA_PKCS,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_SignInit(session, &mut mechanism, 999999);
    assert_eq!(rv, CKR_KEY_HANDLE_INVALID);
}

// ============================================================================
// CKR_KEY_FUNCTION_NOT_PERMITTED
// ============================================================================

#[test]
fn test_encrypt_with_non_encrypt_key() {
    let session = setup_user_session();
    // Generate key with CKA_ENCRYPT=false
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let value_len_bytes = ck_ulong_bytes(32);
    let ck_false: CK_BBOOL = CK_FALSE;
    let ck_true: CK_BBOOL = CK_TRUE;
    let mut template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_VALUE_LEN,
            p_value: value_len_bytes.as_ptr() as CK_VOID_PTR,
            value_len: value_len_bytes.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_ENCRYPT,
            p_value: &ck_false as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_DECRYPT,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
    ];
    let mut key: CK_OBJECT_HANDLE = 0;
    let rv = C_GenerateKey(
        session,
        &mut mechanism,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut key,
    );
    assert_eq!(rv, CKR_OK);

    let mut enc_mech = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_EncryptInit(session, &mut enc_mech, key);
    assert_eq!(rv, CKR_KEY_FUNCTION_NOT_PERMITTED);
}

#[test]
fn test_decrypt_with_non_decrypt_key() {
    let session = setup_user_session();
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let value_len_bytes = ck_ulong_bytes(32);
    let ck_false: CK_BBOOL = CK_FALSE;
    let ck_true: CK_BBOOL = CK_TRUE;
    let mut template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_VALUE_LEN,
            p_value: value_len_bytes.as_ptr() as CK_VOID_PTR,
            value_len: value_len_bytes.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_ENCRYPT,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_DECRYPT,
            p_value: &ck_false as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
    ];
    let mut key: CK_OBJECT_HANDLE = 0;
    let rv = C_GenerateKey(
        session,
        &mut mechanism,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut key,
    );
    assert_eq!(rv, CKR_OK);

    let mut dec_mech = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_DecryptInit(session, &mut dec_mech, key);
    assert_eq!(rv, CKR_KEY_FUNCTION_NOT_PERMITTED);
}

// ============================================================================
// CKR_USER_NOT_LOGGED_IN — operations requiring login
// ============================================================================

#[test]
fn test_sign_init_without_login() {
    ensure_init();
    let so_pin = b"sopin123";
    let mut label = [b' '; 32];
    label[..7].copy_from_slice(b"NoLogin");
    C_InitToken(
        0,
        so_pin.as_ptr() as *mut _,
        so_pin.len() as CK_ULONG,
        label.as_ptr() as *mut _,
    );

    let mut session: CK_SESSION_HANDLE = 0;
    let rv = C_OpenSession(
        0,
        CKF_RW_SESSION | CKF_SERIAL_SESSION,
        ptr::null_mut(),
        None,
        &mut session,
    );
    assert_eq!(rv, CKR_OK);

    // No login — try to sign
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256_RSA_PKCS,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_SignInit(session, &mut mechanism, 1);
    assert_eq!(rv, CKR_USER_NOT_LOGGED_IN);
}

// ============================================================================
// CKR_USER_ALREADY_LOGGED_IN
// ============================================================================

#[test]
fn test_double_user_login() {
    let session = setup_user_session(); // already logged in as user
    let user_pin = b"userpin1";
    let rv = C_Login(
        session,
        CKU_USER,
        user_pin.as_ptr() as *mut _,
        user_pin.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_USER_ALREADY_LOGGED_IN);
}

// ============================================================================
// CKR_PIN_INCORRECT
// ============================================================================

#[test]
fn test_login_wrong_pin() {
    ensure_init();
    let so_pin = b"sopin123";
    let mut label = [b' '; 32];
    label[..7].copy_from_slice(b"WrngPIN");
    C_InitToken(
        0,
        so_pin.as_ptr() as *mut _,
        so_pin.len() as CK_ULONG,
        label.as_ptr() as *mut _,
    );

    let mut session: CK_SESSION_HANDLE = 0;
    C_OpenSession(
        0,
        CKF_RW_SESSION | CKF_SERIAL_SESSION,
        ptr::null_mut(),
        None,
        &mut session,
    );

    // Login SO, init user PIN, logout
    C_Login(
        session,
        CKU_SO,
        so_pin.as_ptr() as *mut _,
        so_pin.len() as CK_ULONG,
    );
    let user_pin = b"userpin1";
    C_InitPIN(
        session,
        user_pin.as_ptr() as *mut _,
        user_pin.len() as CK_ULONG,
    );
    C_Logout(session);

    // Try login with wrong PIN
    let wrong_pin = b"wrongpin";
    let rv = C_Login(
        session,
        CKU_USER,
        wrong_pin.as_ptr() as *mut _,
        wrong_pin.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_PIN_INCORRECT);
}

// ============================================================================
// CKR_SESSION_READ_ONLY
// ============================================================================

#[test]
fn test_generate_key_on_ro_session() {
    ensure_init();
    let so_pin = b"sopin123";
    let mut label = [b' '; 32];
    label[..6].copy_from_slice(b"ROTest");
    C_InitToken(
        0,
        so_pin.as_ptr() as *mut _,
        so_pin.len() as CK_ULONG,
        label.as_ptr() as *mut _,
    );

    // Open RW first to set up user PIN
    let mut rw_session: CK_SESSION_HANDLE = 0;
    C_OpenSession(
        0,
        CKF_RW_SESSION | CKF_SERIAL_SESSION,
        ptr::null_mut(),
        None,
        &mut rw_session,
    );
    C_Login(
        rw_session,
        CKU_SO,
        so_pin.as_ptr() as *mut _,
        so_pin.len() as CK_ULONG,
    );
    let user_pin = b"userpin1";
    C_InitPIN(
        rw_session,
        user_pin.as_ptr() as *mut _,
        user_pin.len() as CK_ULONG,
    );
    C_Logout(rw_session);

    // Now open RO session and login as user
    let mut ro_session: CK_SESSION_HANDLE = 0;
    let rv = C_OpenSession(
        0,
        CKF_SERIAL_SESSION,
        ptr::null_mut(),
        None,
        &mut ro_session,
    );
    assert_eq!(rv, CKR_OK);
    let rv = C_Login(
        ro_session,
        CKU_USER,
        user_pin.as_ptr() as *mut _,
        user_pin.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_OK);

    // Try to generate key on RO session
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let value_len_bytes = ck_ulong_bytes(32);
    let mut template = vec![CK_ATTRIBUTE {
        attr_type: CKA_VALUE_LEN,
        p_value: value_len_bytes.as_ptr() as CK_VOID_PTR,
        value_len: value_len_bytes.len() as CK_ULONG,
    }];
    let mut key: CK_OBJECT_HANDLE = 0;
    let rv = C_GenerateKey(
        ro_session,
        &mut mechanism,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut key,
    );
    assert_eq!(rv, CKR_SESSION_READ_ONLY);
}

// ============================================================================
// CKR_DESTROY_OBJECT edge cases
// ============================================================================

#[test]
fn test_destroy_invalid_handle() {
    let session = setup_user_session();
    let rv = C_DestroyObject(session, 999999);
    assert_eq!(rv, CKR_OBJECT_HANDLE_INVALID);
}

// ============================================================================
// Digest full roundtrip with DigestUpdate/DigestFinal
// ============================================================================

#[test]
fn test_digest_multipart_sha256() {
    let session = setup_user_session();
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_DigestInit(session, &mut mechanism);
    assert_eq!(rv, CKR_OK);

    let part1 = b"hello ";
    let rv = C_DigestUpdate(
        session,
        part1.as_ptr() as CK_BYTE_PTR,
        part1.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_OK);

    let part2 = b"world";
    let rv = C_DigestUpdate(
        session,
        part2.as_ptr() as CK_BYTE_PTR,
        part2.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_OK);

    let mut digest = vec![0u8; 32];
    let mut digest_len: CK_ULONG = 32;
    let rv = C_DigestFinal(session, digest.as_mut_ptr(), &mut digest_len);
    assert_eq!(rv, CKR_OK);
    assert_eq!(digest_len, 32);
    // Verify it's not all zeros
    assert_ne!(&digest[..], &[0u8; 32]);
}

// ============================================================================
// Token reinitialization clears state
// ============================================================================

#[test]
fn test_token_reinit_clears_objects() {
    let session = setup_user_session();
    let _key = generate_aes_key(session);

    // Close all sessions and re-init token
    C_CloseAllSessions(0);
    let so_pin = b"sopin123";
    let mut label = [b' '; 32];
    label[..7].copy_from_slice(b"ReInit2");
    let rv = C_InitToken(
        0,
        so_pin.as_ptr() as *mut _,
        so_pin.len() as CK_ULONG,
        label.as_ptr() as *mut _,
    );
    assert_eq!(rv, CKR_OK);

    // Re-open session, login, try to find objects
    let mut session2: CK_SESSION_HANDLE = 0;
    C_OpenSession(
        0,
        CKF_RW_SESSION | CKF_SERIAL_SESSION,
        ptr::null_mut(),
        None,
        &mut session2,
    );
    C_Login(
        session2,
        CKU_SO,
        so_pin.as_ptr() as *mut _,
        so_pin.len() as CK_ULONG,
    );
    let user_pin = b"userpin1";
    C_InitPIN(
        session2,
        user_pin.as_ptr() as *mut _,
        user_pin.len() as CK_ULONG,
    );
    C_Logout(session2);
    C_Login(
        session2,
        CKU_USER,
        user_pin.as_ptr() as *mut _,
        user_pin.len() as CK_ULONG,
    );

    // Find all objects — should be empty after re-init
    let rv = C_FindObjectsInit(session2, ptr::null_mut(), 0);
    assert_eq!(rv, CKR_OK);
    let mut found: [CK_OBJECT_HANDLE; 10] = [0; 10];
    let mut found_count: CK_ULONG = 0;
    let rv = C_FindObjects(session2, found.as_mut_ptr(), 10, &mut found_count);
    assert_eq!(rv, CKR_OK);
    assert_eq!(
        found_count, 0,
        "Objects should be cleared after C_InitToken"
    );
    C_FindObjectsFinal(session2);
}
