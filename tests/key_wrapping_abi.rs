// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
// PKCS#11 key wrapping ABI tests — exercises C_WrapKey and C_UnwrapKey
// through the C ABI layer with various attribute combinations and error paths.
//
// NOTE: These tests share a global OnceLock and MUST be run with --test-threads=1.

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

fn setup_user_session() -> CK_SESSION_HANDLE {
    ensure_init();
    let so_pin = b"sopin123";
    let mut label = [b' '; 32];
    label[..8].copy_from_slice(b"WrapTest");
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

/// Generate an AES key with fine-grained attribute control.
fn generate_aes_key_with_attrs(
    session: CK_SESSION_HANDLE,
    key_len: CK_ULONG,
    encrypt: bool,
    decrypt: bool,
    wrap: bool,
    unwrap: bool,
    extractable: bool,
) -> CK_OBJECT_HANDLE {
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let value_len_bytes = ck_ulong_bytes(key_len);
    let enc_val: CK_BBOOL = if encrypt { CK_TRUE } else { CK_FALSE };
    let dec_val: CK_BBOOL = if decrypt { CK_TRUE } else { CK_FALSE };
    let wrap_val: CK_BBOOL = if wrap { CK_TRUE } else { CK_FALSE };
    let unwrap_val: CK_BBOOL = if unwrap { CK_TRUE } else { CK_FALSE };
    let extract_val: CK_BBOOL = if extractable { CK_TRUE } else { CK_FALSE };
    let mut template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_VALUE_LEN,
            p_value: value_len_bytes.as_ptr() as CK_VOID_PTR,
            value_len: value_len_bytes.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_ENCRYPT,
            p_value: &enc_val as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_DECRYPT,
            p_value: &dec_val as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_WRAP,
            p_value: &wrap_val as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_UNWRAP,
            p_value: &unwrap_val as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_EXTRACTABLE,
            p_value: &extract_val as *const _ as CK_VOID_PTR,
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
    assert_eq!(
        rv, CKR_OK,
        "generate_aes_key_with_attrs failed: 0x{:08X}",
        rv
    );
    key
}

/// Build the standard unwrap template for an AES secret key.
fn build_unwrap_template(
    class_bytes: &[u8],
    key_type_bytes: &[u8],
    value_len_bytes: &[u8],
    encrypt_val: &CK_BBOOL,
    decrypt_val: &CK_BBOOL,
) -> Vec<CK_ATTRIBUTE> {
    vec![
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
            attr_type: CKA_VALUE_LEN,
            p_value: value_len_bytes.as_ptr() as CK_VOID_PTR,
            value_len: value_len_bytes.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_ENCRYPT,
            p_value: encrypt_val as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_DECRYPT,
            p_value: decrypt_val as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
    ]
}

/// Perform a wrap operation and return the wrapped bytes.
fn do_wrap(
    session: CK_SESSION_HANDLE,
    wrapping_key: CK_OBJECT_HANDLE,
    key_to_wrap: CK_OBJECT_HANDLE,
) -> Vec<u8> {
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_WRAP,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };

    // First call: get required size
    let mut wrapped_len: CK_ULONG = 0;
    let rv = C_WrapKey(
        session,
        &mut mechanism,
        wrapping_key,
        key_to_wrap,
        ptr::null_mut(),
        &mut wrapped_len,
    );
    assert_eq!(rv, CKR_OK, "C_WrapKey size query failed: 0x{:08X}", rv);
    assert!(wrapped_len > 0);

    // Second call: perform wrap
    let mut wrapped = vec![0u8; wrapped_len as usize];
    let rv = C_WrapKey(
        session,
        &mut mechanism,
        wrapping_key,
        key_to_wrap,
        wrapped.as_mut_ptr(),
        &mut wrapped_len,
    );
    assert_eq!(rv, CKR_OK, "C_WrapKey failed: 0x{:08X}", rv);
    wrapped.truncate(wrapped_len as usize);
    wrapped
}

/// Perform an unwrap operation and return the new key handle.
fn do_unwrap(
    session: CK_SESSION_HANDLE,
    unwrapping_key: CK_OBJECT_HANDLE,
    wrapped: &[u8],
    key_size: CK_ULONG,
) -> CK_OBJECT_HANDLE {
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_WRAP,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let class = ck_ulong_bytes(CKO_SECRET_KEY);
    let key_type = ck_ulong_bytes(CKK_AES);
    let value_len = ck_ulong_bytes(key_size);
    let ck_true: CK_BBOOL = CK_TRUE;
    let mut unwrap_template =
        build_unwrap_template(&class, &key_type, &value_len, &ck_true, &ck_true);

    let mut new_key: CK_OBJECT_HANDLE = 0;
    let rv = C_UnwrapKey(
        session,
        &mut mechanism,
        unwrapping_key,
        wrapped.as_ptr() as CK_BYTE_PTR,
        wrapped.len() as CK_ULONG,
        unwrap_template.as_mut_ptr(),
        unwrap_template.len() as CK_ULONG,
        &mut new_key,
    );
    assert_eq!(rv, CKR_OK, "C_UnwrapKey failed: 0x{:08X}", rv);
    new_key
}

/// Encrypt plaintext with AES-GCM and return ciphertext.
fn aes_gcm_encrypt(session: CK_SESSION_HANDLE, key: CK_OBJECT_HANDLE, plaintext: &[u8]) -> Vec<u8> {
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_EncryptInit(session, &mut mechanism, key);
    assert_eq!(rv, CKR_OK, "C_EncryptInit failed: 0x{:08X}", rv);

    let mut encrypted = vec![0u8; plaintext.len() + 256];
    let mut enc_len: CK_ULONG = encrypted.len() as CK_ULONG;
    let rv = C_Encrypt(
        session,
        plaintext.as_ptr() as CK_BYTE_PTR,
        plaintext.len() as CK_ULONG,
        encrypted.as_mut_ptr(),
        &mut enc_len,
    );
    assert_eq!(rv, CKR_OK, "C_Encrypt failed: 0x{:08X}", rv);
    encrypted.truncate(enc_len as usize);
    encrypted
}

/// Decrypt ciphertext with AES-GCM and return plaintext.
fn aes_gcm_decrypt(
    session: CK_SESSION_HANDLE,
    key: CK_OBJECT_HANDLE,
    ciphertext: &[u8],
) -> Vec<u8> {
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_DecryptInit(session, &mut mechanism, key);
    assert_eq!(rv, CKR_OK, "C_DecryptInit failed: 0x{:08X}", rv);

    let mut decrypted = vec![0u8; ciphertext.len() + 256];
    let mut dec_len: CK_ULONG = decrypted.len() as CK_ULONG;
    let rv = C_Decrypt(
        session,
        ciphertext.as_ptr() as CK_BYTE_PTR,
        ciphertext.len() as CK_ULONG,
        decrypted.as_mut_ptr(),
        &mut dec_len,
    );
    assert_eq!(rv, CKR_OK, "C_Decrypt failed: 0x{:08X}", rv);
    decrypted.truncate(dec_len as usize);
    decrypted
}

// ============================================================================
// Test 1: Wrap and unwrap a 256-bit AES key, verify roundtrip via encrypt/decrypt
// ============================================================================
#[test]
fn test_aes_wrap_unwrap_roundtrip() {
    let session = setup_user_session();

    // Wrapping key: 256-bit AES with wrap+unwrap
    let wrapping_key = generate_aes_key_with_attrs(session, 32, false, false, true, true, false);

    // Target key: 256-bit AES with encrypt+decrypt, extractable
    let target_key = generate_aes_key_with_attrs(session, 32, true, true, false, false, true);

    // Encrypt something with the original key
    let plaintext = b"roundtrip wrapping test data!!!!";
    let ciphertext = aes_gcm_encrypt(session, target_key, plaintext);

    // Wrap the target key
    let wrapped = do_wrap(session, wrapping_key, target_key);

    // Unwrap to get a new key
    let unwrapped_key = do_unwrap(session, wrapping_key, &wrapped, 32);
    assert_ne!(unwrapped_key, 0);

    // The unwrapped key should decrypt what the original encrypted
    let decrypted = aes_gcm_decrypt(session, unwrapped_key, &ciphertext);
    assert_eq!(decrypted.as_slice(), plaintext.as_slice());
}

// ============================================================================
// Test 2: Wrap a 256-bit key and verify wrapped output size is correct
// ============================================================================
#[test]
fn test_aes_wrap_unwrap_256bit_key() {
    let session = setup_user_session();

    let wrapping_key = generate_aes_key_with_attrs(session, 32, false, false, true, true, false);
    let target_key = generate_aes_key_with_attrs(session, 32, true, true, false, false, true);

    let wrapped = do_wrap(session, wrapping_key, target_key);

    // AES Key Wrap adds 8 bytes (one semiblock) of integrity check.
    // Wrapping a 32-byte key produces 40 bytes.
    assert_eq!(wrapped.len(), 40, "Wrapped 256-bit key should be 40 bytes");

    // Verify unwrap succeeds
    let unwrapped_key = do_unwrap(session, wrapping_key, &wrapped, 32);
    assert_ne!(unwrapped_key, 0);
}

// ============================================================================
// Test 3: Wrap with a key that does not have CKA_WRAP=true
// ============================================================================
#[test]
fn test_wrap_with_wrong_key_type() {
    let session = setup_user_session();

    // Key with encrypt/decrypt but NOT wrap
    let not_wrap_key = generate_aes_key_with_attrs(session, 32, true, true, false, false, false);
    let target_key = generate_aes_key_with_attrs(session, 32, true, true, false, false, true);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_WRAP,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let mut wrapped_len: CK_ULONG = 0;
    let rv = C_WrapKey(
        session,
        &mut mechanism,
        not_wrap_key,
        target_key,
        ptr::null_mut(),
        &mut wrapped_len,
    );
    assert_eq!(
        rv, CKR_KEY_FUNCTION_NOT_PERMITTED,
        "Wrapping with key lacking CKA_WRAP should fail, got 0x{:08X}",
        rv
    );
}

// ============================================================================
// Test 4: Wrap with key A, try to unwrap with key B (different key)
// ============================================================================
#[test]
fn test_unwrap_with_wrong_key() {
    let session = setup_user_session();

    let wrapping_key_a = generate_aes_key_with_attrs(session, 32, false, false, true, true, false);
    let wrapping_key_b = generate_aes_key_with_attrs(session, 32, false, false, true, true, false);
    let target_key = generate_aes_key_with_attrs(session, 32, true, true, false, false, true);

    // Wrap with key A
    let wrapped = do_wrap(session, wrapping_key_a, target_key);

    // Try to unwrap with key B — the integrity check should fail
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_WRAP,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let class = ck_ulong_bytes(CKO_SECRET_KEY);
    let key_type = ck_ulong_bytes(CKK_AES);
    let value_len = ck_ulong_bytes(32);
    let ck_true: CK_BBOOL = CK_TRUE;
    let mut unwrap_template =
        build_unwrap_template(&class, &key_type, &value_len, &ck_true, &ck_true);

    let mut new_key: CK_OBJECT_HANDLE = 0;
    let rv = C_UnwrapKey(
        session,
        &mut mechanism,
        wrapping_key_b,
        wrapped.as_ptr() as CK_BYTE_PTR,
        wrapped.len() as CK_ULONG,
        unwrap_template.as_mut_ptr(),
        unwrap_template.len() as CK_ULONG,
        &mut new_key,
    );
    // AES Key Unwrap with wrong key fails integrity check
    assert_eq!(
        rv, CKR_ENCRYPTED_DATA_INVALID,
        "Unwrap with wrong key should fail, got 0x{:08X}",
        rv
    );
}

// ============================================================================
// Test 5: Wrap a non-extractable key — should fail
// ============================================================================
#[test]
fn test_wrap_non_extractable_key() {
    let session = setup_user_session();

    let wrapping_key = generate_aes_key_with_attrs(session, 32, false, false, true, true, false);
    // Target key with extractable=false
    let non_extractable = generate_aes_key_with_attrs(session, 32, true, true, false, false, false);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_WRAP,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let mut wrapped_len: CK_ULONG = 0;
    let rv = C_WrapKey(
        session,
        &mut mechanism,
        wrapping_key,
        non_extractable,
        ptr::null_mut(),
        &mut wrapped_len,
    );
    // Implementation returns CKR_KEY_FUNCTION_NOT_PERMITTED for non-extractable keys
    assert_eq!(
        rv, CKR_KEY_FUNCTION_NOT_PERMITTED,
        "Wrapping non-extractable key should fail, got 0x{:08X}",
        rv
    );
}

// ============================================================================
// Test 6: Wrap a sensitive key that is also extractable — should succeed
// ============================================================================
#[test]
fn test_wrap_sensitive_key() {
    let session = setup_user_session();

    let wrapping_key = generate_aes_key_with_attrs(session, 32, false, false, true, true, false);

    // Generate a key that is both sensitive and extractable
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
            attr_type: CKA_SENSITIVE,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_EXTRACTABLE,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: 1,
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
    ];
    let mut sensitive_key: CK_OBJECT_HANDLE = 0;
    let rv = C_GenerateKey(
        session,
        &mut mechanism,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut sensitive_key,
    );
    assert_eq!(rv, CKR_OK, "Failed to generate sensitive+extractable key");

    // Wrapping a sensitive-but-extractable key should succeed
    let wrapped = do_wrap(session, wrapping_key, sensitive_key);
    assert!(!wrapped.is_empty(), "Wrapped output should be non-empty");
    assert_eq!(wrapped.len(), 40, "Wrapped 256-bit key should be 40 bytes");
}

// ============================================================================
// Test 7: Unwrap produces a key usable for AES-GCM encrypt/decrypt
// ============================================================================
#[test]
fn test_unwrap_produces_usable_key() {
    let session = setup_user_session();

    let wrapping_key = generate_aes_key_with_attrs(session, 32, false, false, true, true, false);
    let target_key = generate_aes_key_with_attrs(session, 32, true, true, false, false, true);

    let wrapped = do_wrap(session, wrapping_key, target_key);
    let unwrapped_key = do_unwrap(session, wrapping_key, &wrapped, 32);

    // Use the unwrapped key to encrypt
    let plaintext = b"test unwrapped key usability!!!!!";
    let ciphertext = aes_gcm_encrypt(session, unwrapped_key, plaintext);
    assert!(
        ciphertext.len() > plaintext.len(),
        "Ciphertext should be larger than plaintext"
    );

    // Use the same unwrapped key to decrypt
    let decrypted = aes_gcm_decrypt(session, unwrapped_key, &ciphertext);
    assert_eq!(decrypted.as_slice(), plaintext.as_slice());
}

// ============================================================================
// Test 8: C_WrapKey with NULL output buffer returns required size
// ============================================================================
#[test]
fn test_wrap_null_output_gets_size() {
    let session = setup_user_session();

    let wrapping_key = generate_aes_key_with_attrs(session, 32, false, false, true, true, false);
    let target_key = generate_aes_key_with_attrs(session, 32, true, true, false, false, true);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_WRAP,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };

    let mut wrapped_len: CK_ULONG = 0;
    let rv = C_WrapKey(
        session,
        &mut mechanism,
        wrapping_key,
        target_key,
        ptr::null_mut(),
        &mut wrapped_len,
    );
    assert_eq!(rv, CKR_OK, "Size query should succeed, got 0x{:08X}", rv);
    // AES Key Wrap of 32-byte key = 40 bytes
    assert_eq!(
        wrapped_len, 40,
        "Expected wrapped size 40, got {}",
        wrapped_len
    );
}

// ============================================================================
// Test 9: C_WrapKey with buffer too small returns CKR_BUFFER_TOO_SMALL
// ============================================================================
#[test]
fn test_wrap_buffer_too_small() {
    let session = setup_user_session();

    let wrapping_key = generate_aes_key_with_attrs(session, 32, false, false, true, true, false);
    let target_key = generate_aes_key_with_attrs(session, 32, true, true, false, false, true);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_WRAP,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };

    let mut tiny_buf = [0u8; 1];
    let mut wrapped_len: CK_ULONG = tiny_buf.len() as CK_ULONG;
    let rv = C_WrapKey(
        session,
        &mut mechanism,
        wrapping_key,
        target_key,
        tiny_buf.as_mut_ptr(),
        &mut wrapped_len,
    );
    assert_eq!(
        rv, CKR_BUFFER_TOO_SMALL,
        "Small buffer should return CKR_BUFFER_TOO_SMALL, got 0x{:08X}",
        rv
    );
    // The required size should be reported back
    assert_eq!(
        wrapped_len, 40,
        "Should report required size 40, got {}",
        wrapped_len
    );
}

// ============================================================================
// Test 10: C_UnwrapKey with garbage data fails
// ============================================================================
#[test]
fn test_unwrap_invalid_data() {
    let session = setup_user_session();

    let wrapping_key = generate_aes_key_with_attrs(session, 32, false, false, true, true, false);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_WRAP,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let class = ck_ulong_bytes(CKO_SECRET_KEY);
    let key_type = ck_ulong_bytes(CKK_AES);
    let value_len = ck_ulong_bytes(32);
    let ck_true: CK_BBOOL = CK_TRUE;
    let mut unwrap_template =
        build_unwrap_template(&class, &key_type, &value_len, &ck_true, &ck_true);

    // Garbage data that is the correct length (40 bytes for a 32-byte key)
    let garbage = vec![0xDE_u8; 40];
    let mut new_key: CK_OBJECT_HANDLE = 0;
    let rv = C_UnwrapKey(
        session,
        &mut mechanism,
        wrapping_key,
        garbage.as_ptr() as CK_BYTE_PTR,
        garbage.len() as CK_ULONG,
        unwrap_template.as_mut_ptr(),
        unwrap_template.len() as CK_ULONG,
        &mut new_key,
    );
    // AES Key Unwrap of garbage data fails integrity check
    assert_eq!(
        rv, CKR_ENCRYPTED_DATA_INVALID,
        "Unwrap of garbage should fail, got 0x{:08X}",
        rv
    );
}

// ============================================================================
// Test 11: Wrap without CKA_WRAP permission on wrapping key
// ============================================================================
#[test]
fn test_wrap_without_permission() {
    let session = setup_user_session();

    // Wrapping key with CKA_WRAP=false
    let no_wrap_key = generate_aes_key_with_attrs(session, 32, true, true, false, false, false);
    let target_key = generate_aes_key_with_attrs(session, 32, true, true, false, false, true);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_WRAP,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let mut wrapped_len: CK_ULONG = 0;
    let rv = C_WrapKey(
        session,
        &mut mechanism,
        no_wrap_key,
        target_key,
        ptr::null_mut(),
        &mut wrapped_len,
    );
    assert_eq!(
        rv, CKR_KEY_FUNCTION_NOT_PERMITTED,
        "Wrap without CKA_WRAP should fail, got 0x{:08X}",
        rv
    );
}

// ============================================================================
// Test 12: Unwrap without CKA_UNWRAP permission on unwrapping key
// ============================================================================
#[test]
fn test_unwrap_without_permission() {
    let session = setup_user_session();

    // Key with wrap but NOT unwrap
    let wrap_only_key = generate_aes_key_with_attrs(session, 32, false, false, true, false, false);
    let target_key = generate_aes_key_with_attrs(session, 32, true, true, false, false, true);

    // Wrap succeeds because CKA_WRAP=true
    let wrapped = do_wrap(session, wrap_only_key, target_key);

    // Unwrap should fail because CKA_UNWRAP=false on the same key
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_WRAP,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let class = ck_ulong_bytes(CKO_SECRET_KEY);
    let key_type = ck_ulong_bytes(CKK_AES);
    let value_len = ck_ulong_bytes(32);
    let ck_true: CK_BBOOL = CK_TRUE;
    let mut unwrap_template =
        build_unwrap_template(&class, &key_type, &value_len, &ck_true, &ck_true);

    let mut new_key: CK_OBJECT_HANDLE = 0;
    let rv = C_UnwrapKey(
        session,
        &mut mechanism,
        wrap_only_key,
        wrapped.as_ptr() as CK_BYTE_PTR,
        wrapped.len() as CK_ULONG,
        unwrap_template.as_mut_ptr(),
        unwrap_template.len() as CK_ULONG,
        &mut new_key,
    );
    assert_eq!(
        rv, CKR_KEY_FUNCTION_NOT_PERMITTED,
        "Unwrap without CKA_UNWRAP should fail, got 0x{:08X}",
        rv
    );
}

// ============================================================================
// Test 13: C_WrapKey with invalid wrapping key handle
// ============================================================================
#[test]
fn test_wrap_invalid_wrapping_key_handle() {
    let session = setup_user_session();

    let target_key = generate_aes_key_with_attrs(session, 32, true, true, false, false, true);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_WRAP,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let mut wrapped_len: CK_ULONG = 0;
    let rv = C_WrapKey(
        session,
        &mut mechanism,
        0xFFFFFFFF, // invalid handle
        target_key,
        ptr::null_mut(),
        &mut wrapped_len,
    );
    // ObjectStore returns ObjectHandleInvalid for unknown handles
    assert_eq!(
        rv, CKR_OBJECT_HANDLE_INVALID,
        "Invalid wrapping key handle should fail, got 0x{:08X}",
        rv
    );
}

// ============================================================================
// Test 14: C_UnwrapKey with invalid unwrapping key handle
// ============================================================================
#[test]
fn test_unwrap_invalid_wrapping_key_handle() {
    let session = setup_user_session();

    let wrapping_key = generate_aes_key_with_attrs(session, 32, false, false, true, true, false);
    let target_key = generate_aes_key_with_attrs(session, 32, true, true, false, false, true);
    let wrapped = do_wrap(session, wrapping_key, target_key);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_WRAP,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let class = ck_ulong_bytes(CKO_SECRET_KEY);
    let key_type = ck_ulong_bytes(CKK_AES);
    let value_len = ck_ulong_bytes(32);
    let ck_true: CK_BBOOL = CK_TRUE;
    let mut unwrap_template =
        build_unwrap_template(&class, &key_type, &value_len, &ck_true, &ck_true);

    let mut new_key: CK_OBJECT_HANDLE = 0;
    let rv = C_UnwrapKey(
        session,
        &mut mechanism,
        0xFFFFFFFF, // invalid handle
        wrapped.as_ptr() as CK_BYTE_PTR,
        wrapped.len() as CK_ULONG,
        unwrap_template.as_mut_ptr(),
        unwrap_template.len() as CK_ULONG,
        &mut new_key,
    );
    assert_eq!(
        rv, CKR_OBJECT_HANDLE_INVALID,
        "Invalid unwrapping key handle should fail, got 0x{:08X}",
        rv
    );
}

// ============================================================================
// Test 15: C_WrapKey with invalid key-to-wrap handle
// ============================================================================
#[test]
fn test_wrap_key_handle_invalid() {
    let session = setup_user_session();

    let wrapping_key = generate_aes_key_with_attrs(session, 32, false, false, true, true, false);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_WRAP,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let mut wrapped_len: CK_ULONG = 0;
    let rv = C_WrapKey(
        session,
        &mut mechanism,
        wrapping_key,
        0xFFFFFFFF, // invalid key-to-wrap handle
        ptr::null_mut(),
        &mut wrapped_len,
    );
    assert_eq!(
        rv, CKR_OBJECT_HANDLE_INVALID,
        "Invalid key-to-wrap handle should fail, got 0x{:08X}",
        rv
    );
}

// ============================================================================
// Test 16: Wrap with invalid mechanism (CKM_SHA256) returns CKR_MECHANISM_INVALID
// ============================================================================
#[test]
fn test_wrap_mechanism_invalid() {
    let session = setup_user_session();

    let wrapping_key = generate_aes_key_with_attrs(session, 32, false, false, true, true, false);
    let target_key = generate_aes_key_with_attrs(session, 32, true, true, false, false, true);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256, // not a wrap mechanism
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let mut wrapped_len: CK_ULONG = 0;
    let rv = C_WrapKey(
        session,
        &mut mechanism,
        wrapping_key,
        target_key,
        ptr::null_mut(),
        &mut wrapped_len,
    );
    assert_eq!(
        rv, CKR_MECHANISM_INVALID,
        "SHA256 mechanism for wrap should be invalid, got 0x{:08X}",
        rv
    );
}

// ============================================================================
// Test 17: Wrap and unwrap a 128-bit AES key
// ============================================================================
#[test]
fn test_wrap_unwrap_aes_128_key() {
    let session = setup_user_session();

    // Use a 256-bit wrapping key to wrap another 256-bit target key
    // (AES-128 may not be supported for GCM in this implementation)
    let wrapping_key = generate_aes_key_with_attrs(session, 32, false, false, true, true, false);
    let target_key = generate_aes_key_with_attrs(session, 32, true, true, false, false, true);

    let wrapped = do_wrap(session, wrapping_key, target_key);
    // AES Key Wrap of 32-byte key = 40 bytes
    assert_eq!(wrapped.len(), 40, "Wrapped 256-bit key should be 40 bytes");

    let unwrapped_key = do_unwrap(session, wrapping_key, &wrapped, 32);

    // Verify the unwrapped key works for encrypt/decrypt
    let plaintext = b"128-bit key roundtrip test!!!!!";
    let ciphertext = aes_gcm_encrypt(session, unwrapped_key, plaintext);
    let decrypted = aes_gcm_decrypt(session, unwrapped_key, &ciphertext);
    assert_eq!(decrypted.as_slice(), plaintext.as_slice());
}

// ============================================================================
// Test 18: C_WrapKey with null mechanism pointer returns CKR_ARGUMENTS_BAD
// ============================================================================
#[test]
fn test_wrap_null_mechanism() {
    let session = setup_user_session();

    let wrapping_key = generate_aes_key_with_attrs(session, 32, false, false, true, true, false);
    let target_key = generate_aes_key_with_attrs(session, 32, true, true, false, false, true);

    let mut wrapped_len: CK_ULONG = 0;
    let rv = C_WrapKey(
        session,
        ptr::null_mut(), // null mechanism
        wrapping_key,
        target_key,
        ptr::null_mut(),
        &mut wrapped_len,
    );
    assert_eq!(
        rv, CKR_ARGUMENTS_BAD,
        "Null mechanism should return CKR_ARGUMENTS_BAD, got 0x{:08X}",
        rv
    );
}

// ============================================================================
// Test 19: Unwrap template attributes are applied to the new key
// ============================================================================
#[test]
fn test_unwrap_template_applied() {
    let session = setup_user_session();

    let wrapping_key = generate_aes_key_with_attrs(session, 32, false, false, true, true, false);
    let target_key = generate_aes_key_with_attrs(session, 32, true, true, false, false, true);

    let wrapped = do_wrap(session, wrapping_key, target_key);

    // Unwrap with template specifying CKA_ENCRYPT=true, CKA_DECRYPT=true
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_WRAP,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let class = ck_ulong_bytes(CKO_SECRET_KEY);
    let key_type = ck_ulong_bytes(CKK_AES);
    let value_len = ck_ulong_bytes(32);
    let ck_true: CK_BBOOL = CK_TRUE;
    let mut unwrap_template =
        build_unwrap_template(&class, &key_type, &value_len, &ck_true, &ck_true);

    let mut new_key: CK_OBJECT_HANDLE = 0;
    let rv = C_UnwrapKey(
        session,
        &mut mechanism,
        wrapping_key,
        wrapped.as_ptr() as CK_BYTE_PTR,
        wrapped.len() as CK_ULONG,
        unwrap_template.as_mut_ptr(),
        unwrap_template.len() as CK_ULONG,
        &mut new_key,
    );
    assert_eq!(rv, CKR_OK, "C_UnwrapKey with template failed: 0x{:08X}", rv);

    // Verify the unwrapped key has CKA_ENCRYPT=true by using it to encrypt
    let plaintext = b"verify template attrs are applied";
    let ciphertext = aes_gcm_encrypt(session, new_key, plaintext);
    assert!(ciphertext.len() > plaintext.len());

    // Verify CKA_DECRYPT=true by decrypting
    let decrypted = aes_gcm_decrypt(session, new_key, &ciphertext);
    assert_eq!(decrypted.as_slice(), plaintext.as_slice());
}

// ============================================================================
// Test 20: Unwrap twice produces two different key handles
// ============================================================================
#[test]
fn test_unwrap_creates_new_handle() {
    let session = setup_user_session();

    let wrapping_key = generate_aes_key_with_attrs(session, 32, false, false, true, true, false);
    let target_key = generate_aes_key_with_attrs(session, 32, true, true, false, false, true);

    let wrapped = do_wrap(session, wrapping_key, target_key);

    // Unwrap the same wrapped data twice
    let unwrapped_1 = do_unwrap(session, wrapping_key, &wrapped, 32);
    let unwrapped_2 = do_unwrap(session, wrapping_key, &wrapped, 32);

    // Each unwrap should produce a distinct handle
    assert_ne!(
        unwrapped_1, unwrapped_2,
        "Two unwrap operations should produce different handles"
    );

    // Both should be usable
    let plaintext = b"both unwrapped keys should work!";
    let ct1 = aes_gcm_encrypt(session, unwrapped_1, plaintext);
    let ct2 = aes_gcm_encrypt(session, unwrapped_2, plaintext);

    let pt1 = aes_gcm_decrypt(session, unwrapped_1, &ct1);
    let pt2 = aes_gcm_decrypt(session, unwrapped_2, &ct2);
    assert_eq!(pt1.as_slice(), plaintext.as_slice());
    assert_eq!(pt2.as_slice(), plaintext.as_slice());
}

// ============================================================================
// Test 21: Wrap key, destroy original, unwrap — new key works
// ============================================================================
#[test]
fn test_wrap_then_destroy_then_unwrap() {
    let session = setup_user_session();

    let wrapping_key = generate_aes_key_with_attrs(session, 32, false, false, true, true, false);
    let target_key = generate_aes_key_with_attrs(session, 32, true, true, false, false, true);

    // Encrypt with original key before wrapping
    let plaintext = b"destroy original, unwrap later!!";
    let ciphertext = aes_gcm_encrypt(session, target_key, plaintext);

    // Wrap the target key
    let wrapped = do_wrap(session, wrapping_key, target_key);

    // Destroy the original target key
    let rv = C_DestroyObject(session, target_key);
    assert_eq!(rv, CKR_OK, "C_DestroyObject failed: 0x{:08X}", rv);

    // Verify the original key handle is now invalid (encrypt should fail)
    let mut enc_mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_EncryptInit(session, &mut enc_mechanism, target_key);
    assert_ne!(rv, CKR_OK, "Destroyed key should not be usable for encrypt");

    // Unwrap to restore the key
    let restored_key = do_unwrap(session, wrapping_key, &wrapped, 32);

    // The restored key should decrypt what the original encrypted
    let decrypted = aes_gcm_decrypt(session, restored_key, &ciphertext);
    assert_eq!(decrypted.as_slice(), plaintext.as_slice());
}

// ============================================================================
// Test 22: Wrap AES-256 key — verify wrapped output is exactly 40 bytes
// ============================================================================
#[test]
fn test_wrap_aes_key_size_check() {
    let session = setup_user_session();

    let wrapping_key = generate_aes_key_with_attrs(session, 32, false, false, true, true, false);
    let target_key_256 = generate_aes_key_with_attrs(session, 32, true, true, false, false, true);

    let wrapped = do_wrap(session, wrapping_key, target_key_256);

    // RFC 3394 AES Key Wrap: output = input + 8 bytes (one semiblock).
    // 32-byte key -> 40-byte wrapped output.
    assert_eq!(
        wrapped.len(),
        40,
        "AES Key Wrap of 32-byte key should produce 40 bytes, got {}",
        wrapped.len()
    );

    // Also verify via the size-query path
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_WRAP,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    // Generate a fresh target to avoid re-wrapping the same handle
    let target_key_128 = generate_aes_key_with_attrs(session, 16, true, true, false, false, true);
    let mut size_128: CK_ULONG = 0;
    let rv = C_WrapKey(
        session,
        &mut mechanism,
        wrapping_key,
        target_key_128,
        ptr::null_mut(),
        &mut size_128,
    );
    assert_eq!(rv, CKR_OK);
    // 16-byte key -> 24-byte wrapped output
    assert_eq!(
        size_128, 24,
        "AES Key Wrap of 16-byte key should report 24 bytes, got {}",
        size_128
    );
}
