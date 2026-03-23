// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
// Supplementary function integration tests — C_CopyObject and C_DigestKey.
//
// Must run with --test-threads=1 due to global OnceLock state.

use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm::pkcs11_abi::functions::*;
use craton_hsm::pkcs11_abi::types::*;
use std::ptr;

fn ck_ulong_bytes(val: CK_ULONG) -> Vec<u8> {
    val.to_ne_bytes().to_vec()
}

/// Initialize PKCS#11, open an RW session, and log in as user.
fn setup_session() -> CK_SESSION_HANDLE {
    let rv = C_Initialize(ptr::null_mut());
    assert!(rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED);

    let so_pin = b"12345678";
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

/// Generate an AES-256 key (non-sensitive, extractable). Returns the key handle.
fn generate_aes_key(session: CK_SESSION_HANDLE) -> CK_OBJECT_HANDLE {
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let key_len = ck_ulong_bytes(32);
    let encrypt_true: CK_BBOOL = CK_TRUE;
    let decrypt_true: CK_BBOOL = CK_TRUE;
    let sensitive_false: CK_BBOOL = CK_FALSE;
    let extractable_true: CK_BBOOL = CK_TRUE;
    let class = ck_ulong_bytes(CKO_SECRET_KEY);
    let key_type = ck_ulong_bytes(CKK_AES);
    let label = b"test-aes-key";

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
            attr_type: CKA_VALUE_LEN,
            p_value: key_len.as_ptr() as CK_VOID_PTR,
            value_len: key_len.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_ENCRYPT,
            p_value: &encrypt_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_DECRYPT,
            p_value: &decrypt_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_SENSITIVE,
            p_value: &sensitive_false as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_EXTRACTABLE,
            p_value: &extractable_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_LABEL,
            p_value: label.as_ptr() as CK_VOID_PTR,
            value_len: label.len() as CK_ULONG,
        },
    ];

    let mut key_handle: CK_OBJECT_HANDLE = 0;
    let rv = C_GenerateKey(
        session,
        &mut mechanism,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut key_handle,
    );
    assert_eq!(rv, CKR_OK);
    key_handle
}

/// Generate a sensitive AES-256 key (sensitive=true, extractable=false).
fn generate_sensitive_aes_key(session: CK_SESSION_HANDLE) -> CK_OBJECT_HANDLE {
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let key_len = ck_ulong_bytes(32);
    let encrypt_true: CK_BBOOL = CK_TRUE;
    let decrypt_true: CK_BBOOL = CK_TRUE;
    let sensitive_true: CK_BBOOL = CK_TRUE;
    let extractable_false: CK_BBOOL = CK_FALSE;
    let class = ck_ulong_bytes(CKO_SECRET_KEY);
    let key_type = ck_ulong_bytes(CKK_AES);
    let label = b"sensitive-aes-key";

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
            attr_type: CKA_VALUE_LEN,
            p_value: key_len.as_ptr() as CK_VOID_PTR,
            value_len: key_len.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_ENCRYPT,
            p_value: &encrypt_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_DECRYPT,
            p_value: &decrypt_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_SENSITIVE,
            p_value: &sensitive_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_EXTRACTABLE,
            p_value: &extractable_false as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_LABEL,
            p_value: label.as_ptr() as CK_VOID_PTR,
            value_len: label.len() as CK_ULONG,
        },
    ];

    let mut key_handle: CK_OBJECT_HANDLE = 0;
    let rv = C_GenerateKey(
        session,
        &mut mechanism,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut key_handle,
    );
    assert_eq!(rv, CKR_OK);
    key_handle
}

/// Read a single attribute value from an object.
fn get_attribute(
    session: CK_SESSION_HANDLE,
    handle: CK_OBJECT_HANDLE,
    attr_type: CK_ATTRIBUTE_TYPE,
) -> Vec<u8> {
    // First call: get the size
    let mut tmpl = CK_ATTRIBUTE {
        attr_type,
        p_value: ptr::null_mut(),
        value_len: 0,
    };
    let rv = C_GetAttributeValue(session, handle, &mut tmpl, 1);
    assert_eq!(
        rv, CKR_OK,
        "get attr size failed for attr_type 0x{:08x}",
        attr_type
    );
    assert!(
        tmpl.value_len > 0,
        "attr 0x{:08x} returned 0 length",
        attr_type
    );

    // Second call: get the data
    let mut buf = vec![0u8; tmpl.value_len as usize];
    tmpl.p_value = buf.as_mut_ptr() as CK_VOID_PTR;
    let rv = C_GetAttributeValue(session, handle, &mut tmpl, 1);
    assert_eq!(
        rv, CKR_OK,
        "get attr value failed for attr_type 0x{:08x}",
        attr_type
    );
    buf
}

/// Single-shot AES-GCM encrypt.
fn aes_gcm_encrypt(session: CK_SESSION_HANDLE, key: CK_OBJECT_HANDLE, plaintext: &[u8]) -> Vec<u8> {
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };

    let rv = C_EncryptInit(session, &mut mechanism, key);
    assert_eq!(rv, CKR_OK);

    let mut ct_len: CK_ULONG = 0;
    let rv = C_Encrypt(
        session,
        plaintext.as_ptr() as *mut _,
        plaintext.len() as CK_ULONG,
        ptr::null_mut(),
        &mut ct_len,
    );
    assert_eq!(rv, CKR_OK);

    let mut ciphertext = vec![0u8; ct_len as usize];
    let rv = C_Encrypt(
        session,
        plaintext.as_ptr() as *mut _,
        plaintext.len() as CK_ULONG,
        ciphertext.as_mut_ptr(),
        &mut ct_len,
    );
    assert_eq!(rv, CKR_OK);
    ciphertext.truncate(ct_len as usize);
    ciphertext
}

/// Single-shot AES-GCM decrypt.
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
    assert_eq!(rv, CKR_OK);

    let mut pt_len: CK_ULONG = 0;
    let rv = C_Decrypt(
        session,
        ciphertext.as_ptr() as *mut _,
        ciphertext.len() as CK_ULONG,
        ptr::null_mut(),
        &mut pt_len,
    );
    assert_eq!(rv, CKR_OK);

    let mut plaintext = vec![0u8; pt_len as usize];
    let rv = C_Decrypt(
        session,
        ciphertext.as_ptr() as *mut _,
        ciphertext.len() as CK_ULONG,
        plaintext.as_mut_ptr(),
        &mut pt_len,
    );
    assert_eq!(rv, CKR_OK);
    plaintext.truncate(pt_len as usize);
    plaintext
}

// ============================================================================
// C_CopyObject Tests
// ============================================================================

#[test]
fn test_01_copy_aes_key_basic() {
    let session = setup_session();
    let key = generate_aes_key(session);

    // Copy with no template modifications
    let mut new_handle: CK_OBJECT_HANDLE = 0;
    let rv = C_CopyObject(session, key, ptr::null_mut(), 0, &mut new_handle);
    assert_eq!(
        rv, CKR_OK,
        "C_CopyObject should succeed with empty template"
    );
    assert_ne!(new_handle, key, "Copy should have a different handle");

    // Verify the copy has the same class and key type
    let orig_class = get_attribute(session, key, CKA_CLASS);
    let copy_class = get_attribute(session, new_handle, CKA_CLASS);
    assert_eq!(orig_class, copy_class, "Copy should have same class");

    let orig_kt = get_attribute(session, key, CKA_KEY_TYPE);
    let copy_kt = get_attribute(session, new_handle, CKA_KEY_TYPE);
    assert_eq!(orig_kt, copy_kt, "Copy should have same key type");

    C_Finalize(ptr::null_mut());
}

#[test]
fn test_02_copy_with_modified_label() {
    let session = setup_session();
    let key = generate_aes_key(session);

    // Copy with a new label
    let new_label = b"copied-key";
    let mut template = [CK_ATTRIBUTE {
        attr_type: CKA_LABEL,
        p_value: new_label.as_ptr() as CK_VOID_PTR,
        value_len: new_label.len() as CK_ULONG,
    }];

    let mut new_handle: CK_OBJECT_HANDLE = 0;
    let rv = C_CopyObject(
        session,
        key,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut new_handle,
    );
    assert_eq!(rv, CKR_OK);

    // Verify original label unchanged
    let orig_label = get_attribute(session, key, CKA_LABEL);
    assert_eq!(&orig_label, b"test-aes-key");

    // Verify copy has new label
    let copy_label = get_attribute(session, new_handle, CKA_LABEL);
    assert_eq!(&copy_label, b"copied-key");

    C_Finalize(ptr::null_mut());
}

#[test]
fn test_03_copy_key_roundtrip_encrypt_decrypt() {
    let session = setup_session();
    let key = generate_aes_key(session);

    // Copy the key
    let mut new_handle: CK_OBJECT_HANDLE = 0;
    let rv = C_CopyObject(session, key, ptr::null_mut(), 0, &mut new_handle);
    assert_eq!(rv, CKR_OK);

    // Encrypt with original key
    let plaintext = b"Hello from CopyObject test!";
    let ciphertext = aes_gcm_encrypt(session, key, plaintext);

    // Decrypt with copied key
    let decrypted = aes_gcm_decrypt(session, new_handle, &ciphertext);
    assert_eq!(
        &decrypted, plaintext,
        "Copied key should decrypt data encrypted by original"
    );

    C_Finalize(ptr::null_mut());
}

#[test]
fn test_04_copy_sensitive_key_remains_sensitive() {
    let session = setup_session();
    let key = generate_sensitive_aes_key(session);

    // Copy without changing sensitivity
    let mut new_handle: CK_OBJECT_HANDLE = 0;
    let rv = C_CopyObject(session, key, ptr::null_mut(), 0, &mut new_handle);
    assert_eq!(rv, CKR_OK);

    // Verify copy is also sensitive
    let sensitive = get_attribute(session, new_handle, CKA_SENSITIVE);
    assert_eq!(sensitive[0], 1, "Copy of sensitive key should be sensitive");

    C_Finalize(ptr::null_mut());
}

#[test]
fn test_05_copy_cannot_decrease_sensitivity() {
    let session = setup_session();
    let key = generate_sensitive_aes_key(session);

    // Try to copy with sensitive=false — should fail
    let sensitive_false: CK_BBOOL = CK_FALSE;
    let mut template = [CK_ATTRIBUTE {
        attr_type: CKA_SENSITIVE,
        p_value: &sensitive_false as *const _ as CK_VOID_PTR,
        value_len: 1,
    }];

    let mut new_handle: CK_OBJECT_HANDLE = 0;
    let rv = C_CopyObject(
        session,
        key,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut new_handle,
    );
    assert_eq!(
        rv, CKR_TEMPLATE_INCONSISTENT,
        "Cannot decrease sensitivity on copy"
    );

    C_Finalize(ptr::null_mut());
}

#[test]
fn test_06_copy_cannot_increase_extractability() {
    let session = setup_session();
    let key = generate_sensitive_aes_key(session); // extractable=false

    // Try to copy with extractable=true — should fail
    let extractable_true: CK_BBOOL = CK_TRUE;
    let mut template = [CK_ATTRIBUTE {
        attr_type: CKA_EXTRACTABLE,
        p_value: &extractable_true as *const _ as CK_VOID_PTR,
        value_len: 1,
    }];

    let mut new_handle: CK_OBJECT_HANDLE = 0;
    let rv = C_CopyObject(
        session,
        key,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut new_handle,
    );
    assert_eq!(
        rv, CKR_TEMPLATE_INCONSISTENT,
        "Cannot increase extractability on copy"
    );

    C_Finalize(ptr::null_mut());
}

#[test]
fn test_07_copy_can_increase_sensitivity() {
    let session = setup_session();
    let key = generate_aes_key(session); // sensitive=false by default

    // Copy with sensitive=true — should succeed
    let sensitive_true: CK_BBOOL = CK_TRUE;
    let mut template = [CK_ATTRIBUTE {
        attr_type: CKA_SENSITIVE,
        p_value: &sensitive_true as *const _ as CK_VOID_PTR,
        value_len: 1,
    }];

    let mut new_handle: CK_OBJECT_HANDLE = 0;
    let rv = C_CopyObject(
        session,
        key,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut new_handle,
    );
    assert_eq!(rv, CKR_OK, "Should be able to increase sensitivity on copy");

    let sensitive = get_attribute(session, new_handle, CKA_SENSITIVE);
    assert_eq!(sensitive[0], 1, "Copy should be sensitive");

    // Original should remain non-sensitive
    let orig_sensitive = get_attribute(session, key, CKA_SENSITIVE);
    assert_eq!(orig_sensitive[0], 0, "Original should remain non-sensitive");

    C_Finalize(ptr::null_mut());
}

#[test]
fn test_08_copy_cannot_change_class() {
    let session = setup_session();
    let key = generate_aes_key(session);

    // Try to change class to CKO_PUBLIC_KEY — should fail
    let new_class = ck_ulong_bytes(CKO_PUBLIC_KEY);
    let mut template = [CK_ATTRIBUTE {
        attr_type: CKA_CLASS,
        p_value: new_class.as_ptr() as CK_VOID_PTR,
        value_len: new_class.len() as CK_ULONG,
    }];

    let mut new_handle: CK_OBJECT_HANDLE = 0;
    let rv = C_CopyObject(
        session,
        key,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut new_handle,
    );
    assert_eq!(rv, CKR_TEMPLATE_INCONSISTENT, "Cannot change class on copy");

    C_Finalize(ptr::null_mut());
}

#[test]
fn test_09_copy_nonexistent_object() {
    let session = setup_session();

    let mut new_handle: CK_OBJECT_HANDLE = 0;
    let rv = C_CopyObject(session, 99999, ptr::null_mut(), 0, &mut new_handle);
    assert_eq!(
        rv, CKR_OBJECT_HANDLE_INVALID,
        "Copying non-existent object should fail"
    );

    C_Finalize(ptr::null_mut());
}

#[test]
fn test_10_copy_null_new_handle_ptr() {
    let session = setup_session();
    let key = generate_aes_key(session);

    let rv = C_CopyObject(session, key, ptr::null_mut(), 0, ptr::null_mut());
    assert_eq!(rv, CKR_ARGUMENTS_BAD, "Null new handle pointer should fail");

    C_Finalize(ptr::null_mut());
}

// ============================================================================
// C_DigestKey Tests
// ============================================================================

#[test]
fn test_11_digest_key_basic() {
    let session = setup_session();
    let key = generate_aes_key(session);

    // Get key material for manual comparison
    let key_value = get_attribute(session, key, CKA_VALUE);

    // Start a digest, update with "hello", then digest the key, then finalize
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_DigestInit(session, &mut mechanism);
    assert_eq!(rv, CKR_OK);

    let data = b"hello";
    let rv = C_DigestUpdate(session, data.as_ptr() as *mut _, data.len() as CK_ULONG);
    assert_eq!(rv, CKR_OK);

    // Digest the key
    let rv = C_DigestKey(session, key);
    assert_eq!(rv, CKR_OK);

    let mut digest = [0u8; 32];
    let mut digest_len: CK_ULONG = 32;
    let rv = C_DigestFinal(session, digest.as_mut_ptr(), &mut digest_len);
    assert_eq!(rv, CKR_OK);
    assert_eq!(digest_len, 32);

    // Manually compute SHA-256("hello" || key_value)
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"hello");
    hasher.update(&key_value);
    let expected = hasher.finalize();

    assert_eq!(
        &digest[..],
        expected.as_slice(),
        "C_DigestKey result should match manual hash"
    );

    C_Finalize(ptr::null_mut());
}

#[test]
fn test_12_digest_key_only() {
    let session = setup_session();
    let key = generate_aes_key(session);

    // Get key material
    let key_value = get_attribute(session, key, CKA_VALUE);

    // Digest only the key (no DigestUpdate before)
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_DigestInit(session, &mut mechanism);
    assert_eq!(rv, CKR_OK);

    let rv = C_DigestKey(session, key);
    assert_eq!(rv, CKR_OK);

    let mut digest = [0u8; 32];
    let mut digest_len: CK_ULONG = 32;
    let rv = C_DigestFinal(session, digest.as_mut_ptr(), &mut digest_len);
    assert_eq!(rv, CKR_OK);

    // Manual SHA-256(key_value)
    use sha2::{Digest, Sha256};
    let expected = Sha256::digest(&key_value);
    assert_eq!(
        &digest[..],
        expected.as_slice(),
        "C_DigestKey-only result should match SHA-256(key_value)"
    );

    C_Finalize(ptr::null_mut());
}

#[test]
fn test_13_digest_key_without_init() {
    let session = setup_session();
    let key = generate_aes_key(session);

    // No C_DigestInit — should fail
    let rv = C_DigestKey(session, key);
    assert_eq!(
        rv, CKR_OPERATION_NOT_INITIALIZED,
        "DigestKey without DigestInit should fail"
    );

    C_Finalize(ptr::null_mut());
}

#[test]
fn test_14_digest_key_sensitive_non_extractable() {
    let session = setup_session();
    let key = generate_sensitive_aes_key(session); // sensitive=true, extractable=false

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_DigestInit(session, &mut mechanism);
    assert_eq!(rv, CKR_OK);

    // Cannot digest a sensitive+non-extractable key (can't read value)
    let rv = C_DigestKey(session, key);
    assert_eq!(
        rv, CKR_KEY_INDIGESTIBLE,
        "Sensitive+non-extractable key should be indigestible"
    );

    C_Finalize(ptr::null_mut());
}

#[test]
fn test_15_digest_key_nonexistent() {
    let session = setup_session();

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_DigestInit(session, &mut mechanism);
    assert_eq!(rv, CKR_OK);

    let rv = C_DigestKey(session, 99999);
    assert_eq!(
        rv, CKR_KEY_HANDLE_INVALID,
        "Nonexistent key should return KEY_HANDLE_INVALID"
    );

    C_Finalize(ptr::null_mut());
}
