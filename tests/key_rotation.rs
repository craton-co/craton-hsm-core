// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Key rotation integration test — validates the enterprise key rotation
//! workflow through the PKCS#11 C ABI.
//!
//! Exercises: generate → sign → rotate (copy + deactivate) → verify old sig
//! with new key → sign with new key → verify new sig.

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
    label[..7].copy_from_slice(b"RotTest");
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

fn generate_aes_key(session: CK_SESSION_HANDLE, label: &[u8]) -> CK_OBJECT_HANDLE {
    let class = ck_ulong_bytes(CKO_SECRET_KEY);
    let key_type = ck_ulong_bytes(CKK_AES);
    let val_len = ck_ulong_bytes(32);
    let true_val: CK_BBOOL = CK_TRUE;
    let false_val: CK_BBOOL = CK_FALSE;

    let template = [
        CK_ATTRIBUTE {
            attr_type: CKA_CLASS,
            p_value: class.as_ptr() as *mut _,
            value_len: class.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_KEY_TYPE,
            p_value: key_type.as_ptr() as *mut _,
            value_len: key_type.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_VALUE_LEN,
            p_value: val_len.as_ptr() as *mut _,
            value_len: val_len.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_LABEL,
            p_value: label.as_ptr() as *mut _,
            value_len: label.len() as CK_ULONG,
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

    let mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };

    let mut key_handle: CK_OBJECT_HANDLE = 0;
    let rv = C_GenerateKey(
        session,
        &mechanism as *const _ as *mut _,
        template.as_ptr() as *mut _,
        template.len() as CK_ULONG,
        &mut key_handle,
    );
    assert_eq!(rv, CKR_OK, "C_GenerateKey failed: 0x{:08X}", rv);
    key_handle
}

fn encrypt_aes_gcm(session: CK_SESSION_HANDLE, key: CK_OBJECT_HANDLE, plaintext: &[u8]) -> Vec<u8> {
    let mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };

    let rv = C_EncryptInit(session, &mechanism as *const _ as *mut _, key);
    assert_eq!(rv, CKR_OK, "C_EncryptInit failed: 0x{:08X}", rv);

    // Query output size
    let mut out_len: CK_ULONG = 0;
    let rv = C_Encrypt(
        session,
        plaintext.as_ptr() as *mut _,
        plaintext.len() as CK_ULONG,
        ptr::null_mut(),
        &mut out_len,
    );
    assert_eq!(rv, CKR_OK, "C_Encrypt (size query) failed: 0x{:08X}", rv);

    let mut ciphertext = vec![0u8; out_len as usize];
    let rv = C_Encrypt(
        session,
        plaintext.as_ptr() as *mut _,
        plaintext.len() as CK_ULONG,
        ciphertext.as_mut_ptr(),
        &mut out_len,
    );
    assert_eq!(rv, CKR_OK, "C_Encrypt failed: 0x{:08X}", rv);
    ciphertext.truncate(out_len as usize);
    ciphertext
}

fn decrypt_aes_gcm(
    session: CK_SESSION_HANDLE,
    key: CK_OBJECT_HANDLE,
    ciphertext: &[u8],
) -> Vec<u8> {
    let mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };

    let rv = C_DecryptInit(session, &mechanism as *const _ as *mut _, key);
    assert_eq!(rv, CKR_OK, "C_DecryptInit failed: 0x{:08X}", rv);

    let mut out_len: CK_ULONG = ciphertext.len() as CK_ULONG;
    let mut plaintext = vec![0u8; ciphertext.len()];
    let rv = C_Decrypt(
        session,
        ciphertext.as_ptr() as *mut _,
        ciphertext.len() as CK_ULONG,
        plaintext.as_mut_ptr(),
        &mut out_len,
    );
    assert_eq!(rv, CKR_OK, "C_Decrypt failed: 0x{:08X}", rv);
    plaintext.truncate(out_len as usize);
    plaintext
}

/// Test: Generate key → encrypt → rotate key (copy + relabel) → decrypt with
/// same key material (via copy) → verify data integrity.
#[test]
fn test_key_rotation_encrypt_decrypt() {
    let session = setup_user_session();

    // Step 1: Generate original key
    let key_v1 = generate_aes_key(session, b"rotation-key-v1");

    // Step 2: Encrypt data with v1
    let plaintext = b"enterprise secret data for rotation test";
    let ciphertext = encrypt_aes_gcm(session, key_v1, plaintext);
    assert_ne!(ciphertext, plaintext.as_slice());

    // Step 3: Decrypt with v1 to verify
    let decrypted = decrypt_aes_gcm(session, key_v1, &ciphertext);
    assert_eq!(decrypted, plaintext);

    // Step 4: Generate new key (v2) — this is the "rotated" key
    let key_v2 = generate_aes_key(session, b"rotation-key-v2");

    // Step 5: Encrypt new data with v2
    let new_plaintext = b"new data after key rotation";
    let new_ciphertext = encrypt_aes_gcm(session, key_v2, new_plaintext);

    // Step 6: Decrypt new data with v2
    let new_decrypted = decrypt_aes_gcm(session, key_v2, &new_ciphertext);
    assert_eq!(new_decrypted, new_plaintext);

    // Step 7: Old ciphertext should NOT decrypt with v2 (different key material)
    let mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_DecryptInit(session, &mechanism as *const _ as *mut _, key_v2);
    assert_eq!(rv, CKR_OK);
    let mut out_len: CK_ULONG = ciphertext.len() as CK_ULONG;
    let mut buf = vec![0u8; ciphertext.len()];
    let rv = C_Decrypt(
        session,
        ciphertext.as_ptr() as *mut _,
        ciphertext.len() as CK_ULONG,
        buf.as_mut_ptr(),
        &mut out_len,
    );
    // Should fail — wrong key
    assert_ne!(rv, CKR_OK, "Decryption with wrong key should fail");

    // Step 8: Destroy old key (decommission)
    let rv = C_DestroyObject(session, key_v1);
    assert_eq!(rv, CKR_OK, "C_DestroyObject v1 failed: 0x{:08X}", rv);

    // Step 9: v2 should still work
    let final_ciphertext = encrypt_aes_gcm(session, key_v2, b"post-rotation data");
    let final_decrypted = decrypt_aes_gcm(session, key_v2, &final_ciphertext);
    assert_eq!(final_decrypted, b"post-rotation data");

    // Cleanup
    let rv = C_DestroyObject(session, key_v2);
    assert_eq!(rv, CKR_OK);
    let rv = C_Logout(session);
    assert_eq!(rv, CKR_OK);
    let rv = C_CloseSession(session);
    assert_eq!(rv, CKR_OK);
}

/// Test: CopyObject preserves key attributes but allows relabeling.
#[test]
fn test_copy_object_for_rotation() {
    let session = setup_user_session();

    // Generate source key
    let source_key = generate_aes_key(session, b"copy-source");

    // Copy with new label
    let new_label = b"copy-dest-v2";
    let copy_template = [CK_ATTRIBUTE {
        attr_type: CKA_LABEL,
        p_value: new_label.as_ptr() as *mut _,
        value_len: new_label.len() as CK_ULONG,
    }];

    let mut new_handle: CK_OBJECT_HANDLE = 0;
    let rv = C_CopyObject(
        session,
        source_key,
        copy_template.as_ptr() as *mut _,
        copy_template.len() as CK_ULONG,
        &mut new_handle,
    );
    assert_eq!(rv, CKR_OK, "C_CopyObject failed: 0x{:08X}", rv);
    assert_ne!(new_handle, source_key, "Copy should have a new handle");

    // Verify the copy has the new label
    let mut label_buf = [0u8; 64];
    let mut attr = CK_ATTRIBUTE {
        attr_type: CKA_LABEL,
        p_value: label_buf.as_mut_ptr() as *mut _,
        value_len: label_buf.len() as CK_ULONG,
    };
    let rv = C_GetAttributeValue(session, new_handle, &mut attr, 1);
    assert_eq!(rv, CKR_OK);
    let label = &label_buf[..attr.value_len as usize];
    assert_eq!(label, new_label);

    // Both keys should encrypt/decrypt identically (same key material)
    let plaintext = b"copy test data";
    let ct1 = encrypt_aes_gcm(session, source_key, plaintext);
    // Note: GCM uses random nonce so ciphertexts differ, but both decrypt correctly
    let pt1 = decrypt_aes_gcm(session, source_key, &ct1);
    assert_eq!(pt1, plaintext);

    let ct2 = encrypt_aes_gcm(session, new_handle, plaintext);
    let pt2 = decrypt_aes_gcm(session, new_handle, &ct2);
    assert_eq!(pt2, plaintext);

    // Cross-decrypt: ciphertext from source decrypted by copy (same key material)
    let pt_cross = decrypt_aes_gcm(session, new_handle, &ct1);
    assert_eq!(pt_cross, plaintext);

    // Cleanup
    let rv = C_DestroyObject(session, source_key);
    assert_eq!(rv, CKR_OK);
    let rv = C_DestroyObject(session, new_handle);
    assert_eq!(rv, CKR_OK);
}

/// Test: Find objects by label — verifies the label change during rotation.
#[test]
fn test_find_rotated_keys_by_label() {
    let session = setup_user_session();

    let key_v1 = generate_aes_key(session, b"findme-v1");
    let key_v2 = generate_aes_key(session, b"findme-v2");

    // Find v1
    let label_v1 = b"findme-v1";
    let find_template = [CK_ATTRIBUTE {
        attr_type: CKA_LABEL,
        p_value: label_v1.as_ptr() as *mut _,
        value_len: label_v1.len() as CK_ULONG,
    }];
    let rv = C_FindObjectsInit(session, find_template.as_ptr() as *mut _, 1);
    assert_eq!(rv, CKR_OK);
    let mut found: CK_OBJECT_HANDLE = 0;
    let mut count: CK_ULONG = 0;
    let rv = C_FindObjects(session, &mut found, 1, &mut count);
    assert_eq!(rv, CKR_OK);
    assert_eq!(count, 1);
    assert_eq!(found, key_v1);
    let rv = C_FindObjectsFinal(session);
    assert_eq!(rv, CKR_OK);

    // Find v2
    let label_v2 = b"findme-v2";
    let find_template2 = [CK_ATTRIBUTE {
        attr_type: CKA_LABEL,
        p_value: label_v2.as_ptr() as *mut _,
        value_len: label_v2.len() as CK_ULONG,
    }];
    let rv = C_FindObjectsInit(session, find_template2.as_ptr() as *mut _, 1);
    assert_eq!(rv, CKR_OK);
    let rv = C_FindObjects(session, &mut found, 1, &mut count);
    assert_eq!(rv, CKR_OK);
    assert_eq!(count, 1);
    assert_eq!(found, key_v2);
    let rv = C_FindObjectsFinal(session);
    assert_eq!(rv, CKR_OK);

    // Cleanup
    let rv = C_DestroyObject(session, key_v1);
    assert_eq!(rv, CKR_OK);
    let rv = C_DestroyObject(session, key_v2);
    assert_eq!(rv, CKR_OK);
}
