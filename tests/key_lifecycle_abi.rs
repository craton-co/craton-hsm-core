// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
// Key Lifecycle (SP 800-57) ABI tests — exercises lifecycle state transitions and
// operation restrictions through the PKCS#11 C ABI.

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
    label[..7].copy_from_slice(b"LCyTest");
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

/// Generate an AES-256 key with encrypt+decrypt+sign permissions.
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
    assert_eq!(rv, CKR_OK, "generate_aes_key failed: 0x{:08X}", rv);
    key
}

/// Generate AES-256 key with start_date set (YYYYMMDD ASCII format).
fn generate_aes_key_with_dates(
    session: CK_SESSION_HANDLE,
    start_date: Option<&[u8; 8]>,
    end_date: Option<&[u8; 8]>,
) -> CK_OBJECT_HANDLE {
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
    ];
    if let Some(sd) = start_date {
        template.push(CK_ATTRIBUTE {
            attr_type: CKA_START_DATE,
            p_value: sd.as_ptr() as CK_VOID_PTR,
            value_len: 8,
        });
    }
    if let Some(ed) = end_date {
        template.push(CK_ATTRIBUTE {
            attr_type: CKA_END_DATE,
            p_value: ed.as_ptr() as CK_VOID_PTR,
            value_len: 8,
        });
    }
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
        "generate_aes_key_with_dates failed: 0x{:08X}",
        rv
    );
    key
}

/// Generate RSA-2048 keypair.
fn generate_rsa_keypair(session: CK_SESSION_HANDLE) -> (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) {
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let modulus_bits_bytes = ck_ulong_bytes(2048);
    let public_exponent: [u8; 3] = [0x01, 0x00, 0x01];
    let ck_true: CK_BBOOL = CK_TRUE;

    let mut pub_template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_MODULUS_BITS,
            p_value: modulus_bits_bytes.as_ptr() as CK_VOID_PTR,
            value_len: modulus_bits_bytes.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_PUBLIC_EXPONENT,
            p_value: public_exponent.as_ptr() as CK_VOID_PTR,
            value_len: 3,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_ENCRYPT,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_VERIFY,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
    ];
    let mut priv_template = vec![
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
        CK_ATTRIBUTE {
            attr_type: CKA_SENSITIVE,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: 1,
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
    assert_eq!(rv, CKR_OK, "RSA keygen failed: 0x{:08X}", rv);
    (pub_key, priv_key)
}

// ============================================================================
// Basic lifecycle: Active key (default) - all operations work
// ============================================================================

#[test]
fn test_active_key_can_encrypt() {
    let session = setup_user_session();
    let key = generate_aes_key(session);
    let iv = [0u8; 12];
    let mut mech = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: iv.as_ptr() as CK_VOID_PTR,
        parameter_len: iv.len() as CK_ULONG,
    };
    let rv = C_EncryptInit(session, &mut mech, key);
    assert_eq!(rv, CKR_OK, "Active key should allow EncryptInit");
}

#[test]
fn test_active_key_can_decrypt() {
    let session = setup_user_session();
    let key = generate_aes_key(session);
    let iv = [0u8; 12];
    let mut mech = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: iv.as_ptr() as CK_VOID_PTR,
        parameter_len: iv.len() as CK_ULONG,
    };

    // Encrypt something first
    let rv = C_EncryptInit(session, &mut mech, key);
    assert_eq!(rv, CKR_OK);
    let plaintext = b"test data for lifecycle";
    let mut ct_len: CK_ULONG = 256;
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

    // Decrypt
    let rv = C_DecryptInit(session, &mut mech, key);
    assert_eq!(rv, CKR_OK, "Active key should allow DecryptInit");
    let mut pt_len: CK_ULONG = 256;
    let mut decrypted = vec![0u8; pt_len as usize];
    let rv = C_Decrypt(
        session,
        ciphertext.as_mut_ptr(),
        ct_len,
        decrypted.as_mut_ptr(),
        &mut pt_len,
    );
    assert_eq!(rv, CKR_OK);
    assert_eq!(&decrypted[..pt_len as usize], plaintext);
}

#[test]
fn test_active_rsa_key_can_sign() {
    let session = setup_user_session();
    let (_pub_key, priv_key) = generate_rsa_keypair(session);
    let mut mech = CK_MECHANISM {
        mechanism: CKM_SHA256_RSA_PKCS,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_SignInit(session, &mut mech, priv_key);
    assert_eq!(rv, CKR_OK, "Active RSA key should allow SignInit");
}

#[test]
fn test_active_rsa_key_can_verify() {
    let session = setup_user_session();
    let (pub_key, priv_key) = generate_rsa_keypair(session);
    let data = b"lifecycle test data";

    // Sign
    let mut mech = CK_MECHANISM {
        mechanism: CKM_SHA256_RSA_PKCS,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_SignInit(session, &mut mech, priv_key);
    assert_eq!(rv, CKR_OK);
    let mut sig_len: CK_ULONG = 512;
    let mut signature = vec![0u8; sig_len as usize];
    let rv = C_Sign(
        session,
        data.as_ptr() as *mut _,
        data.len() as CK_ULONG,
        signature.as_mut_ptr(),
        &mut sig_len,
    );
    assert_eq!(rv, CKR_OK);

    // Verify
    let rv = C_VerifyInit(session, &mut mech, pub_key);
    assert_eq!(rv, CKR_OK, "Active RSA key should allow VerifyInit");
    let rv = C_Verify(
        session,
        data.as_ptr() as *mut _,
        data.len() as CK_ULONG,
        signature.as_mut_ptr(),
        sig_len,
    );
    assert_eq!(rv, CKR_OK);
}

// ============================================================================
// Key with future start_date — pre-activation, operations blocked
// ============================================================================

#[test]
fn test_preactivation_key_encrypt_blocked() {
    let session = setup_user_session();
    // A date far in the future
    let future_date: [u8; 8] = *b"20990101";
    let key = generate_aes_key_with_dates(session, Some(&future_date), None);
    let iv = [0u8; 12];
    let mut mech = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: iv.as_ptr() as CK_VOID_PTR,
        parameter_len: iv.len() as CK_ULONG,
    };
    let rv = C_EncryptInit(session, &mut mech, key);
    // Pre-activation key should block encrypt
    assert_ne!(
        rv, CKR_OK,
        "Pre-activation key should block EncryptInit, got CKR_OK"
    );
}

#[test]
fn test_preactivation_key_decrypt_blocked() {
    let session = setup_user_session();
    let future_date: [u8; 8] = *b"20990101";
    let key = generate_aes_key_with_dates(session, Some(&future_date), None);
    let iv = [0u8; 12];
    let mut mech = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: iv.as_ptr() as CK_VOID_PTR,
        parameter_len: iv.len() as CK_ULONG,
    };
    let rv = C_DecryptInit(session, &mut mech, key);
    assert_ne!(rv, CKR_OK, "Pre-activation key should block DecryptInit");
}

// ============================================================================
// Key with past end_date — deactivated, encrypt blocked, decrypt allowed
// ============================================================================

#[test]
fn test_deactivated_key_encrypt_blocked() {
    let session = setup_user_session();
    // A date in the past
    let past_start: [u8; 8] = *b"20200101";
    let past_end: [u8; 8] = *b"20200601";
    let key = generate_aes_key_with_dates(session, Some(&past_start), Some(&past_end));
    let iv = [0u8; 12];
    let mut mech = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: iv.as_ptr() as CK_VOID_PTR,
        parameter_len: iv.len() as CK_ULONG,
    };
    let rv = C_EncryptInit(session, &mut mech, key);
    assert_ne!(rv, CKR_OK, "Deactivated key should block EncryptInit");
}

#[test]
fn test_deactivated_key_decrypt_allowed() {
    let session = setup_user_session();
    // First create an active key, encrypt with it
    let active_key = generate_aes_key(session);
    let iv = [0u8; 12];
    let mut mech = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: iv.as_ptr() as CK_VOID_PTR,
        parameter_len: iv.len() as CK_ULONG,
    };
    let rv = C_EncryptInit(session, &mut mech, active_key);
    assert_eq!(rv, CKR_OK);
    let plaintext = b"deactivated test";
    let mut ct_len: CK_ULONG = 256;
    let mut ciphertext = vec![0u8; ct_len as usize];
    let rv = C_Encrypt(
        session,
        plaintext.as_ptr() as *mut _,
        plaintext.len() as CK_ULONG,
        ciphertext.as_mut_ptr(),
        &mut ct_len,
    );
    assert_eq!(rv, CKR_OK);

    // Now try decrypt with a deactivated key — we need to use the same key for encrypt/decrypt.
    // Since we can't deactivate a key after creation via C ABI easily, let's verify that
    // deactivated key (past end_date) DecryptInit returns OK (decrypt is allowed for deactivated)
    let past_start: [u8; 8] = *b"20200101";
    let past_end: [u8; 8] = *b"20200601";
    let deact_key = generate_aes_key_with_dates(session, Some(&past_start), Some(&past_end));
    let rv = C_DecryptInit(session, &mut mech, deact_key);
    // Deactivated keys SHOULD allow decrypt (processing existing data)
    assert_eq!(
        rv, CKR_OK,
        "Deactivated key should allow DecryptInit for processing existing data"
    );
}

// ============================================================================
// Key with no dates — default active state
// ============================================================================

#[test]
fn test_no_dates_key_is_active() {
    let session = setup_user_session();
    let key = generate_aes_key_with_dates(session, None, None);
    let iv = [0u8; 12];
    let mut mech = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: iv.as_ptr() as CK_VOID_PTR,
        parameter_len: iv.len() as CK_ULONG,
    };
    let rv = C_EncryptInit(session, &mut mech, key);
    assert_eq!(
        rv, CKR_OK,
        "Key without dates should default to Active state"
    );
}

#[test]
fn test_key_with_past_start_current_end_is_active() {
    let session = setup_user_session();
    // start_date in the past, end_date far in the future → Active
    let past_start: [u8; 8] = *b"20200101";
    let future_end: [u8; 8] = *b"20990101";
    let key = generate_aes_key_with_dates(session, Some(&past_start), Some(&future_end));
    let iv = [0u8; 12];
    let mut mech = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: iv.as_ptr() as CK_VOID_PTR,
        parameter_len: iv.len() as CK_ULONG,
    };
    let rv = C_EncryptInit(session, &mut mech, key);
    assert_eq!(
        rv, CKR_OK,
        "Key with past start and future end should be Active"
    );
}

// ============================================================================
// Object attribute tests
// ============================================================================

#[test]
fn test_read_start_date_attribute() {
    let session = setup_user_session();
    let start_date: [u8; 8] = *b"20250101";
    let key = generate_aes_key_with_dates(session, Some(&start_date), None);

    // Read back CKA_START_DATE
    let mut buf = [0u8; 8];
    let mut template = [CK_ATTRIBUTE {
        attr_type: CKA_START_DATE,
        p_value: buf.as_mut_ptr() as CK_VOID_PTR,
        value_len: 8,
    }];
    let rv = C_GetAttributeValue(session, key, template.as_mut_ptr(), 1);
    assert_eq!(rv, CKR_OK, "Should read CKA_START_DATE");
    assert_eq!(&buf, b"20250101");
}

#[test]
fn test_read_end_date_attribute() {
    let session = setup_user_session();
    let end_date: [u8; 8] = *b"20301231";
    let key = generate_aes_key_with_dates(session, None, Some(&end_date));

    let mut buf = [0u8; 8];
    let mut template = [CK_ATTRIBUTE {
        attr_type: CKA_END_DATE,
        p_value: buf.as_mut_ptr() as CK_VOID_PTR,
        value_len: 8,
    }];
    let rv = C_GetAttributeValue(session, key, template.as_mut_ptr(), 1);
    assert_eq!(rv, CKR_OK, "Should read CKA_END_DATE");
    assert_eq!(&buf, b"20301231");
}

// ============================================================================
// Destroy and handle invalidation
// ============================================================================

#[test]
fn test_destroy_key_invalidates_handle() {
    let session = setup_user_session();
    let key = generate_aes_key(session);
    let rv = C_DestroyObject(session, key);
    assert_eq!(rv, CKR_OK, "DestroyObject should succeed");

    // Try to use destroyed key
    let iv = [0u8; 12];
    let mut mech = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: iv.as_ptr() as CK_VOID_PTR,
        parameter_len: iv.len() as CK_ULONG,
    };
    let rv = C_EncryptInit(session, &mut mech, key);
    assert_ne!(rv, CKR_OK, "Destroyed key handle should be invalid");
}

#[test]
fn test_destroy_key_get_attribute_fails() {
    let session = setup_user_session();
    let key = generate_aes_key(session);
    let rv = C_DestroyObject(session, key);
    assert_eq!(rv, CKR_OK);

    // Try to read attribute from destroyed key
    let mut val: CK_ULONG = 0;
    let mut template = [CK_ATTRIBUTE {
        attr_type: CKA_VALUE_LEN,
        p_value: &mut val as *mut _ as CK_VOID_PTR,
        value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
    }];
    let rv = C_GetAttributeValue(session, key, template.as_mut_ptr(), 1);
    assert_ne!(rv, CKR_OK, "GetAttributeValue on destroyed key should fail");
}

#[test]
fn test_destroy_key_find_objects_empty() {
    let session = setup_user_session();
    let label = b"lifecycle_destroy_test";
    let ck_true: CK_BBOOL = CK_TRUE;
    let value_len_bytes = ck_ulong_bytes(32);

    // Generate with label
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
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
            attr_type: CKA_LABEL,
            p_value: label.as_ptr() as CK_VOID_PTR,
            value_len: label.len() as CK_ULONG,
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

    // Destroy
    let rv = C_DestroyObject(session, key);
    assert_eq!(rv, CKR_OK);

    // Find by label — should be empty
    let mut find_template = [CK_ATTRIBUTE {
        attr_type: CKA_LABEL,
        p_value: label.as_ptr() as CK_VOID_PTR,
        value_len: label.len() as CK_ULONG,
    }];
    let rv = C_FindObjectsInit(session, find_template.as_mut_ptr(), 1);
    assert_eq!(rv, CKR_OK);
    let mut found: [CK_OBJECT_HANDLE; 10] = [0; 10];
    let mut count: CK_ULONG = 0;
    let rv = C_FindObjects(session, found.as_mut_ptr(), 10, &mut count);
    assert_eq!(rv, CKR_OK);
    assert_eq!(count, 0, "Destroyed key should not appear in FindObjects");
    C_FindObjectsFinal(session);
}

// ============================================================================
// Object size
// ============================================================================

#[test]
fn test_get_object_size_aes() {
    let session = setup_user_session();
    let key = generate_aes_key(session);
    let mut size: CK_ULONG = 0;
    let rv = C_GetObjectSize(session, key, &mut size);
    assert_eq!(rv, CKR_OK, "C_GetObjectSize should succeed");
    assert!(size > 0, "Object size should be > 0");
}

#[test]
fn test_get_object_size_rsa() {
    let session = setup_user_session();
    let (pub_key, priv_key) = generate_rsa_keypair(session);
    let mut pub_size: CK_ULONG = 0;
    let mut priv_size: CK_ULONG = 0;
    let rv = C_GetObjectSize(session, pub_key, &mut pub_size);
    assert_eq!(rv, CKR_OK);
    let rv = C_GetObjectSize(session, priv_key, &mut priv_size);
    assert_eq!(rv, CKR_OK);
    assert!(priv_size > 0, "RSA private key size should be > 0");
    assert!(pub_size > 0, "RSA public key size should be > 0");
}

#[test]
fn test_get_object_size_invalid_handle() {
    let session = setup_user_session();
    let mut size: CK_ULONG = 0;
    let rv = C_GetObjectSize(session, 0xFFFFFFFF, &mut size);
    assert_ne!(rv, CKR_OK, "GetObjectSize with invalid handle should fail");
}

// ============================================================================
// Key attributes after generation
// ============================================================================

#[test]
fn test_aes_key_value_len_attribute() {
    let session = setup_user_session();
    let key = generate_aes_key(session);
    let mut val_len: CK_ULONG = 0;
    let mut template = [CK_ATTRIBUTE {
        attr_type: CKA_VALUE_LEN,
        p_value: &mut val_len as *mut _ as CK_VOID_PTR,
        value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
    }];
    let rv = C_GetAttributeValue(session, key, template.as_mut_ptr(), 1);
    assert_eq!(rv, CKR_OK);
    assert_eq!(val_len, 32, "AES-256 key should have VALUE_LEN=32");
}

#[test]
fn test_aes_key_class_attribute() {
    let session = setup_user_session();
    let key = generate_aes_key(session);
    let mut class_val: CK_ULONG = 0;
    let mut template = [CK_ATTRIBUTE {
        attr_type: CKA_CLASS,
        p_value: &mut class_val as *mut _ as CK_VOID_PTR,
        value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
    }];
    let rv = C_GetAttributeValue(session, key, template.as_mut_ptr(), 1);
    assert_eq!(rv, CKR_OK);
    assert_eq!(
        class_val, CKO_SECRET_KEY,
        "AES key should be CKO_SECRET_KEY"
    );
}

#[test]
fn test_aes_key_type_attribute() {
    let session = setup_user_session();
    let key = generate_aes_key(session);
    let mut kt: CK_ULONG = 0;
    let mut template = [CK_ATTRIBUTE {
        attr_type: CKA_KEY_TYPE,
        p_value: &mut kt as *mut _ as CK_VOID_PTR,
        value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
    }];
    let rv = C_GetAttributeValue(session, key, template.as_mut_ptr(), 1);
    assert_eq!(rv, CKR_OK);
    assert_eq!(kt, CKK_AES, "AES key should have key_type CKK_AES");
}

#[test]
fn test_rsa_public_key_class() {
    let session = setup_user_session();
    let (pub_key, _priv_key) = generate_rsa_keypair(session);
    let mut class_val: CK_ULONG = 0;
    let mut template = [CK_ATTRIBUTE {
        attr_type: CKA_CLASS,
        p_value: &mut class_val as *mut _ as CK_VOID_PTR,
        value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
    }];
    let rv = C_GetAttributeValue(session, pub_key, template.as_mut_ptr(), 1);
    assert_eq!(rv, CKR_OK);
    assert_eq!(
        class_val, CKO_PUBLIC_KEY,
        "RSA public key should be CKO_PUBLIC_KEY"
    );
}

#[test]
fn test_rsa_private_key_class() {
    let session = setup_user_session();
    let (_pub_key, priv_key) = generate_rsa_keypair(session);
    let mut class_val: CK_ULONG = 0;
    let mut template = [CK_ATTRIBUTE {
        attr_type: CKA_CLASS,
        p_value: &mut class_val as *mut _ as CK_VOID_PTR,
        value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
    }];
    let rv = C_GetAttributeValue(session, priv_key, template.as_mut_ptr(), 1);
    assert_eq!(rv, CKR_OK);
    assert_eq!(
        class_val, CKO_PRIVATE_KEY,
        "RSA private key should be CKO_PRIVATE_KEY"
    );
}

// ============================================================================
// Multiple key generation produces unique handles
// ============================================================================

#[test]
fn test_multiple_keys_unique_handles() {
    let session = setup_user_session();
    let key1 = generate_aes_key(session);
    let key2 = generate_aes_key(session);
    let key3 = generate_aes_key(session);
    assert_ne!(key1, key2, "Keys should have unique handles");
    assert_ne!(key2, key3, "Keys should have unique handles");
    assert_ne!(key1, key3, "Keys should have unique handles");
}

#[test]
fn test_destroy_double_destroy_fails() {
    let session = setup_user_session();
    let key = generate_aes_key(session);
    let rv = C_DestroyObject(session, key);
    assert_eq!(rv, CKR_OK, "First destroy should succeed");
    let rv = C_DestroyObject(session, key);
    assert_ne!(rv, CKR_OK, "Double destroy should fail");
}
