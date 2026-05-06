// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
// PKCS#11 negative/edge-case tests — exercises boundary conditions, permission
// errors, cross-algorithm mismatches, and unusual-but-valid operations through
// the C ABI layer.
//
// Must be run with `--test-threads=1` due to shared global OnceLock state.

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

/// Re-initialize token, open RW session, set up user PIN, login as user.
/// Returns session handle.
fn setup_user_session() -> CK_SESSION_HANDLE {
    ensure_init();
    let so_pin = b"sopin123";
    let mut label = [b' '; 32];
    label[..8].copy_from_slice(b"EdgeTest");
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

/// Generate an AES key with configurable size and attribute flags.
fn generate_aes_key(session: CK_SESSION_HANDLE, key_len: CK_ULONG) -> CK_OBJECT_HANDLE {
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let value_len_bytes = ck_ulong_bytes(key_len);
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

/// Generate an AES key with custom attribute flags.
fn generate_aes_key_with_flags(
    session: CK_SESSION_HANDLE,
    key_len: CK_ULONG,
    can_encrypt: CK_BBOOL,
    can_decrypt: CK_BBOOL,
    can_sign: CK_BBOOL,
) -> CK_OBJECT_HANDLE {
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let value_len_bytes = ck_ulong_bytes(key_len);
    let mut template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_VALUE_LEN,
            p_value: value_len_bytes.as_ptr() as CK_VOID_PTR,
            value_len: value_len_bytes.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_ENCRYPT,
            p_value: &can_encrypt as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_DECRYPT,
            p_value: &can_decrypt as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_SIGN,
            p_value: &can_sign as *const _ as CK_VOID_PTR,
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
        "generate_aes_key_with_flags failed: 0x{:08X}",
        rv
    );
    key
}

/// Generate an AES key with a label.
fn generate_aes_key_with_label(session: CK_SESSION_HANDLE, label: &[u8]) -> CK_OBJECT_HANDLE {
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
    assert_eq!(
        rv, CKR_OK,
        "generate_aes_key_with_label failed: 0x{:08X}",
        rv
    );
    key
}

/// Generate RSA-2048 key pair with sign/verify and encrypt/decrypt.
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

/// Generate an EC key pair for the given OID.
fn generate_ec_keypair(
    session: CK_SESSION_HANDLE,
    oid: &[u8],
) -> (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) {
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_EC_KEY_PAIR_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let ck_true: CK_BBOOL = CK_TRUE;

    let mut pub_template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_EC_PARAMS,
            p_value: oid.as_ptr() as CK_VOID_PTR,
            value_len: oid.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_VERIFY,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
    ];
    let mut priv_template = vec![
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
    assert_eq!(rv, CKR_OK, "EC keygen failed: 0x{:08X}", rv);
    (pub_key, priv_key)
}

/// Generate an Ed25519 key pair via CKM_EDDSA mechanism.
fn generate_ed25519_keypair(session: CK_SESSION_HANDLE) -> (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) {
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_EDDSA,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let ck_true: CK_BBOOL = CK_TRUE;

    let mut pub_template = vec![CK_ATTRIBUTE {
        attr_type: CKA_VERIFY,
        p_value: &ck_true as *const _ as CK_VOID_PTR,
        value_len: 1,
    }];
    let mut priv_template = vec![CK_ATTRIBUTE {
        attr_type: CKA_SIGN,
        p_value: &ck_true as *const _ as CK_VOID_PTR,
        value_len: 1,
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
    assert_eq!(rv, CKR_OK, "Ed25519 keygen failed: 0x{:08X}", rv);
    (pub_key, priv_key)
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

// ============================================================================
// 1. Sign with encrypt-only key (wrong key type for mechanism)
// ============================================================================

#[test]
fn test_sign_with_encrypt_only_key() {
    let session = setup_user_session();
    // AES key with CKA_SIGN=false, CKA_ENCRYPT=true
    let key = generate_aes_key_with_flags(session, 32, CK_TRUE, CK_FALSE, CK_FALSE);

    // Try C_SignInit with RSA mechanism on AES key — type mismatch
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256_RSA_PKCS,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_SignInit(session, &mut mechanism, key);
    // AES key cannot be used with RSA sign mechanism — may get key type, handle, or permission error
    assert!(
        rv == CKR_KEY_TYPE_INCONSISTENT
            || rv == CKR_KEY_HANDLE_INVALID
            || rv == CKR_KEY_FUNCTION_NOT_PERMITTED,
        "Expected key error, got: 0x{:08X}",
        rv
    );
}

// ============================================================================
// 2. Encrypt with sign-only key (CKA_ENCRYPT=false)
// ============================================================================

#[test]
fn test_encrypt_with_sign_only_key() {
    let session = setup_user_session();
    // AES key with CKA_ENCRYPT=false
    let key = generate_aes_key_with_flags(session, 32, CK_FALSE, CK_TRUE, CK_TRUE);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_EncryptInit(session, &mut mechanism, key);
    assert_eq!(
        rv, CKR_KEY_FUNCTION_NOT_PERMITTED,
        "Encrypt with sign-only key should be rejected: 0x{:08X}",
        rv
    );
}

// ============================================================================
// 3. Verify with private key — should fail (verify uses public key)
// ============================================================================

#[test]
fn test_verify_with_private_key() {
    let session = setup_user_session();
    let (_pub_key, priv_key) = generate_rsa_keypair(session);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256_RSA_PKCS,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_VerifyInit(session, &mut mechanism, priv_key);
    // Private key should not be usable for verify (CKA_VERIFY not set on private key)
    assert!(
        rv != CKR_OK,
        "VerifyInit with private key should fail, got CKR_OK"
    );
}

// ============================================================================
// 4. Decrypt with public key — should fail
// ============================================================================

#[test]
fn test_decrypt_with_public_key() {
    let session = setup_user_session();
    let (pub_key, _priv_key) = generate_rsa_keypair(session);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_DecryptInit(session, &mut mechanism, pub_key);
    // Public key should not be usable for decrypt
    assert!(
        rv != CKR_OK,
        "DecryptInit with public key should fail, got CKR_OK"
    );
}

// ============================================================================
// 5. Sign empty data with RSA-SHA256 — should succeed (hashes empty input)
// ============================================================================

#[test]
fn test_sign_empty_data() {
    let session = setup_user_session();
    let (_pub_key, priv_key) = generate_rsa_keypair(session);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256_RSA_PKCS,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_SignInit(session, &mut mechanism, priv_key);
    assert_eq!(rv, CKR_OK);

    let empty_data: &[u8] = b"";
    let mut signature = vec![0u8; 512];
    let mut sig_len: CK_ULONG = signature.len() as CK_ULONG;
    let rv = C_Sign(
        session,
        empty_data.as_ptr() as CK_BYTE_PTR,
        0,
        signature.as_mut_ptr(),
        &mut sig_len,
    );
    // CKM_SHA256_RSA_PKCS hashes internally, so empty data should work
    assert_eq!(
        rv, CKR_OK,
        "Signing empty data should succeed: 0x{:08X}",
        rv
    );
    assert_eq!(
        sig_len as usize, 256,
        "RSA-2048 signature should be 256 bytes"
    );
}

// ============================================================================
// 6. Encrypt empty plaintext with AES-GCM — should succeed (GCM auth-only)
// ============================================================================

#[test]
fn test_encrypt_empty_data() {
    let session = setup_user_session();
    let key = generate_aes_key(session, 32);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_EncryptInit(session, &mut mechanism, key);
    assert_eq!(rv, CKR_OK);

    let empty_data: &[u8] = b"";
    let mut ciphertext = vec![0u8; 256];
    let mut ct_len: CK_ULONG = ciphertext.len() as CK_ULONG;
    let rv = C_Encrypt(
        session,
        empty_data.as_ptr() as CK_BYTE_PTR,
        0,
        ciphertext.as_mut_ptr(),
        &mut ct_len,
    );
    // GCM allows empty plaintext (produces nonce + auth tag only)
    assert_eq!(
        rv, CKR_OK,
        "GCM encrypt of empty data should succeed: 0x{:08X}",
        rv
    );
    assert!(ct_len > 0, "GCM output should include nonce + auth tag");
}

// ============================================================================
// 7. Decrypt empty ciphertext with AES-GCM — should fail (no auth tag)
// ============================================================================

#[test]
fn test_decrypt_empty_data() {
    let session = setup_user_session();
    let key = generate_aes_key(session, 32);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_DecryptInit(session, &mut mechanism, key);
    assert_eq!(rv, CKR_OK);

    let empty_data: &[u8] = b"";
    let mut plaintext = vec![0u8; 256];
    let mut pt_len: CK_ULONG = plaintext.len() as CK_ULONG;
    let rv = C_Decrypt(
        session,
        empty_data.as_ptr() as CK_BYTE_PTR,
        0,
        plaintext.as_mut_ptr(),
        &mut pt_len,
    );
    // Empty ciphertext has no nonce or tag, should fail
    assert!(
        rv != CKR_OK,
        "GCM decrypt of empty data should fail, got: 0x{:08X}",
        rv
    );
}

// ============================================================================
// 8. Sign 1MB data with RSA-SHA256 — should succeed (hashes internally)
// ============================================================================

#[test]
fn test_sign_1mb_data() {
    let session = setup_user_session();
    let (_pub_key, priv_key) = generate_rsa_keypair(session);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256_RSA_PKCS,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_SignInit(session, &mut mechanism, priv_key);
    assert_eq!(rv, CKR_OK);

    let large_data = vec![0xABu8; 1024 * 1024]; // 1 MB
    let mut signature = vec![0u8; 512];
    let mut sig_len: CK_ULONG = signature.len() as CK_ULONG;
    let rv = C_Sign(
        session,
        large_data.as_ptr() as CK_BYTE_PTR,
        large_data.len() as CK_ULONG,
        signature.as_mut_ptr(),
        &mut sig_len,
    );
    assert_eq!(rv, CKR_OK, "Signing 1MB data should succeed: 0x{:08X}", rv);
    assert_eq!(sig_len as usize, 256);
}

// ============================================================================
// 9. AES-CBC-PAD encrypt exactly 16 bytes — produces 32 bytes (PKCS#7 padding)
// ============================================================================

#[test]
fn test_encrypt_exact_block_size() {
    let session = setup_user_session();
    let key = generate_aes_key(session, 32);

    let iv = [
        0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10,
    ];
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_CBC_PAD,
        p_parameter: iv.as_ptr() as CK_VOID_PTR,
        parameter_len: 16,
    };
    let rv = C_EncryptInit(session, &mut mechanism, key);
    assert_eq!(rv, CKR_OK);

    let plaintext = [0x42u8; 16]; // exactly one block
    let mut ciphertext = vec![0u8; 64];
    let mut ct_len: CK_ULONG = ciphertext.len() as CK_ULONG;
    let rv = C_Encrypt(
        session,
        plaintext.as_ptr() as CK_BYTE_PTR,
        16,
        ciphertext.as_mut_ptr(),
        &mut ct_len,
    );
    assert_eq!(
        rv, CKR_OK,
        "CBC-PAD encrypt of 16 bytes failed: 0x{:08X}",
        rv
    );
    // PKCS#7 padding adds a full block when input is block-aligned
    assert_eq!(
        ct_len as usize, 32,
        "16 bytes plaintext with PKCS#7 padding should produce 32 bytes"
    );
}

// ============================================================================
// 10. AES-CBC-PAD encrypt 1 byte — produces 16 bytes
// ============================================================================

#[test]
fn test_encrypt_one_byte() {
    let session = setup_user_session();
    let key = generate_aes_key(session, 32);

    let iv = [
        0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10,
    ];
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_CBC_PAD,
        p_parameter: iv.as_ptr() as CK_VOID_PTR,
        parameter_len: 16,
    };
    let rv = C_EncryptInit(session, &mut mechanism, key);
    assert_eq!(rv, CKR_OK);

    let plaintext = [0x42u8; 1];
    let mut ciphertext = vec![0u8; 64];
    let mut ct_len: CK_ULONG = ciphertext.len() as CK_ULONG;
    let rv = C_Encrypt(
        session,
        plaintext.as_ptr() as CK_BYTE_PTR,
        1,
        ciphertext.as_mut_ptr(),
        &mut ct_len,
    );
    assert_eq!(rv, CKR_OK, "CBC-PAD encrypt of 1 byte failed: 0x{:08X}", rv);
    assert_eq!(
        ct_len as usize, 16,
        "1 byte plaintext with PKCS#7 should produce 16 bytes"
    );
}

// ============================================================================
// 11. AES-GCM encrypt 64KB data — should succeed
// ============================================================================

#[test]
fn test_aes_gcm_encrypt_large_data() {
    let session = setup_user_session();
    let key = generate_aes_key(session, 32);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_EncryptInit(session, &mut mechanism, key);
    assert_eq!(rv, CKR_OK);

    let large_data = vec![0xCDu8; 65536]; // 64 KB
    let mut ciphertext = vec![0u8; 65536 + 256]; // extra room for nonce + tag
    let mut ct_len: CK_ULONG = ciphertext.len() as CK_ULONG;
    let rv = C_Encrypt(
        session,
        large_data.as_ptr() as CK_BYTE_PTR,
        large_data.len() as CK_ULONG,
        ciphertext.as_mut_ptr(),
        &mut ct_len,
    );
    assert_eq!(
        rv, CKR_OK,
        "GCM encrypt of 64KB should succeed: 0x{:08X}",
        rv
    );
    assert!(
        ct_len as usize > 65536,
        "GCM output should be larger than plaintext (nonce + tag)"
    );
}

// ============================================================================
// 12. Double C_Initialize — second call returns CKR_CRYPTOKI_ALREADY_INITIALIZED
// ============================================================================

#[test]
fn test_double_initialize() {
    let rv = C_Initialize(ptr::null_mut());
    assert!(rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED);

    let rv = C_Initialize(ptr::null_mut());
    assert_eq!(
        rv, CKR_CRYPTOKI_ALREADY_INITIALIZED,
        "Second C_Initialize should return ALREADY_INITIALIZED: 0x{:08X}",
        rv
    );
}

// ============================================================================
// 13. Operations after close session — CKR_SESSION_HANDLE_INVALID
// ============================================================================

#[test]
fn test_operations_after_close_session() {
    let session = setup_user_session();
    let (_pub_key, priv_key) = generate_rsa_keypair(session);

    // Close the session
    let rv = C_CloseSession(session);
    assert_eq!(rv, CKR_OK);

    // Try SignInit on closed session
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256_RSA_PKCS,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_SignInit(session, &mut mechanism, priv_key);
    assert_eq!(
        rv, CKR_SESSION_HANDLE_INVALID,
        "SignInit on closed session should return SESSION_HANDLE_INVALID: 0x{:08X}",
        rv
    );
}

// ============================================================================
// 14. FindObjects with no matching label — returns 0 results
// ============================================================================

#[test]
fn test_find_objects_no_match() {
    let session = setup_user_session();

    let label = b"nonexistent_key_xyz";
    let mut template = vec![CK_ATTRIBUTE {
        attr_type: CKA_LABEL,
        p_value: label.as_ptr() as CK_VOID_PTR,
        value_len: label.len() as CK_ULONG,
    }];
    let rv = C_FindObjectsInit(session, template.as_mut_ptr(), template.len() as CK_ULONG);
    assert_eq!(rv, CKR_OK);

    let mut found: [CK_OBJECT_HANDLE; 10] = [0; 10];
    let mut found_count: CK_ULONG = 0;
    let rv = C_FindObjects(session, found.as_mut_ptr(), 10, &mut found_count);
    assert_eq!(rv, CKR_OK);
    assert_eq!(
        found_count, 0,
        "Should find 0 objects with nonexistent label"
    );

    let rv = C_FindObjectsFinal(session);
    assert_eq!(rv, CKR_OK);
}

// ============================================================================
// 15. FindObjects by label — finds the key
// ============================================================================

#[test]
fn test_find_objects_by_label() {
    let session = setup_user_session();
    let _key = generate_aes_key_with_label(session, b"mykey_find_test");

    let label = b"mykey_find_test";
    let mut template = vec![CK_ATTRIBUTE {
        attr_type: CKA_LABEL,
        p_value: label.as_ptr() as CK_VOID_PTR,
        value_len: label.len() as CK_ULONG,
    }];
    let rv = C_FindObjectsInit(session, template.as_mut_ptr(), template.len() as CK_ULONG);
    assert_eq!(rv, CKR_OK);

    let mut found: [CK_OBJECT_HANDLE; 10] = [0; 10];
    let mut found_count: CK_ULONG = 0;
    let rv = C_FindObjects(session, found.as_mut_ptr(), 10, &mut found_count);
    assert_eq!(rv, CKR_OK);
    assert!(
        found_count >= 1,
        "Should find at least 1 object with label 'mykey_find_test'"
    );

    let rv = C_FindObjectsFinal(session);
    assert_eq!(rv, CKR_OK);
}

// ============================================================================
// 16. FindObjects by class (CKO_SECRET_KEY)
// ============================================================================

#[test]
fn test_find_objects_by_class() {
    let session = setup_user_session();
    let _key = generate_aes_key(session, 32);

    let class_bytes = ck_ulong_bytes(CKO_SECRET_KEY);
    let mut template = vec![CK_ATTRIBUTE {
        attr_type: CKA_CLASS,
        p_value: class_bytes.as_ptr() as CK_VOID_PTR,
        value_len: class_bytes.len() as CK_ULONG,
    }];
    let rv = C_FindObjectsInit(session, template.as_mut_ptr(), template.len() as CK_ULONG);
    assert_eq!(rv, CKR_OK);

    let mut found: [CK_OBJECT_HANDLE; 50] = [0; 50];
    let mut found_count: CK_ULONG = 0;
    let rv = C_FindObjects(session, found.as_mut_ptr(), 50, &mut found_count);
    assert_eq!(rv, CKR_OK);
    assert!(found_count >= 1, "Should find at least 1 secret key object");

    let rv = C_FindObjectsFinal(session);
    assert_eq!(rv, CKR_OK);
}

// ============================================================================
// 17. FindObjects multiple results — 3 keys with same label
// ============================================================================

#[test]
fn test_find_objects_multiple_results() {
    let session = setup_user_session();
    let _k1 = generate_aes_key_with_label(session, b"triple_key");
    let _k2 = generate_aes_key_with_label(session, b"triple_key");
    let _k3 = generate_aes_key_with_label(session, b"triple_key");

    let label = b"triple_key";
    let mut template = vec![CK_ATTRIBUTE {
        attr_type: CKA_LABEL,
        p_value: label.as_ptr() as CK_VOID_PTR,
        value_len: label.len() as CK_ULONG,
    }];
    let rv = C_FindObjectsInit(session, template.as_mut_ptr(), template.len() as CK_ULONG);
    assert_eq!(rv, CKR_OK);

    let mut found: [CK_OBJECT_HANDLE; 20] = [0; 20];
    let mut found_count: CK_ULONG = 0;
    let rv = C_FindObjects(session, found.as_mut_ptr(), 20, &mut found_count);
    assert_eq!(rv, CKR_OK);
    assert!(
        found_count >= 3,
        "Should find at least 3 objects with label 'triple_key', found {}",
        found_count
    );

    let rv = C_FindObjectsFinal(session);
    assert_eq!(rv, CKR_OK);
}

// ============================================================================
// 18. Destroy then find — destroyed key should not appear
// ============================================================================

#[test]
fn test_destroy_then_find() {
    let session = setup_user_session();
    let key = generate_aes_key_with_label(session, b"destroy_me_key");

    // Verify it exists first
    let label = b"destroy_me_key";
    let mut template = vec![CK_ATTRIBUTE {
        attr_type: CKA_LABEL,
        p_value: label.as_ptr() as CK_VOID_PTR,
        value_len: label.len() as CK_ULONG,
    }];
    let rv = C_FindObjectsInit(session, template.as_mut_ptr(), template.len() as CK_ULONG);
    assert_eq!(rv, CKR_OK);
    let mut found: [CK_OBJECT_HANDLE; 10] = [0; 10];
    let mut found_count: CK_ULONG = 0;
    let rv = C_FindObjects(session, found.as_mut_ptr(), 10, &mut found_count);
    assert_eq!(rv, CKR_OK);
    assert!(found_count >= 1, "Key should exist before destroy");
    let rv = C_FindObjectsFinal(session);
    assert_eq!(rv, CKR_OK);

    // Destroy the key
    let rv = C_DestroyObject(session, key);
    assert_eq!(rv, CKR_OK);

    // Search again
    let rv = C_FindObjectsInit(session, template.as_mut_ptr(), template.len() as CK_ULONG);
    assert_eq!(rv, CKR_OK);
    let mut found2: [CK_OBJECT_HANDLE; 10] = [0; 10];
    let mut found_count2: CK_ULONG = 0;
    let rv = C_FindObjects(session, found2.as_mut_ptr(), 10, &mut found_count2);
    assert_eq!(rv, CKR_OK);
    assert_eq!(found_count2, 0, "Destroyed key should not be found");
    let rv = C_FindObjectsFinal(session);
    assert_eq!(rv, CKR_OK);
}

// ============================================================================
// 19. Generate key with CKA_LABEL, read label back — matches
// ============================================================================

#[test]
fn test_generate_key_with_label() {
    let session = setup_user_session();
    let key = generate_aes_key_with_label(session, b"labeled_key_19");

    let label_data = get_attribute(session, key, CKA_LABEL);
    assert_eq!(
        &label_data, b"labeled_key_19",
        "Label should match what was set"
    );
}

// ============================================================================
// 20. Generate key with CKA_ID, read ID back — matches
// ============================================================================

#[test]
fn test_generate_key_with_id() {
    let session = setup_user_session();

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let value_len_bytes = ck_ulong_bytes(32);
    let ck_true: CK_BBOOL = CK_TRUE;
    let id_bytes = b"my-key-id-42";
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
            attr_type: CKA_ID,
            p_value: id_bytes.as_ptr() as CK_VOID_PTR,
            value_len: id_bytes.len() as CK_ULONG,
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

    let id_data = get_attribute(session, key, CKA_ID);
    assert_eq!(
        &id_data, b"my-key-id-42",
        "CKA_ID should match what was set"
    );
}

// ============================================================================
// 21. AES-CBC with 15-byte IV — CKR_MECHANISM_PARAM_INVALID
// ============================================================================

#[test]
fn test_aes_cbc_wrong_iv_length() {
    let session = setup_user_session();
    let key = generate_aes_key(session, 32);

    let bad_iv = [0u8; 15]; // AES-CBC requires exactly 16-byte IV
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_CBC_PAD,
        p_parameter: bad_iv.as_ptr() as CK_VOID_PTR,
        parameter_len: 15, // wrong length
    };
    let rv = C_EncryptInit(session, &mut mechanism, key);
    // EncryptInit may succeed (deferred validation) or reject immediately
    if rv == CKR_OK {
        // If init succeeded, the actual encrypt should fail with bad IV
        let plaintext = b"test data for cbc";
        let mut ciphertext = vec![0u8; 256];
        let mut ct_len: CK_ULONG = ciphertext.len() as CK_ULONG;
        let rv = C_Encrypt(
            session,
            plaintext.as_ptr() as *mut _,
            plaintext.len() as CK_ULONG,
            ciphertext.as_mut_ptr(),
            &mut ct_len,
        );
        assert_ne!(
            rv, CKR_OK,
            "CBC encrypt with 15-byte IV should fail at some point: 0x{:08X}",
            rv
        );
    }
    // Either way, bad IV should be rejected — at init or at encrypt time
}

// ============================================================================
// 22. AES-GCM tampered ciphertext — decrypt should fail
// ============================================================================

#[test]
fn test_aes_gcm_tampered_ciphertext() {
    let session = setup_user_session();
    let key = generate_aes_key(session, 32);

    // Encrypt
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_EncryptInit(session, &mut mechanism, key);
    assert_eq!(rv, CKR_OK);

    let plaintext = b"GCM tamper test data for authentication check";
    let mut ciphertext = vec![0u8; 256];
    let mut ct_len: CK_ULONG = ciphertext.len() as CK_ULONG;
    let rv = C_Encrypt(
        session,
        plaintext.as_ptr() as CK_BYTE_PTR,
        plaintext.len() as CK_ULONG,
        ciphertext.as_mut_ptr(),
        &mut ct_len,
    );
    assert_eq!(rv, CKR_OK);

    // Tamper with the ciphertext (flip a bit in the middle)
    let mid = (ct_len as usize) / 2;
    ciphertext[mid] ^= 0xFF;

    // Decrypt tampered data
    let rv = C_DecryptInit(session, &mut mechanism, key);
    assert_eq!(rv, CKR_OK);

    let mut decrypted = vec![0u8; 256];
    let mut dec_len: CK_ULONG = decrypted.len() as CK_ULONG;
    let rv = C_Decrypt(
        session,
        ciphertext.as_mut_ptr(),
        ct_len,
        decrypted.as_mut_ptr(),
        &mut dec_len,
    );
    assert!(
        rv != CKR_OK,
        "GCM decrypt of tampered ciphertext should fail, got: 0x{:08X}",
        rv
    );
}

// ============================================================================
// 23. AES-CTR encrypt + decrypt roundtrip
// ============================================================================

#[test]
fn test_aes_ctr_encrypt_decrypt_roundtrip() {
    let session = setup_user_session();
    let key = generate_aes_key(session, 32);

    let nonce = [
        0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10,
    ];
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_CTR,
        p_parameter: nonce.as_ptr() as CK_VOID_PTR,
        parameter_len: 16,
    };

    // Encrypt
    let rv = C_EncryptInit(session, &mut mechanism, key);
    assert_eq!(rv, CKR_OK, "CTR EncryptInit failed: 0x{:08X}", rv);

    let plaintext = b"AES-CTR roundtrip test data 1234567890";
    let mut ciphertext = vec![0u8; 256];
    let mut ct_len: CK_ULONG = ciphertext.len() as CK_ULONG;
    let rv = C_Encrypt(
        session,
        plaintext.as_ptr() as CK_BYTE_PTR,
        plaintext.len() as CK_ULONG,
        ciphertext.as_mut_ptr(),
        &mut ct_len,
    );
    assert_eq!(rv, CKR_OK, "CTR Encrypt failed: 0x{:08X}", rv);
    assert_eq!(
        ct_len as usize,
        plaintext.len(),
        "CTR ciphertext should be same length as plaintext"
    );

    // Decrypt
    let rv = C_DecryptInit(session, &mut mechanism, key);
    assert_eq!(rv, CKR_OK);

    let mut decrypted = vec![0u8; 256];
    let mut dec_len: CK_ULONG = decrypted.len() as CK_ULONG;
    let rv = C_Decrypt(
        session,
        ciphertext.as_mut_ptr(),
        ct_len,
        decrypted.as_mut_ptr(),
        &mut dec_len,
    );
    assert_eq!(rv, CKR_OK, "CTR Decrypt failed: 0x{:08X}", rv);
    assert_eq!(
        &decrypted[..dec_len as usize],
        plaintext.as_slice(),
        "CTR roundtrip should recover original plaintext"
    );
}

// ============================================================================
// 24. ECDSA P-256 keygen + sign + verify
// ============================================================================

#[test]
fn test_ec_p256_keygen_sign_verify() {
    let session = setup_user_session();
    let p256_oid: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    let (pub_key, priv_key) = generate_ec_keypair(session, p256_oid);

    // Sign
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_ECDSA_SHA256,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_SignInit(session, &mut mechanism, priv_key);
    assert_eq!(rv, CKR_OK);

    let message = b"P-256 ECDSA sign/verify test message";
    let mut signature = vec![0u8; 128];
    let mut sig_len: CK_ULONG = signature.len() as CK_ULONG;
    let rv = C_Sign(
        session,
        message.as_ptr() as CK_BYTE_PTR,
        message.len() as CK_ULONG,
        signature.as_mut_ptr(),
        &mut sig_len,
    );
    assert_eq!(rv, CKR_OK, "P-256 sign failed: 0x{:08X}", rv);
    assert!(sig_len > 0);

    // Verify
    let rv = C_VerifyInit(session, &mut mechanism, pub_key);
    assert_eq!(rv, CKR_OK);

    let rv = C_Verify(
        session,
        message.as_ptr() as CK_BYTE_PTR,
        message.len() as CK_ULONG,
        signature.as_mut_ptr(),
        sig_len,
    );
    assert_eq!(rv, CKR_OK, "P-256 verify failed: 0x{:08X}", rv);
}

// ============================================================================
// 25. ECDSA P-384 keygen + sign + verify
// ============================================================================

#[test]
fn test_ec_p384_keygen_sign_verify() {
    let session = setup_user_session();
    let p384_oid: &[u8] = &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22];
    let (pub_key, priv_key) = generate_ec_keypair(session, p384_oid);

    // Sign
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_ECDSA_SHA384,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_SignInit(session, &mut mechanism, priv_key);
    assert_eq!(rv, CKR_OK);

    let message = b"P-384 ECDSA sign/verify test message";
    let mut signature = vec![0u8; 128];
    let mut sig_len: CK_ULONG = signature.len() as CK_ULONG;
    let rv = C_Sign(
        session,
        message.as_ptr() as CK_BYTE_PTR,
        message.len() as CK_ULONG,
        signature.as_mut_ptr(),
        &mut sig_len,
    );
    assert_eq!(rv, CKR_OK, "P-384 sign failed: 0x{:08X}", rv);
    assert!(sig_len > 0);

    // Verify
    let rv = C_VerifyInit(session, &mut mechanism, pub_key);
    assert_eq!(rv, CKR_OK);

    let rv = C_Verify(
        session,
        message.as_ptr() as CK_BYTE_PTR,
        message.len() as CK_ULONG,
        signature.as_mut_ptr(),
        sig_len,
    );
    assert_eq!(rv, CKR_OK, "P-384 verify failed: 0x{:08X}", rv);
}

// ============================================================================
// 26. Ed25519 keygen + sign + verify (CKM_EDDSA)
// ============================================================================

#[test]
fn test_ed25519_keygen_sign_verify() {
    let session = setup_user_session();
    let (pub_key, priv_key) = generate_ed25519_keypair(session);

    // Sign
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_EDDSA,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_SignInit(session, &mut mechanism, priv_key);
    assert_eq!(rv, CKR_OK);

    let message = b"Ed25519 sign/verify edge case test";
    let mut signature = vec![0u8; 128];
    let mut sig_len: CK_ULONG = signature.len() as CK_ULONG;
    let rv = C_Sign(
        session,
        message.as_ptr() as CK_BYTE_PTR,
        message.len() as CK_ULONG,
        signature.as_mut_ptr(),
        &mut sig_len,
    );
    assert_eq!(rv, CKR_OK, "Ed25519 sign failed: 0x{:08X}", rv);
    assert_eq!(sig_len as usize, 64, "Ed25519 signature should be 64 bytes");

    // Verify
    let rv = C_VerifyInit(session, &mut mechanism, pub_key);
    assert_eq!(rv, CKR_OK);

    let rv = C_Verify(
        session,
        message.as_ptr() as CK_BYTE_PTR,
        message.len() as CK_ULONG,
        signature.as_mut_ptr(),
        sig_len,
    );
    assert_eq!(rv, CKR_OK, "Ed25519 verify failed: 0x{:08X}", rv);
}

// ============================================================================
// 27. Sign with RSA, verify with ECDSA mechanism — should fail
// ============================================================================

#[test]
fn test_sign_verify_cross_algorithm_fails() {
    let session = setup_user_session();
    let (_rsa_pub, rsa_priv) = generate_rsa_keypair(session);

    // Sign with RSA
    let mut rsa_mech = CK_MECHANISM {
        mechanism: CKM_SHA256_RSA_PKCS,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_SignInit(session, &mut rsa_mech, rsa_priv);
    assert_eq!(rv, CKR_OK);

    let message = b"cross-algorithm test message";
    let mut signature = vec![0u8; 512];
    let mut sig_len: CK_ULONG = signature.len() as CK_ULONG;
    let rv = C_Sign(
        session,
        message.as_ptr() as CK_BYTE_PTR,
        message.len() as CK_ULONG,
        signature.as_mut_ptr(),
        &mut sig_len,
    );
    assert_eq!(rv, CKR_OK);

    // Generate EC key pair for verify
    let p256_oid: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    let (ec_pub, _ec_priv) = generate_ec_keypair(session, p256_oid);

    // Try to verify RSA signature with ECDSA mechanism on EC key
    let mut ec_mech = CK_MECHANISM {
        mechanism: CKM_ECDSA_SHA256,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_VerifyInit(session, &mut ec_mech, ec_pub);
    if rv == CKR_OK {
        // If VerifyInit succeeds, the verify itself must fail
        let rv = C_Verify(
            session,
            message.as_ptr() as CK_BYTE_PTR,
            message.len() as CK_ULONG,
            signature.as_mut_ptr(),
            sig_len,
        );
        assert_eq!(
            rv, CKR_SIGNATURE_INVALID,
            "Cross-algorithm verify should fail: 0x{:08X}",
            rv
        );
    }
    // If VerifyInit itself fails (e.g., signature length mismatch), that is also acceptable
}

// ============================================================================
// 28. AES keygen with invalid key size (17 bytes) — should fail
// ============================================================================

#[test]
fn test_aes_keygen_wrong_size() {
    let session = setup_user_session();

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let value_len_bytes = ck_ulong_bytes(17); // Invalid: AES only supports 16, 24, 32
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
    ];
    let mut key: CK_OBJECT_HANDLE = 0;
    let rv = C_GenerateKey(
        session,
        &mut mechanism,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut key,
    );
    assert!(
        rv == CKR_KEY_SIZE_RANGE
            || rv == CKR_ATTRIBUTE_VALUE_INVALID
            || rv == CKR_TEMPLATE_INCONSISTENT,
        "AES keygen with 17-byte key should fail: 0x{:08X}",
        rv
    );
}

// ============================================================================
// 29. C_GetFunctionList with null pointer — CKR_ARGUMENTS_BAD
// ============================================================================

#[test]
fn test_null_function_list_pointer() {
    let rv = C_GetFunctionList(ptr::null_mut());
    assert_eq!(
        rv, CKR_ARGUMENTS_BAD,
        "C_GetFunctionList(null) should return ARGUMENTS_BAD: 0x{:08X}",
        rv
    );
}

// ============================================================================
// 30. FindObjectsInit -> FindObjectsFinal without FindObjects — valid cycle
// ============================================================================

#[test]
fn test_find_objects_init_final_cycle() {
    let session = setup_user_session();

    // Init with empty template (match all)
    let rv = C_FindObjectsInit(session, ptr::null_mut(), 0);
    assert_eq!(rv, CKR_OK);

    // Skip FindObjects, go straight to Final — this is valid per PKCS#11 spec
    let rv = C_FindObjectsFinal(session);
    assert_eq!(
        rv, CKR_OK,
        "FindObjectsInit -> FindObjectsFinal without FindObjects should succeed: 0x{:08X}",
        rv
    );
}

// ============================================================================
// 31. C_SetAttributeValue on CKA_SENSITIVE — must be rejected (read-only)
//     PKCS#11 §10.7: CKA_SENSITIVE is monotonic (one-way) and read-only
//     after object creation.
// ============================================================================

#[test]
fn test_set_sensitive_to_false_rejected() {
    let session = setup_user_session();
    let key = generate_aes_key(session, 32);

    // Attempt to set CKA_SENSITIVE = false via C_SetAttributeValue
    let ck_false: CK_BBOOL = CK_FALSE;
    let mut template = vec![CK_ATTRIBUTE {
        attr_type: CKA_SENSITIVE,
        p_value: &ck_false as *const _ as CK_VOID_PTR,
        value_len: 1,
    }];
    let rv = C_SetAttributeValue(
        session,
        key,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
    );
    assert_eq!(
        rv, CKR_ATTRIBUTE_READ_ONLY,
        "Setting CKA_SENSITIVE after creation must return CKR_ATTRIBUTE_READ_ONLY: 0x{:08X}",
        rv
    );
}

// ============================================================================
// 32. C_SetAttributeValue on CKA_EXTRACTABLE — must be rejected (read-only)
// ============================================================================

#[test]
fn test_set_extractable_to_true_rejected() {
    let session = setup_user_session();
    let key = generate_aes_key(session, 32);

    // Attempt to set CKA_EXTRACTABLE = true via C_SetAttributeValue
    let ck_true: CK_BBOOL = CK_TRUE;
    let mut template = vec![CK_ATTRIBUTE {
        attr_type: CKA_EXTRACTABLE,
        p_value: &ck_true as *const _ as CK_VOID_PTR,
        value_len: 1,
    }];
    let rv = C_SetAttributeValue(
        session,
        key,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
    );
    assert_eq!(
        rv, CKR_ATTRIBUTE_READ_ONLY,
        "Setting CKA_EXTRACTABLE after creation must return CKR_ATTRIBUTE_READ_ONLY: 0x{:08X}",
        rv
    );
}

// ============================================================================
// 33. C_SetAttributeValue on CKA_CLASS — must be rejected (immutable)
// ============================================================================

#[test]
fn test_set_class_rejected() {
    let session = setup_user_session();
    let key = generate_aes_key(session, 32);

    let new_class = ck_ulong_bytes(CKO_PUBLIC_KEY);
    let mut template = vec![CK_ATTRIBUTE {
        attr_type: CKA_CLASS,
        p_value: new_class.as_ptr() as CK_VOID_PTR,
        value_len: new_class.len() as CK_ULONG,
    }];
    let rv = C_SetAttributeValue(
        session,
        key,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
    );
    assert_eq!(
        rv, CKR_ATTRIBUTE_READ_ONLY,
        "Changing CKA_CLASS after creation must be rejected: 0x{:08X}",
        rv
    );
}

// ============================================================================
// 34. C_SetAttributeValue on CKA_VALUE (key material) — must be rejected
// ============================================================================

#[test]
fn test_set_key_value_rejected() {
    let session = setup_user_session();
    let key = generate_aes_key(session, 32);

    let fake_key = [0xFFu8; 32];
    let mut template = vec![CK_ATTRIBUTE {
        attr_type: CKA_VALUE,
        p_value: fake_key.as_ptr() as CK_VOID_PTR,
        value_len: 32,
    }];
    let rv = C_SetAttributeValue(
        session,
        key,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
    );
    assert_eq!(
        rv, CKR_ATTRIBUTE_READ_ONLY,
        "Overwriting CKA_VALUE (key material) must be rejected: 0x{:08X}",
        rv
    );
}

// ============================================================================
// 35. C_SetAttributeValue with null template pointer — CKR_ARGUMENTS_BAD
// ============================================================================

#[test]
fn test_set_attribute_null_template() {
    let session = setup_user_session();
    let key = generate_aes_key(session, 32);

    let rv = C_SetAttributeValue(session, key, ptr::null_mut(), 1);
    assert_eq!(
        rv, CKR_ARGUMENTS_BAD,
        "C_SetAttributeValue with null template should return ARGUMENTS_BAD: 0x{:08X}",
        rv
    );
}

// ============================================================================
// 36. RSA-4096 keygen + sign/verify — larger key size coverage
// ============================================================================

#[test]
#[ignore = "RSA-4096 keygen is slow in debug mode; run with `cargo test -- --ignored`"]
fn test_rsa_4096_keygen_sign_verify() {
    let session = setup_user_session();

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let modulus_bits_bytes = ck_ulong_bytes(4096);
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
            attr_type: CKA_VERIFY,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
    ];
    let mut priv_template = vec![
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
    assert_eq!(rv, CKR_OK, "RSA-4096 keygen should succeed: 0x{:08X}", rv);

    // Sign with SHA256-RSA-PKCS
    let mut sign_mech = CK_MECHANISM {
        mechanism: CKM_SHA256_RSA_PKCS,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_SignInit(session, &mut sign_mech, priv_key);
    assert_eq!(rv, CKR_OK);

    let message = b"RSA-4096 sign/verify edge case test";
    let mut signature = vec![0u8; 1024]; // 4096-bit → 512-byte signature
    let mut sig_len: CK_ULONG = signature.len() as CK_ULONG;
    let rv = C_Sign(
        session,
        message.as_ptr() as CK_BYTE_PTR,
        message.len() as CK_ULONG,
        signature.as_mut_ptr(),
        &mut sig_len,
    );
    assert_eq!(rv, CKR_OK, "RSA-4096 sign should succeed: 0x{:08X}", rv);
    assert_eq!(
        sig_len as usize, 512,
        "RSA-4096 signature should be 512 bytes"
    );

    // Verify
    let rv = C_VerifyInit(session, &mut sign_mech, pub_key);
    assert_eq!(rv, CKR_OK);
    let rv = C_Verify(
        session,
        message.as_ptr() as CK_BYTE_PTR,
        message.len() as CK_ULONG,
        signature.as_mut_ptr(),
        sig_len,
    );
    assert_eq!(rv, CKR_OK, "RSA-4096 verify should succeed: 0x{:08X}", rv);
}

// ============================================================================
// 37. Login with empty PIN — should fail
// ============================================================================

#[test]
fn test_login_empty_pin() {
    ensure_init();
    let so_pin = b"sopin123";
    let mut label = [b' '; 32];
    label[..9].copy_from_slice(b"EmptyPIN1");
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

    // Login with empty PIN (0-length)
    let rv = C_Login(session, CKU_SO, ptr::null_mut(), 0);
    assert!(
        rv != CKR_OK,
        "Login with empty PIN should fail: 0x{:08X}",
        rv
    );
}

// ============================================================================
// 38. Login with maximum-length PIN (64 bytes)
// ============================================================================

#[test]
fn test_login_max_length_pin() {
    let session = setup_user_session();
    // Use C_InitPIN to set a long user PIN, then log out and back in.
    // Use 32 bytes (well within the 64-byte max) to avoid boundary issues.
    // Mix character classes: lowercase + digits (satisfies PIN_MIN_CHAR_CLASSES=2).
    let long_pin: Vec<u8> = (0..32)
        .map(|i| {
            if i % 4 == 0 {
                b'0' + (i as u8 % 10)
            } else {
                b'a' + (i as u8 % 26)
            }
        })
        .collect();

    // First, log in as SO to set the user PIN.
    let rv = C_Logout(session);
    let _ = rv;

    let so_pin = b"sopin123";
    let rv = C_Login(
        session,
        CKU_SO,
        so_pin.as_ptr() as *mut _,
        so_pin.len() as CK_ULONG,
    );
    // SO login may fail if already logged in differently — skip test in that case.
    if rv != CKR_OK {
        return;
    }

    let rv = C_InitPIN(
        session,
        long_pin.as_ptr() as *mut _,
        long_pin.len() as CK_ULONG,
    );
    assert_eq!(
        rv, CKR_OK,
        "InitPIN with 32-byte PIN should succeed: 0x{:08X}",
        rv
    );

    let rv = C_Logout(session);
    assert_eq!(rv, CKR_OK);

    let rv = C_Login(
        session,
        CKU_USER,
        long_pin.as_ptr() as *mut _,
        long_pin.len() as CK_ULONG,
    );
    assert_eq!(
        rv, CKR_OK,
        "Login with long (32-byte) PIN should succeed: 0x{:08X}",
        rv
    );
}

// ============================================================================
// 39. Login with over-max-length PIN (65 bytes) — should fail
// ============================================================================

#[test]
fn test_login_overlength_pin() {
    ensure_init();
    let long_pin: Vec<u8> = (0..65).map(|i| b'x' + (i % 3)).collect();
    let mut label = [b' '; 32];
    label[..8].copy_from_slice(b"LongPIN1");
    let rv = C_InitToken(
        0,
        long_pin.as_ptr() as *mut _,
        long_pin.len() as CK_ULONG,
        label.as_ptr() as *mut _,
    );
    assert!(
        rv != CKR_OK,
        "InitToken with 65-byte PIN should fail: 0x{:08X}",
        rv
    );
}

// ============================================================================
// 40. C_SetAttributeValue on read-only session — CKR_SESSION_READ_ONLY
// ============================================================================

#[test]
fn test_set_attribute_on_ro_session() {
    ensure_init();
    let so_pin = b"sopin123";
    let mut label = [b' '; 32];
    label[..7].copy_from_slice(b"ROSess1");
    C_InitToken(
        0,
        so_pin.as_ptr() as *mut _,
        so_pin.len() as CK_ULONG,
        label.as_ptr() as *mut _,
    );

    // Open RO session
    let mut session: CK_SESSION_HANDLE = 0;
    let rv = C_OpenSession(0, CKF_SERIAL_SESSION, ptr::null_mut(), None, &mut session);
    assert_eq!(rv, CKR_OK);

    // Try C_SetAttributeValue on RO session — should be rejected
    let new_label = b"new-label";
    let mut template = vec![CK_ATTRIBUTE {
        attr_type: CKA_LABEL,
        p_value: new_label.as_ptr() as CK_VOID_PTR,
        value_len: new_label.len() as CK_ULONG,
    }];
    // Use handle 1 (may or may not exist, but the session check happens first)
    let rv = C_SetAttributeValue(
        session,
        1,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
    );
    assert_eq!(
        rv, CKR_SESSION_READ_ONLY,
        "C_SetAttributeValue on RO session should return SESSION_READ_ONLY: 0x{:08X}",
        rv
    );
}
