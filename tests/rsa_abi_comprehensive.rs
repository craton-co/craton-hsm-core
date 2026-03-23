// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
// Comprehensive RSA operations through PKCS#11 C ABI.
// 28 tests covering sign, verify, encrypt, decrypt, keygen, attributes, and error paths.
//
// IMPORTANT: These tests share global OnceLock state and MUST be run with --test-threads=1.

use craton_hsm::crypto::sign::{self as crypto_sign, OaepHash};
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

/// Re-initialize token, open RW session, login as user. Returns session handle.
fn setup_user_session() -> CK_SESSION_HANDLE {
    ensure_init();
    let so_pin = b"sopin123";
    let mut label = [b' '; 32];
    label[..7].copy_from_slice(b"RSATest");
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

/// Generate an RSA key pair with the specified bit size. Returns (pub_key, priv_key).
fn generate_rsa_keypair(
    session: CK_SESSION_HANDLE,
    bits: CK_ULONG,
) -> (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) {
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let modulus_bits_bytes = ck_ulong_bytes(bits);
    let public_exponent: [u8; 3] = [0x01, 0x00, 0x01]; // 65537
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
    assert_eq!(
        rv, CKR_OK,
        "RSA keygen failed for {} bits: 0x{:08X}",
        bits, rv
    );
    (pub_key, priv_key)
}

/// Helper: sign data and return signature bytes.
fn sign_data(
    session: CK_SESSION_HANDLE,
    priv_key: CK_OBJECT_HANDLE,
    mechanism_type: CK_MECHANISM_TYPE,
    data: &[u8],
) -> Vec<u8> {
    let mut mechanism = CK_MECHANISM {
        mechanism: mechanism_type,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_SignInit(session, &mut mechanism, priv_key);
    assert_eq!(rv, CKR_OK, "C_SignInit failed: 0x{:08X}", rv);

    let mut signature = vec![0u8; 512];
    let mut sig_len: CK_ULONG = signature.len() as CK_ULONG;
    let rv = C_Sign(
        session,
        data.as_ptr() as CK_BYTE_PTR,
        data.len() as CK_ULONG,
        signature.as_mut_ptr(),
        &mut sig_len,
    );
    assert_eq!(rv, CKR_OK, "C_Sign failed: 0x{:08X}", rv);
    signature.truncate(sig_len as usize);
    signature
}

/// Helper: verify signature and return CK_RV.
fn verify_data(
    session: CK_SESSION_HANDLE,
    pub_key: CK_OBJECT_HANDLE,
    mechanism_type: CK_MECHANISM_TYPE,
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

/// Read CKA_MODULUS and CKA_PUBLIC_EXPONENT from a public key handle via C_GetAttributeValue.
fn read_rsa_public_components(
    session: CK_SESSION_HANDLE,
    pub_key: CK_OBJECT_HANDLE,
) -> (Vec<u8>, Vec<u8>) {
    // Get sizes
    let mut mod_template = [CK_ATTRIBUTE {
        attr_type: CKA_MODULUS,
        p_value: ptr::null_mut(),
        value_len: 0,
    }];
    let rv = C_GetAttributeValue(session, pub_key, mod_template.as_mut_ptr(), 1);
    assert_eq!(rv, CKR_OK);
    let mod_len = mod_template[0].value_len as usize;

    let mut exp_template = [CK_ATTRIBUTE {
        attr_type: CKA_PUBLIC_EXPONENT,
        p_value: ptr::null_mut(),
        value_len: 0,
    }];
    let rv = C_GetAttributeValue(session, pub_key, exp_template.as_mut_ptr(), 1);
    assert_eq!(rv, CKR_OK);
    let exp_len = exp_template[0].value_len as usize;

    // Get values
    let mut modulus = vec![0u8; mod_len];
    mod_template[0].p_value = modulus.as_mut_ptr() as CK_VOID_PTR;
    mod_template[0].value_len = mod_len as CK_ULONG;
    let rv = C_GetAttributeValue(session, pub_key, mod_template.as_mut_ptr(), 1);
    assert_eq!(rv, CKR_OK);

    let mut pub_exp = vec![0u8; exp_len];
    exp_template[0].p_value = pub_exp.as_mut_ptr() as CK_VOID_PTR;
    exp_template[0].value_len = exp_len as CK_ULONG;
    let rv = C_GetAttributeValue(session, pub_key, exp_template.as_mut_ptr(), 1);
    assert_eq!(rv, CKR_OK);

    (modulus, pub_exp)
}

/// Encrypt plaintext using OAEP via the internal crypto module.
/// This is needed because the ABI's C_Encrypt has a limitation where public keys
/// (which have can_encrypt but no key_material) fail at the key_material extraction
/// step before reaching the OAEP code path. We use the internal API for encryption
/// and the C ABI for decryption to still exercise the ABI decrypt path.
fn oaep_encrypt_via_internal(modulus: &[u8], pub_exp: &[u8], plaintext: &[u8]) -> Vec<u8> {
    crypto_sign::rsa_oaep_encrypt(modulus, pub_exp, plaintext, OaepHash::Sha256)
        .expect("Internal OAEP encrypt failed")
}

// ============================================================================
// 1. RSA-2048 PKCS#1 v1.5 SHA-256 sign/verify
// ============================================================================

#[test]
fn test_rsa_2048_pkcs1v15_sign_verify() {
    let session = setup_user_session();
    let (pub_key, priv_key) = generate_rsa_keypair(session, 2048);
    let data = b"test data for signing";

    let sig = sign_data(session, priv_key, CKM_SHA256_RSA_PKCS, data);
    assert_eq!(sig.len(), 256, "RSA-2048 signature should be 256 bytes");

    let rv = verify_data(session, pub_key, CKM_SHA256_RSA_PKCS, data, &sig);
    assert_eq!(rv, CKR_OK, "Verify should succeed");
}

// ============================================================================
// 2. RSA-2048 PSS SHA-256 sign/verify
// ============================================================================

#[test]
fn test_rsa_2048_pss_sign_verify() {
    let session = setup_user_session();
    let (pub_key, priv_key) = generate_rsa_keypair(session, 2048);
    let data = b"PSS test data";

    let sig = sign_data(session, priv_key, CKM_SHA256_RSA_PKCS_PSS, data);
    assert_eq!(sig.len(), 256, "RSA-2048 PSS signature should be 256 bytes");

    let rv = verify_data(session, pub_key, CKM_SHA256_RSA_PKCS_PSS, data, &sig);
    assert_eq!(rv, CKR_OK, "PSS verify should succeed");
}

// ============================================================================
// 3. RSA-2048 OAEP encrypt/decrypt roundtrip
// ============================================================================

#[test]
fn test_rsa_2048_oaep_encrypt_decrypt() {
    let session = setup_user_session();
    let (pub_key, priv_key) = generate_rsa_keypair(session, 2048);
    let plaintext = b"OAEP encrypt test data";

    // Read public components for internal OAEP encrypt
    let (modulus, pub_exp) = read_rsa_public_components(session, pub_key);
    let ciphertext = oaep_encrypt_via_internal(&modulus, &pub_exp, plaintext);
    assert_eq!(
        ciphertext.len(),
        256,
        "RSA-2048 OAEP ciphertext should be 256 bytes"
    );

    // Decrypt via C ABI with private key
    let mut dec_mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_OAEP,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_DecryptInit(session, &mut dec_mechanism, priv_key);
    assert_eq!(rv, CKR_OK, "DecryptInit failed: 0x{:08X}", rv);

    let mut decrypted = vec![0u8; 512];
    let mut dec_len: CK_ULONG = decrypted.len() as CK_ULONG;
    let rv = C_Decrypt(
        session,
        ciphertext.as_ptr() as CK_BYTE_PTR,
        ciphertext.len() as CK_ULONG,
        decrypted.as_mut_ptr(),
        &mut dec_len,
    );
    assert_eq!(rv, CKR_OK, "Decrypt failed: 0x{:08X}", rv);
    assert_eq!(&decrypted[..dec_len as usize], plaintext.as_slice());
}

// ============================================================================
// 4. RSA-3072 keygen (slow in debug)
// ============================================================================

#[test]
fn test_rsa_3072_keygen() {
    let session = setup_user_session();
    let (pub_key, priv_key) = generate_rsa_keypair(session, 3072);
    assert_ne!(pub_key, 0);
    assert_ne!(priv_key, 0);
}

// ============================================================================
// 5. RSA-3072 sign/verify
// ============================================================================

#[test]
fn test_rsa_3072_sign_verify() {
    let session = setup_user_session();
    let (pub_key, priv_key) = generate_rsa_keypair(session, 3072);
    let data = b"3072-bit RSA sign test";

    let sig = sign_data(session, priv_key, CKM_SHA256_RSA_PKCS, data);
    assert_eq!(sig.len(), 384, "RSA-3072 signature should be 384 bytes");

    let rv = verify_data(session, pub_key, CKM_SHA256_RSA_PKCS, data, &sig);
    assert_eq!(rv, CKR_OK, "3072-bit verify should succeed");
}

// ============================================================================
// 6. Sign with key A, verify with key B -> SIGNATURE_INVALID
// ============================================================================

#[test]
fn test_rsa_sign_wrong_key_verifies_false() {
    let session = setup_user_session();
    let (_pub_a, priv_a) = generate_rsa_keypair(session, 2048);
    let (pub_b, _priv_b) = generate_rsa_keypair(session, 2048);
    let data = b"cross-key verification test";

    let sig = sign_data(session, priv_a, CKM_SHA256_RSA_PKCS, data);

    let rv = verify_data(session, pub_b, CKM_SHA256_RSA_PKCS, data, &sig);
    assert_eq!(
        rv, CKR_SIGNATURE_INVALID,
        "Verify with wrong key should fail"
    );
}

// ============================================================================
// 7. Sign data, modify data, verify -> SIGNATURE_INVALID
// ============================================================================

#[test]
fn test_rsa_sign_tampered_data_fails() {
    let session = setup_user_session();
    let (pub_key, priv_key) = generate_rsa_keypair(session, 2048);
    let data = b"original data to sign";

    let sig = sign_data(session, priv_key, CKM_SHA256_RSA_PKCS, data);

    let tampered = b"tampered data to sign";
    let rv = verify_data(session, pub_key, CKM_SHA256_RSA_PKCS, tampered, &sig);
    assert_eq!(
        rv, CKR_SIGNATURE_INVALID,
        "Tampered data should fail verification"
    );
}

// ============================================================================
// 8. PKCS#1 v1.5 SHA-384 sign/verify
// ============================================================================

#[test]
fn test_rsa_pkcs1v15_sha384_sign_verify() {
    let session = setup_user_session();
    let (pub_key, priv_key) = generate_rsa_keypair(session, 2048);
    let data = b"SHA-384 test data for signing";

    let sig = sign_data(session, priv_key, CKM_SHA384_RSA_PKCS, data);
    assert_eq!(sig.len(), 256);

    let rv = verify_data(session, pub_key, CKM_SHA384_RSA_PKCS, data, &sig);
    assert_eq!(rv, CKR_OK, "SHA-384 verify should succeed");
}

// ============================================================================
// 9. PKCS#1 v1.5 SHA-512 sign/verify
// ============================================================================

#[test]
fn test_rsa_pkcs1v15_sha512_sign_verify() {
    let session = setup_user_session();
    let (pub_key, priv_key) = generate_rsa_keypair(session, 2048);
    let data = b"SHA-512 test data for signing";

    let sig = sign_data(session, priv_key, CKM_SHA512_RSA_PKCS, data);
    assert_eq!(sig.len(), 256);

    let rv = verify_data(session, pub_key, CKM_SHA512_RSA_PKCS, data, &sig);
    assert_eq!(rv, CKR_OK, "SHA-512 verify should succeed");
}

// ============================================================================
// 10. PSS SHA-384 sign/verify
// ============================================================================

#[test]
fn test_rsa_pss_sha384_sign_verify() {
    let session = setup_user_session();
    let (pub_key, priv_key) = generate_rsa_keypair(session, 2048);
    let data = b"PSS SHA-384 test data";

    let sig = sign_data(session, priv_key, CKM_SHA384_RSA_PKCS_PSS, data);
    assert_eq!(sig.len(), 256);

    let rv = verify_data(session, pub_key, CKM_SHA384_RSA_PKCS_PSS, data, &sig);
    assert_eq!(rv, CKR_OK, "PSS SHA-384 verify should succeed");
}

// ============================================================================
// 11. PSS SHA-512 sign/verify
// ============================================================================

#[test]
fn test_rsa_pss_sha512_sign_verify() {
    let session = setup_user_session();
    let (pub_key, priv_key) = generate_rsa_keypair(session, 2048);
    let data = b"PSS SHA-512 test data";

    let sig = sign_data(session, priv_key, CKM_SHA512_RSA_PKCS_PSS, data);
    assert_eq!(sig.len(), 256);

    let rv = verify_data(session, pub_key, CKM_SHA512_RSA_PKCS_PSS, data, &sig);
    assert_eq!(rv, CKR_OK, "PSS SHA-512 verify should succeed");
}

// ============================================================================
// 12. OAEP encrypt with pub_A, decrypt with priv_B -> error
// ============================================================================

#[test]
fn test_rsa_oaep_wrong_key_decrypt_fails() {
    let session = setup_user_session();
    let (pub_a, _priv_a) = generate_rsa_keypair(session, 2048);
    let (_pub_b, priv_b) = generate_rsa_keypair(session, 2048);
    let plaintext = b"cross-key OAEP test";

    // Encrypt with pub_A's components via internal API
    let (modulus_a, pub_exp_a) = read_rsa_public_components(session, pub_a);
    let ciphertext = oaep_encrypt_via_internal(&modulus_a, &pub_exp_a, plaintext);

    // Decrypt with priv_B via C ABI -- should fail
    let mut dec_mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_OAEP,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_DecryptInit(session, &mut dec_mechanism, priv_b);
    assert_eq!(rv, CKR_OK);

    let mut decrypted = vec![0u8; 512];
    let mut dec_len: CK_ULONG = decrypted.len() as CK_ULONG;
    let rv = C_Decrypt(
        session,
        ciphertext.as_ptr() as CK_BYTE_PTR,
        ciphertext.len() as CK_ULONG,
        decrypted.as_mut_ptr(),
        &mut dec_len,
    );
    assert_ne!(rv, CKR_OK, "Decrypt with wrong private key should fail");
}

// ============================================================================
// 13. OAEP tampered ciphertext -> error
// ============================================================================

#[test]
fn test_rsa_oaep_tampered_ciphertext_fails() {
    let session = setup_user_session();
    let (pub_key, priv_key) = generate_rsa_keypair(session, 2048);
    let plaintext = b"tamper ciphertext test";

    // Encrypt via internal API
    let (modulus, pub_exp) = read_rsa_public_components(session, pub_key);
    let mut ciphertext = oaep_encrypt_via_internal(&modulus, &pub_exp, plaintext);

    // Tamper with first byte
    ciphertext[0] ^= 0xFF;

    // Decrypt via C ABI should fail
    let mut dec_mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_OAEP,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_DecryptInit(session, &mut dec_mechanism, priv_key);
    assert_eq!(rv, CKR_OK);

    let mut decrypted = vec![0u8; 512];
    let mut dec_len: CK_ULONG = decrypted.len() as CK_ULONG;
    let rv = C_Decrypt(
        session,
        ciphertext.as_mut_ptr(),
        ciphertext.len() as CK_ULONG,
        decrypted.as_mut_ptr(),
        &mut dec_len,
    );
    assert_ne!(rv, CKR_OK, "Tampered ciphertext should fail decryption");
}

// ============================================================================
// 14. C_Sign with null output -> returns needed signature size
// ============================================================================

#[test]
fn test_rsa_sign_null_output_gets_size() {
    let session = setup_user_session();
    let (_pub_key, priv_key) = generate_rsa_keypair(session, 2048);
    let data = b"size query test";

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256_RSA_PKCS,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_SignInit(session, &mut mechanism, priv_key);
    assert_eq!(rv, CKR_OK);

    // First call with null output to get size
    let mut sig_len: CK_ULONG = 0;
    let rv = C_Sign(
        session,
        data.as_ptr() as CK_BYTE_PTR,
        data.len() as CK_ULONG,
        ptr::null_mut(),
        &mut sig_len,
    );
    assert_eq!(rv, CKR_OK, "Null output call should succeed");
    assert_eq!(
        sig_len as usize, 256,
        "Should report 256-byte signature for RSA-2048"
    );
}

// ============================================================================
// 15. C_Sign with too-small buffer -> CKR_BUFFER_TOO_SMALL
// ============================================================================

#[test]
fn test_rsa_sign_buffer_too_small() {
    let session = setup_user_session();
    let (_pub_key, priv_key) = generate_rsa_keypair(session, 2048);
    let data = b"buffer too small test";

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256_RSA_PKCS,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_SignInit(session, &mut mechanism, priv_key);
    assert_eq!(rv, CKR_OK);

    let mut small_buf = [0u8; 1];
    let mut sig_len: CK_ULONG = small_buf.len() as CK_ULONG;
    let rv = C_Sign(
        session,
        data.as_ptr() as CK_BYTE_PTR,
        data.len() as CK_ULONG,
        small_buf.as_mut_ptr(),
        &mut sig_len,
    );
    assert_eq!(rv, CKR_BUFFER_TOO_SMALL, "Should return BUFFER_TOO_SMALL");
    assert_eq!(sig_len as usize, 256, "Should report required size");
}

// ============================================================================
// 16. C_Decrypt with null output -> returns needed plaintext buffer size
// ============================================================================

#[test]
fn test_rsa_decrypt_null_output_gets_size() {
    let session = setup_user_session();
    let (pub_key, priv_key) = generate_rsa_keypair(session, 2048);
    let plaintext = b"decrypt size query";

    // Encrypt via internal API
    let (modulus, pub_exp) = read_rsa_public_components(session, pub_key);
    let ciphertext = oaep_encrypt_via_internal(&modulus, &pub_exp, plaintext);

    // DecryptInit
    let mut dec_mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_OAEP,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_DecryptInit(session, &mut dec_mechanism, priv_key);
    assert_eq!(rv, CKR_OK);

    // First call with null output to get size
    let mut dec_len: CK_ULONG = 0;
    let rv = C_Decrypt(
        session,
        ciphertext.as_ptr() as CK_BYTE_PTR,
        ciphertext.len() as CK_ULONG,
        ptr::null_mut(),
        &mut dec_len,
    );
    assert_eq!(rv, CKR_OK, "Null output call should succeed");
    assert!(dec_len > 0, "Should report non-zero decrypted size");
}

// ============================================================================
// 17. Keygen attributes: CKA_MODULUS_BITS matches requested
// ============================================================================

#[test]
fn test_rsa_keygen_attributes_correct() {
    let session = setup_user_session();
    let (pub_key, _priv_key) = generate_rsa_keypair(session, 2048);

    // Read CKA_MODULUS_BITS from public key
    let mut modulus_bits_val: CK_ULONG = 0;
    let mut template = [CK_ATTRIBUTE {
        attr_type: CKA_MODULUS_BITS,
        p_value: &mut modulus_bits_val as *mut _ as CK_VOID_PTR,
        value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
    }];
    let rv = C_GetAttributeValue(session, pub_key, template.as_mut_ptr(), 1);
    assert_eq!(rv, CKR_OK, "GetAttributeValue failed: 0x{:08X}", rv);
    assert_eq!(modulus_bits_val, 2048, "Modulus bits should be 2048");
}

// ============================================================================
// 18. Public exponent is [0x01, 0x00, 0x01] (65537)
// ============================================================================

#[test]
fn test_rsa_keygen_public_exponent() {
    let session = setup_user_session();
    let (pub_key, _priv_key) = generate_rsa_keypair(session, 2048);

    // First call to get size
    let mut template = [CK_ATTRIBUTE {
        attr_type: CKA_PUBLIC_EXPONENT,
        p_value: ptr::null_mut(),
        value_len: 0,
    }];
    let rv = C_GetAttributeValue(session, pub_key, template.as_mut_ptr(), 1);
    assert_eq!(
        rv, CKR_OK,
        "GetAttributeValue size query failed: 0x{:08X}",
        rv
    );
    let exp_len = template[0].value_len as usize;
    assert!(exp_len > 0, "Public exponent should have non-zero length");

    // Second call to get value
    let mut exp_buf = vec![0u8; exp_len];
    template[0].p_value = exp_buf.as_mut_ptr() as CK_VOID_PTR;
    template[0].value_len = exp_len as CK_ULONG;
    let rv = C_GetAttributeValue(session, pub_key, template.as_mut_ptr(), 1);
    assert_eq!(
        rv, CKR_OK,
        "GetAttributeValue value query failed: 0x{:08X}",
        rv
    );
    assert_eq!(
        &exp_buf[..template[0].value_len as usize],
        &[0x01, 0x00, 0x01],
        "Public exponent should be 65537"
    );
}

// ============================================================================
// 19. Private key has CKA_SENSITIVE = CK_TRUE
// ============================================================================

#[test]
fn test_rsa_private_key_is_sensitive() {
    let session = setup_user_session();
    let (_pub_key, priv_key) = generate_rsa_keypair(session, 2048);

    let mut sensitive_val: CK_BBOOL = CK_FALSE;
    let mut template = [CK_ATTRIBUTE {
        attr_type: CKA_SENSITIVE,
        p_value: &mut sensitive_val as *mut _ as CK_VOID_PTR,
        value_len: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
    }];
    let rv = C_GetAttributeValue(session, priv_key, template.as_mut_ptr(), 1);
    assert_eq!(rv, CKR_OK, "GetAttributeValue failed: 0x{:08X}", rv);
    assert_eq!(sensitive_val, CK_TRUE, "Private key should be sensitive");
}

// ============================================================================
// 20. Public key has CKA_SENSITIVE = CK_FALSE (or attribute not applicable)
// ============================================================================

#[test]
fn test_rsa_public_key_not_sensitive() {
    let session = setup_user_session();
    let (pub_key, _priv_key) = generate_rsa_keypair(session, 2048);

    let mut sensitive_val: CK_BBOOL = CK_TRUE; // Initialize to TRUE, expect FALSE
    let mut template = [CK_ATTRIBUTE {
        attr_type: CKA_SENSITIVE,
        p_value: &mut sensitive_val as *mut _ as CK_VOID_PTR,
        value_len: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
    }];
    let rv = C_GetAttributeValue(session, pub_key, template.as_mut_ptr(), 1);
    // Either CKR_OK with CK_FALSE, or CKR_ATTRIBUTE_TYPE_INVALID for public keys
    if rv == CKR_OK {
        assert_eq!(
            sensitive_val, CK_FALSE,
            "Public key should not be sensitive"
        );
    } else {
        assert_eq!(
            rv, CKR_ATTRIBUTE_TYPE_INVALID,
            "Public key CKA_SENSITIVE should be CK_FALSE or unsupported: 0x{:08X}",
            rv
        );
    }
}

// ============================================================================
// 21. Sign without login -> CKR_USER_NOT_LOGGED_IN
// ============================================================================

#[test]
fn test_rsa_sign_without_login_fails() {
    ensure_init();
    let so_pin = b"sopin123";
    let mut label = [b' '; 32];
    label[..7].copy_from_slice(b"NoLogin");
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

    // Do NOT login -- try to SignInit with a bogus key handle
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256_RSA_PKCS,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_SignInit(session, &mut mechanism, 999);
    assert_eq!(
        rv, CKR_USER_NOT_LOGGED_IN,
        "SignInit without login should fail"
    );

    let rv = C_CloseSession(session);
    assert_eq!(rv, CKR_OK);
}

// ============================================================================
// 22. Keygen on RO session -> CKR_SESSION_READ_ONLY
// ============================================================================

#[test]
fn test_rsa_keygen_on_ro_session_fails() {
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

    // Set up user PIN via SO session first
    let mut rw_session: CK_SESSION_HANDLE = 0;
    let rv = C_OpenSession(
        0,
        CKF_RW_SESSION | CKF_SERIAL_SESSION,
        ptr::null_mut(),
        None,
        &mut rw_session,
    );
    assert_eq!(rv, CKR_OK);
    let rv = C_Login(
        rw_session,
        CKU_SO,
        so_pin.as_ptr() as *mut _,
        so_pin.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_OK);
    let user_pin = b"userpin1";
    let rv = C_InitPIN(
        rw_session,
        user_pin.as_ptr() as *mut _,
        user_pin.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_OK);
    let rv = C_Logout(rw_session);
    assert_eq!(rv, CKR_OK);
    let rv = C_CloseSession(rw_session);
    assert_eq!(rv, CKR_OK);

    // Open RO session (CKF_SERIAL_SESSION only, no CKF_RW_SESSION)
    let mut ro_session: CK_SESSION_HANDLE = 0;
    let rv = C_OpenSession(
        0,
        CKF_SERIAL_SESSION,
        ptr::null_mut(),
        None,
        &mut ro_session,
    );
    assert_eq!(rv, CKR_OK);

    // Login as user on RO session
    let rv = C_Login(
        ro_session,
        CKU_USER,
        user_pin.as_ptr() as *mut _,
        user_pin.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_OK);

    // Try to generate RSA keypair
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
            attr_type: CKA_VERIFY,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
    ];
    let mut priv_template = vec![CK_ATTRIBUTE {
        attr_type: CKA_SIGN,
        p_value: &ck_true as *const _ as CK_VOID_PTR,
        value_len: 1,
    }];
    let mut pub_key: CK_OBJECT_HANDLE = 0;
    let mut priv_key: CK_OBJECT_HANDLE = 0;
    let rv = C_GenerateKeyPair(
        ro_session,
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
        "Keygen on RO session should fail"
    );

    let rv = C_CloseSession(ro_session);
    assert_eq!(rv, CKR_OK);
}

// ============================================================================
// 23. Sign with AES key using RSA mechanism -> error
// ============================================================================

#[test]
fn test_rsa_sign_init_wrong_key_type() {
    let session = setup_user_session();

    // Generate an AES key with CKA_SIGN set
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
            attr_type: CKA_SIGN,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: 1,
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
    assert_eq!(rv, CKR_OK, "AES keygen failed");

    // Try to use AES key for RSA signing
    let mut rsa_sign_mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256_RSA_PKCS,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_SignInit(session, &mut rsa_sign_mechanism, aes_key);

    if rv == CKR_OK {
        // SignInit succeeded, the error will come from C_Sign
        let data = b"wrong key type test";
        let mut sig_buf = vec![0u8; 512];
        let mut sig_len: CK_ULONG = sig_buf.len() as CK_ULONG;
        let rv = C_Sign(
            session,
            data.as_ptr() as CK_BYTE_PTR,
            data.len() as CK_ULONG,
            sig_buf.as_mut_ptr(),
            &mut sig_len,
        );
        assert_ne!(
            rv, CKR_OK,
            "RSA sign with AES key should fail: 0x{:08X}",
            rv
        );
    } else {
        // SignInit itself rejected it
        assert!(
            rv == CKR_KEY_TYPE_INCONSISTENT || rv == CKR_KEY_HANDLE_INVALID || rv == CKR_KEY_FUNCTION_NOT_PERMITTED,
            "SignInit with wrong key type should return KEY_TYPE_INCONSISTENT, KEY_HANDLE_INVALID, or KEY_FUNCTION_NOT_PERMITTED, got 0x{:08X}", rv
        );
    }
}

// ============================================================================
// 24. CKA_MODULUS length is 256 bytes for RSA-2048
// ============================================================================

#[test]
fn test_rsa_2048_keygen_modulus_size() {
    let session = setup_user_session();
    let (pub_key, _priv_key) = generate_rsa_keypair(session, 2048);

    // First call: get modulus size
    let mut template = [CK_ATTRIBUTE {
        attr_type: CKA_MODULUS,
        p_value: ptr::null_mut(),
        value_len: 0,
    }];
    let rv = C_GetAttributeValue(session, pub_key, template.as_mut_ptr(), 1);
    assert_eq!(
        rv, CKR_OK,
        "GetAttributeValue size query failed: 0x{:08X}",
        rv
    );
    let modulus_len = template[0].value_len as usize;
    assert_eq!(modulus_len, 256, "RSA-2048 modulus should be 256 bytes");

    // Second call: get modulus value
    let mut modulus_buf = vec![0u8; modulus_len];
    template[0].p_value = modulus_buf.as_mut_ptr() as CK_VOID_PTR;
    template[0].value_len = modulus_len as CK_ULONG;
    let rv = C_GetAttributeValue(session, pub_key, template.as_mut_ptr(), 1);
    assert_eq!(
        rv, CKR_OK,
        "GetAttributeValue value query failed: 0x{:08X}",
        rv
    );
    // Modulus should not be all zeros
    assert!(
        !modulus_buf.iter().all(|&b| b == 0),
        "Modulus should not be all zeros"
    );
}

// ============================================================================
// 25. Sign with private, verify with public key handle
// ============================================================================

#[test]
fn test_rsa_verify_with_public_key_only() {
    let session = setup_user_session();
    let (pub_key, priv_key) = generate_rsa_keypair(session, 2048);
    let data = b"verify with public key handle test";

    // Sign with private key
    let sig = sign_data(session, priv_key, CKM_SHA256_RSA_PKCS, data);

    // Verify with public key handle
    let rv = verify_data(session, pub_key, CKM_SHA256_RSA_PKCS, data, &sig);
    assert_eq!(
        rv, CKR_OK,
        "Verification with public key handle should succeed"
    );
}

// ============================================================================
// 26. Sign different data -> different signatures
// ============================================================================

#[test]
fn test_rsa_sign_different_data_different_sigs() {
    let session = setup_user_session();
    let (_pub_key, priv_key) = generate_rsa_keypair(session, 2048);

    let sig1 = sign_data(session, priv_key, CKM_SHA256_RSA_PKCS, b"hello");
    let sig2 = sign_data(session, priv_key, CKM_SHA256_RSA_PKCS, b"world");

    assert_eq!(sig1.len(), sig2.len(), "Signatures should be same length");
    assert_ne!(sig1, sig2, "Signatures for different data should differ");
}

// ============================================================================
// 27. Sign 4KB data with CKM_SHA256_RSA_PKCS -> succeeds
// ============================================================================

#[test]
fn test_rsa_2048_sign_large_data() {
    let session = setup_user_session();
    let (pub_key, priv_key) = generate_rsa_keypair(session, 2048);
    let large_data = vec![0xABu8; 4096];

    let sig = sign_data(session, priv_key, CKM_SHA256_RSA_PKCS, &large_data);
    assert_eq!(sig.len(), 256, "Signature should still be 256 bytes");

    let rv = verify_data(session, pub_key, CKM_SHA256_RSA_PKCS, &large_data, &sig);
    assert_eq!(rv, CKR_OK, "Verify of large data should succeed");
}

// ============================================================================
// 28. Two keypairs produce different moduli
// ============================================================================

#[test]
fn test_rsa_keygen_produces_unique_keys() {
    let session = setup_user_session();
    let (pub_key_1, _priv_key_1) = generate_rsa_keypair(session, 2048);
    let (pub_key_2, _priv_key_2) = generate_rsa_keypair(session, 2048);

    // Read CKA_MODULUS from both public keys
    fn read_modulus(session: CK_SESSION_HANDLE, pub_key: CK_OBJECT_HANDLE) -> Vec<u8> {
        // Get size
        let mut template = [CK_ATTRIBUTE {
            attr_type: CKA_MODULUS,
            p_value: ptr::null_mut(),
            value_len: 0,
        }];
        let rv = C_GetAttributeValue(session, pub_key, template.as_mut_ptr(), 1);
        assert_eq!(
            rv, CKR_OK,
            "GetAttributeValue size query failed: 0x{:08X}",
            rv
        );
        let modulus_len = template[0].value_len as usize;
        assert!(modulus_len > 0);

        // Get value
        let mut buf = vec![0u8; modulus_len];
        template[0].p_value = buf.as_mut_ptr() as CK_VOID_PTR;
        template[0].value_len = modulus_len as CK_ULONG;
        let rv = C_GetAttributeValue(session, pub_key, template.as_mut_ptr(), 1);
        assert_eq!(
            rv, CKR_OK,
            "GetAttributeValue value query failed: 0x{:08X}",
            rv
        );
        buf
    }

    let modulus_1 = read_modulus(session, pub_key_1);
    let modulus_2 = read_modulus(session, pub_key_2);

    assert_eq!(modulus_1.len(), 256, "First modulus should be 256 bytes");
    assert_eq!(modulus_2.len(), 256, "Second modulus should be 256 bytes");
    assert_ne!(
        modulus_1, modulus_2,
        "Two RSA keypairs should have different moduli"
    );
}
