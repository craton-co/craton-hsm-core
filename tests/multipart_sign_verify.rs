// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
// Multi-part sign/verify integration tests — exercises C_SignUpdate/C_SignFinal
// and C_VerifyUpdate/C_VerifyFinal via the C ABI layer.
//
// Tests cover:
// - RSA PKCS#1 v1.5 with SHA-256/384/512
// - RSA-PSS with SHA-256
// - ECDSA P-256 with SHA-256, ECDSA P-384 with SHA-384
// - Cross-validation: multi-part sign == single-shot sign for same data
// - Error cases: update without init, wrong mechanism
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
/// Returns the session handle.
fn setup_session() -> CK_SESSION_HANDLE {
    let rv = C_Initialize(ptr::null_mut());
    assert!(rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED);

    // Init token
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

    // Open RW session
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

/// Generate an RSA 2048-bit key pair. Returns (pub_key, priv_key).
fn generate_rsa_key_pair(session: CK_SESSION_HANDLE) -> (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) {
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let modulus_bits = ck_ulong_bytes(2048);
    let sign_true: CK_BBOOL = CK_TRUE;
    let verify_true: CK_BBOOL = CK_TRUE;

    let mut pub_template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_MODULUS_BITS,
            p_value: modulus_bits.as_ptr() as CK_VOID_PTR,
            value_len: modulus_bits.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_VERIFY,
            p_value: &verify_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
    ];

    let mut priv_template = vec![CK_ATTRIBUTE {
        attr_type: CKA_SIGN,
        p_value: &sign_true as *const _ as CK_VOID_PTR,
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
    assert_eq!(rv, CKR_OK);
    (pub_key, priv_key)
}

/// Generate an EC P-256 key pair. Returns (pub_key, priv_key).
fn generate_ec_p256_key_pair(session: CK_SESSION_HANDLE) -> (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) {
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_EC_KEY_PAIR_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    // P-256 OID: 1.2.840.10045.3.1.7 = 06 08 2a 86 48 ce 3d 03 01 07
    let ec_params: Vec<u8> = vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    let sign_true: CK_BBOOL = CK_TRUE;
    let verify_true: CK_BBOOL = CK_TRUE;

    let mut pub_template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_EC_PARAMS,
            p_value: ec_params.as_ptr() as CK_VOID_PTR,
            value_len: ec_params.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_VERIFY,
            p_value: &verify_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
    ];

    let mut priv_template = vec![CK_ATTRIBUTE {
        attr_type: CKA_SIGN,
        p_value: &sign_true as *const _ as CK_VOID_PTR,
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
    assert_eq!(rv, CKR_OK);
    (pub_key, priv_key)
}

/// Generate an EC P-384 key pair. Returns (pub_key, priv_key).
fn generate_ec_p384_key_pair(session: CK_SESSION_HANDLE) -> (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) {
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_EC_KEY_PAIR_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    // P-384 OID: 1.3.132.0.34 = 06 05 2B 81 04 00 22
    let ec_params: Vec<u8> = vec![0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22];
    let sign_true: CK_BBOOL = CK_TRUE;
    let verify_true: CK_BBOOL = CK_TRUE;

    let mut pub_template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_EC_PARAMS,
            p_value: ec_params.as_ptr() as CK_VOID_PTR,
            value_len: ec_params.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_VERIFY,
            p_value: &verify_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
    ];

    let mut priv_template = vec![CK_ATTRIBUTE {
        attr_type: CKA_SIGN,
        p_value: &sign_true as *const _ as CK_VOID_PTR,
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
    assert_eq!(rv, CKR_OK);
    (pub_key, priv_key)
}

/// Single-shot sign: C_SignInit + C_Sign
fn single_shot_sign(
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
    assert_eq!(
        rv, CKR_OK,
        "C_SignInit failed for mechanism 0x{:08x}",
        mechanism_type
    );

    let mut sig_buf = vec![0u8; 512];
    let mut sig_len: CK_ULONG = sig_buf.len() as CK_ULONG;
    let rv = C_Sign(
        session,
        data.as_ptr() as CK_BYTE_PTR,
        data.len() as CK_ULONG,
        sig_buf.as_mut_ptr(),
        &mut sig_len,
    );
    assert_eq!(
        rv, CKR_OK,
        "C_Sign failed for mechanism 0x{:08x}",
        mechanism_type
    );
    sig_buf.truncate(sig_len as usize);
    sig_buf
}

/// Multi-part sign: C_SignInit + C_SignUpdate*N + C_SignFinal
fn multi_part_sign(
    session: CK_SESSION_HANDLE,
    mechanism_type: CK_MECHANISM_TYPE,
    priv_key: CK_OBJECT_HANDLE,
    chunks: &[&[u8]],
) -> Vec<u8> {
    let mut mechanism = CK_MECHANISM {
        mechanism: mechanism_type,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_SignInit(session, &mut mechanism, priv_key);
    assert_eq!(
        rv, CKR_OK,
        "C_SignInit failed for multi-part mechanism 0x{:08x}",
        mechanism_type
    );

    for chunk in chunks {
        let rv = C_SignUpdate(
            session,
            chunk.as_ptr() as CK_BYTE_PTR,
            chunk.len() as CK_ULONG,
        );
        assert_eq!(
            rv, CKR_OK,
            "C_SignUpdate failed for mechanism 0x{:08x}",
            mechanism_type
        );
    }

    let mut sig_buf = vec![0u8; 512];
    let mut sig_len: CK_ULONG = sig_buf.len() as CK_ULONG;
    let rv = C_SignFinal(session, sig_buf.as_mut_ptr(), &mut sig_len);
    assert_eq!(
        rv, CKR_OK,
        "C_SignFinal failed for mechanism 0x{:08x}",
        mechanism_type
    );
    sig_buf.truncate(sig_len as usize);
    sig_buf
}

/// Single-shot verify: C_VerifyInit + C_Verify
fn single_shot_verify(
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
    assert_eq!(
        rv, CKR_OK,
        "C_VerifyInit failed for mechanism 0x{:08x}",
        mechanism_type
    );

    C_Verify(
        session,
        data.as_ptr() as CK_BYTE_PTR,
        data.len() as CK_ULONG,
        signature.as_ptr() as CK_BYTE_PTR,
        signature.len() as CK_ULONG,
    )
}

/// Multi-part verify: C_VerifyInit + C_VerifyUpdate*N + C_VerifyFinal
fn multi_part_verify(
    session: CK_SESSION_HANDLE,
    mechanism_type: CK_MECHANISM_TYPE,
    pub_key: CK_OBJECT_HANDLE,
    chunks: &[&[u8]],
    signature: &[u8],
) -> CK_RV {
    let mut mechanism = CK_MECHANISM {
        mechanism: mechanism_type,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_VerifyInit(session, &mut mechanism, pub_key);
    assert_eq!(
        rv, CKR_OK,
        "C_VerifyInit failed for multi-part mechanism 0x{:08x}",
        mechanism_type
    );

    for chunk in chunks {
        let rv = C_VerifyUpdate(
            session,
            chunk.as_ptr() as CK_BYTE_PTR,
            chunk.len() as CK_ULONG,
        );
        assert_eq!(
            rv, CKR_OK,
            "C_VerifyUpdate failed for mechanism 0x{:08x}",
            mechanism_type
        );
    }

    C_VerifyFinal(
        session,
        signature.as_ptr() as CK_BYTE_PTR,
        signature.len() as CK_ULONG,
    )
}

#[test]
fn test_multipart_sign_verify() {
    let session = setup_session();
    let (rsa_pub, rsa_priv) = generate_rsa_key_pair(session);
    let (ec256_pub, ec256_priv) = generate_ec_p256_key_pair(session);
    let (ec384_pub, ec384_priv) = generate_ec_p384_key_pair(session);

    let message = b"The quick brown fox jumps over the lazy dog. This message will be signed.";
    let chunk1 = &message[..20];
    let chunk2 = &message[20..50];
    let chunk3 = &message[50..];
    let chunks: Vec<&[u8]> = vec![chunk1, chunk2, chunk3];

    // ========================================================================
    // 1. RSA PKCS#1 v1.5 + SHA-256: multi-part sign, single-shot verify
    // ========================================================================
    println!("Test 1: RSA SHA-256 multi-part sign → single-shot verify");
    let sig = multi_part_sign(session, CKM_SHA256_RSA_PKCS, rsa_priv, &chunks);
    assert_eq!(sig.len(), 256, "RSA-2048 signature should be 256 bytes");
    let rv = single_shot_verify(session, CKM_SHA256_RSA_PKCS, rsa_pub, message, &sig);
    assert_eq!(
        rv, CKR_OK,
        "Single-shot verify of multi-part signature failed"
    );

    // ========================================================================
    // 2. RSA PKCS#1 v1.5 + SHA-256: single-shot sign, multi-part verify
    // ========================================================================
    println!("Test 2: RSA SHA-256 single-shot sign → multi-part verify");
    let sig = single_shot_sign(session, CKM_SHA256_RSA_PKCS, rsa_priv, message);
    let rv = multi_part_verify(session, CKM_SHA256_RSA_PKCS, rsa_pub, &chunks, &sig);
    assert_eq!(
        rv, CKR_OK,
        "Multi-part verify of single-shot signature failed"
    );

    // ========================================================================
    // 3. RSA PKCS#1 v1.5 + SHA-384: multi-part sign + multi-part verify
    // ========================================================================
    println!("Test 3: RSA SHA-384 multi-part sign → multi-part verify");
    let sig = multi_part_sign(session, CKM_SHA384_RSA_PKCS, rsa_priv, &chunks);
    assert_eq!(sig.len(), 256);
    let rv = multi_part_verify(session, CKM_SHA384_RSA_PKCS, rsa_pub, &chunks, &sig);
    assert_eq!(
        rv, CKR_OK,
        "Multi-part verify of multi-part sign (SHA-384) failed"
    );

    // ========================================================================
    // 4. RSA PKCS#1 v1.5 + SHA-512: multi-part sign + single-shot verify
    // ========================================================================
    println!("Test 4: RSA SHA-512 multi-part sign → single-shot verify");
    let sig = multi_part_sign(session, CKM_SHA512_RSA_PKCS, rsa_priv, &chunks);
    assert_eq!(sig.len(), 256);
    let rv = single_shot_verify(session, CKM_SHA512_RSA_PKCS, rsa_pub, message, &sig);
    assert_eq!(
        rv, CKR_OK,
        "Single-shot verify of multi-part sign (SHA-512) failed"
    );

    // ========================================================================
    // 5. RSA-PSS + SHA-256: multi-part sign + single-shot verify
    // ========================================================================
    println!("Test 5: RSA-PSS SHA-256 multi-part sign → single-shot verify");
    let sig = multi_part_sign(session, CKM_SHA256_RSA_PKCS_PSS, rsa_priv, &chunks);
    assert_eq!(sig.len(), 256);
    // NOTE: RSA-PSS is randomized, so multi-part result != single-shot result.
    // Verify the multi-part signature with single-shot verify:
    let rv = single_shot_verify(session, CKM_SHA256_RSA_PKCS_PSS, rsa_pub, message, &sig);
    assert_eq!(
        rv, CKR_OK,
        "Single-shot verify of multi-part RSA-PSS sign failed"
    );

    // ========================================================================
    // 6. RSA-PSS + SHA-256: single-shot sign + multi-part verify
    // ========================================================================
    println!("Test 6: RSA-PSS SHA-256 single-shot sign → multi-part verify");
    let sig = single_shot_sign(session, CKM_SHA256_RSA_PKCS_PSS, rsa_priv, message);
    let rv = multi_part_verify(session, CKM_SHA256_RSA_PKCS_PSS, rsa_pub, &chunks, &sig);
    assert_eq!(
        rv, CKR_OK,
        "Multi-part verify of single-shot RSA-PSS sign failed"
    );

    // ========================================================================
    // 7. ECDSA P-256 + SHA-256: multi-part sign + single-shot verify
    // ========================================================================
    println!("Test 7: ECDSA P-256 SHA-256 multi-part sign → single-shot verify");
    let sig = multi_part_sign(session, CKM_ECDSA_SHA256, ec256_priv, &chunks);
    let rv = single_shot_verify(session, CKM_ECDSA_SHA256, ec256_pub, message, &sig);
    assert_eq!(
        rv, CKR_OK,
        "Single-shot verify of multi-part ECDSA P-256 sign failed"
    );

    // ========================================================================
    // 8. ECDSA P-256 + SHA-256: single-shot sign + multi-part verify
    // ========================================================================
    println!("Test 8: ECDSA P-256 SHA-256 single-shot sign → multi-part verify");
    let sig = single_shot_sign(session, CKM_ECDSA_SHA256, ec256_priv, message);
    let rv = multi_part_verify(session, CKM_ECDSA_SHA256, ec256_pub, &chunks, &sig);
    assert_eq!(
        rv, CKR_OK,
        "Multi-part verify of single-shot ECDSA P-256 sign failed"
    );

    // ========================================================================
    // 9. ECDSA P-384 + SHA-384: multi-part sign + multi-part verify
    // ========================================================================
    println!("Test 9: ECDSA P-384 SHA-384 multi-part sign → multi-part verify");
    let sig = multi_part_sign(session, CKM_ECDSA_SHA384, ec384_priv, &chunks);
    let rv = multi_part_verify(session, CKM_ECDSA_SHA384, ec384_pub, &chunks, &sig);
    assert_eq!(
        rv, CKR_OK,
        "Multi-part verify of multi-part ECDSA P-384 sign failed"
    );

    // ========================================================================
    // 10. Edge case: empty data multi-part sign + verify
    // ========================================================================
    println!("Test 10: RSA SHA-256 empty data multi-part sign → verify");
    let empty_chunks: Vec<&[u8]> = vec![b""];
    let sig = multi_part_sign(session, CKM_SHA256_RSA_PKCS, rsa_priv, &empty_chunks);
    let rv = single_shot_verify(session, CKM_SHA256_RSA_PKCS, rsa_pub, b"", &sig);
    assert_eq!(rv, CKR_OK, "Empty data multi-part sign/verify failed");

    // ========================================================================
    // 11. Edge case: single-byte chunks
    // ========================================================================
    println!("Test 11: RSA SHA-256 single-byte chunks");
    let short_msg = b"Hi!";
    let byte_chunks: Vec<&[u8]> = short_msg.iter().map(|b| std::slice::from_ref(b)).collect();
    let sig = multi_part_sign(session, CKM_SHA256_RSA_PKCS, rsa_priv, &byte_chunks);
    let rv = single_shot_verify(session, CKM_SHA256_RSA_PKCS, rsa_pub, short_msg, &sig);
    assert_eq!(rv, CKR_OK, "Single-byte chunks sign/verify failed");

    // ========================================================================
    // 12. Cross-validation: multi-part RSA PKCS#1v15 sign == single-shot
    // ========================================================================
    println!("Test 12: RSA SHA-256 cross-validation (multi-part == single-shot)");
    // For PKCS#1 v1.5 (deterministic), multi-part and single-shot should
    // produce identical signatures for the same message
    let sig_single = single_shot_sign(session, CKM_SHA256_RSA_PKCS, rsa_priv, message);
    let sig_multi = multi_part_sign(session, CKM_SHA256_RSA_PKCS, rsa_priv, &chunks);
    assert_eq!(
        sig_single, sig_multi,
        "RSA PKCS#1v15 SHA-256: single-shot and multi-part signatures should be identical"
    );

    // ========================================================================
    // 13. Error: multi-part verify with wrong data should fail
    // ========================================================================
    println!("Test 13: RSA SHA-256 multi-part verify with wrong data");
    let sig = single_shot_sign(session, CKM_SHA256_RSA_PKCS, rsa_priv, message);
    let wrong_chunks: Vec<&[u8]> = vec![b"wrong", b" data"];
    let rv = multi_part_verify(session, CKM_SHA256_RSA_PKCS, rsa_pub, &wrong_chunks, &sig);
    assert_eq!(
        rv, CKR_SIGNATURE_INVALID,
        "Multi-part verify with wrong data should fail"
    );

    // ========================================================================
    // 14. Error: C_SignUpdate without C_SignInit
    // ========================================================================
    println!("Test 14: C_SignUpdate without C_SignInit");
    let rv = C_SignUpdate(
        session,
        message.as_ptr() as CK_BYTE_PTR,
        message.len() as CK_ULONG,
    );
    assert_eq!(
        rv, CKR_OPERATION_NOT_INITIALIZED,
        "SignUpdate without SignInit should fail"
    );

    // ========================================================================
    // 15. Error: C_SignFinal without C_SignInit
    // ========================================================================
    println!("Test 15: C_SignFinal without C_SignInit");
    let mut sig_buf = vec![0u8; 512];
    let mut sig_len: CK_ULONG = sig_buf.len() as CK_ULONG;
    let rv = C_SignFinal(session, sig_buf.as_mut_ptr(), &mut sig_len);
    assert_eq!(
        rv, CKR_OPERATION_NOT_INITIALIZED,
        "SignFinal without SignInit should fail"
    );

    // ========================================================================
    // 16. Error: C_VerifyUpdate without C_VerifyInit
    // ========================================================================
    println!("Test 16: C_VerifyUpdate without C_VerifyInit");
    let rv = C_VerifyUpdate(
        session,
        message.as_ptr() as CK_BYTE_PTR,
        message.len() as CK_ULONG,
    );
    assert_eq!(
        rv, CKR_OPERATION_NOT_INITIALIZED,
        "VerifyUpdate without VerifyInit should fail"
    );

    // ========================================================================
    // 17. Error: C_VerifyFinal without C_VerifyInit
    // ========================================================================
    println!("Test 17: C_VerifyFinal without C_VerifyInit");
    let dummy_sig = vec![0u8; 256];
    let rv = C_VerifyFinal(
        session,
        dummy_sig.as_ptr() as CK_BYTE_PTR,
        dummy_sig.len() as CK_ULONG,
    );
    assert_eq!(
        rv, CKR_OPERATION_NOT_INITIALIZED,
        "VerifyFinal without VerifyInit should fail"
    );

    // ========================================================================
    // 18. Large data: 64KB in 4KB chunks
    // ========================================================================
    println!("Test 18: RSA SHA-256 large data (64KB in 4KB chunks)");
    let large_data: Vec<u8> = (0..65536u32).map(|i| (i % 256) as u8).collect();
    let large_chunks: Vec<&[u8]> = large_data.chunks(4096).collect();
    let sig = multi_part_sign(session, CKM_SHA256_RSA_PKCS, rsa_priv, &large_chunks);
    let rv = single_shot_verify(session, CKM_SHA256_RSA_PKCS, rsa_pub, &large_data, &sig);
    assert_eq!(rv, CKR_OK, "Large data multi-part sign/verify failed");

    // ========================================================================
    // 19. Large data with ECDSA: 64KB in 4KB chunks
    // ========================================================================
    println!("Test 19: ECDSA P-256 SHA-256 large data (64KB in 4KB chunks)");
    let sig = multi_part_sign(session, CKM_ECDSA_SHA256, ec256_priv, &large_chunks);
    let rv = single_shot_verify(session, CKM_ECDSA_SHA256, ec256_pub, &large_data, &sig);
    assert_eq!(rv, CKR_OK, "ECDSA large data multi-part sign/verify failed");

    // ========================================================================
    // 20. Multi-part sign with many small updates
    // ========================================================================
    println!("Test 20: RSA SHA-256 many small updates (100 chunks)");
    let many_msg: Vec<u8> = (0..100u8).collect();
    let many_chunks: Vec<&[u8]> = many_msg.iter().map(|b| std::slice::from_ref(b)).collect();
    let sig = multi_part_sign(session, CKM_SHA256_RSA_PKCS, rsa_priv, &many_chunks);
    let rv = single_shot_verify(session, CKM_SHA256_RSA_PKCS, rsa_pub, &many_msg, &sig);
    assert_eq!(rv, CKR_OK, "Many small updates sign/verify failed");

    // Cleanup
    let rv = C_Logout(session);
    assert!(rv == CKR_OK || rv == CKR_USER_NOT_LOGGED_IN);
    let rv = C_CloseSession(session);
    assert_eq!(rv, CKR_OK);

    println!("All 20 multi-part sign/verify tests passed!");
}
