// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Integration tests for PKCS#11 dual-function operations and data recovery signing/verifying:
//! - C_SignRecoverInit / C_SignRecover
//! - C_VerifyRecoverInit / C_VerifyRecover
//! - C_DigestEncryptUpdate
//! - C_DecryptDigestUpdate
//! - C_SignEncryptUpdate
//! - C_DecryptVerifyUpdate
//!
//! Must run with --test-threads=1 due to global PKCS#11 state.

use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm::pkcs11_abi::functions::*;
use craton_hsm::pkcs11_abi::types::*;
use sha2::{Digest, Sha256};
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
    label[..9].copy_from_slice(b"DualToken");
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

fn teardown_session(session: CK_SESSION_HANDLE) {
    let _ = C_CloseSession(session);
    let _ = C_Finalize(ptr::null_mut());
}

fn generate_aes_key(session: CK_SESSION_HANDLE) -> CK_OBJECT_HANDLE {
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let key_len = ck_ulong_bytes(32);
    let encrypt_true: CK_BBOOL = CK_TRUE;
    let decrypt_true: CK_BBOOL = CK_TRUE;
    let class = ck_ulong_bytes(CKO_SECRET_KEY);
    let key_type = ck_ulong_bytes(CKK_AES);

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
        CK_ATTRIBUTE {
            attr_type: CKA_VERIFY_RECOVER,
            p_value: &verify_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
    ];

    let mut priv_template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_SIGN,
            p_value: &sign_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_SIGN_RECOVER,
            p_value: &sign_true as *const _ as CK_VOID_PTR,
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
    assert_eq!(rv, CKR_OK);
    (pub_key, priv_key)
}

#[test]
fn test_rsa_sign_recover_and_verify_recover_roundtrip() {
    let session = setup_session();
    let (pub_key, priv_key) = generate_rsa_key_pair(session);

    let mut mech = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };

    let rv = C_SignRecoverInit(session, &mut mech, priv_key);
    assert_eq!(rv, CKR_OK, "C_SignRecoverInit failed");

    let message = b"Confidential recovered data payload 12345";

    // Length query
    let mut sig_len: CK_ULONG = 0;
    let rv = C_SignRecover(
        session,
        message.as_ptr() as CK_BYTE_PTR,
        message.len() as CK_ULONG,
        ptr::null_mut(),
        &mut sig_len,
    );
    assert_eq!(rv, CKR_OK);
    assert_eq!(sig_len, 256, "2048-bit RSA should have 256-byte signature");

    // Real sign recover
    let mut signature = vec![0u8; sig_len as usize];
    let rv = C_SignRecover(
        session,
        message.as_ptr() as CK_BYTE_PTR,
        message.len() as CK_ULONG,
        signature.as_mut_ptr(),
        &mut sig_len,
    );
    assert_eq!(rv, CKR_OK, "C_SignRecover failed");

    // Verify recover init
    let rv = C_VerifyRecoverInit(session, &mut mech, pub_key);
    assert_eq!(rv, CKR_OK, "C_VerifyRecoverInit failed");

    // Length query
    let mut rec_len: CK_ULONG = 0;
    let rv = C_VerifyRecover(
        session,
        signature.as_mut_ptr(),
        sig_len,
        ptr::null_mut(),
        &mut rec_len,
    );
    assert_eq!(rv, CKR_OK);
    assert_eq!(rec_len, message.len() as CK_ULONG);

    // Real verify recover
    let mut recovered = vec![0u8; rec_len as usize];
    let rv = C_VerifyRecover(
        session,
        signature.as_mut_ptr(),
        sig_len,
        recovered.as_mut_ptr(),
        &mut rec_len,
    );
    assert_eq!(rv, CKR_OK, "C_VerifyRecover failed");
    assert_eq!(&recovered[..rec_len as usize], message);

    teardown_session(session);
}

#[test]
fn test_rsa_verify_recover_corrupted_signature() {
    let session = setup_session();
    let (pub_key, priv_key) = generate_rsa_key_pair(session);

    let mut mech = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };

    let rv = C_SignRecoverInit(session, &mut mech, priv_key);
    assert_eq!(rv, CKR_OK);

    let message = b"tamper test payload";
    let mut signature = vec![0u8; 256];
    let mut sig_len = 256 as CK_ULONG;
    let rv = C_SignRecover(
        session,
        message.as_ptr() as CK_BYTE_PTR,
        message.len() as CK_ULONG,
        signature.as_mut_ptr(),
        &mut sig_len,
    );
    assert_eq!(rv, CKR_OK);

    // Corrupt signature
    signature[10] ^= 0x55;

    let rv = C_VerifyRecoverInit(session, &mut mech, pub_key);
    assert_eq!(rv, CKR_OK);

    let mut recovered = vec![0u8; 256];
    let mut rec_len = 256 as CK_ULONG;
    let rv = C_VerifyRecover(
        session,
        signature.as_mut_ptr(),
        sig_len,
        recovered.as_mut_ptr(),
        &mut rec_len,
    );
    assert_eq!(rv, CKR_SIGNATURE_INVALID);

    teardown_session(session);
}

#[test]
fn test_digest_encrypt_update_dual() {
    let session = setup_session();
    let aes_key = generate_aes_key(session);

    let iv = [0x42u8; 16];
    let mut enc_mech = CK_MECHANISM {
        mechanism: CKM_AES_CBC_PAD,
        p_parameter: iv.as_ptr() as *mut _,
        parameter_len: 16,
    };
    let mut digest_mech = CK_MECHANISM {
        mechanism: CKM_SHA256,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };

    let rv = C_EncryptInit(session, &mut enc_mech, aes_key);
    assert_eq!(rv, CKR_OK);
    let rv = C_DigestInit(session, &mut digest_mech);
    assert_eq!(rv, CKR_OK);

    let part1 = b"Part 1 of the message to encrypt and digest";
    let part2 = b", and Part 2 continues.";

    let mut enc_part = vec![0u8; 128];
    let mut enc_part_len: CK_ULONG = enc_part.len() as CK_ULONG;

    let rv = C_DigestEncryptUpdate(
        session,
        part1.as_ptr() as CK_BYTE_PTR,
        part1.len() as CK_ULONG,
        enc_part.as_mut_ptr(),
        &mut enc_part_len,
    );
    assert_eq!(rv, CKR_OK);

    let rv = C_DigestEncryptUpdate(
        session,
        part2.as_ptr() as CK_BYTE_PTR,
        part2.len() as CK_ULONG,
        enc_part.as_mut_ptr(),
        &mut enc_part_len,
    );
    assert_eq!(rv, CKR_OK);

    // Finalize Encrypt
    let mut last_enc = vec![0u8; 256];
    let mut last_enc_len: CK_ULONG = last_enc.len() as CK_ULONG;
    let rv = C_EncryptFinal(session, last_enc.as_mut_ptr(), &mut last_enc_len);
    assert_eq!(rv, CKR_OK);
    last_enc.truncate(last_enc_len as usize);

    // Finalize Digest
    let mut digest = vec![0u8; 32];
    let mut digest_len: CK_ULONG = 32;
    let rv = C_DigestFinal(session, digest.as_mut_ptr(), &mut digest_len);
    assert_eq!(rv, CKR_OK);

    // Verify digest against reference SHA-256
    let mut full_msg = Vec::new();
    full_msg.extend_from_slice(part1);
    full_msg.extend_from_slice(part2);
    let expected_digest = Sha256::digest(&full_msg);
    assert_eq!(digest.as_slice(), expected_digest.as_slice());

    // Verify ciphertext decrypts to full_msg
    let mut dec_mech = CK_MECHANISM {
        mechanism: CKM_AES_CBC_PAD,
        p_parameter: iv.as_ptr() as *mut _,
        parameter_len: 16,
    };
    let rv = C_DecryptInit(session, &mut dec_mech, aes_key);
    assert_eq!(rv, CKR_OK);
    let mut decrypted = vec![0u8; 256];
    let mut dec_len: CK_ULONG = decrypted.len() as CK_ULONG;
    let rv = C_Decrypt(
        session,
        last_enc.as_ptr() as CK_BYTE_PTR,
        last_enc.len() as CK_ULONG,
        decrypted.as_mut_ptr(),
        &mut dec_len,
    );
    assert_eq!(rv, CKR_OK);
    assert_eq!(&decrypted[..dec_len as usize], &full_msg);

    teardown_session(session);
}

#[test]
fn test_decrypt_digest_update_dual() {
    let session = setup_session();
    let aes_key = generate_aes_key(session);

    let iv = [0x77u8; 16];
    let plaintext = b"Plaintext payload that will be decrypted and digested simultaneously!";

    // Encrypt first
    let mut enc_mech = CK_MECHANISM {
        mechanism: CKM_AES_CBC_PAD,
        p_parameter: iv.as_ptr() as *mut _,
        parameter_len: 16,
    };
    let rv = C_EncryptInit(session, &mut enc_mech, aes_key);
    assert_eq!(rv, CKR_OK);
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
    ciphertext.truncate(ct_len as usize);

    // Now test C_DecryptDigestUpdate
    let mut dec_mech = CK_MECHANISM {
        mechanism: CKM_AES_CBC_PAD,
        p_parameter: iv.as_ptr() as *mut _,
        parameter_len: 16,
    };
    let mut digest_mech = CK_MECHANISM {
        mechanism: CKM_SHA256,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };

    let rv = C_DecryptInit(session, &mut dec_mech, aes_key);
    assert_eq!(rv, CKR_OK);
    let rv = C_DigestInit(session, &mut digest_mech);
    assert_eq!(rv, CKR_OK);

    let mut decrypted = vec![0u8; 256];
    let mut dec_len: CK_ULONG = decrypted.len() as CK_ULONG;
    let rv = C_DecryptDigestUpdate(
        session,
        ciphertext.as_ptr() as CK_BYTE_PTR,
        ciphertext.len() as CK_ULONG,
        decrypted.as_mut_ptr(),
        &mut dec_len,
    );
    assert_eq!(rv, CKR_OK);
    assert_eq!(&decrypted[..dec_len as usize], plaintext);

    // Finalize digest
    let mut digest = vec![0u8; 32];
    let mut digest_len: CK_ULONG = 32;
    let rv = C_DigestFinal(session, digest.as_mut_ptr(), &mut digest_len);
    assert_eq!(rv, CKR_OK);

    let expected_digest = Sha256::digest(plaintext);
    assert_eq!(digest.as_slice(), expected_digest.as_slice());

    teardown_session(session);
}

#[test]
fn test_sign_encrypt_update_dual() {
    let session = setup_session();
    let (rsa_pub, rsa_priv) = generate_rsa_key_pair(session);
    let aes_key = generate_aes_key(session);

    let iv = [0x99u8; 16];
    let mut sign_mech = CK_MECHANISM {
        mechanism: CKM_SHA256_RSA_PKCS,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let mut enc_mech = CK_MECHANISM {
        mechanism: CKM_AES_CBC_PAD,
        p_parameter: iv.as_ptr() as *mut _,
        parameter_len: 16,
    };

    let rv = C_EncryptInit(session, &mut enc_mech, aes_key);
    assert_eq!(rv, CKR_OK);
    let rv = C_SignInit(session, &mut sign_mech, rsa_priv);
    assert_eq!(rv, CKR_OK);

    let msg = b"Authenticated and confidential message!";
    let mut enc_out = vec![0u8; 128];
    let mut enc_out_len: CK_ULONG = 128;

    let rv = C_SignEncryptUpdate(
        session,
        msg.as_ptr() as CK_BYTE_PTR,
        msg.len() as CK_ULONG,
        enc_out.as_mut_ptr(),
        &mut enc_out_len,
    );
    assert_eq!(rv, CKR_OK);

    // Finalize Sign
    let mut signature = vec![0u8; 256];
    let mut sig_len: CK_ULONG = 256;
    let rv = C_SignFinal(session, signature.as_mut_ptr(), &mut sig_len);
    assert_eq!(rv, CKR_OK);

    // Finalize Encrypt
    let mut last_enc = vec![0u8; 256];
    let mut last_enc_len: CK_ULONG = 256;
    let rv = C_EncryptFinal(session, last_enc.as_mut_ptr(), &mut last_enc_len);
    assert_eq!(rv, CKR_OK);
    last_enc.truncate(last_enc_len as usize);

    // Verify signature
    let mut verify_mech = CK_MECHANISM {
        mechanism: CKM_SHA256_RSA_PKCS,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_VerifyInit(session, &mut verify_mech, rsa_pub);
    assert_eq!(rv, CKR_OK);
    let rv = C_Verify(
        session,
        msg.as_ptr() as CK_BYTE_PTR,
        msg.len() as CK_ULONG,
        signature.as_mut_ptr(),
        sig_len,
    );
    assert_eq!(rv, CKR_OK, "Signature should verify successfully");

    // Decrypt ciphertext
    let mut dec_mech = CK_MECHANISM {
        mechanism: CKM_AES_CBC_PAD,
        p_parameter: iv.as_ptr() as *mut _,
        parameter_len: 16,
    };
    let rv = C_DecryptInit(session, &mut dec_mech, aes_key);
    assert_eq!(rv, CKR_OK);
    let mut decrypted = vec![0u8; 256];
    let mut dec_len: CK_ULONG = 256;
    let rv = C_Decrypt(
        session,
        last_enc.as_ptr() as CK_BYTE_PTR,
        last_enc.len() as CK_ULONG,
        decrypted.as_mut_ptr(),
        &mut dec_len,
    );
    assert_eq!(rv, CKR_OK);
    assert_eq!(&decrypted[..dec_len as usize], msg);

    teardown_session(session);
}

#[test]
fn test_decrypt_verify_update_dual() {
    let session = setup_session();
    let (rsa_pub, rsa_priv) = generate_rsa_key_pair(session);
    let aes_key = generate_aes_key(session);

    let iv = [0x55u8; 16];
    let msg = b"Payload to decrypt and verify in one operation!";

    // Sign msg
    let mut sign_mech = CK_MECHANISM {
        mechanism: CKM_SHA256_RSA_PKCS,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_SignInit(session, &mut sign_mech, rsa_priv);
    assert_eq!(rv, CKR_OK);
    let mut signature = vec![0u8; 256];
    let mut sig_len: CK_ULONG = 256;
    let rv = C_Sign(
        session,
        msg.as_ptr() as CK_BYTE_PTR,
        msg.len() as CK_ULONG,
        signature.as_mut_ptr(),
        &mut sig_len,
    );
    assert_eq!(rv, CKR_OK);

    // Encrypt msg
    let mut enc_mech = CK_MECHANISM {
        mechanism: CKM_AES_CBC_PAD,
        p_parameter: iv.as_ptr() as *mut _,
        parameter_len: 16,
    };
    let rv = C_EncryptInit(session, &mut enc_mech, aes_key);
    assert_eq!(rv, CKR_OK);
    let mut ciphertext = vec![0u8; 256];
    let mut ct_len: CK_ULONG = 256;
    let rv = C_Encrypt(
        session,
        msg.as_ptr() as CK_BYTE_PTR,
        msg.len() as CK_ULONG,
        ciphertext.as_mut_ptr(),
        &mut ct_len,
    );
    assert_eq!(rv, CKR_OK);
    ciphertext.truncate(ct_len as usize);

    // Dual Decrypt + Verify
    let mut dec_mech = CK_MECHANISM {
        mechanism: CKM_AES_CBC_PAD,
        p_parameter: iv.as_ptr() as *mut _,
        parameter_len: 16,
    };
    let mut verify_mech = CK_MECHANISM {
        mechanism: CKM_SHA256_RSA_PKCS,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };

    let rv = C_DecryptInit(session, &mut dec_mech, aes_key);
    assert_eq!(rv, CKR_OK);
    let rv = C_VerifyInit(session, &mut verify_mech, rsa_pub);
    assert_eq!(rv, CKR_OK);

    let mut decrypted = vec![0u8; 256];
    let mut dec_len: CK_ULONG = 256;
    let rv = C_DecryptVerifyUpdate(
        session,
        ciphertext.as_ptr() as CK_BYTE_PTR,
        ciphertext.len() as CK_ULONG,
        decrypted.as_mut_ptr(),
        &mut dec_len,
    );
    assert_eq!(rv, CKR_OK);
    assert_eq!(&decrypted[..dec_len as usize], msg);

    // Verify Final
    let rv = C_VerifyFinal(session, signature.as_mut_ptr(), sig_len);
    assert_eq!(rv, CKR_OK, "C_VerifyFinal should succeed");

    teardown_session(session);
}

#[test]
fn test_dual_operations_uninitialized_errors() {
    let session = setup_session();

    let mut buf = vec![0u8; 64];
    let mut len: CK_ULONG = 64;

    // None initialized -> CKR_OPERATION_NOT_INITIALIZED
    assert_eq!(
        C_DigestEncryptUpdate(session, buf.as_mut_ptr(), 16, buf.as_mut_ptr(), &mut len),
        CKR_OPERATION_NOT_INITIALIZED
    );
    assert_eq!(
        C_DecryptDigestUpdate(session, buf.as_mut_ptr(), 16, buf.as_mut_ptr(), &mut len),
        CKR_OPERATION_NOT_INITIALIZED
    );
    assert_eq!(
        C_SignEncryptUpdate(session, buf.as_mut_ptr(), 16, buf.as_mut_ptr(), &mut len),
        CKR_OPERATION_NOT_INITIALIZED
    );
    assert_eq!(
        C_DecryptVerifyUpdate(session, buf.as_mut_ptr(), 16, buf.as_mut_ptr(), &mut len),
        CKR_OPERATION_NOT_INITIALIZED
    );
    assert_eq!(
        C_SignRecover(session, buf.as_mut_ptr(), 16, buf.as_mut_ptr(), &mut len),
        CKR_OPERATION_NOT_INITIALIZED
    );
    assert_eq!(
        C_VerifyRecover(session, buf.as_mut_ptr(), 16, buf.as_mut_ptr(), &mut len),
        CKR_OPERATION_NOT_INITIALIZED
    );

    teardown_session(session);
}

#[test]
fn test_rsa_sign_recover_buffer_too_small_preserves_op() {
    let session = setup_session();
    let (_rsa_pub, rsa_priv) = generate_rsa_key_pair(session);

    let mut sign_mech = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };

    let rv = C_SignRecoverInit(session, &mut sign_mech, rsa_priv);
    assert_eq!(rv, CKR_OK);

    let msg = b"data to sign and recover";
    let mut sig_buf = vec![0u8; 10]; // Intentionally too small
    let mut sig_len: CK_ULONG = sig_buf.len() as CK_ULONG;

    let rv = C_SignRecover(
        session,
        msg.as_ptr() as CK_BYTE_PTR,
        msg.len() as CK_ULONG,
        sig_buf.as_mut_ptr(),
        &mut sig_len,
    );
    assert_eq!(rv, CKR_BUFFER_TOO_SMALL);
    assert!(sig_len >= 256);

    // Operation must be preserved so we can allocate and retry
    let mut full_sig_buf = vec![0u8; sig_len as usize];
    let rv = C_SignRecover(
        session,
        msg.as_ptr() as CK_BYTE_PTR,
        msg.len() as CK_ULONG,
        full_sig_buf.as_mut_ptr(),
        &mut sig_len,
    );
    assert_eq!(rv, CKR_OK);

    teardown_session(session);
}

#[test]
fn test_decrypt_digest_update_multipart_cbc() {
    let session = setup_session();
    let aes_key = generate_aes_key(session);

    let iv = [0x42u8; 16];
    let plaintext = b"0123456789abcdef0123456789abcdef"; // exactly 32 bytes (2 blocks)

    let mut enc_mech = CK_MECHANISM {
        mechanism: CKM_AES_CBC,
        p_parameter: iv.as_ptr() as *mut _,
        parameter_len: 16,
    };

    let rv = C_EncryptInit(session, &mut enc_mech, aes_key);
    assert_eq!(rv, CKR_OK);

    let mut ciphertext = vec![0u8; 32];
    let mut ct_len: CK_ULONG = 32;
    let rv = C_Encrypt(
        session,
        plaintext.as_ptr() as CK_BYTE_PTR,
        plaintext.len() as CK_ULONG,
        ciphertext.as_mut_ptr(),
        &mut ct_len,
    );
    assert_eq!(rv, CKR_OK);

    let mut dec_mech = CK_MECHANISM {
        mechanism: CKM_AES_CBC,
        p_parameter: iv.as_ptr() as *mut _,
        parameter_len: 16,
    };
    let mut digest_mech = CK_MECHANISM {
        mechanism: CKM_SHA256,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };

    let rv = C_DecryptInit(session, &mut dec_mech, aes_key);
    assert_eq!(rv, CKR_OK);
    let rv = C_DigestInit(session, &mut digest_mech);
    assert_eq!(rv, CKR_OK);

    // Multi-part update: chunk 1 (16 bytes)
    let mut part1 = vec![0u8; 16];
    let mut part1_len: CK_ULONG = 16;
    let rv = C_DecryptDigestUpdate(
        session,
        ciphertext[..16].as_ptr() as CK_BYTE_PTR,
        16,
        part1.as_mut_ptr(),
        &mut part1_len,
    );
    assert_eq!(rv, CKR_OK);
    assert_eq!(&part1[..part1_len as usize], &plaintext[..16]);

    // Multi-part update: chunk 2 (16 bytes) — requires IV progression from chunk 1
    let mut part2 = vec![0u8; 16];
    let mut part2_len: CK_ULONG = 16;
    let rv = C_DecryptDigestUpdate(
        session,
        ciphertext[16..].as_ptr() as CK_BYTE_PTR,
        16,
        part2.as_mut_ptr(),
        &mut part2_len,
    );
    assert_eq!(rv, CKR_OK);
    assert_eq!(&part2[..part2_len as usize], &plaintext[16..]);

    let mut digest = vec![0u8; 32];
    let mut digest_len: CK_ULONG = 32;
    let rv = C_DigestFinal(session, digest.as_mut_ptr(), &mut digest_len);
    assert_eq!(rv, CKR_OK);

    let expected_digest = Sha256::digest(plaintext);
    assert_eq!(digest.as_slice(), expected_digest.as_slice());

    teardown_session(session);
}

#[test]
fn test_decrypt_digest_update_multipart_cbc_pad() {
    let session = setup_session();
    let aes_key = generate_aes_key(session);

    let iv = [0x55u8; 16];
    let plaintext = b"0123456789abcdef0123456789abcdef"; // 32 bytes

    let mut enc_mech = CK_MECHANISM {
        mechanism: CKM_AES_CBC_PAD,
        p_parameter: iv.as_ptr() as *mut _,
        parameter_len: 16,
    };

    let rv = C_EncryptInit(session, &mut enc_mech, aes_key);
    assert_eq!(rv, CKR_OK);

    let mut ciphertext = vec![0u8; 64];
    let mut ct_len: CK_ULONG = 64;
    let rv = C_Encrypt(
        session,
        plaintext.as_ptr() as CK_BYTE_PTR,
        plaintext.len() as CK_ULONG,
        ciphertext.as_mut_ptr(),
        &mut ct_len,
    );
    assert_eq!(rv, CKR_OK);
    assert_eq!(ct_len, 48); // 32 bytes data + 16 bytes padding block

    let mut dec_mech = CK_MECHANISM {
        mechanism: CKM_AES_CBC_PAD,
        p_parameter: iv.as_ptr() as *mut _,
        parameter_len: 16,
    };
    let mut digest_mech = CK_MECHANISM {
        mechanism: CKM_SHA256,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };

    let rv = C_DecryptInit(session, &mut dec_mech, aes_key);
    assert_eq!(rv, CKR_OK);
    let rv = C_DigestInit(session, &mut digest_mech);
    assert_eq!(rv, CKR_OK);

    // Chunk 1 (16 bytes intermediate)
    let mut part1 = vec![0u8; 32];
    let mut part1_len: CK_ULONG = 32;
    let rv = C_DecryptDigestUpdate(
        session,
        ciphertext[..16].as_ptr() as CK_BYTE_PTR,
        16,
        part1.as_mut_ptr(),
        &mut part1_len,
    );
    assert_eq!(rv, CKR_OK);
    assert_eq!(&part1[..part1_len as usize], &plaintext[..16]);

    // Chunk 2 (16 bytes intermediate)
    let mut part2 = vec![0u8; 32];
    let mut part2_len: CK_ULONG = 32;
    let rv = C_DecryptDigestUpdate(
        session,
        ciphertext[16..32].as_ptr() as CK_BYTE_PTR,
        16,
        part2.as_mut_ptr(),
        &mut part2_len,
    );
    assert_eq!(rv, CKR_OK);
    assert_eq!(&part2[..part2_len as usize], &plaintext[16..32]);

    // Chunk 3 (16 bytes padding block)
    let mut part3 = vec![0u8; 32];
    let mut part3_len: CK_ULONG = 32;
    let rv = C_DecryptDigestUpdate(
        session,
        ciphertext[32..48].as_ptr() as CK_BYTE_PTR,
        16,
        part3.as_mut_ptr(),
        &mut part3_len,
    );
    assert_eq!(rv, CKR_OK);
    assert_eq!(part3_len, 0); // padding removed

    let mut digest = vec![0u8; 32];
    let mut digest_len: CK_ULONG = 32;
    let rv = C_DigestFinal(session, digest.as_mut_ptr(), &mut digest_len);
    assert_eq!(rv, CKR_OK);

    let expected_digest = Sha256::digest(plaintext);
    assert_eq!(digest.as_slice(), expected_digest.as_slice());

    teardown_session(session);
}

#[test]
fn test_rsa_sign_recover_disallowed_by_template_attribute() {
    let session = setup_session();

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let modulus_bits = ck_ulong_bytes(2048);
    let sign_true: CK_BBOOL = CK_TRUE;
    let sign_recover_false: CK_BBOOL = CK_FALSE;
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

    let mut priv_template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_SIGN,
            p_value: &sign_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_SIGN_RECOVER,
            p_value: &sign_recover_false as *const _ as CK_VOID_PTR,
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
    assert_eq!(rv, CKR_OK);

    let mut sign_mech = CK_MECHANISM {
        mechanism: CKM_SHA256_RSA_PKCS,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };

    // Standard C_SignInit should succeed because CKA_SIGN is true
    let rv = C_SignInit(session, &mut sign_mech, priv_key);
    assert_eq!(rv, CKR_OK);
    let mut sig = vec![0u8; 256];
    let mut sig_len: CK_ULONG = 256;
    let _ = C_Sign(session, b"test".as_ptr() as *mut _, 4, sig.as_mut_ptr(), &mut sig_len);

    let mut recover_mech = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };

    // C_SignRecoverInit must fail because CKA_SIGN_RECOVER is explicitly false
    let rv = C_SignRecoverInit(session, &mut recover_mech, priv_key);
    assert_eq!(rv, CKR_KEY_FUNCTION_NOT_PERMITTED);

    teardown_session(session);
}

#[test]
fn test_get_operation_state_returns_unsaveable_on_concurrent_dual_operation() {
    let session = setup_session();
    let aes_key = generate_aes_key(session);

    let iv = [0x55u8; 16];
    let mut dec_mech = CK_MECHANISM {
        mechanism: CKM_AES_CBC_PAD,
        p_parameter: iv.as_ptr() as *mut _,
        parameter_len: 16,
    };
    let mut digest_mech = CK_MECHANISM {
        mechanism: CKM_SHA256,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };

    let rv = C_DecryptInit(session, &mut dec_mech, aes_key);
    assert_eq!(rv, CKR_OK);
    let rv = C_DigestInit(session, &mut digest_mech);
    assert_eq!(rv, CKR_OK);

    // Both decrypt and digest active concurrently: C_GetOperationState must return CKR_STATE_UNSAVEABLE
    let mut state_len: CK_ULONG = 0;
    let rv = C_GetOperationState(session, ptr::null_mut(), &mut state_len);
    assert_eq!(rv, CKR_STATE_UNSAVEABLE);

    teardown_session(session);
}
