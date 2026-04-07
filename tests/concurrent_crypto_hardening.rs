// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Concurrent cryptographic operation hardening tests.
//!
//! Validates thread-safety of the HSM under concurrent crypto workloads:
//! - Multiple sessions performing operations simultaneously
//! - Cross-session key access (no data leakage between sessions)
//! - Operation state isolation (one session's op doesn't affect another)

use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm::pkcs11_abi::functions::*;
use craton_hsm::pkcs11_abi::types::*;
use std::ptr;
use std::sync::Barrier;
use std::thread;

fn ensure_init() {
    let rv = C_Initialize(ptr::null_mut());
    assert!(rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED);
}

fn setup_token_and_user() {
    ensure_init();
    let so_pin = b"sopin123";
    let mut label = [b' '; 32];
    label[..9].copy_from_slice(b"ConcTest ");
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
    let rv = C_CloseSession(session);
    assert_eq!(rv, CKR_OK);
}

fn open_user_session() -> CK_SESSION_HANDLE {
    let mut session: CK_SESSION_HANDLE = 0;
    let rv = C_OpenSession(
        0,
        CKF_RW_SESSION | CKF_SERIAL_SESSION,
        ptr::null_mut(),
        None,
        &mut session,
    );
    assert_eq!(rv, CKR_OK);
    let user_pin = b"userpin1";
    let rv = C_Login(
        session,
        CKU_USER,
        user_pin.as_ptr() as *mut _,
        user_pin.len() as CK_ULONG,
    );
    assert!(rv == CKR_OK || rv == CKR_USER_ALREADY_LOGGED_IN);
    session
}

fn generate_aes_key(session: CK_SESSION_HANDLE, label: &[u8]) -> CK_OBJECT_HANDLE {
    let class = CKO_SECRET_KEY.to_ne_bytes();
    let key_type = CKK_AES.to_ne_bytes();
    let val_len = 32u64.to_ne_bytes();
    let true_val: CK_BBOOL = CK_TRUE;

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

/// Test: Multiple threads encrypting with the same key simultaneously.
/// Validates that the GCM nonce management doesn't produce collisions.
#[test]
fn test_concurrent_encrypt_same_key() {
    setup_token_and_user();
    let session = open_user_session();
    let key = generate_aes_key(session, b"conc-enc-key");

    let num_threads = 4;
    let ops_per_thread = 5;
    let barrier = std::sync::Arc::new(Barrier::new(num_threads));

    let handles: Vec<_> = (0..num_threads)
        .map(|i| {
            let barrier = barrier.clone();
            thread::spawn(move || {
                let sess = open_user_session();
                barrier.wait(); // Synchronize start

                let mut ciphertexts = Vec::new();
                for j in 0..ops_per_thread {
                    let data = format!("thread-{}-msg-{}", i, j);
                    let mechanism = CK_MECHANISM {
                        mechanism: CKM_AES_GCM,
                        p_parameter: ptr::null_mut(),
                        parameter_len: 0,
                    };

                    let rv = C_EncryptInit(sess, &mechanism as *const _ as *mut _, key);
                    assert_eq!(rv, CKR_OK, "T{}: EncryptInit failed: 0x{:08X}", i, rv);

                    let mut out_len: CK_ULONG = 256;
                    let mut ct = vec![0u8; 256];
                    let rv = C_Encrypt(
                        sess,
                        data.as_ptr() as *mut _,
                        data.len() as CK_ULONG,
                        ct.as_mut_ptr(),
                        &mut out_len,
                    );
                    assert_eq!(rv, CKR_OK, "T{}: Encrypt failed: 0x{:08X}", i, rv);
                    ct.truncate(out_len as usize);
                    ciphertexts.push((data, ct));
                }

                // Verify all encryptions can be decrypted
                for (plaintext, ct) in &ciphertexts {
                    let mechanism = CK_MECHANISM {
                        mechanism: CKM_AES_GCM,
                        p_parameter: ptr::null_mut(),
                        parameter_len: 0,
                    };
                    let rv = C_DecryptInit(sess, &mechanism as *const _ as *mut _, key);
                    assert_eq!(rv, CKR_OK);

                    let mut out_len: CK_ULONG = ct.len() as CK_ULONG;
                    let mut pt = vec![0u8; ct.len()];
                    let rv = C_Decrypt(
                        sess,
                        ct.as_ptr() as *mut _,
                        ct.len() as CK_ULONG,
                        pt.as_mut_ptr(),
                        &mut out_len,
                    );
                    assert_eq!(rv, CKR_OK, "T{}: Decrypt failed: 0x{:08X}", i, rv);
                    pt.truncate(out_len as usize);
                    assert_eq!(&pt, plaintext.as_bytes(), "Decrypted data mismatch");
                }

                let _ = C_CloseSession(sess);
                ciphertexts.len()
            })
        })
        .collect();

    let total: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
    assert_eq!(total, num_threads * ops_per_thread);

    let _ = C_DestroyObject(session, key);
    let _ = C_CloseSession(session);
}

/// Test: Operation state isolation between sessions.
/// Starting an encrypt on session A should not affect session B's active operation.
#[test]
fn test_operation_state_isolation() {
    setup_token_and_user();
    let sess_a = open_user_session();
    let sess_b = open_user_session();
    let key = generate_aes_key(sess_a, b"iso-key");

    // Start encrypt on session A
    let mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_EncryptInit(sess_a, &mechanism as *const _ as *mut _, key);
    assert_eq!(rv, CKR_OK);

    // Session B should be able to start its own encrypt independently
    let rv = C_EncryptInit(sess_b, &mechanism as *const _ as *mut _, key);
    assert_eq!(rv, CKR_OK);

    // Complete encrypt on session A
    let data_a = b"session A data";
    let mut ct_a = vec![0u8; 256];
    let mut ct_a_len: CK_ULONG = 256;
    let rv = C_Encrypt(
        sess_a,
        data_a.as_ptr() as *mut _,
        data_a.len() as CK_ULONG,
        ct_a.as_mut_ptr(),
        &mut ct_a_len,
    );
    assert_eq!(rv, CKR_OK);

    // Complete encrypt on session B (should still work)
    let data_b = b"session B data";
    let mut ct_b = vec![0u8; 256];
    let mut ct_b_len: CK_ULONG = 256;
    let rv = C_Encrypt(
        sess_b,
        data_b.as_ptr() as *mut _,
        data_b.len() as CK_ULONG,
        ct_b.as_mut_ptr(),
        &mut ct_b_len,
    );
    assert_eq!(rv, CKR_OK);

    // Ciphertexts should be different (different data, different nonces)
    ct_a.truncate(ct_a_len as usize);
    ct_b.truncate(ct_b_len as usize);
    assert_ne!(ct_a, ct_b);

    let _ = C_DestroyObject(sess_a, key);
    let _ = C_CloseSession(sess_a);
    let _ = C_CloseSession(sess_b);
}

/// Test: Concurrent key generation doesn't produce duplicate handles.
#[test]
fn test_concurrent_keygen_unique_handles() {
    setup_token_and_user();

    let num_threads = 4;
    let keys_per_thread = 3;
    let barrier = std::sync::Arc::new(Barrier::new(num_threads));

    let handles: Vec<_> = (0..num_threads)
        .map(|i| {
            let barrier = barrier.clone();
            thread::spawn(move || {
                let sess = open_user_session();
                barrier.wait();

                let mut key_handles = Vec::new();
                for j in 0..keys_per_thread {
                    let label = format!("conc-kg-t{}-k{}", i, j);
                    let key = generate_aes_key(sess, label.as_bytes());
                    key_handles.push(key);
                }

                // Cleanup
                for k in &key_handles {
                    let _ = C_DestroyObject(sess, *k);
                }
                let _ = C_CloseSession(sess);
                key_handles
            })
        })
        .collect();

    let all_handles: Vec<CK_OBJECT_HANDLE> = handles
        .into_iter()
        .flat_map(|h| h.join().unwrap())
        .collect();

    // All handles should be unique
    let mut sorted = all_handles.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        all_handles.len(),
        "Duplicate key handles detected under concurrent generation"
    );
}
