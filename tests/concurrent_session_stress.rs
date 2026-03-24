// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
// Concurrent session stress tests — exercises session/object management under
// multi-threaded contention at the C ABI level.
//
// Must run with --test-threads=1 relative to other PKCS#11 ABI test files
// (shared global state), but individual tests here spawn their own threads.

use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm::pkcs11_abi::functions::*;
use craton_hsm::pkcs11_abi::types::*;
use std::collections::HashSet;
use std::ptr;
use std::sync::{Arc, Barrier};

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

/// Re-initialize token, open RW session, set up user PIN and login.
fn setup_user_session() -> CK_SESSION_HANDLE {
    ensure_init();
    let so_pin = b"sopin123";
    let mut label = [b' '; 32];
    label[..9].copy_from_slice(b"ConcTests");
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

#[test]
fn test_concurrent_session_open_close() {
    let _ = setup_user_session();
    C_CloseAllSessions(0);

    // Re-init token for clean state
    ensure_init();
    let so_pin = b"sopin123";
    let mut label = [b' '; 32];
    label[..7].copy_from_slice(b"ConcOC1");
    C_InitToken(
        0,
        so_pin.as_ptr() as *mut _,
        so_pin.len() as CK_ULONG,
        label.as_ptr() as *mut _,
    );

    let num_threads = 10;
    let ops_per_thread = 5;
    let barrier = Arc::new(Barrier::new(num_threads));

    let handles: Vec<_> = (0..num_threads)
        .map(|_| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let mut sessions = Vec::new();
                for _ in 0..ops_per_thread {
                    let mut session: CK_SESSION_HANDLE = 0;
                    let rv = C_OpenSession(
                        0,
                        CKF_RW_SESSION | CKF_SERIAL_SESSION,
                        ptr::null_mut(),
                        None,
                        &mut session,
                    );
                    if rv == CKR_OK {
                        sessions.push(session);
                    }
                    // Don't assert — session count limit may be reached
                }
                for s in sessions {
                    let _ = C_CloseSession(s);
                }
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }

    // Cleanup
    C_CloseAllSessions(0);
}

#[test]
fn test_concurrent_object_create_find_destroy() {
    let session = setup_user_session();

    let num_threads = 5;
    let objects_per_thread = 4;
    let barrier = Arc::new(Barrier::new(num_threads));

    let handles: Vec<_> = (0..num_threads)
        .map(|tid| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let mut created = Vec::new();
                for i in 0..objects_per_thread {
                    let value_len_bytes = ck_ulong_bytes(32);
                    let ck_true: CK_BBOOL = CK_TRUE;
                    let label = format!("t{}-k{}", tid, i);
                    let label_bytes = label.as_bytes().to_vec();
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
                            p_value: label_bytes.as_ptr() as CK_VOID_PTR,
                            value_len: label_bytes.len() as CK_ULONG,
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
                    if rv == CKR_OK {
                        created.push(key);
                    }
                }
                // Find objects
                let rv = C_FindObjectsInit(session, ptr::null_mut(), 0);
                if rv == CKR_OK {
                    let mut found: [CK_OBJECT_HANDLE; 100] = [0; 100];
                    let mut found_count: CK_ULONG = 0;
                    let _ = C_FindObjects(session, found.as_mut_ptr(), 100, &mut found_count);
                    C_FindObjectsFinal(session);
                }
                // Destroy our objects
                for h in &created {
                    let _ = C_DestroyObject(session, *h);
                }
                created.len()
            })
        })
        .collect();

    let total_created: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
    assert!(
        total_created > 0,
        "Should have created at least some objects"
    );
}

#[test]
fn test_session_handle_uniqueness_under_contention() {
    let _ = setup_user_session();
    C_CloseAllSessions(0);

    ensure_init();
    let so_pin = b"sopin123";
    let mut label = [b' '; 32];
    label[..6].copy_from_slice(b"Unique");
    C_InitToken(
        0,
        so_pin.as_ptr() as *mut _,
        so_pin.len() as CK_ULONG,
        label.as_ptr() as *mut _,
    );

    let num_threads = 10;
    let sessions_per_thread = 3;
    let barrier = Arc::new(Barrier::new(num_threads));

    let handles: Vec<_> = (0..num_threads)
        .map(|_| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let mut sessions = Vec::new();
                for _ in 0..sessions_per_thread {
                    let mut session: CK_SESSION_HANDLE = 0;
                    let rv = C_OpenSession(
                        0,
                        CKF_RW_SESSION | CKF_SERIAL_SESSION,
                        ptr::null_mut(),
                        None,
                        &mut session,
                    );
                    if rv == CKR_OK {
                        sessions.push(session);
                    }
                }
                sessions
            })
        })
        .collect();

    let mut all_handles = Vec::new();
    for h in handles {
        all_handles.extend(h.join().unwrap());
    }

    // All handles should be unique
    let unique: HashSet<_> = all_handles.iter().collect();
    assert_eq!(
        unique.len(),
        all_handles.len(),
        "Session handles must be unique"
    );

    C_CloseAllSessions(0);
}

#[test]
fn test_concurrent_encrypt_different_sessions() {
    let _ = setup_user_session();

    // Generate a shared AES key
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

    // Use the initial session for keygen
    let mut setup_session: CK_SESSION_HANDLE = 0;
    let rv = C_OpenSession(
        0,
        CKF_RW_SESSION | CKF_SERIAL_SESSION,
        ptr::null_mut(),
        None,
        &mut setup_session,
    );
    if rv != CKR_OK {
        return; // session limit — skip test
    }

    let mut key: CK_OBJECT_HANDLE = 0;
    let rv = C_GenerateKey(
        setup_session,
        &mut mechanism,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut key,
    );
    assert_eq!(rv, CKR_OK);
    let _ = C_CloseSession(setup_session);

    let num_threads = 5;
    let barrier = Arc::new(Barrier::new(num_threads));

    let handles: Vec<_> = (0..num_threads)
        .map(|_| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();

                // Each thread opens its own session
                let mut session: CK_SESSION_HANDLE = 0;
                let rv = C_OpenSession(
                    0,
                    CKF_RW_SESSION | CKF_SERIAL_SESSION,
                    ptr::null_mut(),
                    None,
                    &mut session,
                );
                if rv != CKR_OK {
                    return false; // session limit
                }
                let user_pin = b"userpin1";
                let rv = C_Login(
                    session,
                    CKU_USER,
                    user_pin.as_ptr() as *mut _,
                    user_pin.len() as CK_ULONG,
                );
                // May be ALREADY_LOGGED_IN from another thread
                if rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN {
                    C_CloseSession(session);
                    return false;
                }

                // Encrypt something
                let mut enc_mech = CK_MECHANISM {
                    mechanism: CKM_AES_GCM,
                    p_parameter: ptr::null_mut(),
                    parameter_len: 0,
                };
                let rv = C_EncryptInit(session, &mut enc_mech, key);
                if rv != CKR_OK {
                    C_CloseSession(session);
                    return false;
                }

                let data = b"concurrent encryption test data!!";
                let mut out = vec![0u8; 256];
                let mut out_len: CK_ULONG = out.len() as CK_ULONG;
                let rv = C_Encrypt(
                    session,
                    data.as_ptr() as CK_BYTE_PTR,
                    data.len() as CK_ULONG,
                    out.as_mut_ptr(),
                    &mut out_len,
                );

                C_CloseSession(session);
                rv == CKR_OK
            })
        })
        .collect();

    let success_count: usize = handles
        .into_iter()
        .map(|h| if h.join().unwrap() { 1 } else { 0 })
        .sum();

    // At least some threads should succeed
    assert!(
        success_count > 0,
        "At least one concurrent encryption should succeed"
    );
}

#[test]
fn test_concurrent_find_objects_while_creating() {
    let session = setup_user_session();

    let num_writers = 3;
    let num_readers = 3;
    let barrier = Arc::new(Barrier::new(num_writers + num_readers));

    // Writer threads: create objects
    let mut writer_handles = Vec::new();
    for tid in 0..num_writers {
        let barrier = barrier.clone();
        let h = std::thread::spawn(move || {
            barrier.wait();
            for i in 0..3 {
                let value_len_bytes = ck_ulong_bytes(32);
                let ck_true: CK_BBOOL = CK_TRUE;
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
                ];
                let mut key: CK_OBJECT_HANDLE = 0;
                let _ = C_GenerateKey(
                    session,
                    &mut mechanism,
                    template.as_mut_ptr(),
                    template.len() as CK_ULONG,
                    &mut key,
                );
            }
        });
        writer_handles.push(h);
    }

    // Reader threads: find objects
    let mut reader_handles = Vec::new();
    for _ in 0..num_readers {
        let barrier = barrier.clone();
        let h = std::thread::spawn(move || {
            barrier.wait();
            let mut total_found: CK_ULONG = 0;
            for _ in 0..5 {
                let rv = C_FindObjectsInit(session, ptr::null_mut(), 0);
                if rv == CKR_OK {
                    let mut found: [CK_OBJECT_HANDLE; 100] = [0; 100];
                    let mut found_count: CK_ULONG = 0;
                    let rv = C_FindObjects(session, found.as_mut_ptr(), 100, &mut found_count);
                    if rv == CKR_OK {
                        total_found = total_found.wrapping_add(found_count);
                    }
                    C_FindObjectsFinal(session);
                }
            }
            total_found
        });
        reader_handles.push(h);
    }

    for h in writer_handles {
        h.join().unwrap();
    }
    for h in reader_handles {
        let _ = h.join().unwrap(); // Just ensure no panics
    }
}

#[test]
fn test_concurrent_session_login_logout() {
    let _ = setup_user_session();
    C_CloseAllSessions(0);

    ensure_init();
    let so_pin = b"sopin123";
    let mut label = [b' '; 32];
    label[..8].copy_from_slice(b"LoginOut");
    C_InitToken(
        0,
        so_pin.as_ptr() as *mut _,
        so_pin.len() as CK_ULONG,
        label.as_ptr() as *mut _,
    );

    // Setup user PIN
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
    C_CloseSession(rw_session);

    let num_threads = 5;
    let barrier = Arc::new(Barrier::new(num_threads));

    let handles: Vec<_> = (0..num_threads)
        .map(|_| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let mut session: CK_SESSION_HANDLE = 0;
                let rv = C_OpenSession(
                    0,
                    CKF_RW_SESSION | CKF_SERIAL_SESSION,
                    ptr::null_mut(),
                    None,
                    &mut session,
                );
                if rv != CKR_OK {
                    return;
                }

                for _ in 0..3 {
                    let user_pin = b"userpin1";
                    let rv = C_Login(
                        session,
                        CKU_USER,
                        user_pin.as_ptr() as *mut _,
                        user_pin.len() as CK_ULONG,
                    );
                    // Accept OK or ALREADY_LOGGED_IN
                    if rv == CKR_OK || rv == CKR_USER_ALREADY_LOGGED_IN {
                        let _ = C_Logout(session);
                    }
                }
                C_CloseSession(session);
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap(); // No panics or deadlocks
    }
    C_CloseAllSessions(0);
}
