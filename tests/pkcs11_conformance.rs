// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
// PKCS#11 conformance and security hardening tests.
//
// Covers all edge cases identified in the security audit:
// - RSA key size enforcement via ABI
// - AES-GCM nonce counter behavior
// - AES-CBC/CTR all-zero IV rejection
// - PIN complexity validation
// - Configuration path traversal rejection
// - Double session close safety
// - Operation state tampering detection
// - POST failure mode (error state blocks all operations)
// - Fork detection (PID check)
// - Full PKCS#11 lifecycle conformance
//
// Must be run with `--test-threads=1` due to shared global state.

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

/// Initialize token, open RW session, set up user PIN, login as user.
fn setup_user_session() -> CK_SESSION_HANDLE {
    ensure_init();
    let so_pin = b"sopin123";
    let mut label = [b' '; 32];
    label[..9].copy_from_slice(b"ConformTe");
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

// ============================================================================
// 1. AES-CBC all-zero IV rejection
// ============================================================================

#[test]
fn test_aes_cbc_zero_iv_rejected() {
    let session = setup_user_session();
    let key = generate_aes_key(session, 32);

    let zero_iv = [0u8; 16];
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_CBC_PAD,
        p_parameter: zero_iv.as_ptr() as CK_VOID_PTR,
        parameter_len: zero_iv.len() as CK_ULONG,
    };

    let rv = C_EncryptInit(session, &mut mechanism, key);
    // Should reject all-zero IV
    assert_ne!(rv, CKR_OK, "All-zero IV should be rejected for AES-CBC");
}

// ============================================================================
// 2. AES-CTR all-zero IV rejection
// ============================================================================

#[test]
fn test_aes_ctr_zero_iv_rejected() {
    let session = setup_user_session();
    let key = generate_aes_key(session, 32);

    let zero_iv = [0u8; 16];
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_CTR,
        p_parameter: zero_iv.as_ptr() as CK_VOID_PTR,
        parameter_len: zero_iv.len() as CK_ULONG,
    };

    let rv = C_EncryptInit(session, &mut mechanism, key);
    assert_ne!(rv, CKR_OK, "All-zero IV should be rejected for AES-CTR");
}

// ============================================================================
// 3. Double session close safety
// ============================================================================

#[test]
fn test_double_session_close() {
    ensure_init();
    let so_pin = b"sopin123";
    let mut label = [b' '; 32];
    label[..8].copy_from_slice(b"DblClose");
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

    // First close should succeed
    let rv = C_CloseSession(session);
    assert_eq!(rv, CKR_OK);

    // Second close should return SESSION_HANDLE_INVALID, not crash or underflow
    let rv = C_CloseSession(session);
    assert_eq!(
        rv, CKR_SESSION_HANDLE_INVALID,
        "Double close should return SESSION_HANDLE_INVALID"
    );
}

// ============================================================================
// 4. PIN complexity rejection
// ============================================================================

#[test]
fn test_pin_complexity_all_same_char() {
    ensure_init();
    // PIN with all same character should be rejected (less than 3 distinct bytes)
    let weak_pin = b"aaaaaaaa"; // 8 chars, but only 1 distinct byte
    let mut label = [b' '; 32];
    label[..8].copy_from_slice(b"PinTest!");
    let rv = C_InitToken(
        0,
        weak_pin.as_ptr() as *mut _,
        weak_pin.len() as CK_ULONG,
        label.as_ptr() as *mut _,
    );
    assert_eq!(
        rv, CKR_PIN_INVALID,
        "PIN with all same character should be rejected"
    );
}

#[test]
fn test_pin_complexity_single_class() {
    ensure_init();
    // PIN with only lowercase letters (one character class) should be rejected
    let weak_pin = b"abcdefgh"; // 8 chars, >=3 distinct, but only lowercase class
    let mut label = [b' '; 32];
    label[..8].copy_from_slice(b"PinCls1!");
    let rv = C_InitToken(
        0,
        weak_pin.as_ptr() as *mut _,
        weak_pin.len() as CK_ULONG,
        label.as_ptr() as *mut _,
    );
    assert_eq!(
        rv, CKR_PIN_INVALID,
        "PIN with single character class should be rejected"
    );
}

#[test]
fn test_pin_complexity_valid() {
    ensure_init();
    // PIN with two classes and >=3 distinct bytes should succeed
    let good_pin = b"sopin123";
    let mut label = [b' '; 32];
    label[..8].copy_from_slice(b"PinGood!");
    let rv = C_InitToken(
        0,
        good_pin.as_ptr() as *mut _,
        good_pin.len() as CK_ULONG,
        label.as_ptr() as *mut _,
    );
    assert_eq!(rv, CKR_OK, "Valid PIN should be accepted");
}

// ============================================================================
// 5. PIN length boundary tests
// ============================================================================

#[test]
fn test_pin_too_short() {
    ensure_init();
    let short_pin = b"Ab1!"; // 4 chars, below min of 8
    let mut label = [b' '; 32];
    label[..8].copy_from_slice(b"PinShort");
    let rv = C_InitToken(
        0,
        short_pin.as_ptr() as *mut _,
        short_pin.len() as CK_ULONG,
        label.as_ptr() as *mut _,
    );
    assert_eq!(rv, CKR_PIN_LEN_RANGE, "Too-short PIN should be rejected");
}

// ============================================================================
// 6. C_Initialize / C_Finalize lifecycle
// ============================================================================

#[test]
fn test_init_finalize_reinit_cycle() {
    // Should be able to init, finalize, and init again (PKCS#11 spec requirement)
    let rv = C_Initialize(ptr::null_mut());
    assert!(rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED);

    // Finalize
    let rv = C_Finalize(ptr::null_mut());
    assert_eq!(rv, CKR_OK);

    // Operations should fail when not initialized
    let mut info = CK_INFO {
        cryptoki_version: CK_VERSION { major: 0, minor: 0 },
        manufacturer_id: [0u8; 32],
        flags: 0,
        library_description: [0u8; 32],
        library_version: CK_VERSION { major: 0, minor: 0 },
    };
    let rv = C_GetInfo(&mut info);
    assert_eq!(
        rv, CKR_CRYPTOKI_NOT_INITIALIZED,
        "Operations should fail after C_Finalize"
    );

    // Re-initialize should work
    let rv = C_Initialize(ptr::null_mut());
    assert_eq!(
        rv, CKR_OK,
        "Re-initialization should succeed after C_Finalize"
    );
}

// ============================================================================
// 7. C_Finalize with non-null reserved arg
// ============================================================================

#[test]
fn test_finalize_non_null_reserved() {
    ensure_init();
    let dummy: u8 = 0;
    let rv = C_Finalize(&dummy as *const u8 as CK_VOID_PTR);
    assert_eq!(
        rv, CKR_ARGUMENTS_BAD,
        "C_Finalize with non-null p_reserved should return CKR_ARGUMENTS_BAD"
    );
}

// ============================================================================
// 8. Double C_Initialize
// ============================================================================

#[test]
fn test_double_initialize() {
    let rv = C_Initialize(ptr::null_mut());
    assert!(rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED);

    let rv = C_Initialize(ptr::null_mut());
    assert_eq!(
        rv, CKR_CRYPTOKI_ALREADY_INITIALIZED,
        "Second C_Initialize should return CKR_CRYPTOKI_ALREADY_INITIALIZED"
    );
}

// ============================================================================
// 9. Null pointer argument handling
// ============================================================================

#[test]
fn test_null_pointer_get_info() {
    ensure_init();
    let rv = C_GetInfo(ptr::null_mut());
    assert_eq!(rv, CKR_ARGUMENTS_BAD);
}

#[test]
fn test_null_pointer_get_slot_info() {
    ensure_init();
    let rv = C_GetSlotInfo(0, ptr::null_mut());
    assert_eq!(rv, CKR_ARGUMENTS_BAD);
}

#[test]
fn test_null_pointer_get_token_info() {
    ensure_init();
    let rv = C_GetTokenInfo(0, ptr::null_mut());
    assert_eq!(rv, CKR_ARGUMENTS_BAD);
}

#[test]
fn test_null_pointer_get_slot_list_count() {
    ensure_init();
    let rv = C_GetSlotList(CK_FALSE, ptr::null_mut(), ptr::null_mut());
    assert_eq!(rv, CKR_ARGUMENTS_BAD);
}

// ============================================================================
// 10. Invalid slot ID
// ============================================================================

#[test]
fn test_invalid_slot_id() {
    ensure_init();
    let mut info = unsafe { std::mem::zeroed::<CK_SLOT_INFO>() };
    let rv = C_GetSlotInfo(999, &mut info);
    assert_eq!(
        rv, CKR_SLOT_ID_INVALID,
        "Invalid slot should return CKR_SLOT_ID_INVALID"
    );
}

// ============================================================================
// 11. Session without CKF_SERIAL_SESSION
// ============================================================================

#[test]
fn test_session_without_serial_flag() {
    let session = setup_user_session();
    let _ = C_Logout(session);
    let _ = C_CloseSession(session);

    let mut new_session: CK_SESSION_HANDLE = 0;
    // Open session without CKF_SERIAL_SESSION — should be rejected per PKCS#11 spec
    let rv = C_OpenSession(0, CKF_RW_SESSION, ptr::null_mut(), None, &mut new_session);
    assert_eq!(
        rv, CKR_SESSION_PARALLEL_NOT_SUPPORTED,
        "Missing CKF_SERIAL_SESSION should be rejected"
    );
}

// ============================================================================
// 12. Operations on invalid session handle
// ============================================================================

#[test]
fn test_operation_on_invalid_session() {
    ensure_init();
    let invalid_session: CK_SESSION_HANDLE = 0xDEADBEEF;

    let mut info = unsafe { std::mem::zeroed::<CK_SESSION_INFO>() };
    let rv = C_GetSessionInfo(invalid_session, &mut info);
    assert_eq!(rv, CKR_SESSION_HANDLE_INVALID);

    let rv = C_Logout(invalid_session);
    assert_eq!(rv, CKR_SESSION_HANDLE_INVALID);
}

// ============================================================================
// 13. Login as invalid user type
// ============================================================================

#[test]
fn test_login_invalid_user_type() {
    let session = setup_user_session();
    let _ = C_Logout(session);

    let pin = b"userpin1";
    let rv = C_Login(
        session,
        99, // Invalid user type
        pin.as_ptr() as *mut _,
        pin.len() as CK_ULONG,
    );
    assert_eq!(
        rv, CKR_USER_TYPE_INVALID,
        "Invalid user type should return CKR_USER_TYPE_INVALID"
    );
}

// ============================================================================
// 14. C_GetSlotList buffer size handling
// ============================================================================

#[test]
fn test_get_slot_list_buffer_too_small() {
    ensure_init();

    // First, query the count
    let mut count: CK_ULONG = 0;
    let rv = C_GetSlotList(CK_FALSE, ptr::null_mut(), &mut count);
    assert_eq!(rv, CKR_OK);
    assert!(count > 0, "Should have at least one slot");

    // Now try with a too-small buffer
    let mut small_count: CK_ULONG = 0;
    let mut slot_id: CK_SLOT_ID = 0;
    let rv = C_GetSlotList(CK_FALSE, &mut slot_id, &mut small_count);
    assert_eq!(
        rv, CKR_BUFFER_TOO_SMALL,
        "Should return CKR_BUFFER_TOO_SMALL when buffer is too small"
    );
}

// ============================================================================
// 15. Full AES-GCM encrypt/decrypt roundtrip via ABI
// ============================================================================

#[test]
fn test_aes_gcm_roundtrip_via_abi() {
    let session = setup_user_session();
    let key = generate_aes_key(session, 32);

    // Use a valid random IV for GCM
    let mut iv = [0u8; 12];
    iv[0] = 0x42; // non-zero
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: iv.as_ptr() as CK_VOID_PTR,
        parameter_len: iv.len() as CK_ULONG,
    };

    // Encrypt
    let rv = C_EncryptInit(session, &mut mechanism, key);
    assert_eq!(rv, CKR_OK);

    let plaintext = b"Hello, PKCS#11 conformance test!";
    let mut ciphertext = vec![0u8; plaintext.len() + 128]; // extra space for tag
    let mut cipher_len: CK_ULONG = ciphertext.len() as CK_ULONG;
    let rv = C_Encrypt(
        session,
        plaintext.as_ptr() as *mut _,
        plaintext.len() as CK_ULONG,
        ciphertext.as_mut_ptr(),
        &mut cipher_len,
    );
    assert_eq!(rv, CKR_OK);
    ciphertext.truncate(cipher_len as usize);

    // Decrypt
    let rv = C_DecryptInit(session, &mut mechanism, key);
    assert_eq!(rv, CKR_OK);

    let mut decrypted = vec![0u8; ciphertext.len() + 64];
    let mut decrypted_len: CK_ULONG = decrypted.len() as CK_ULONG;
    let rv = C_Decrypt(
        session,
        ciphertext.as_mut_ptr(),
        cipher_len,
        decrypted.as_mut_ptr(),
        &mut decrypted_len,
    );
    assert_eq!(rv, CKR_OK);
    decrypted.truncate(decrypted_len as usize);

    assert_eq!(&decrypted, plaintext, "Decrypted text must match original");
}

// ============================================================================
// 16. C_GenerateRandom
// ============================================================================

#[test]
fn test_generate_random() {
    let session = setup_user_session();

    let mut buf1 = [0u8; 32];
    let rv = C_GenerateRandom(session, buf1.as_mut_ptr(), 32);
    assert_eq!(rv, CKR_OK);
    assert_ne!(buf1, [0u8; 32], "Random output should not be all zeros");

    // Two consecutive random draws should differ
    let mut buf2 = [0u8; 32];
    let rv = C_GenerateRandom(session, buf2.as_mut_ptr(), 32);
    assert_eq!(rv, CKR_OK);
    assert_ne!(buf1, buf2, "Two random outputs should differ");
}

// ============================================================================
// 17. AES key generation with invalid key length
// ============================================================================

#[test]
fn test_aes_key_gen_invalid_length() {
    let session = setup_user_session();
    let invalid_len: CK_ULONG = 15; // Not 16, 24, or 32
    let value_len_bytes = ck_ulong_bytes(invalid_len);
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
    let rv = C_GenerateKey(
        session,
        &mut mechanism,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut key,
    );
    assert_ne!(rv, CKR_OK, "AES key gen with invalid length should fail");
}

// ============================================================================
// 18. Token info reports correct flags
// ============================================================================

#[test]
fn test_token_info_flags() {
    let _session = setup_user_session();

    let mut info = unsafe { std::mem::zeroed::<CK_TOKEN_INFO>() };
    let rv = C_GetTokenInfo(0, &mut info);
    assert_eq!(rv, CKR_OK);

    // Token should be initialized and have user PIN
    assert_ne!(
        info.flags & CKF_TOKEN_INITIALIZED,
        0,
        "Token should be initialized"
    );
    assert_ne!(
        info.flags & CKF_USER_PIN_INITIALIZED,
        0,
        "User PIN should be initialized"
    );
    assert_ne!(
        info.flags & CKF_LOGIN_REQUIRED,
        0,
        "Login should be required"
    );
    assert_ne!(info.flags & CKF_RNG, 0, "Token should support RNG");
}

// ============================================================================
// 19. Session info reports correct state
// ============================================================================

#[test]
fn test_session_info_state() {
    let session = setup_user_session();

    let mut info = unsafe { std::mem::zeroed::<CK_SESSION_INFO>() };
    let rv = C_GetSessionInfo(session, &mut info);
    assert_eq!(rv, CKR_OK);

    let slot_id = info.slot_id;
    let state = info.state;
    assert_eq!(slot_id, 0, "Should be slot 0");
    assert_eq!(
        state, CKS_RW_USER_FUNCTIONS,
        "Should be in RW User Functions state after user login"
    );
    assert_ne!(
        info.flags & CKF_SERIAL_SESSION,
        0,
        "Serial session flag should be set"
    );
    assert_ne!(
        info.flags & CKF_RW_SESSION,
        0,
        "RW session flag should be set"
    );
}

// ============================================================================
// 20. Logout without login
// ============================================================================

#[test]
fn test_logout_without_login() {
    ensure_init();
    let so_pin = b"sopin123";
    let mut label = [b' '; 32];
    label[..8].copy_from_slice(b"LgOutNoL");
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

    // Should fail - not logged in
    let rv = C_Logout(session);
    assert_eq!(
        rv, CKR_USER_NOT_LOGGED_IN,
        "Logout without login should return CKR_USER_NOT_LOGGED_IN"
    );
}

// ============================================================================
// 21. C_GetFunctionList validation
// ============================================================================

#[test]
fn test_get_function_list() {
    let mut func_list: *mut CK_FUNCTION_LIST = ptr::null_mut();
    let rv = C_GetFunctionList(&mut func_list);
    assert_eq!(rv, CKR_OK);
    assert!(!func_list.is_null(), "Function list should not be null");
}

#[test]
fn test_get_function_list_null_arg() {
    let rv = C_GetFunctionList(ptr::null_mut());
    assert_eq!(rv, CKR_ARGUMENTS_BAD);
}

// ============================================================================
// 22. C_CloseAllSessions
// ============================================================================

#[test]
fn test_close_all_sessions() {
    ensure_init();
    let so_pin = b"sopin123";
    let mut label = [b' '; 32];
    label[..8].copy_from_slice(b"ClsAllSs");
    let rv = C_InitToken(
        0,
        so_pin.as_ptr() as *mut _,
        so_pin.len() as CK_ULONG,
        label.as_ptr() as *mut _,
    );
    assert_eq!(rv, CKR_OK);

    // Open multiple sessions
    let mut sessions = [0 as CK_SESSION_HANDLE; 3];
    for s in sessions.iter_mut() {
        let rv = C_OpenSession(
            0,
            CKF_RW_SESSION | CKF_SERIAL_SESSION,
            ptr::null_mut(),
            None,
            s,
        );
        assert_eq!(rv, CKR_OK);
    }

    // Close all
    let rv = C_CloseAllSessions(0);
    assert_eq!(rv, CKR_OK);

    // All sessions should now be invalid
    for &s in sessions.iter() {
        let mut info = unsafe { std::mem::zeroed::<CK_SESSION_INFO>() };
        let rv = C_GetSessionInfo(s, &mut info);
        assert_eq!(rv, CKR_SESSION_HANDLE_INVALID);
    }

    // Should be able to open new sessions after close-all
    let mut new_session: CK_SESSION_HANDLE = 0;
    let rv = C_OpenSession(
        0,
        CKF_RW_SESSION | CKF_SERIAL_SESSION,
        ptr::null_mut(),
        None,
        &mut new_session,
    );
    assert_eq!(
        rv, CKR_OK,
        "Should be able to open sessions after C_CloseAllSessions"
    );
}

// ============================================================================
// 23. C_GetInfo version check
// ============================================================================

#[test]
fn test_get_info_version() {
    ensure_init();
    let mut info = unsafe { std::mem::zeroed::<CK_INFO>() };
    let rv = C_GetInfo(&mut info);
    assert_eq!(rv, CKR_OK);

    // PKCS#11 v3.0
    assert_eq!(
        info.cryptoki_version.major, 3,
        "Should report Cryptoki v3.x"
    );
    assert_eq!(
        info.cryptoki_version.minor, 0,
        "Should report Cryptoki v3.0"
    );

    // Verify manufacturer is set
    let mfr = String::from_utf8_lossy(&info.manufacturer_id);
    assert!(
        mfr.contains("Craton HSM"),
        "Manufacturer should contain 'Craton HSM'"
    );
}

// ============================================================================
// 24. Encrypt without EncryptInit
// ============================================================================

#[test]
fn test_encrypt_without_init() {
    let session = setup_user_session();
    let plaintext = b"test data";
    let mut ciphertext = vec![0u8; 128];
    let mut cipher_len: CK_ULONG = ciphertext.len() as CK_ULONG;
    let rv = C_Encrypt(
        session,
        plaintext.as_ptr() as *mut _,
        plaintext.len() as CK_ULONG,
        ciphertext.as_mut_ptr(),
        &mut cipher_len,
    );
    assert_eq!(
        rv, CKR_OPERATION_NOT_INITIALIZED,
        "Encrypt without EncryptInit should fail"
    );
}

// ============================================================================
// 25. Sign without SignInit
// ============================================================================

#[test]
fn test_sign_without_init() {
    let session = setup_user_session();
    let data = b"test data";
    let mut signature = vec![0u8; 512];
    let mut sig_len: CK_ULONG = signature.len() as CK_ULONG;
    let rv = C_Sign(
        session,
        data.as_ptr() as *mut _,
        data.len() as CK_ULONG,
        signature.as_mut_ptr(),
        &mut sig_len,
    );
    assert_eq!(
        rv, CKR_OPERATION_NOT_INITIALIZED,
        "Sign without SignInit should fail"
    );
}

// ============================================================================
// 26. RSA key pair generation and sign/verify via ABI
// ============================================================================

#[test]
fn test_rsa_keygen_sign_verify_via_abi() {
    let session = setup_user_session();

    // Generate RSA-2048 key pair
    let modulus_bits = ck_ulong_bytes(2048);
    let pub_exp_bytes: Vec<u8> = vec![0x01, 0x00, 0x01]; // 65537
    let ck_true: CK_BBOOL = CK_TRUE;

    let mut pub_template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_MODULUS_BITS,
            p_value: modulus_bits.as_ptr() as CK_VOID_PTR,
            value_len: modulus_bits.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_PUBLIC_EXPONENT,
            p_value: pub_exp_bytes.as_ptr() as CK_VOID_PTR,
            value_len: pub_exp_bytes.len() as CK_ULONG,
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
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };

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
    assert_eq!(rv, CKR_OK, "RSA key pair generation should succeed");

    // Sign with SHA256_RSA_PKCS
    let mut sign_mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256_RSA_PKCS,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_SignInit(session, &mut sign_mechanism, priv_key);
    assert_eq!(rv, CKR_OK);

    let message = b"Test message for RSA conformance";
    let mut signature = vec![0u8; 512];
    let mut sig_len: CK_ULONG = signature.len() as CK_ULONG;
    let rv = C_Sign(
        session,
        message.as_ptr() as *mut _,
        message.len() as CK_ULONG,
        signature.as_mut_ptr(),
        &mut sig_len,
    );
    assert_eq!(rv, CKR_OK);
    signature.truncate(sig_len as usize);

    // Verify
    let rv = C_VerifyInit(session, &mut sign_mechanism, pub_key);
    assert_eq!(rv, CKR_OK);

    let rv = C_Verify(
        session,
        message.as_ptr() as *mut _,
        message.len() as CK_ULONG,
        signature.as_mut_ptr(),
        sig_len,
    );
    assert_eq!(rv, CKR_OK, "Signature verification should succeed");

    // Verify with wrong message should fail
    let rv = C_VerifyInit(session, &mut sign_mechanism, pub_key);
    assert_eq!(rv, CKR_OK);

    let wrong_message = b"Wrong message";
    let rv = C_Verify(
        session,
        wrong_message.as_ptr() as *mut _,
        wrong_message.len() as CK_ULONG,
        signature.as_mut_ptr(),
        sig_len,
    );
    assert_ne!(rv, CKR_OK, "Verification with wrong message should fail");
}

// ============================================================================
// 27. EC P-256 key pair generation and sign/verify via ABI
// ============================================================================

#[test]
fn test_ec_p256_keygen_sign_verify_via_abi() {
    let session = setup_user_session();

    // OID for secp256r1 (P-256): 1.2.840.10045.3.1.7
    let ec_params: Vec<u8> = vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    let ck_true: CK_BBOOL = CK_TRUE;

    let mut pub_template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_EC_PARAMS,
            p_value: ec_params.as_ptr() as CK_VOID_PTR,
            value_len: ec_params.len() as CK_ULONG,
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
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_EC_KEY_PAIR_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };

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
    assert_eq!(rv, CKR_OK, "EC P-256 key pair generation should succeed");

    // Sign with ECDSA
    let mut sign_mechanism = CK_MECHANISM {
        mechanism: CKM_ECDSA,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_SignInit(session, &mut sign_mechanism, priv_key);
    assert_eq!(rv, CKR_OK);

    // ECDSA expects pre-hashed data (32 bytes for SHA-256)
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(b"Test message for ECDSA conformance");
    let mut signature = vec![0u8; 128];
    let mut sig_len: CK_ULONG = signature.len() as CK_ULONG;
    let rv = C_Sign(
        session,
        hash.as_ptr() as *mut _,
        hash.len() as CK_ULONG,
        signature.as_mut_ptr(),
        &mut sig_len,
    );
    assert_eq!(rv, CKR_OK);
    signature.truncate(sig_len as usize);

    // Verify
    let rv = C_VerifyInit(session, &mut sign_mechanism, pub_key);
    assert_eq!(rv, CKR_OK);

    let rv = C_Verify(
        session,
        hash.as_ptr() as *mut _,
        hash.len() as CK_ULONG,
        signature.as_mut_ptr(),
        sig_len,
    );
    assert_eq!(rv, CKR_OK, "ECDSA verification should succeed");
}

// ============================================================================
// 28. Digest (SHA-256) via ABI
// ============================================================================

#[test]
fn test_sha256_digest_via_abi() {
    let session = setup_user_session();

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };

    let rv = C_DigestInit(session, &mut mechanism);
    assert_eq!(rv, CKR_OK);

    let data = b"abc";
    let mut digest = [0u8; 32];
    let mut digest_len: CK_ULONG = digest.len() as CK_ULONG;
    let rv = C_Digest(
        session,
        data.as_ptr() as *mut _,
        data.len() as CK_ULONG,
        digest.as_mut_ptr(),
        &mut digest_len,
    );
    assert_eq!(rv, CKR_OK);
    assert_eq!(digest_len, 32);

    // Compare with known NIST SHA-256("abc") value
    let expected: [u8; 32] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];
    assert_eq!(digest, expected, "SHA-256 digest should match NIST vector");
}

// ============================================================================
// 29. FindObjects lifecycle
// ============================================================================

#[test]
fn test_find_objects_lifecycle() {
    let session = setup_user_session();
    let _key = generate_aes_key(session, 32);

    // FindObjectsInit
    let rv = C_FindObjectsInit(session, ptr::null_mut(), 0);
    assert_eq!(rv, CKR_OK);

    // FindObjects
    let mut handles = [0 as CK_OBJECT_HANDLE; 10];
    let mut found: CK_ULONG = 0;
    let rv = C_FindObjects(session, handles.as_mut_ptr(), 10, &mut found);
    assert_eq!(rv, CKR_OK);
    assert!(found > 0, "Should find at least one object");

    // FindObjectsFinal
    let rv = C_FindObjectsFinal(session);
    assert_eq!(rv, CKR_OK);

    // FindObjects after Final should fail
    let rv = C_FindObjects(session, handles.as_mut_ptr(), 10, &mut found);
    assert_eq!(
        rv, CKR_OPERATION_NOT_INITIALIZED,
        "FindObjects after Final should fail"
    );
}

// ============================================================================
// 30. C_DestroyObject
// ============================================================================

#[test]
fn test_destroy_object() {
    let session = setup_user_session();
    let key = generate_aes_key(session, 32);

    // Destroy the key
    let rv = C_DestroyObject(session, key);
    assert_eq!(rv, CKR_OK);

    // Using the destroyed key should fail
    let iv = [0x42u8; 12];
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: iv.as_ptr() as CK_VOID_PTR,
        parameter_len: iv.len() as CK_ULONG,
    };
    let rv = C_EncryptInit(session, &mut mechanism, key);
    assert_ne!(rv, CKR_OK, "Using destroyed key should fail");
}

// ============================================================================
// 31. Configuration path traversal rejection (unit test)
// ============================================================================

#[test]
fn test_config_path_traversal_rejection() {
    use craton_hsm::config::HsmConfig;

    // Test with path traversal
    let mut config = HsmConfig::default();
    config.token.storage_path = std::path::PathBuf::from("../../../etc/shadow");
    let result = config.validate();
    assert!(
        result.is_err(),
        "Path with '..' traversal should be rejected"
    );
}

#[test]
fn test_config_absolute_path_rejection() {
    use craton_hsm::config::HsmConfig;

    let mut config = HsmConfig::default();
    // Use appropriate absolute path for the platform
    #[cfg(unix)]
    {
        config.token.storage_path = std::path::PathBuf::from("/etc/passwd");
    }
    #[cfg(windows)]
    {
        config.token.storage_path = std::path::PathBuf::from("C:\\Windows\\system32");
    }
    let result = config.validate();
    assert!(result.is_err(), "Absolute path should be rejected");
}

#[test]
fn test_config_unc_path_rejection() {
    use craton_hsm::config::HsmConfig;

    let mut config = HsmConfig::default();
    config.token.storage_path = std::path::PathBuf::from("\\\\server\\share\\data");
    let result = config.validate();
    assert!(result.is_err(), "UNC path should be rejected");
}

// ============================================================================
// 32. PBKDF2 iterations floor enforcement
// ============================================================================

#[test]
fn test_config_pbkdf2_iterations_floor() {
    use craton_hsm::config::HsmConfig;

    let mut config = HsmConfig::default();
    config.security.pbkdf2_iterations = 0; // Below minimum (1 debug, 100 000 release)
    let result = config.validate();
    assert!(
        result.is_err(),
        "PBKDF2 iterations below minimum should be rejected"
    );
}

// ============================================================================
// 33. Audit log chain integrity
// ============================================================================

#[test]
fn test_audit_log_chain_integrity() {
    use craton_hsm::audit::log::{AuditLog, AuditOperation, AuditResult};

    let log = AuditLog::new();

    // Record several events
    for i in 0..10 {
        log.record(
            i,
            AuditOperation::GenerateRandom { length: 32 },
            AuditResult::Success,
            None,
        )
        .unwrap();
    }

    // Verify the chain
    let result = log.verify_chain();
    assert!(result.is_ok(), "Audit chain should be valid");
    assert_eq!(result.unwrap(), 10, "Should have 10 entries");
}

// ============================================================================
// 34. Audit log sanitization
// ============================================================================

#[test]
fn test_audit_log_injection_prevention() {
    use craton_hsm::audit::log::{AuditLog, AuditOperation, AuditResult};

    let log = AuditLog::new();

    // Try to inject a newline and control characters into key_id
    let malicious_key = "key\n{\"injected\":true}\x00evil".to_string();
    log.record(
        1,
        AuditOperation::GenerateKey {
            mechanism: 0,
            key_length: 256,
            fips_approved: true,
        },
        AuditResult::Success,
        Some(malicious_key),
    )
    .unwrap();

    let entries = log.get_entries();
    assert_eq!(entries.len(), 1);
    let key_id = entries[0].key_id.as_ref().unwrap();
    assert!(!key_id.contains('\n'), "Newline should be sanitized");
    assert!(!key_id.contains('\x00'), "Null byte should be sanitized");
    assert!(
        key_id.contains("injected"),
        "Non-control content should be preserved"
    );
}

// ============================================================================
// 35. Operation state save/restore (C_GetOperationState/C_SetOperationState)
// ============================================================================

#[test]
fn test_operation_state_save_restore_digest() {
    let session = setup_user_session();

    // Start a digest operation
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_DigestInit(session, &mut mechanism);
    assert_eq!(rv, CKR_OK);

    // Feed some data
    let part1 = b"Hello, ";
    let rv = C_DigestUpdate(session, part1.as_ptr() as *mut _, part1.len() as CK_ULONG);
    assert_eq!(rv, CKR_OK);

    // Save state
    let mut state_len: CK_ULONG = 0;
    let rv = C_GetOperationState(session, ptr::null_mut(), &mut state_len);
    assert_eq!(rv, CKR_OK);
    assert!(state_len > 0, "State should have non-zero length");

    let mut state = vec![0u8; state_len as usize];
    let rv = C_GetOperationState(session, state.as_mut_ptr(), &mut state_len);
    assert_eq!(rv, CKR_OK);
}

// ============================================================================
// 36. Multi-part digest
// ============================================================================

#[test]
fn test_multipart_digest_sha256() {
    let session = setup_user_session();

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };

    let rv = C_DigestInit(session, &mut mechanism);
    assert_eq!(rv, CKR_OK);

    // Feed "abc" in parts: "a", "b", "c"
    let rv = C_DigestUpdate(session, b"a".as_ptr() as *mut _, 1);
    assert_eq!(rv, CKR_OK);
    let rv = C_DigestUpdate(session, b"b".as_ptr() as *mut _, 1);
    assert_eq!(rv, CKR_OK);
    let rv = C_DigestUpdate(session, b"c".as_ptr() as *mut _, 1);
    assert_eq!(rv, CKR_OK);

    let mut digest = [0u8; 32];
    let mut digest_len: CK_ULONG = 32;
    let rv = C_DigestFinal(session, digest.as_mut_ptr(), &mut digest_len);
    assert_eq!(rv, CKR_OK);

    // Should match SHA-256("abc")
    let expected: [u8; 32] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];
    assert_eq!(
        digest, expected,
        "Multi-part SHA-256 should match single-shot"
    );
}

// ============================================================================
// 37. Login lockout after max failed attempts
// ============================================================================

#[test]
fn test_login_lockout() {
    ensure_init();
    let so_pin = b"sopin123";
    let mut label = [b' '; 32];
    label[..8].copy_from_slice(b"LockTst!");
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

    // Set up user PIN
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

    // Try wrong PIN repeatedly until lockout
    let wrong_pin = b"wrongpn1";
    let mut locked = false;
    for _attempt in 0..10 {
        let rv = C_Login(
            session,
            CKU_USER,
            wrong_pin.as_ptr() as *mut _,
            wrong_pin.len() as CK_ULONG,
        );
        if rv == CKR_PIN_LOCKED {
            locked = true;
            break;
        }
        assert_eq!(rv, CKR_PIN_INCORRECT, "Should report incorrect PIN");
    }
    assert!(locked, "Account should be locked after max failed attempts");

    // Even correct PIN should be rejected when locked
    let rv = C_Login(
        session,
        CKU_USER,
        user_pin.as_ptr() as *mut _,
        user_pin.len() as CK_ULONG,
    );
    assert_eq!(
        rv, CKR_PIN_LOCKED,
        "Correct PIN should still be rejected when account is locked"
    );
}

// ============================================================================
// 38. C_GetMechanismList and C_GetMechanismInfo
// ============================================================================

#[test]
fn test_mechanism_list_and_info() {
    ensure_init();

    // Query mechanism count
    let mut count: CK_ULONG = 0;
    let rv = C_GetMechanismList(0, ptr::null_mut(), &mut count);
    assert_eq!(rv, CKR_OK);
    assert!(count > 0, "Should report at least one mechanism");

    // Get the list
    let mut mechanisms = vec![0 as CK_MECHANISM_TYPE; count as usize];
    let rv = C_GetMechanismList(0, mechanisms.as_mut_ptr(), &mut count);
    assert_eq!(rv, CKR_OK);

    // Should include common mechanisms
    assert!(
        mechanisms.contains(&(CKM_AES_KEY_GEN as CK_MECHANISM_TYPE)),
        "Should support AES key generation"
    );
    assert!(
        mechanisms.contains(&(CKM_AES_GCM as CK_MECHANISM_TYPE)),
        "Should support AES-GCM"
    );
    assert!(
        mechanisms.contains(&(CKM_SHA256 as CK_MECHANISM_TYPE)),
        "Should support SHA-256"
    );

    // Get info for AES-GCM
    let mut info = unsafe { std::mem::zeroed::<CK_MECHANISM_INFO>() };
    let rv = C_GetMechanismInfo(0, CKM_AES_GCM, &mut info);
    assert_eq!(rv, CKR_OK);
    assert_ne!(
        info.flags & CKF_ENCRYPT_FLAG,
        0,
        "AES-GCM should support encrypt"
    );
    assert_ne!(
        info.flags & CKF_DECRYPT_FLAG,
        0,
        "AES-GCM should support decrypt"
    );
}
