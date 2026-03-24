// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
// Random generation and session management ABI tests.

use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm::pkcs11_abi::functions::*;
use craton_hsm::pkcs11_abi::types::*;
use std::ptr;

fn ensure_init() {
    let rv = C_Initialize(ptr::null_mut());
    assert!(
        rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED,
        "C_Initialize failed: 0x{:08X}",
        rv
    );
}

fn setup_token() {
    ensure_init();
    let so_pin = b"sopin123";
    let mut label = [b' '; 32];
    label[..7].copy_from_slice(b"RndTest");
    let rv = C_InitToken(
        0,
        so_pin.as_ptr() as *mut _,
        so_pin.len() as CK_ULONG,
        label.as_ptr() as *mut _,
    );
    assert_eq!(rv, CKR_OK, "C_InitToken failed");
}

fn setup_user_session() -> CK_SESSION_HANDLE {
    setup_token();
    let so_pin = b"sopin123";

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

// ============================================================================
// C_GenerateRandom tests
// ============================================================================

#[test]
fn test_generate_random_32_bytes() {
    let session = setup_user_session();
    let mut buf = [0u8; 32];
    let rv = C_GenerateRandom(session, buf.as_mut_ptr(), 32);
    assert_eq!(rv, CKR_OK, "C_GenerateRandom(32) failed: 0x{:08X}", rv);
    // Verify not all zeros (extremely unlikely for 32 random bytes)
    assert!(
        buf.iter().any(|&b| b != 0),
        "Random bytes should not be all zeros"
    );
}

#[test]
fn test_generate_random_1_byte() {
    let session = setup_user_session();
    let mut buf = [0u8; 1];
    let rv = C_GenerateRandom(session, buf.as_mut_ptr(), 1);
    assert_eq!(rv, CKR_OK, "C_GenerateRandom(1) should succeed");
}

#[test]
fn test_generate_random_256_bytes() {
    let session = setup_user_session();
    let mut buf = vec![0u8; 256];
    let rv = C_GenerateRandom(session, buf.as_mut_ptr(), 256);
    assert_eq!(rv, CKR_OK);
    assert!(buf.iter().any(|&b| b != 0));
}

#[test]
fn test_generate_random_different_calls() {
    let session = setup_user_session();
    let mut buf1 = [0u8; 32];
    let mut buf2 = [0u8; 32];
    let rv = C_GenerateRandom(session, buf1.as_mut_ptr(), 32);
    assert_eq!(rv, CKR_OK);
    let rv = C_GenerateRandom(session, buf2.as_mut_ptr(), 32);
    assert_eq!(rv, CKR_OK);
    // Two random calls should produce different output (extremely high probability)
    assert_ne!(buf1, buf2, "Two random outputs should differ");
}

#[test]
fn test_generate_random_large() {
    let session = setup_user_session();
    let mut buf = vec![0u8; 4096];
    let rv = C_GenerateRandom(session, buf.as_mut_ptr(), 4096);
    assert_eq!(rv, CKR_OK, "C_GenerateRandom(4096) should succeed");
}

#[test]
fn test_generate_random_zero_length() {
    let session = setup_user_session();
    let mut buf = [0u8; 1];
    let rv = C_GenerateRandom(session, buf.as_mut_ptr(), 0);
    // Zero-length random request should succeed (no-op)
    assert_eq!(
        rv, CKR_OK,
        "C_GenerateRandom(0) should succeed: 0x{:08X}",
        rv
    );
}

// ============================================================================
// C_SeedRandom tests
// ============================================================================

#[test]
fn test_seed_random() {
    let session = setup_user_session();
    let seed = [0x42u8; 16];
    let rv = C_SeedRandom(session, seed.as_ptr() as *mut _, 16);
    // May return CKR_RANDOM_SEED_NOT_SUPPORTED or CKR_OK
    assert!(
        rv == CKR_OK || rv == CKR_RANDOM_SEED_NOT_SUPPORTED,
        "C_SeedRandom: 0x{:08X}",
        rv
    );
}

// ============================================================================
// Session management tests
// ============================================================================

#[test]
fn test_open_rw_session() {
    setup_token();
    let mut session: CK_SESSION_HANDLE = 0;
    let rv = C_OpenSession(
        0,
        CKF_RW_SESSION | CKF_SERIAL_SESSION,
        ptr::null_mut(),
        None,
        &mut session,
    );
    assert_eq!(rv, CKR_OK);
    assert_ne!(session, 0, "Session handle should be non-zero");
    C_CloseSession(session);
}

#[test]
fn test_open_ro_session() {
    setup_token();
    let mut session: CK_SESSION_HANDLE = 0;
    let rv = C_OpenSession(0, CKF_SERIAL_SESSION, ptr::null_mut(), None, &mut session);
    assert_eq!(rv, CKR_OK, "RO session should open OK");
    C_CloseSession(session);
}

#[test]
fn test_get_session_info_rw() {
    setup_token();
    let mut session: CK_SESSION_HANDLE = 0;
    C_OpenSession(
        0,
        CKF_RW_SESSION | CKF_SERIAL_SESSION,
        ptr::null_mut(),
        None,
        &mut session,
    );

    let mut info: CK_SESSION_INFO = unsafe { std::mem::zeroed() };
    let rv = C_GetSessionInfo(session, &mut info);
    assert_eq!(rv, CKR_OK, "GetSessionInfo failed: 0x{:08X}", rv);
    let slot_id = info.slot_id;
    let state = info.state;
    let flags = info.flags;
    assert_eq!(slot_id, 0, "Session should be on slot 0");
    // RW public session = state 2
    assert_eq!(
        state, CKS_RW_PUBLIC_SESSION,
        "RW session without login should be CKS_RW_PUBLIC_SESSION"
    );
    assert_ne!(
        flags & CKF_RW_SESSION,
        0,
        "Session flags should include CKF_RW_SESSION"
    );
    assert_ne!(
        flags & CKF_SERIAL_SESSION,
        0,
        "Session flags should include CKF_SERIAL_SESSION"
    );
    C_CloseSession(session);
}

#[test]
fn test_get_session_info_after_login() {
    let session = setup_user_session();
    let mut info: CK_SESSION_INFO = unsafe { std::mem::zeroed() };
    let rv = C_GetSessionInfo(session, &mut info);
    assert_eq!(rv, CKR_OK);
    let state = info.state;
    assert_eq!(
        state, CKS_RW_USER_FUNCTIONS,
        "Should be CKS_RW_USER_FUNCTIONS after user login"
    );
}

#[test]
fn test_close_session() {
    setup_token();
    let mut session: CK_SESSION_HANDLE = 0;
    C_OpenSession(
        0,
        CKF_RW_SESSION | CKF_SERIAL_SESSION,
        ptr::null_mut(),
        None,
        &mut session,
    );
    let rv = C_CloseSession(session);
    assert_eq!(rv, CKR_OK, "CloseSession should succeed");

    // Using closed session should fail
    let mut info: CK_SESSION_INFO = unsafe { std::mem::zeroed() };
    let rv = C_GetSessionInfo(session, &mut info);
    assert_eq!(
        rv, CKR_SESSION_HANDLE_INVALID,
        "Closed session should be invalid"
    );
}

#[test]
fn test_close_all_sessions() {
    setup_token();
    let mut s1: CK_SESSION_HANDLE = 0;
    let mut s2: CK_SESSION_HANDLE = 0;
    C_OpenSession(
        0,
        CKF_RW_SESSION | CKF_SERIAL_SESSION,
        ptr::null_mut(),
        None,
        &mut s1,
    );
    C_OpenSession(
        0,
        CKF_RW_SESSION | CKF_SERIAL_SESSION,
        ptr::null_mut(),
        None,
        &mut s2,
    );

    let rv = C_CloseAllSessions(0);
    assert_eq!(rv, CKR_OK, "CloseAllSessions should succeed");

    // Both sessions should be invalid
    let mut info: CK_SESSION_INFO = unsafe { std::mem::zeroed() };
    let rv = C_GetSessionInfo(s1, &mut info);
    assert_eq!(rv, CKR_SESSION_HANDLE_INVALID);
    let rv = C_GetSessionInfo(s2, &mut info);
    assert_eq!(rv, CKR_SESSION_HANDLE_INVALID);
}

#[test]
fn test_session_invalid_slot() {
    ensure_init();
    let mut session: CK_SESSION_HANDLE = 0;
    let rv = C_OpenSession(
        99,
        CKF_RW_SESSION | CKF_SERIAL_SESSION,
        ptr::null_mut(),
        None,
        &mut session,
    );
    assert_eq!(
        rv, CKR_SLOT_ID_INVALID,
        "Invalid slot should return CKR_SLOT_ID_INVALID"
    );
}

#[test]
fn test_double_login_fails() {
    let session = setup_user_session();
    let user_pin = b"userpin1";
    // Already logged in as user, try again
    let rv = C_Login(
        session,
        CKU_USER,
        user_pin.as_ptr() as *mut _,
        user_pin.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_USER_ALREADY_LOGGED_IN, "Double login should fail");
}

#[test]
fn test_login_wrong_pin() {
    setup_token();
    let mut session: CK_SESSION_HANDLE = 0;
    C_OpenSession(
        0,
        CKF_RW_SESSION | CKF_SERIAL_SESSION,
        ptr::null_mut(),
        None,
        &mut session,
    );

    let wrong_pin = b"wrongpin";
    let rv = C_Login(
        session,
        CKU_SO,
        wrong_pin.as_ptr() as *mut _,
        wrong_pin.len() as CK_ULONG,
    );
    assert_eq!(
        rv, CKR_PIN_INCORRECT,
        "Wrong PIN should return CKR_PIN_INCORRECT"
    );
}

#[test]
fn test_set_pin() {
    let session = setup_user_session();
    let old_pin = b"userpin1";
    let new_pin = b"newuserpin";

    let rv = C_SetPIN(
        session,
        old_pin.as_ptr() as *mut _,
        old_pin.len() as CK_ULONG,
        new_pin.as_ptr() as *mut _,
        new_pin.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_OK, "C_SetPIN should succeed: 0x{:08X}", rv);
}

#[test]
fn test_logout_and_re_login() {
    let session = setup_user_session();
    let rv = C_Logout(session);
    assert_eq!(rv, CKR_OK);

    let user_pin = b"userpin1";
    let rv = C_Login(
        session,
        CKU_USER,
        user_pin.as_ptr() as *mut _,
        user_pin.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_OK, "Re-login after logout should succeed");
}

#[test]
fn test_get_session_info_invalid_session() {
    ensure_init();
    let mut info: CK_SESSION_INFO = unsafe { std::mem::zeroed() };
    let rv = C_GetSessionInfo(0xFFFFFFFF, &mut info);
    assert_eq!(rv, CKR_SESSION_HANDLE_INVALID);
}

#[test]
fn test_close_session_twice_fails() {
    setup_token();
    let mut session: CK_SESSION_HANDLE = 0;
    C_OpenSession(
        0,
        CKF_RW_SESSION | CKF_SERIAL_SESSION,
        ptr::null_mut(),
        None,
        &mut session,
    );
    let rv = C_CloseSession(session);
    assert_eq!(rv, CKR_OK);
    let rv = C_CloseSession(session);
    assert_eq!(rv, CKR_SESSION_HANDLE_INVALID, "Double close should fail");
}

#[test]
fn test_random_after_logout() {
    let session = setup_user_session();
    C_Logout(session);
    // Random generation should still work without login (public operation)
    let mut buf = [0u8; 16];
    let rv = C_GenerateRandom(session, buf.as_mut_ptr(), 16);
    // May require login depending on implementation. Test the behavior.
    // Either OK or USER_NOT_LOGGED_IN is acceptable.
    assert!(
        rv == CKR_OK || rv == CKR_USER_NOT_LOGGED_IN,
        "Random after logout: 0x{:08X}",
        rv
    );
}

#[test]
fn test_so_login_session_state() {
    setup_token();
    let so_pin = b"sopin123";
    let mut session: CK_SESSION_HANDLE = 0;
    C_OpenSession(
        0,
        CKF_RW_SESSION | CKF_SERIAL_SESSION,
        ptr::null_mut(),
        None,
        &mut session,
    );
    let rv = C_Login(
        session,
        CKU_SO,
        so_pin.as_ptr() as *mut _,
        so_pin.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_OK);

    let mut info: CK_SESSION_INFO = unsafe { std::mem::zeroed() };
    let rv = C_GetSessionInfo(session, &mut info);
    assert_eq!(rv, CKR_OK);
    let state = info.state;
    assert_eq!(
        state, CKS_RW_SO_FUNCTIONS,
        "SO login should be CKS_RW_SO_FUNCTIONS"
    );
    C_Logout(session);
    C_CloseSession(session);
}
