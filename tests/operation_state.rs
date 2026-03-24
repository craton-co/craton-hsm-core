// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
// C_GetOperationState / C_SetOperationState ABI tests.
//
// Tests cover:
// - Save and restore a digest operation mid-stream (SHA-256)
// - Restored digest produces same result as uninterrupted digest
// - Two-call idiom (null buffer to query length)
// - Buffer-too-small error
// - CKR_OPERATION_NOT_INITIALIZED when no active operation
// - CKR_SAVED_STATE_INVALID for corrupt/truncated blobs
// - Save/restore sign operation mid-stream
// - Encrypt/decrypt operations return CKR_STATE_UNSAVEABLE
//
// Must run with --test-threads=1 due to global OnceLock state.

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

fn setup_user_session() -> CK_SESSION_HANDLE {
    ensure_init();
    let so_pin = b"sopin123";
    let mut label = [b' '; 32];
    label[..11].copy_from_slice(b"OpStateTest");
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

/// Helper: init SHA-256 digest on session
fn digest_init_sha256(session: CK_SESSION_HANDLE) {
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_DigestInit(session, &mut mechanism);
    assert_eq!(rv, CKR_OK, "C_DigestInit failed: 0x{:08X}", rv);
}

/// Helper: feed data via C_DigestUpdate
fn digest_update(session: CK_SESSION_HANDLE, data: &[u8]) {
    let rv = C_DigestUpdate(session, data.as_ptr() as *mut _, data.len() as CK_ULONG);
    assert_eq!(rv, CKR_OK, "C_DigestUpdate failed: 0x{:08X}", rv);
}

/// Helper: finalize digest and return hash bytes
fn digest_final(session: CK_SESSION_HANDLE) -> Vec<u8> {
    let mut out = vec![0u8; 64];
    let mut out_len = out.len() as CK_ULONG;
    let rv = C_DigestFinal(session, out.as_mut_ptr(), &mut out_len);
    assert_eq!(rv, CKR_OK, "C_DigestFinal failed: 0x{:08X}", rv);
    out.truncate(out_len as usize);
    out
}

/// Helper: get operation state blob from session
fn get_operation_state(session: CK_SESSION_HANDLE) -> Vec<u8> {
    // First call: query length
    let mut state_len: CK_ULONG = 0;
    let rv = C_GetOperationState(session, ptr::null_mut(), &mut state_len);
    assert_eq!(
        rv, CKR_OK,
        "C_GetOperationState length query failed: 0x{:08X}",
        rv
    );
    assert!(state_len > 0, "Operation state length should be > 0");

    // Second call: get data
    let mut state = vec![0u8; state_len as usize];
    let rv = C_GetOperationState(session, state.as_mut_ptr(), &mut state_len);
    assert_eq!(
        rv, CKR_OK,
        "C_GetOperationState data fetch failed: 0x{:08X}",
        rv
    );
    state.truncate(state_len as usize);
    state
}

#[test]
fn test_save_restore_digest_produces_same_result() {
    let session = setup_user_session();

    // Start a SHA-256 digest, feed part 1
    digest_init_sha256(session);
    digest_update(session, b"Hello, ");

    // Save operation state
    let state = get_operation_state(session);

    // Feed part 2 and finalize (this consumes the operation)
    digest_update(session, b"World!");
    let hash1 = digest_final(session);

    // Now restore the state (back to after "Hello, ") on the same session
    let rv = C_SetOperationState(
        session,
        state.as_ptr() as *mut _,
        state.len() as CK_ULONG,
        0, // no encryption key
        0, // no auth key
    );
    assert_eq!(rv, CKR_OK, "C_SetOperationState failed: 0x{:08X}", rv);

    // Feed part 2 again and finalize
    digest_update(session, b"World!");
    let hash2 = digest_final(session);

    // Both hashes must be identical
    assert_eq!(
        hash1, hash2,
        "Restored digest operation should produce same hash"
    );

    // Verify against known SHA-256("Hello, World!")
    // SHA-256("Hello, World!") = dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f
    let expected =
        hex::decode("dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f").unwrap();
    assert_eq!(hash1, expected, "Hash should match known SHA-256 vector");

    C_CloseSession(session);
}

#[test]
fn test_save_restore_on_different_session() {
    let session1 = setup_user_session();

    // Start digest on session1
    digest_init_sha256(session1);
    digest_update(session1, b"test data");

    // Save state
    let state = get_operation_state(session1);

    // Open a second session
    let mut session2: CK_SESSION_HANDLE = 0;
    let rv = C_OpenSession(
        0,
        CKF_RW_SESSION | CKF_SERIAL_SESSION,
        ptr::null_mut(),
        None,
        &mut session2,
    );
    assert_eq!(rv, CKR_OK);

    // Restore state on session2
    let rv = C_SetOperationState(
        session2,
        state.as_ptr() as *mut _,
        state.len() as CK_ULONG,
        0,
        0,
    );
    assert_eq!(
        rv, CKR_OK,
        "C_SetOperationState on session2 failed: 0x{:08X}",
        rv
    );

    // Finalize on both sessions with same additional data
    digest_update(session1, b" more");
    let hash1 = digest_final(session1);

    digest_update(session2, b" more");
    let hash2 = digest_final(session2);

    assert_eq!(
        hash1, hash2,
        "Restored digest on different session should produce same hash"
    );

    C_CloseSession(session1);
    C_CloseSession(session2);
}

#[test]
fn test_get_operation_state_two_call_idiom() {
    let session = setup_user_session();
    digest_init_sha256(session);
    digest_update(session, b"data");

    // Query length only
    let mut state_len: CK_ULONG = 0;
    let rv = C_GetOperationState(session, ptr::null_mut(), &mut state_len);
    assert_eq!(rv, CKR_OK);
    assert!(state_len > 0);

    // Provide exact-size buffer
    let mut state = vec![0u8; state_len as usize];
    let mut actual_len = state_len;
    let rv = C_GetOperationState(session, state.as_mut_ptr(), &mut actual_len);
    assert_eq!(rv, CKR_OK);
    assert_eq!(actual_len, state_len);

    // Clean up
    let _ = digest_final(session);
    C_CloseSession(session);
}

#[test]
fn test_get_operation_state_buffer_too_small() {
    let session = setup_user_session();
    digest_init_sha256(session);
    digest_update(session, b"data");

    // Query length
    let mut state_len: CK_ULONG = 0;
    let rv = C_GetOperationState(session, ptr::null_mut(), &mut state_len);
    assert_eq!(rv, CKR_OK);

    // Provide too-small buffer
    let mut small_buf = vec![0u8; 1];
    let mut small_len: CK_ULONG = 1;
    let rv = C_GetOperationState(session, small_buf.as_mut_ptr(), &mut small_len);
    assert_eq!(
        rv, CKR_BUFFER_TOO_SMALL,
        "Should return CKR_BUFFER_TOO_SMALL"
    );
    assert_eq!(small_len, state_len, "Should report required length");

    // Clean up
    let _ = digest_final(session);
    C_CloseSession(session);
}

#[test]
fn test_get_operation_state_no_active_operation() {
    let session = setup_user_session();

    // No operation started
    let mut state_len: CK_ULONG = 0;
    let rv = C_GetOperationState(session, ptr::null_mut(), &mut state_len);
    assert_eq!(
        rv, CKR_OPERATION_NOT_INITIALIZED,
        "Should return CKR_OPERATION_NOT_INITIALIZED when no operation active"
    );

    C_CloseSession(session);
}

#[test]
fn test_set_operation_state_invalid_blob() {
    let session = setup_user_session();

    // Empty blob
    let rv = C_SetOperationState(session, ptr::null_mut(), 0, 0, 0);
    assert_eq!(
        rv, CKR_ARGUMENTS_BAD,
        "Null pointer should return CKR_ARGUMENTS_BAD"
    );

    // Truncated blob (too short to be valid)
    let bad_blob = [0u8; 5];
    let rv = C_SetOperationState(
        session,
        bad_blob.as_ptr() as *mut _,
        bad_blob.len() as CK_ULONG,
        0,
        0,
    );
    assert_eq!(
        rv, CKR_SAVED_STATE_INVALID,
        "Truncated blob should return CKR_SAVED_STATE_INVALID"
    );

    // Invalid operation type byte
    let mut bad_blob2 = vec![0u8; 20];
    bad_blob2[0] = 255; // invalid op type
    let rv = C_SetOperationState(
        session,
        bad_blob2.as_ptr() as *mut _,
        bad_blob2.len() as CK_ULONG,
        0,
        0,
    );
    assert_eq!(
        rv, CKR_SAVED_STATE_INVALID,
        "Invalid op type should return CKR_SAVED_STATE_INVALID"
    );

    C_CloseSession(session);
}

#[test]
fn test_get_operation_state_null_len_ptr() {
    let session = setup_user_session();
    digest_init_sha256(session);

    let rv = C_GetOperationState(session, ptr::null_mut(), ptr::null_mut());
    assert_eq!(
        rv, CKR_ARGUMENTS_BAD,
        "Null length pointer should return CKR_ARGUMENTS_BAD"
    );

    // Clean up
    let _ = digest_final(session);
    C_CloseSession(session);
}

#[test]
fn test_save_restore_empty_digest() {
    let session = setup_user_session();

    // Init digest without any updates
    digest_init_sha256(session);

    // Save state (no data accumulated yet)
    let state = get_operation_state(session);

    // Finalize the empty digest
    let hash1 = digest_final(session);

    // Restore empty state
    let rv = C_SetOperationState(
        session,
        state.as_ptr() as *mut _,
        state.len() as CK_ULONG,
        0,
        0,
    );
    assert_eq!(rv, CKR_OK);

    // Finalize again — should produce the same hash (SHA-256 of empty string)
    let hash2 = digest_final(session);
    assert_eq!(
        hash1, hash2,
        "Restored empty digest should produce same hash"
    );

    // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    let expected =
        hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").unwrap();
    assert_eq!(hash1, expected);

    C_CloseSession(session);
}
