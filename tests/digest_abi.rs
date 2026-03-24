// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
// PKCS#11 digest/hash ABI tests — exercises C_DigestInit, C_Digest,
// C_DigestUpdate, and C_DigestFinal through the C ABI layer.
//
// Tests cover:
// - Single-part digest for SHA-1, SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512
// - Multi-part digest (DigestUpdate + DigestFinal) for SHA-256, SHA-384, SHA-512, SHA3-256
// - NIST known-answer vectors for SHA-256 and SHA-512
// - Empty data, large data, single-byte updates
// - Two-call idiom (null output to query size)
// - Buffer-too-small error handling
// - Operation sequencing errors (without init, double init)
// - No-login-required (digest is a public operation)
// - Invalid mechanism rejection
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
    label[..10].copy_from_slice(b"DigestTest");
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

/// Helper: perform single-part digest and return the output bytes.
fn digest_single_part(
    session: CK_SESSION_HANDLE,
    mechanism_type: CK_ULONG,
    data: &[u8],
) -> Vec<u8> {
    let mut mechanism = CK_MECHANISM {
        mechanism: mechanism_type,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_DigestInit(session, &mut mechanism);
    assert_eq!(
        rv, CKR_OK,
        "C_DigestInit failed for mechanism 0x{:08X}",
        mechanism_type
    );

    // Use a generous buffer (128 bytes covers all digest sizes up to SHA-512)
    let mut digest = vec![0u8; 128];
    let mut out_len: CK_ULONG = digest.len() as CK_ULONG;
    let rv = C_Digest(
        session,
        data.as_ptr() as CK_BYTE_PTR,
        data.len() as CK_ULONG,
        digest.as_mut_ptr(),
        &mut out_len,
    );
    assert_eq!(
        rv, CKR_OK,
        "C_Digest failed for mechanism 0x{:08X}",
        mechanism_type
    );
    digest.truncate(out_len as usize);
    digest
}

/// Helper: perform multi-part digest and return the output bytes.
fn digest_multi_part(
    session: CK_SESSION_HANDLE,
    mechanism_type: CK_ULONG,
    chunks: &[&[u8]],
) -> Vec<u8> {
    let mut mechanism = CK_MECHANISM {
        mechanism: mechanism_type,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_DigestInit(session, &mut mechanism);
    assert_eq!(
        rv, CKR_OK,
        "C_DigestInit failed for multi-part mechanism 0x{:08X}",
        mechanism_type
    );

    for chunk in chunks {
        let rv = C_DigestUpdate(
            session,
            chunk.as_ptr() as CK_BYTE_PTR,
            chunk.len() as CK_ULONG,
        );
        assert_eq!(
            rv, CKR_OK,
            "C_DigestUpdate failed for mechanism 0x{:08X}",
            mechanism_type
        );
    }

    // Use a generous buffer (128 bytes covers all digest sizes up to SHA-512)
    let mut digest = vec![0u8; 128];
    let mut out_len: CK_ULONG = digest.len() as CK_ULONG;
    let rv = C_DigestFinal(session, digest.as_mut_ptr(), &mut out_len);
    assert_eq!(
        rv, CKR_OK,
        "C_DigestFinal failed for mechanism 0x{:08X}",
        mechanism_type
    );
    digest.truncate(out_len as usize);
    digest
}

// =============================================================================
// Test 1: SHA-256 single-part
// =============================================================================
#[test]
fn test_sha256_single_part() {
    let session = setup_user_session();
    let data = b"hello world";
    let digest = digest_single_part(session, CKM_SHA256, data);
    assert_eq!(digest.len(), 32, "SHA-256 digest should be 32 bytes");
    let rv = C_CloseSession(session);
    assert_eq!(rv, CKR_OK);
}

// =============================================================================
// Test 2: SHA-384 single-part
// =============================================================================
#[test]
fn test_sha384_single_part() {
    let session = setup_user_session();
    let data = b"hello world";
    let digest = digest_single_part(session, CKM_SHA384, data);
    assert_eq!(digest.len(), 48, "SHA-384 digest should be 48 bytes");
    let rv = C_CloseSession(session);
    assert_eq!(rv, CKR_OK);
}

// =============================================================================
// Test 3: SHA-512 single-part
// =============================================================================
#[test]
fn test_sha512_single_part() {
    let session = setup_user_session();
    let data = b"hello world";
    let digest = digest_single_part(session, CKM_SHA512, data);
    assert_eq!(digest.len(), 64, "SHA-512 digest should be 64 bytes");
    let rv = C_CloseSession(session);
    assert_eq!(rv, CKR_OK);
}

// =============================================================================
// Test 4: SHA-1 single-part
// =============================================================================
#[test]
fn test_sha1_single_part() {
    let session = setup_user_session();
    let data = b"hello world";
    let digest = digest_single_part(session, CKM_SHA_1, data);
    assert_eq!(digest.len(), 20, "SHA-1 digest should be 20 bytes");
    let rv = C_CloseSession(session);
    assert_eq!(rv, CKR_OK);
}

// =============================================================================
// Test 5: SHA3-256 single-part
// =============================================================================
#[test]
fn test_sha3_256_single_part() {
    let session = setup_user_session();
    let data = b"hello world";
    let digest = digest_single_part(session, CKM_SHA3_256, data);
    assert_eq!(digest.len(), 32, "SHA3-256 digest should be 32 bytes");
    let rv = C_CloseSession(session);
    assert_eq!(rv, CKR_OK);
}

// =============================================================================
// Test 6: SHA3-384 single-part
// =============================================================================
#[test]
fn test_sha3_384_single_part() {
    let session = setup_user_session();
    let data = b"hello world";
    let digest = digest_single_part(session, CKM_SHA3_384, data);
    assert_eq!(digest.len(), 48, "SHA3-384 digest should be 48 bytes");
    let rv = C_CloseSession(session);
    assert_eq!(rv, CKR_OK);
}

// =============================================================================
// Test 7: SHA3-512 single-part
// =============================================================================
#[test]
fn test_sha3_512_single_part() {
    let session = setup_user_session();
    let data = b"hello world";
    let digest = digest_single_part(session, CKM_SHA3_512, data);
    assert_eq!(digest.len(), 64, "SHA3-512 digest should be 64 bytes");
    let rv = C_CloseSession(session);
    assert_eq!(rv, CKR_OK);
}

// =============================================================================
// Test 8: SHA-256 multi-part
// =============================================================================
#[test]
fn test_sha256_multipart() {
    let session = setup_user_session();
    let chunks: &[&[u8]] = &[b"hel", b"lo ", b"world"];
    let digest_mp = digest_multi_part(session, CKM_SHA256, chunks);
    assert_eq!(
        digest_mp.len(),
        32,
        "SHA-256 multi-part digest should be 32 bytes"
    );

    // Compare with single-part on the same data
    let digest_sp = digest_single_part(session, CKM_SHA256, b"hello world");
    assert_eq!(
        digest_mp, digest_sp,
        "SHA-256 multi-part digest must match single-part digest"
    );
    let rv = C_CloseSession(session);
    assert_eq!(rv, CKR_OK);
}

// =============================================================================
// Test 9: SHA-384 multi-part
// =============================================================================
#[test]
fn test_sha384_multipart() {
    let session = setup_user_session();
    let chunks: &[&[u8]] = &[b"hel", b"lo ", b"world"];
    let digest_mp = digest_multi_part(session, CKM_SHA384, chunks);
    assert_eq!(
        digest_mp.len(),
        48,
        "SHA-384 multi-part digest should be 48 bytes"
    );

    let digest_sp = digest_single_part(session, CKM_SHA384, b"hello world");
    assert_eq!(
        digest_mp, digest_sp,
        "SHA-384 multi-part digest must match single-part digest"
    );
    let rv = C_CloseSession(session);
    assert_eq!(rv, CKR_OK);
}

// =============================================================================
// Test 10: SHA-512 multi-part
// =============================================================================
#[test]
fn test_sha512_multipart() {
    let session = setup_user_session();
    let chunks: &[&[u8]] = &[b"hel", b"lo ", b"world"];
    let digest_mp = digest_multi_part(session, CKM_SHA512, chunks);
    assert_eq!(
        digest_mp.len(),
        64,
        "SHA-512 multi-part digest should be 64 bytes"
    );

    let digest_sp = digest_single_part(session, CKM_SHA512, b"hello world");
    assert_eq!(
        digest_mp, digest_sp,
        "SHA-512 multi-part digest must match single-part digest"
    );
    let rv = C_CloseSession(session);
    assert_eq!(rv, CKR_OK);
}

// =============================================================================
// Test 11: SHA3-256 multi-part
// =============================================================================
#[test]
fn test_sha3_256_multipart() {
    let session = setup_user_session();
    let chunks: &[&[u8]] = &[b"hel", b"lo ", b"world"];
    let digest_mp = digest_multi_part(session, CKM_SHA3_256, chunks);
    assert_eq!(
        digest_mp.len(),
        32,
        "SHA3-256 multi-part digest should be 32 bytes"
    );

    let digest_sp = digest_single_part(session, CKM_SHA3_256, b"hello world");
    assert_eq!(
        digest_mp, digest_sp,
        "SHA3-256 multi-part digest must match single-part digest"
    );
    let rv = C_CloseSession(session);
    assert_eq!(rv, CKR_OK);
}

// =============================================================================
// Test 12: SHA-256 empty data
// =============================================================================
#[test]
fn test_sha256_empty_data() {
    let session = setup_user_session();
    let digest = digest_single_part(session, CKM_SHA256, b"");
    assert_eq!(digest.len(), 32, "SHA-256 of empty data should be 32 bytes");

    // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    let expected: [u8; 32] = [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
        0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55,
    ];
    assert_eq!(
        digest, expected,
        "SHA-256 of empty string does not match known vector"
    );
    let rv = C_CloseSession(session);
    assert_eq!(rv, CKR_OK);
}

// =============================================================================
// Test 13: SHA-256 known answer vector ("abc")
// =============================================================================
#[test]
fn test_sha256_known_vector() {
    let session = setup_user_session();
    let digest = digest_single_part(session, CKM_SHA256, b"abc");
    assert_eq!(digest.len(), 32);

    // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    let expected: [u8; 32] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];
    assert_eq!(
        digest, expected,
        "SHA-256('abc') does not match NIST known-answer vector"
    );
    let rv = C_CloseSession(session);
    assert_eq!(rv, CKR_OK);
}

// =============================================================================
// Test 14: SHA-512 known answer vector ("abc")
// =============================================================================
#[test]
fn test_sha512_known_vector() {
    let session = setup_user_session();
    let digest = digest_single_part(session, CKM_SHA512, b"abc");
    assert_eq!(digest.len(), 64);

    // SHA-512("abc") first 8 bytes: ddaf35a193617aba
    // Full vector:
    let expected: [u8; 64] = [
        0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41,
        0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55,
        0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3,
        0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f,
        0xa5, 0x4c, 0xa4, 0x9f,
    ];
    assert_eq!(
        digest, expected,
        "SHA-512('abc') does not match NIST known-answer vector"
    );
    let rv = C_CloseSession(session);
    assert_eq!(rv, CKR_OK);
}

// =============================================================================
// Test 15: Null output pointer returns required size (two-call idiom)
// =============================================================================
#[test]
fn test_digest_null_output_gets_size() {
    let session = setup_user_session();
    let data = b"hello world";

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_DigestInit(session, &mut mechanism);
    assert_eq!(rv, CKR_OK);

    let mut digest_len: CK_ULONG = 0;
    let rv = C_Digest(
        session,
        data.as_ptr() as CK_BYTE_PTR,
        data.len() as CK_ULONG,
        ptr::null_mut(),
        &mut digest_len,
    );
    assert_eq!(rv, CKR_OK, "C_Digest with null output should return CKR_OK");
    assert_eq!(
        digest_len as usize, 32,
        "SHA-256 should report 32 bytes required"
    );

    let rv = C_CloseSession(session);
    assert_eq!(rv, CKR_OK);
}

// =============================================================================
// Test 16: Buffer too small returns CKR_BUFFER_TOO_SMALL
// =============================================================================
#[test]
fn test_digest_buffer_too_small() {
    let session = setup_user_session();
    let data = b"hello world";

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_DigestInit(session, &mut mechanism);
    assert_eq!(rv, CKR_OK);

    let mut tiny_buf = [0u8; 1];
    let mut buf_len: CK_ULONG = tiny_buf.len() as CK_ULONG;
    let rv = C_Digest(
        session,
        data.as_ptr() as CK_BYTE_PTR,
        data.len() as CK_ULONG,
        tiny_buf.as_mut_ptr(),
        &mut buf_len,
    );
    assert_eq!(
        rv, CKR_BUFFER_TOO_SMALL,
        "C_Digest with 1-byte buffer should return CKR_BUFFER_TOO_SMALL, got 0x{:08X}",
        rv
    );
    // The required size should be written back
    assert_eq!(
        buf_len as usize, 32,
        "Required size should be 32 for SHA-256"
    );

    let rv = C_CloseSession(session);
    assert_eq!(rv, CKR_OK);
}

// =============================================================================
// Test 17: C_Digest without C_DigestInit
// =============================================================================
#[test]
fn test_digest_without_init() {
    let session = setup_user_session();
    let data = b"hello world";

    let mut digest = vec![0u8; 64];
    let mut digest_len: CK_ULONG = digest.len() as CK_ULONG;
    let rv = C_Digest(
        session,
        data.as_ptr() as CK_BYTE_PTR,
        data.len() as CK_ULONG,
        digest.as_mut_ptr(),
        &mut digest_len,
    );
    assert_eq!(
        rv, CKR_OPERATION_NOT_INITIALIZED,
        "C_Digest without C_DigestInit should return CKR_OPERATION_NOT_INITIALIZED, got 0x{:08X}",
        rv
    );
    let rv = C_CloseSession(session);
    assert_eq!(rv, CKR_OK);
}

// =============================================================================
// Test 18: C_DigestUpdate without C_DigestInit
// =============================================================================
#[test]
fn test_digest_update_without_init() {
    let session = setup_user_session();
    let data = b"hello";

    let rv = C_DigestUpdate(
        session,
        data.as_ptr() as CK_BYTE_PTR,
        data.len() as CK_ULONG,
    );
    assert_eq!(
        rv, CKR_OPERATION_NOT_INITIALIZED,
        "C_DigestUpdate without C_DigestInit should return CKR_OPERATION_NOT_INITIALIZED, got 0x{:08X}",
        rv
    );
    let rv = C_CloseSession(session);
    assert_eq!(rv, CKR_OK);
}

// =============================================================================
// Test 19: C_DigestFinal without C_DigestInit
// =============================================================================
#[test]
fn test_digest_final_without_init() {
    let session = setup_user_session();

    let mut digest = vec![0u8; 64];
    let mut digest_len: CK_ULONG = digest.len() as CK_ULONG;
    let rv = C_DigestFinal(session, digest.as_mut_ptr(), &mut digest_len);
    assert_eq!(
        rv, CKR_OPERATION_NOT_INITIALIZED,
        "C_DigestFinal without C_DigestInit should return CKR_OPERATION_NOT_INITIALIZED, got 0x{:08X}",
        rv
    );
    let rv = C_CloseSession(session);
    assert_eq!(rv, CKR_OK);
}

// =============================================================================
// Test 20: Double C_DigestInit returns CKR_OPERATION_ACTIVE
// =============================================================================
#[test]
fn test_digest_double_init() {
    let session = setup_user_session();

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_DigestInit(session, &mut mechanism);
    assert_eq!(rv, CKR_OK);

    // Second init while first is still active
    let rv = C_DigestInit(session, &mut mechanism);
    assert_eq!(
        rv, CKR_OPERATION_ACTIVE,
        "Double C_DigestInit should return CKR_OPERATION_ACTIVE, got 0x{:08X}",
        rv
    );

    // Clean up: consume the active operation so the session is clean
    let mut digest = vec![0u8; 32];
    let mut digest_len: CK_ULONG = digest.len() as CK_ULONG;
    let _ = C_Digest(
        session,
        b"x".as_ptr() as CK_BYTE_PTR,
        1,
        digest.as_mut_ptr(),
        &mut digest_len,
    );

    let rv = C_CloseSession(session);
    assert_eq!(rv, CKR_OK);
}

// =============================================================================
// Test 21: Multi-part matches single-part byte-for-byte (SHA-256)
// =============================================================================
#[test]
fn test_digest_multipart_matches_single() {
    let session = setup_user_session();
    let data = b"The quick brown fox jumps over the lazy dog";

    let digest_sp = digest_single_part(session, CKM_SHA256, data);

    let chunks: &[&[u8]] = &[
        b"The quick ",
        b"brown fox ",
        b"jumps over ",
        b"the lazy dog",
    ];
    let digest_mp = digest_multi_part(session, CKM_SHA256, chunks);

    assert_eq!(
        digest_sp, digest_mp,
        "SHA-256 multi-part and single-part must produce identical output for the same data"
    );
    let rv = C_CloseSession(session);
    assert_eq!(rv, CKR_OK);
}

// =============================================================================
// Test 22: SHA-256 large data (64KB of 0x42)
// =============================================================================
#[test]
fn test_sha256_large_data() {
    let session = setup_user_session();
    let large_data: Vec<u8> = vec![0x42u8; 65536];
    let digest = digest_single_part(session, CKM_SHA256, &large_data);
    assert_eq!(
        digest.len(),
        32,
        "SHA-256 of 64KB data should produce 32-byte output"
    );
    // Verify it is not all zeros (sanity check)
    assert!(
        digest.iter().any(|&b| b != 0),
        "Digest should not be all zeros"
    );
    let rv = C_CloseSession(session);
    assert_eq!(rv, CKR_OK);
}

// =============================================================================
// Test 23: Single-byte updates (10 bytes, one at a time)
// =============================================================================
#[test]
fn test_digest_single_byte_updates() {
    let session = setup_user_session();
    let data: [u8; 10] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09];

    // Multi-part: one byte at a time
    let chunks: Vec<&[u8]> = data.iter().map(|b| std::slice::from_ref(b)).collect();
    let digest_mp = digest_multi_part(session, CKM_SHA256, &chunks);

    // Single-part: all 10 bytes at once
    let digest_sp = digest_single_part(session, CKM_SHA256, &data);

    assert_eq!(
        digest_mp, digest_sp,
        "Single-byte DigestUpdate results must match single-part Digest for the same data"
    );
    let rv = C_CloseSession(session);
    assert_eq!(rv, CKR_OK);
}

// =============================================================================
// Test 24: Digest works without login (public operation)
// =============================================================================
#[test]
fn test_sha256_no_login_required() {
    ensure_init();
    let so_pin = b"sopin123";
    let mut label = [b' '; 32];
    label[..12].copy_from_slice(b"NoLoginTest!");
    let rv = C_InitToken(
        0,
        so_pin.as_ptr() as *mut _,
        so_pin.len() as CK_ULONG,
        label.as_ptr() as *mut _,
    );
    assert_eq!(rv, CKR_OK, "C_InitToken failed for no-login test");

    let mut session: CK_SESSION_HANDLE = 0;
    let rv = C_OpenSession(
        0,
        CKF_RW_SESSION | CKF_SERIAL_SESSION,
        ptr::null_mut(),
        None,
        &mut session,
    );
    assert_eq!(rv, CKR_OK, "C_OpenSession failed for no-login test");

    // Do NOT login — digest should still work as a public operation
    let data = b"hello world";
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_DigestInit(session, &mut mechanism);
    assert_eq!(rv, CKR_OK, "C_DigestInit without login should succeed");

    let mut digest = vec![0u8; 32];
    let mut digest_len: CK_ULONG = digest.len() as CK_ULONG;
    let rv = C_Digest(
        session,
        data.as_ptr() as CK_BYTE_PTR,
        data.len() as CK_ULONG,
        digest.as_mut_ptr(),
        &mut digest_len,
    );
    assert_eq!(rv, CKR_OK, "C_Digest without login should succeed");
    assert_eq!(
        digest_len as usize, 32,
        "SHA-256 output should be 32 bytes even without login"
    );

    let rv = C_CloseSession(session);
    assert_eq!(rv, CKR_OK);
}

// =============================================================================
// Test 25: Invalid mechanism returns CKR_MECHANISM_INVALID
// =============================================================================
#[test]
fn test_digest_invalid_mechanism() {
    let session = setup_user_session();

    let mut mechanism = CK_MECHANISM {
        mechanism: 0xFFFFFFFF as CK_ULONG,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_DigestInit(session, &mut mechanism);
    assert_eq!(
        rv, CKR_MECHANISM_INVALID,
        "C_DigestInit with invalid mechanism 0xFFFFFFFF should return CKR_MECHANISM_INVALID, got 0x{:08X}",
        rv
    );

    let rv = C_CloseSession(session);
    assert_eq!(rv, CKR_OK);
}
