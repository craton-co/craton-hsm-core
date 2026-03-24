// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
// PKCS#11 info/query function tests — exercises C_GetInfo, C_GetSlotList,
// C_GetSlotInfo, C_GetTokenInfo, C_GetMechanismList, C_GetMechanismInfo,
// and C_GetFunctionList through the C ABI layer.
//
// These tests MUST run with --test-threads=1 due to shared global OnceLock state.

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
    label[..8].copy_from_slice(b"InfoTest");
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

// =============================================================================
// 1. C_GetInfo — cryptoki_version should be v3.0
// =============================================================================
#[test]
fn test_get_info_returns_valid_version() {
    ensure_init();
    let mut info: CK_INFO = unsafe { std::mem::zeroed() };
    let rv = C_GetInfo(&mut info);
    assert_eq!(rv, CKR_OK);
    assert_eq!(
        info.cryptoki_version.major, 3,
        "Expected Cryptoki major version 3"
    );
    assert_eq!(
        info.cryptoki_version.minor, 0,
        "Expected Cryptoki minor version 0"
    );
}

// =============================================================================
// 2. C_GetInfo — library_description is non-empty
// =============================================================================
#[test]
fn test_get_info_library_description() {
    ensure_init();
    let mut info: CK_INFO = unsafe { std::mem::zeroed() };
    let rv = C_GetInfo(&mut info);
    assert_eq!(rv, CKR_OK);
    let desc = &info.library_description;
    let all_spaces = desc.iter().all(|&b| b == b' ');
    assert!(!all_spaces, "library_description should not be all spaces");
}

// =============================================================================
// 3. C_GetInfo — manufacturer_id is non-empty
// =============================================================================
#[test]
fn test_get_info_manufacturer() {
    ensure_init();
    let mut info: CK_INFO = unsafe { std::mem::zeroed() };
    let rv = C_GetInfo(&mut info);
    assert_eq!(rv, CKR_OK);
    let mfr = &info.manufacturer_id;
    let all_spaces = mfr.iter().all(|&b| b == b' ');
    assert!(!all_spaces, "manufacturer_id should not be all spaces");
}

// =============================================================================
// 4. C_GetSlotList with token present — returns at least slot 0
// =============================================================================
#[test]
fn test_get_slot_list_with_token() {
    ensure_init();
    let mut count: CK_ULONG = 0;
    let rv = C_GetSlotList(CK_TRUE, ptr::null_mut(), &mut count);
    assert_eq!(rv, CKR_OK);
    assert!(
        count >= 1,
        "Expected at least 1 slot with token present, got {}",
        count
    );

    let mut slot_ids = vec![0 as CK_SLOT_ID; count as usize];
    let rv = C_GetSlotList(CK_TRUE, slot_ids.as_mut_ptr(), &mut count);
    assert_eq!(rv, CKR_OK);
    assert!(slot_ids.contains(&0), "Slot 0 should be in the list");
}

// =============================================================================
// 5. C_GetSlotList count-only mode — NULL slot list returns count
// =============================================================================
#[test]
fn test_get_slot_list_count_only() {
    ensure_init();
    let mut count: CK_ULONG = 0;
    let rv = C_GetSlotList(CK_FALSE, ptr::null_mut(), &mut count);
    assert_eq!(rv, CKR_OK);
    assert!(count >= 1, "Expected at least 1 slot, got {}", count);
}

// =============================================================================
// 6. C_GetSlotInfo on valid slot — CKF_SLOT_TOKEN_PRESENT flag set
// =============================================================================
#[test]
fn test_get_slot_info_valid_slot() {
    ensure_init();
    let mut slot_info: CK_SLOT_INFO = unsafe { std::mem::zeroed() };
    let rv = C_GetSlotInfo(0, &mut slot_info);
    assert_eq!(rv, CKR_OK);
    assert_ne!(
        slot_info.flags & CKF_SLOT_TOKEN_PRESENT,
        0,
        "CKF_SLOT_TOKEN_PRESENT flag should be set on slot 0"
    );
}

// =============================================================================
// 7. C_GetSlotInfo on invalid slot — returns CKR_SLOT_ID_INVALID
// =============================================================================
#[test]
fn test_get_slot_info_invalid_slot() {
    ensure_init();
    let mut slot_info: CK_SLOT_INFO = unsafe { std::mem::zeroed() };
    let rv = C_GetSlotInfo(99, &mut slot_info);
    assert_eq!(
        rv, CKR_SLOT_ID_INVALID,
        "Expected CKR_SLOT_ID_INVALID for invalid slot 99"
    );
}

// =============================================================================
// 8. C_GetTokenInfo — label starts with "InfoTest"
// =============================================================================
#[test]
fn test_get_token_info_label() {
    let _session = setup_user_session();
    let mut token_info: CK_TOKEN_INFO = unsafe { std::mem::zeroed() };
    let rv = C_GetTokenInfo(0, &mut token_info);
    assert_eq!(rv, CKR_OK);
    let label_str = std::str::from_utf8(&token_info.label).unwrap_or("");
    assert!(
        label_str.starts_with("InfoTest"),
        "Token label should start with 'InfoTest', got '{}'",
        label_str.trim()
    );
}

// =============================================================================
// 9. C_GetTokenInfo — CKF_TOKEN_INITIALIZED flag is set
// =============================================================================
#[test]
fn test_get_token_info_flags() {
    let _session = setup_user_session();
    let mut token_info: CK_TOKEN_INFO = unsafe { std::mem::zeroed() };
    let rv = C_GetTokenInfo(0, &mut token_info);
    assert_eq!(rv, CKR_OK);
    assert_ne!(
        token_info.flags & CKF_TOKEN_INITIALIZED,
        0,
        "CKF_TOKEN_INITIALIZED flag should be set after C_InitToken"
    );
}

// =============================================================================
// 10. C_GetTokenInfo — session_count > 0 after opening a session
// =============================================================================
#[test]
fn test_get_token_info_session_count() {
    let _session = setup_user_session();
    let mut token_info: CK_TOKEN_INFO = unsafe { std::mem::zeroed() };
    let rv = C_GetTokenInfo(0, &mut token_info);
    assert_eq!(rv, CKR_OK);
    // session_count should be > 0 since we have an open session,
    // unless the implementation reports CK_UNAVAILABLE_INFORMATION
    let session_count = token_info.session_count;
    assert!(
        session_count > 0 || session_count == CK_UNAVAILABLE_INFORMATION,
        "session_count should be > 0 or CK_UNAVAILABLE_INFORMATION, got {}",
        session_count
    );
}

// =============================================================================
// 11. C_GetMechanismList — count of mechanisms >= 30
// =============================================================================
#[test]
fn test_get_mechanism_list_count() {
    ensure_init();
    let mut count: CK_ULONG = 0;
    let rv = C_GetMechanismList(0, ptr::null_mut(), &mut count);
    assert_eq!(rv, CKR_OK);
    assert!(
        count >= 30,
        "Expected at least 30 mechanisms, got {}",
        count
    );
}

// =============================================================================
// 12. C_GetMechanismList — contains CKM_RSA_PKCS, CKM_AES_GCM, CKM_SHA256
// =============================================================================
#[test]
fn test_get_mechanism_list_contents() {
    ensure_init();
    let mut count: CK_ULONG = 0;
    let rv = C_GetMechanismList(0, ptr::null_mut(), &mut count);
    assert_eq!(rv, CKR_OK);

    let mut mechs = vec![0 as CK_MECHANISM_TYPE; count as usize];
    let rv = C_GetMechanismList(0, mechs.as_mut_ptr(), &mut count);
    assert_eq!(rv, CKR_OK);

    assert!(
        mechs.contains(&CKM_RSA_PKCS),
        "Mechanism list should contain CKM_RSA_PKCS"
    );
    assert!(
        mechs.contains(&CKM_AES_GCM),
        "Mechanism list should contain CKM_AES_GCM"
    );
    assert!(
        mechs.contains(&CKM_SHA256),
        "Mechanism list should contain CKM_SHA256"
    );
}

// =============================================================================
// 13. C_GetMechanismInfo — CKM_RSA_PKCS: key sizes and SIGN|VERIFY flags
// =============================================================================
#[test]
fn test_get_mechanism_info_rsa_pkcs() {
    ensure_init();
    let mut mech_info: CK_MECHANISM_INFO = unsafe { std::mem::zeroed() };
    let rv = C_GetMechanismInfo(0, CKM_RSA_PKCS, &mut mech_info);
    assert_eq!(rv, CKR_OK);
    let min_key_size = mech_info.min_key_size;
    let max_key_size = mech_info.max_key_size;
    let flags = mech_info.flags;
    assert_eq!(min_key_size, 2048, "RSA PKCS min key size should be 2048");
    assert!(
        max_key_size >= 4096,
        "RSA PKCS max key size should be >= 4096"
    );
    assert_ne!(
        flags & CKF_SIGN_FLAG,
        0,
        "CKM_RSA_PKCS should have CKF_SIGN_FLAG"
    );
    assert_ne!(
        mech_info.flags & CKF_VERIFY_FLAG,
        0,
        "CKM_RSA_PKCS should have CKF_VERIFY_FLAG"
    );
}

// =============================================================================
// 14. C_GetMechanismInfo — CKM_RSA_PKCS_KEY_PAIR_GEN: GENERATE_KEY_PAIR flag
// =============================================================================
#[test]
fn test_get_mechanism_info_rsa_keygen() {
    ensure_init();
    let mut mech_info: CK_MECHANISM_INFO = unsafe { std::mem::zeroed() };
    let rv = C_GetMechanismInfo(0, CKM_RSA_PKCS_KEY_PAIR_GEN, &mut mech_info);
    assert_eq!(rv, CKR_OK);
    assert_ne!(
        mech_info.flags & CKF_GENERATE_KEY_PAIR_FLAG,
        0,
        "CKM_RSA_PKCS_KEY_PAIR_GEN should have CKF_GENERATE_KEY_PAIR_FLAG"
    );
}

// =============================================================================
// 15. C_GetMechanismInfo — CKM_AES_GCM: ENCRYPT|DECRYPT flags
// =============================================================================
#[test]
fn test_get_mechanism_info_aes_gcm() {
    ensure_init();
    let mut mech_info: CK_MECHANISM_INFO = unsafe { std::mem::zeroed() };
    let rv = C_GetMechanismInfo(0, CKM_AES_GCM, &mut mech_info);
    assert_eq!(rv, CKR_OK);
    assert_ne!(
        mech_info.flags & CKF_ENCRYPT_FLAG,
        0,
        "CKM_AES_GCM should have CKF_ENCRYPT_FLAG"
    );
    assert_ne!(
        mech_info.flags & CKF_DECRYPT_FLAG,
        0,
        "CKM_AES_GCM should have CKF_DECRYPT_FLAG"
    );
}

// =============================================================================
// 16. C_GetMechanismInfo — CKM_AES_KEY_GEN: GENERATE flag
// =============================================================================
#[test]
fn test_get_mechanism_info_aes_keygen() {
    ensure_init();
    let mut mech_info: CK_MECHANISM_INFO = unsafe { std::mem::zeroed() };
    let rv = C_GetMechanismInfo(0, CKM_AES_KEY_GEN, &mut mech_info);
    assert_eq!(rv, CKR_OK);
    assert_ne!(
        mech_info.flags & CKF_GENERATE_FLAG,
        0,
        "CKM_AES_KEY_GEN should have CKF_GENERATE_FLAG"
    );
}

// =============================================================================
// 17. C_GetMechanismInfo — CKM_ECDSA: SIGN|VERIFY flags
// =============================================================================
#[test]
fn test_get_mechanism_info_ecdsa() {
    ensure_init();
    let mut mech_info: CK_MECHANISM_INFO = unsafe { std::mem::zeroed() };
    let rv = C_GetMechanismInfo(0, CKM_ECDSA, &mut mech_info);
    assert_eq!(rv, CKR_OK);
    assert_ne!(
        mech_info.flags & CKF_SIGN_FLAG,
        0,
        "CKM_ECDSA should have CKF_SIGN_FLAG"
    );
    assert_ne!(
        mech_info.flags & CKF_VERIFY_FLAG,
        0,
        "CKM_ECDSA should have CKF_VERIFY_FLAG"
    );
}

// =============================================================================
// 18. C_GetMechanismInfo — CKM_SHA256: DIGEST flag
// =============================================================================
#[test]
fn test_get_mechanism_info_sha256() {
    ensure_init();
    let mut mech_info: CK_MECHANISM_INFO = unsafe { std::mem::zeroed() };
    let rv = C_GetMechanismInfo(0, CKM_SHA256, &mut mech_info);
    assert_eq!(rv, CKR_OK);
    assert_ne!(
        mech_info.flags & CKF_DIGEST_FLAG,
        0,
        "CKM_SHA256 should have CKF_DIGEST_FLAG"
    );
}

// =============================================================================
// 19. C_GetMechanismInfo — CKM_SHA3_256: DIGEST flag
// =============================================================================
#[test]
fn test_get_mechanism_info_sha3_256() {
    ensure_init();
    let mut mech_info: CK_MECHANISM_INFO = unsafe { std::mem::zeroed() };
    let rv = C_GetMechanismInfo(0, CKM_SHA3_256, &mut mech_info);
    assert_eq!(rv, CKR_OK);
    assert_ne!(
        mech_info.flags & CKF_DIGEST_FLAG,
        0,
        "CKM_SHA3_256 should have CKF_DIGEST_FLAG"
    );
}

// =============================================================================
// 20. C_GetMechanismInfo — CKM_ML_DSA_44: SIGN|VERIFY flags
// =============================================================================
#[test]
fn test_get_mechanism_info_ml_dsa() {
    ensure_init();
    let mut mech_info: CK_MECHANISM_INFO = unsafe { std::mem::zeroed() };
    let rv = C_GetMechanismInfo(0, CKM_ML_DSA_44, &mut mech_info);
    assert_eq!(rv, CKR_OK);
    assert_ne!(
        mech_info.flags & CKF_SIGN_FLAG,
        0,
        "CKM_ML_DSA_44 should have CKF_SIGN_FLAG"
    );
    assert_ne!(
        mech_info.flags & CKF_VERIFY_FLAG,
        0,
        "CKM_ML_DSA_44 should have CKF_VERIFY_FLAG"
    );
}

// =============================================================================
// 21. C_GetMechanismInfo — CKM_ML_KEM_768: GENERATE_KEY_PAIR|DERIVE flags
// =============================================================================
#[test]
fn test_get_mechanism_info_ml_kem() {
    ensure_init();
    let mut mech_info: CK_MECHANISM_INFO = unsafe { std::mem::zeroed() };
    let rv = C_GetMechanismInfo(0, CKM_ML_KEM_768, &mut mech_info);
    assert_eq!(rv, CKR_OK);
    assert_ne!(
        mech_info.flags & CKF_GENERATE_KEY_PAIR_FLAG,
        0,
        "CKM_ML_KEM_768 should have CKF_GENERATE_KEY_PAIR_FLAG"
    );
    assert_ne!(
        mech_info.flags & CKF_DERIVE_FLAG,
        0,
        "CKM_ML_KEM_768 should have CKF_DERIVE_FLAG"
    );
}

// =============================================================================
// 22. C_GetMechanismInfo — invalid mechanism returns CKR_MECHANISM_INVALID
// =============================================================================
#[test]
fn test_get_mechanism_info_invalid() {
    ensure_init();
    let mut mech_info: CK_MECHANISM_INFO = unsafe { std::mem::zeroed() };
    let rv = C_GetMechanismInfo(0, 0xFFFFFFFF, &mut mech_info);
    assert_eq!(
        rv, CKR_MECHANISM_INVALID,
        "Invalid mechanism 0xFFFFFFFF should return CKR_MECHANISM_INVALID"
    );
}

// =============================================================================
// 23. C_GetMechanismInfo — CKM_EDDSA: SIGN|VERIFY flags
// =============================================================================
#[test]
fn test_get_mechanism_info_eddsa() {
    ensure_init();
    let mut mech_info: CK_MECHANISM_INFO = unsafe { std::mem::zeroed() };
    let rv = C_GetMechanismInfo(0, CKM_EDDSA, &mut mech_info);
    assert_eq!(rv, CKR_OK);
    assert_ne!(
        mech_info.flags & CKF_SIGN_FLAG,
        0,
        "CKM_EDDSA should have CKF_SIGN_FLAG"
    );
    assert_ne!(
        mech_info.flags & CKF_VERIFY_FLAG,
        0,
        "CKM_EDDSA should have CKF_VERIFY_FLAG"
    );
}

// =============================================================================
// 24. C_GetFunctionList — returns CKR_OK with non-null pointer
// =============================================================================
#[test]
fn test_get_function_list() {
    // C_GetFunctionList should work even before C_Initialize
    let mut func_list: *mut CK_FUNCTION_LIST = ptr::null_mut();
    let rv = C_GetFunctionList(&mut func_list);
    assert_eq!(rv, CKR_OK, "C_GetFunctionList should return CKR_OK");
    assert!(
        !func_list.is_null(),
        "C_GetFunctionList should return a non-null pointer"
    );
}

// =============================================================================
// 25. C_GetSlotInfo — firmware version fields are valid
// =============================================================================
#[test]
fn test_get_slot_info_firmware_version() {
    ensure_init();
    let mut slot_info: CK_SLOT_INFO = unsafe { std::mem::zeroed() };
    let rv = C_GetSlotInfo(0, &mut slot_info);
    assert_eq!(rv, CKR_OK);
    // Verify that the firmware and hardware version structs were actually
    // populated by the implementation (not left as zeroed memory). The version
    // fields are u8 so any value is technically valid, but we can verify the
    // struct was written to by checking that the slot_description is non-empty
    // (which proves the implementation filled in the CK_SLOT_INFO struct).
    let desc = &slot_info.slot_description;
    let all_zeros = desc.iter().all(|&b| b == 0);
    assert!(
        !all_zeros,
        "slot_description should be populated, indicating C_GetSlotInfo filled the struct"
    );
    // Verify firmware_version and hardware_version are accessible and consistent
    let fw_major = slot_info.firmware_version.major;
    let fw_minor = slot_info.firmware_version.minor;
    let hw_major = slot_info.hardware_version.major;
    // Versions should be small sensible numbers (not random garbage)
    assert!(
        fw_major < 100,
        "firmware_version.major={} seems unreasonable",
        fw_major
    );
    assert!(
        fw_minor < 100,
        "firmware_version.minor={} seems unreasonable",
        fw_minor
    );
    assert!(
        hw_major < 100,
        "hardware_version.major={} seems unreasonable",
        hw_major
    );
}
