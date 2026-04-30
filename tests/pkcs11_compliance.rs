// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
// PKCS#11 compliance tests — exercises the C ABI layer directly.
// Tests the session state machine, login flows, object management, and crypto.

use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm::pkcs11_abi::functions::*;
use craton_hsm::pkcs11_abi::types::*;
use std::ptr;

fn ck_ulong_bytes(val: CK_ULONG) -> Vec<u8> {
    val.to_ne_bytes().to_vec()
}

// NOTE: Because C_Initialize uses a static OnceLock, tests that call it must
// be run in separate processes or sequentially. For now, we run a single
// integrated test that exercises the full lifecycle.

#[test]
fn test_full_pkcs11_lifecycle() {
    // 1. C_GetFunctionList should work even before init
    let mut func_list: *mut CK_FUNCTION_LIST = ptr::null_mut();
    let rv = C_GetFunctionList(&mut func_list);
    assert_eq!(rv, CKR_OK);
    assert!(!func_list.is_null());

    // 2. C_GetInfo should fail before initialization
    // (OnceLock might have been set by another test in the same process,
    //  so we test the full flow instead)

    // 3. Initialize
    let rv = C_Initialize(ptr::null_mut());
    // May be OK or ALREADY_INITIALIZED if another test ran first
    assert!(rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED);

    // 4. C_GetInfo
    let mut info: CK_INFO = unsafe { std::mem::zeroed() };
    let rv = C_GetInfo(&mut info);
    assert_eq!(rv, CKR_OK);
    assert_eq!(info.cryptoki_version.major, 3);
    assert_eq!(info.cryptoki_version.minor, 0);

    // 5. C_GetSlotList
    let mut count: CK_ULONG = 0;
    let rv = C_GetSlotList(CK_FALSE, ptr::null_mut(), &mut count);
    assert_eq!(rv, CKR_OK);
    assert_eq!(count, 1);

    let mut slot_ids = vec![0 as CK_SLOT_ID; count as usize];
    let rv = C_GetSlotList(CK_FALSE, slot_ids.as_mut_ptr(), &mut count);
    assert_eq!(rv, CKR_OK);
    assert_eq!(slot_ids[0], 0);

    // 6. C_GetSlotInfo
    let mut slot_info: CK_SLOT_INFO = unsafe { std::mem::zeroed() };
    let rv = C_GetSlotInfo(0, &mut slot_info);
    assert_eq!(rv, CKR_OK);
    assert_ne!(slot_info.flags & CKF_SLOT_TOKEN_PRESENT, 0);

    // 7. Invalid slot should fail
    let rv = C_GetSlotInfo(99, &mut slot_info);
    assert_eq!(rv, CKR_SLOT_ID_INVALID);

    // 8. Init token
    let so_pin = b"sopin123";
    let mut label = [b' '; 32];
    label[..9].copy_from_slice(b"TestToken");
    let rv = C_InitToken(
        0,
        so_pin.as_ptr() as *mut _,
        so_pin.len() as CK_ULONG,
        label.as_ptr() as *mut _,
    );
    assert_eq!(rv, CKR_OK);

    // 9. C_GetTokenInfo
    let mut token_info: CK_TOKEN_INFO = unsafe { std::mem::zeroed() };
    let rv = C_GetTokenInfo(0, &mut token_info);
    assert_eq!(rv, CKR_OK);
    assert_ne!(token_info.flags & CKF_TOKEN_INITIALIZED, 0);

    // 10. Open RW session
    let mut session: CK_SESSION_HANDLE = 0;
    let rv = C_OpenSession(
        0,
        CKF_RW_SESSION | CKF_SERIAL_SESSION,
        ptr::null_mut(),
        None,
        &mut session,
    );
    assert_eq!(rv, CKR_OK);
    assert_ne!(session, 0);

    // 11. GetSessionInfo — should be RW_PUBLIC
    let mut sess_info: CK_SESSION_INFO = unsafe { std::mem::zeroed() };
    let rv = C_GetSessionInfo(session, &mut sess_info);
    assert_eq!(rv, CKR_OK);
    let state = sess_info.state;
    assert_eq!(state, CKS_RW_PUBLIC_SESSION);

    // 12. Login as SO
    let rv = C_Login(
        session,
        CKU_SO,
        so_pin.as_ptr() as *mut _,
        so_pin.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_OK);

    // 13. Session should now be RW_SO
    let rv = C_GetSessionInfo(session, &mut sess_info);
    assert_eq!(rv, CKR_OK);
    let state = sess_info.state;
    assert_eq!(state, CKS_RW_SO_FUNCTIONS);

    // 14. Init user PIN
    let user_pin = b"userpin1234";
    let rv = C_InitPIN(
        session,
        user_pin.as_ptr() as *mut _,
        user_pin.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_OK);

    // 15. Logout SO
    let rv = C_Logout(session);
    assert_eq!(rv, CKR_OK);

    // 16. Session should be RW_PUBLIC again
    let rv = C_GetSessionInfo(session, &mut sess_info);
    assert_eq!(rv, CKR_OK);
    let state = sess_info.state;
    assert_eq!(state, CKS_RW_PUBLIC_SESSION);

    // 17. Login as user
    let rv = C_Login(
        session,
        CKU_USER,
        user_pin.as_ptr() as *mut _,
        user_pin.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_OK);

    // 18. Session should be RW_USER
    let rv = C_GetSessionInfo(session, &mut sess_info);
    assert_eq!(rv, CKR_OK);
    let state = sess_info.state;
    assert_eq!(state, CKS_RW_USER_FUNCTIONS);

    // 19. Double login should fail
    let rv = C_Login(
        session,
        CKU_USER,
        user_pin.as_ptr() as *mut _,
        user_pin.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_USER_ALREADY_LOGGED_IN);

    // 20. Generate AES key
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let value_len_bytes = ck_ulong_bytes(32);
    let label_bytes = b"test-aes-key";
    let ck_true: CK_BBOOL = CK_TRUE;
    let mut template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_VALUE_LEN,
            p_value: value_len_bytes.as_ptr() as CK_VOID_PTR,
            value_len: value_len_bytes.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_LABEL,
            p_value: label_bytes.as_ptr() as CK_VOID_PTR,
            value_len: label_bytes.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_ENCRYPT,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_DECRYPT,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ];

    let mut aes_key: CK_OBJECT_HANDLE = 0;
    let rv = C_GenerateKey(
        session,
        &mut mechanism,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut aes_key,
    );
    assert_eq!(rv, CKR_OK);
    assert_ne!(aes_key, 0);

    // 21. Encrypt with AES-GCM
    let mut enc_mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_EncryptInit(session, &mut enc_mechanism, aes_key);
    assert_eq!(rv, CKR_OK);

    let plaintext = b"Hello from PKCS#11 AES-GCM test!";
    let mut encrypted = vec![0u8; 256];
    let mut enc_len: CK_ULONG = encrypted.len() as CK_ULONG;
    let rv = C_Encrypt(
        session,
        plaintext.as_ptr() as CK_BYTE_PTR,
        plaintext.len() as CK_ULONG,
        encrypted.as_mut_ptr(),
        &mut enc_len,
    );
    assert_eq!(rv, CKR_OK);
    assert!(enc_len > plaintext.len() as CK_ULONG); // nonce + tag overhead

    // 22. Decrypt
    let rv = C_DecryptInit(session, &mut enc_mechanism, aes_key);
    assert_eq!(rv, CKR_OK);

    let mut decrypted = vec![0u8; 256];
    let mut dec_len: CK_ULONG = decrypted.len() as CK_ULONG;
    let rv = C_Decrypt(
        session,
        encrypted.as_mut_ptr(),
        enc_len,
        decrypted.as_mut_ptr(),
        &mut dec_len,
    );
    assert_eq!(rv, CKR_OK);
    assert_eq!(&decrypted[..dec_len as usize], plaintext.as_slice());

    // 23. Generate RSA key pair
    let mut rsa_mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let modulus_bits_bytes = ck_ulong_bytes(2048);
    let pub_exp_bytes: Vec<u8> = vec![0x01, 0x00, 0x01]; // 65537
    let sign_true: CK_BBOOL = CK_TRUE;
    let verify_true: CK_BBOOL = CK_TRUE;

    let mut pub_template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_MODULUS_BITS,
            p_value: modulus_bits_bytes.as_ptr() as CK_VOID_PTR,
            value_len: modulus_bits_bytes.len() as CK_ULONG,
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
        &mut rsa_mechanism,
        pub_template.as_mut_ptr(),
        pub_template.len() as CK_ULONG,
        priv_template.as_mut_ptr(),
        priv_template.len() as CK_ULONG,
        &mut pub_key,
        &mut priv_key,
    );
    assert_eq!(rv, CKR_OK);
    assert_ne!(pub_key, 0);
    assert_ne!(priv_key, 0);

    // 24. Sign with RSA
    let mut sign_mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256_RSA_PKCS,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_SignInit(session, &mut sign_mechanism, priv_key);
    assert_eq!(rv, CKR_OK);

    let message = b"Message to sign with RSA-SHA256";
    let mut signature = vec![0u8; 512];
    let mut sig_len: CK_ULONG = signature.len() as CK_ULONG;
    let rv = C_Sign(
        session,
        message.as_ptr() as CK_BYTE_PTR,
        message.len() as CK_ULONG,
        signature.as_mut_ptr(),
        &mut sig_len,
    );
    assert_eq!(rv, CKR_OK);
    assert_eq!(sig_len as usize, 256); // 2048-bit RSA

    // 25. Verify with RSA
    let rv = C_VerifyInit(session, &mut sign_mechanism, pub_key);
    assert_eq!(rv, CKR_OK);

    let rv = C_Verify(
        session,
        message.as_ptr() as CK_BYTE_PTR,
        message.len() as CK_ULONG,
        signature.as_mut_ptr(),
        sig_len,
    );
    assert_eq!(rv, CKR_OK);

    // 26. Verify with wrong message should fail
    let rv = C_VerifyInit(session, &mut sign_mechanism, pub_key);
    assert_eq!(rv, CKR_OK);

    let wrong_message = b"This is not the original message";
    let rv = C_Verify(
        session,
        wrong_message.as_ptr() as CK_BYTE_PTR,
        wrong_message.len() as CK_ULONG,
        signature.as_mut_ptr(),
        sig_len,
    );
    assert_eq!(rv, CKR_SIGNATURE_INVALID);

    // 27. FindObjects
    let find_class = ck_ulong_bytes(CKO_SECRET_KEY);
    let mut find_template = vec![CK_ATTRIBUTE {
        attr_type: CKA_CLASS,
        p_value: find_class.as_ptr() as CK_VOID_PTR,
        value_len: find_class.len() as CK_ULONG,
    }];

    let rv = C_FindObjectsInit(
        session,
        find_template.as_mut_ptr(),
        find_template.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_OK);

    let mut found: [CK_OBJECT_HANDLE; 10] = [0; 10];
    let mut found_count: CK_ULONG = 0;
    let rv = C_FindObjects(session, found.as_mut_ptr(), 10, &mut found_count);
    assert_eq!(rv, CKR_OK);
    assert!(found_count >= 1, "Should find at least the AES key");

    let rv = C_FindObjectsFinal(session);
    assert_eq!(rv, CKR_OK);

    // 28. GenerateRandom
    let mut random_data = [0u8; 32];
    let rv = C_GenerateRandom(session, random_data.as_mut_ptr(), 32);
    assert_eq!(rv, CKR_OK);
    assert_ne!(random_data, [0u8; 32]); // Statistically impossible to be all zeros

    // 29. SeedRandom should return RANDOM_SEED_NOT_SUPPORTED (we use OsRng)
    let rv = C_SeedRandom(session, random_data.as_mut_ptr(), 32);
    assert_eq!(rv, CKR_RANDOM_SEED_NOT_SUPPORTED);

    // 30. C_GetMechanismList
    let mut mech_count: CK_ULONG = 0;
    let rv = C_GetMechanismList(0, ptr::null_mut(), &mut mech_count);
    assert_eq!(rv, CKR_OK);
    assert!(mech_count > 0);

    let mut mechs = vec![0 as CK_MECHANISM_TYPE; mech_count as usize];
    let rv = C_GetMechanismList(0, mechs.as_mut_ptr(), &mut mech_count);
    assert_eq!(rv, CKR_OK);
    assert!(mechs.contains(&CKM_AES_KEY_GEN));
    assert!(mechs.contains(&CKM_RSA_PKCS_KEY_PAIR_GEN));
    assert!(mechs.contains(&CKM_SHA256_RSA_PKCS));

    // 31. Logout
    let rv = C_Logout(session);
    assert_eq!(rv, CKR_OK);

    // 32. SignInit should fail without login
    let rv = C_SignInit(session, &mut sign_mechanism, priv_key);
    assert_eq!(rv, CKR_USER_NOT_LOGGED_IN);

    // 33. Close session
    let rv = C_CloseSession(session);
    assert_eq!(rv, CKR_OK);

    // 34. Session should be invalid now
    let rv = C_GetSessionInfo(session, &mut sess_info);
    assert_eq!(rv, CKR_SESSION_HANDLE_INVALID);

    // 35. Finalize
    let rv = C_Finalize(ptr::null_mut());
    assert_eq!(rv, CKR_OK);
}
