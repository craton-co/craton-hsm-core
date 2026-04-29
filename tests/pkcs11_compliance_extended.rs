// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Extended PKCS#11 compliance tests — session state machine, PIN enforcement,
//! PQC mechanism info, attribute enforcement, find/destroy operations.

use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm::pkcs11_abi::functions::*;
use craton_hsm::pkcs11_abi::types::*;
use std::ptr;

fn ck_ulong_bytes(val: CK_ULONG) -> Vec<u8> {
    val.to_ne_bytes().to_vec()
}

#[test]
fn test_extended_pkcs11_compliance() {
    // Initialize (may already be initialized by other test)
    let rv = C_Initialize(ptr::null_mut());
    assert!(rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED);

    // Init token with SO PIN
    let so_pin = b"sopin123";
    let mut label = [b' '; 32];
    label[..12].copy_from_slice(b"ExtTestToken");
    let rv = C_InitToken(
        0,
        so_pin.as_ptr() as *mut _,
        so_pin.len() as CK_ULONG,
        label.as_ptr() as *mut _,
    );
    assert_eq!(rv, CKR_OK);

    // ========================================================================
    // Test 1: C_GetMechanismList includes PQC mechanisms
    // ========================================================================
    let mut mech_count: CK_ULONG = 0;
    let rv = C_GetMechanismList(0, ptr::null_mut(), &mut mech_count);
    assert_eq!(rv, CKR_OK);
    assert!(
        mech_count >= 40,
        "Should have 40+ mechanisms including PQC, got {}",
        mech_count
    );

    let mut mech_list = vec![0 as CK_MECHANISM_TYPE; mech_count as usize];
    let rv = C_GetMechanismList(0, mech_list.as_mut_ptr(), &mut mech_count);
    assert_eq!(rv, CKR_OK);

    assert!(
        mech_list.contains(&CKM_ML_KEM_512),
        "Missing CKM_ML_KEM_512"
    );
    assert!(mech_list.contains(&CKM_ML_DSA_65), "Missing CKM_ML_DSA_65");
    assert!(
        mech_list.contains(&CKM_SLH_DSA_SHA2_128S),
        "Missing CKM_SLH_DSA_SHA2_128S"
    );
    assert!(
        mech_list.contains(&CKM_HYBRID_ML_DSA_ECDSA),
        "Missing CKM_HYBRID_ML_DSA_ECDSA"
    );

    // ========================================================================
    // Test 2: C_GetMechanismInfo for PQC mechanisms
    // ========================================================================
    let mut mech_info: CK_MECHANISM_INFO = unsafe { std::mem::zeroed() };

    let rv = C_GetMechanismInfo(0, CKM_ML_KEM_768, &mut mech_info);
    assert_eq!(rv, CKR_OK);
    assert_ne!(mech_info.flags & CKF_GENERATE_KEY_PAIR_FLAG, 0);
    assert_ne!(mech_info.flags & CKF_DERIVE_FLAG, 0);

    let rv = C_GetMechanismInfo(0, CKM_ML_DSA_65, &mut mech_info);
    assert_eq!(rv, CKR_OK);
    assert_ne!(mech_info.flags & CKF_SIGN_FLAG, 0);
    assert_ne!(mech_info.flags & CKF_VERIFY_FLAG, 0);
    assert_ne!(mech_info.flags & CKF_GENERATE_KEY_PAIR_FLAG, 0);

    let rv = C_GetMechanismInfo(0, CKM_SLH_DSA_SHA2_128S, &mut mech_info);
    assert_eq!(rv, CKR_OK);
    assert_ne!(mech_info.flags & CKF_SIGN_FLAG, 0);
    assert_ne!(mech_info.flags & CKF_VERIFY_FLAG, 0);

    // Invalid mechanism
    let rv = C_GetMechanismInfo(0, 0xFFFFFFFF, &mut mech_info);
    assert_eq!(rv, CKR_MECHANISM_INVALID);

    // ========================================================================
    // Test 3: Session state machine — RO session limitations
    // ========================================================================
    let mut ro_session: CK_SESSION_HANDLE = 0;
    let rv = C_OpenSession(
        0,
        CKF_SERIAL_SESSION,
        ptr::null_mut(),
        None,
        &mut ro_session,
    );
    assert_eq!(rv, CKR_OK);

    let mut sess_info: CK_SESSION_INFO = unsafe { std::mem::zeroed() };
    let rv = C_GetSessionInfo(ro_session, &mut sess_info);
    assert_eq!(rv, CKR_OK);
    let state = sess_info.state;
    assert_eq!(state, CKS_RO_PUBLIC_SESSION);

    // RO session cannot generate keys
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let value_len_bytes = ck_ulong_bytes(16);
    let mut template = vec![CK_ATTRIBUTE {
        attr_type: CKA_VALUE_LEN,
        p_value: value_len_bytes.as_ptr() as CK_VOID_PTR,
        value_len: value_len_bytes.len() as CK_ULONG,
    }];
    let mut key: CK_OBJECT_HANDLE = 0;
    let rv = C_GenerateKey(
        ro_session,
        &mut mechanism,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut key,
    );
    assert_eq!(rv, CKR_SESSION_READ_ONLY);

    let rv = C_CloseSession(ro_session);
    assert_eq!(rv, CKR_OK);

    // ========================================================================
    // Test 4: Operations require login
    // ========================================================================
    let mut rw_session: CK_SESSION_HANDLE = 0;
    let rv = C_OpenSession(
        0,
        CKF_RW_SESSION | CKF_SERIAL_SESSION,
        ptr::null_mut(),
        None,
        &mut rw_session,
    );
    assert_eq!(rv, CKR_OK);

    // Login SO, init user PIN
    let rv = C_Login(
        rw_session,
        CKU_SO,
        so_pin.as_ptr() as *mut _,
        so_pin.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_OK);
    let user_pin = b"userpass1";
    let rv = C_InitPIN(
        rw_session,
        user_pin.as_ptr() as *mut _,
        user_pin.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_OK);
    let rv = C_Logout(rw_session);
    assert_eq!(rv, CKR_OK);

    // Login as user
    let rv = C_Login(
        rw_session,
        CKU_USER,
        user_pin.as_ptr() as *mut _,
        user_pin.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_OK);

    // ========================================================================
    // Test 5: PQC key pair generation via C_GenerateKeyPair (ML-DSA-44)
    // ========================================================================
    let mut ml_dsa_mechanism = CK_MECHANISM {
        mechanism: CKM_ML_DSA_44,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let ck_true: CK_BBOOL = CK_TRUE;

    let mut pub_template_ml = vec![CK_ATTRIBUTE {
        attr_type: CKA_VERIFY,
        p_value: &ck_true as *const _ as CK_VOID_PTR,
        value_len: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
    }];
    let mut priv_template_ml = vec![CK_ATTRIBUTE {
        attr_type: CKA_SIGN,
        p_value: &ck_true as *const _ as CK_VOID_PTR,
        value_len: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
    }];
    let mut ml_pub: CK_OBJECT_HANDLE = 0;
    let mut ml_priv: CK_OBJECT_HANDLE = 0;
    let rv = C_GenerateKeyPair(
        rw_session,
        &mut ml_dsa_mechanism,
        pub_template_ml.as_mut_ptr(),
        pub_template_ml.len() as CK_ULONG,
        priv_template_ml.as_mut_ptr(),
        priv_template_ml.len() as CK_ULONG,
        &mut ml_pub,
        &mut ml_priv,
    );
    assert_eq!(rv, CKR_OK);
    assert_ne!(ml_pub, 0);
    assert_ne!(ml_priv, 0);

    // ========================================================================
    // Test 6: ML-DSA sign/verify through ABI
    // ========================================================================
    let mut sign_mechanism = CK_MECHANISM {
        mechanism: CKM_ML_DSA_44,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };

    let rv = C_SignInit(rw_session, &mut sign_mechanism, ml_priv);
    assert_eq!(rv, CKR_OK);

    let message = b"PQC ABI compliance test message";
    let mut sig_buf = vec![0u8; 8192]; // ML-DSA-44 sig is 2420 bytes
    let mut sig_len: CK_ULONG = sig_buf.len() as CK_ULONG;
    let rv = C_Sign(
        rw_session,
        message.as_ptr() as CK_BYTE_PTR,
        message.len() as CK_ULONG,
        sig_buf.as_mut_ptr(),
        &mut sig_len,
    );
    assert_eq!(rv, CKR_OK);
    assert_eq!(sig_len, 2420, "ML-DSA-44 signature should be 2420 bytes");

    // Verify
    let rv = C_VerifyInit(rw_session, &mut sign_mechanism, ml_pub);
    assert_eq!(rv, CKR_OK);

    let rv = C_Verify(
        rw_session,
        message.as_ptr() as CK_BYTE_PTR,
        message.len() as CK_ULONG,
        sig_buf.as_mut_ptr(),
        sig_len,
    );
    assert_eq!(rv, CKR_OK);

    // Verify with wrong message should fail
    let rv = C_VerifyInit(rw_session, &mut sign_mechanism, ml_pub);
    assert_eq!(rv, CKR_OK);

    let wrong_msg = b"wrong message";
    let rv = C_Verify(
        rw_session,
        wrong_msg.as_ptr() as CK_BYTE_PTR,
        wrong_msg.len() as CK_ULONG,
        sig_buf.as_mut_ptr(),
        sig_len,
    );
    assert_eq!(rv, CKR_SIGNATURE_INVALID);

    // ========================================================================
    // Test 7: C_FindObjects for PQC keys
    // ========================================================================
    let key_type_ml_dsa = ck_ulong_bytes(CKK_ML_DSA);
    let class_pub = ck_ulong_bytes(CKO_PUBLIC_KEY);
    let mut find_template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_CLASS,
            p_value: class_pub.as_ptr() as CK_VOID_PTR,
            value_len: class_pub.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_KEY_TYPE,
            p_value: key_type_ml_dsa.as_ptr() as CK_VOID_PTR,
            value_len: key_type_ml_dsa.len() as CK_ULONG,
        },
    ];

    let rv = C_FindObjectsInit(
        rw_session,
        find_template.as_mut_ptr(),
        find_template.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_OK);

    let mut found = vec![0 as CK_OBJECT_HANDLE; 10];
    let mut found_count: CK_ULONG = 0;
    let rv = C_FindObjects(rw_session, found.as_mut_ptr(), 10, &mut found_count);
    assert_eq!(rv, CKR_OK);
    assert!(found_count >= 1, "Should find at least 1 ML-DSA public key");

    let rv = C_FindObjectsFinal(rw_session);
    assert_eq!(rv, CKR_OK);

    // ========================================================================
    // Test 8: C_GetAttributeValue for PQC key
    // ========================================================================
    let mut key_type_buf = [0u8; std::mem::size_of::<CK_ULONG>()];
    let mut get_template = vec![CK_ATTRIBUTE {
        attr_type: CKA_KEY_TYPE,
        p_value: key_type_buf.as_mut_ptr() as CK_VOID_PTR,
        value_len: key_type_buf.len() as CK_ULONG,
    }];
    let rv = C_GetAttributeValue(
        rw_session,
        ml_pub,
        get_template.as_mut_ptr(),
        get_template.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_OK);
    let returned_kt = CK_ULONG::from_ne_bytes(key_type_buf);
    assert_eq!(returned_kt, CKK_ML_DSA, "Key type should be CKK_ML_DSA");

    // ========================================================================
    // Test 9: C_DestroyObject
    // ========================================================================
    let rv = C_DestroyObject(rw_session, ml_pub);
    assert_eq!(rv, CKR_OK);

    // Verify it's gone — VerifyInit with destroyed key should fail
    let rv = C_VerifyInit(rw_session, &mut sign_mechanism, ml_pub);
    assert_eq!(rv, CKR_KEY_HANDLE_INVALID);

    // ========================================================================
    // Test 10: PIN change via C_SetPIN
    // ========================================================================
    let new_pin = b"newuser1pin";
    let rv = C_SetPIN(
        rw_session,
        user_pin.as_ptr() as *mut _,
        user_pin.len() as CK_ULONG,
        new_pin.as_ptr() as *mut _,
        new_pin.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_OK);

    // ========================================================================
    // Test 11: Wrong PIN should fail login
    // ========================================================================
    let rv = C_Logout(rw_session);
    assert_eq!(rv, CKR_OK);
    let rv = C_Login(
        rw_session,
        CKU_USER,
        user_pin.as_ptr() as *mut _,
        user_pin.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_PIN_INCORRECT);

    // Correct new PIN should work
    let rv = C_Login(
        rw_session,
        CKU_USER,
        new_pin.as_ptr() as *mut _,
        new_pin.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_OK);

    // ========================================================================
    // Test 12: Invalid session handle
    // ========================================================================
    let rv = C_GetSessionInfo(9999, &mut sess_info);
    assert_eq!(rv, CKR_SESSION_HANDLE_INVALID);

    // Cleanup
    let rv = C_Logout(rw_session);
    assert_eq!(rv, CKR_OK);
    let rv = C_CloseSession(rw_session);
    assert_eq!(rv, CKR_OK);
}
