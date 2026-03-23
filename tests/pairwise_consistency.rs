// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Integration tests for FIPS 140-3 §9.6 Pairwise Consistency Tests.
//!
//! These verify that pairwise tests run during key pair generation
//! and that generated keys actually work (roundtrip sign/verify).

use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm::pkcs11_abi::functions;
use craton_hsm::pkcs11_abi::types::*;

fn init_and_login() -> CK_SESSION_HANDLE {
    let rv = functions::C_Initialize(std::ptr::null_mut());
    assert!(rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED);

    // Init token with SO PIN
    let so_pin = b"sopin123";
    let mut label = [b' '; 32];
    label[..9].copy_from_slice(b"TestToken");
    let rv = functions::C_InitToken(
        0,
        so_pin.as_ptr() as *mut _,
        so_pin.len() as CK_ULONG,
        label.as_ptr() as *mut _,
    );
    assert_eq!(rv, CKR_OK);

    let mut session: CK_SESSION_HANDLE = 0;
    let rv = functions::C_OpenSession(
        0,
        CKF_SERIAL_SESSION | CKF_RW_SESSION,
        std::ptr::null_mut(),
        None,
        &mut session,
    );
    assert_eq!(rv, CKR_OK);

    // Login as SO, init user PIN, logout, then login as user
    let rv = functions::C_Login(
        session,
        CKU_SO,
        so_pin.as_ptr() as *mut _,
        so_pin.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_OK);

    let user_pin = b"userpin1234";
    let rv = functions::C_InitPIN(
        session,
        user_pin.as_ptr() as *mut _,
        user_pin.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_OK);

    let rv = functions::C_Logout(session);
    assert_eq!(rv, CKR_OK);

    let rv = functions::C_Login(
        session,
        CKU_USER,
        user_pin.as_ptr() as *mut _,
        user_pin.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_OK);

    session
}

fn cleanup(session: CK_SESSION_HANDLE) {
    let _ = functions::C_Logout(session);
    let _ = functions::C_CloseSession(session);
}

/// Generate RSA key pair → pairwise test runs → sign/verify roundtrip succeeds.
#[test]
fn rsa_keygen_with_pairwise_test() {
    let session = init_and_login();

    // Generate RSA-2048 key pair
    let modulus_bits: CK_ULONG = 2048;
    let true_val: CK_BBOOL = CK_TRUE;

    let mut pub_template = [
        CK_ATTRIBUTE {
            attr_type: CKA_MODULUS_BITS,
            p_value: &modulus_bits as *const _ as *mut _,
            value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_VERIFY,
            p_value: &true_val as *const _ as *mut _,
            value_len: 1,
        },
    ];

    let mut priv_template = [
        CK_ATTRIBUTE {
            attr_type: CKA_SIGN,
            p_value: &true_val as *const _ as *mut _,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_SENSITIVE,
            p_value: &true_val as *const _ as *mut _,
            value_len: 1,
        },
    ];

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN,
        p_parameter: std::ptr::null_mut(),
        parameter_len: 0,
    };

    let mut pub_key: CK_OBJECT_HANDLE = 0;
    let mut priv_key: CK_OBJECT_HANDLE = 0;
    let rv = functions::C_GenerateKeyPair(
        session,
        &mut mechanism,
        pub_template.as_mut_ptr(),
        pub_template.len() as CK_ULONG,
        priv_template.as_mut_ptr(),
        priv_template.len() as CK_ULONG,
        &mut pub_key,
        &mut priv_key,
    );
    assert_eq!(
        rv, CKR_OK,
        "RSA key generation (with pairwise test) should succeed"
    );

    // POST_FAILED should NOT be set
    assert!(!functions::is_post_failed(), "POST should not have failed");

    // Verify the keys work: sign/verify roundtrip
    let mut sign_mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256_RSA_PKCS,
        p_parameter: std::ptr::null_mut(),
        parameter_len: 0,
    };

    let data = b"pairwise roundtrip test data";

    // Sign
    let rv = functions::C_SignInit(session, &mut sign_mechanism, priv_key);
    assert_eq!(rv, CKR_OK);

    let mut sig = [0u8; 512];
    let mut sig_len: CK_ULONG = 512;
    let rv = functions::C_Sign(
        session,
        data.as_ptr() as *mut _,
        data.len() as CK_ULONG,
        sig.as_mut_ptr(),
        &mut sig_len,
    );
    assert_eq!(rv, CKR_OK);

    // Verify
    let rv = functions::C_VerifyInit(session, &mut sign_mechanism, pub_key);
    assert_eq!(rv, CKR_OK);

    let rv = functions::C_Verify(
        session,
        data.as_ptr() as *mut _,
        data.len() as CK_ULONG,
        sig.as_mut_ptr(),
        sig_len,
    );
    assert_eq!(rv, CKR_OK, "RSA signature verification should succeed");

    // Cleanup
    let _ = functions::C_DestroyObject(session, pub_key);
    let _ = functions::C_DestroyObject(session, priv_key);
    cleanup(session);
}

/// Generate ECDSA P-256 key pair → pairwise test runs → sign/verify roundtrip succeeds.
#[test]
fn ecdsa_p256_keygen_with_pairwise_test() {
    let session = init_and_login();

    // P-256 OID: 1.2.840.10045.3.1.7
    let ec_params: Vec<u8> = vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    let true_val: CK_BBOOL = CK_TRUE;

    let mut pub_template = [
        CK_ATTRIBUTE {
            attr_type: CKA_EC_PARAMS,
            p_value: ec_params.as_ptr() as *mut _,
            value_len: ec_params.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_VERIFY,
            p_value: &true_val as *const _ as *mut _,
            value_len: 1,
        },
    ];

    let mut priv_template = [CK_ATTRIBUTE {
        attr_type: CKA_SIGN,
        p_value: &true_val as *const _ as *mut _,
        value_len: 1,
    }];

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_EC_KEY_PAIR_GEN,
        p_parameter: std::ptr::null_mut(),
        parameter_len: 0,
    };

    let mut pub_key: CK_OBJECT_HANDLE = 0;
    let mut priv_key: CK_OBJECT_HANDLE = 0;
    let rv = functions::C_GenerateKeyPair(
        session,
        &mut mechanism,
        pub_template.as_mut_ptr(),
        pub_template.len() as CK_ULONG,
        priv_template.as_mut_ptr(),
        priv_template.len() as CK_ULONG,
        &mut pub_key,
        &mut priv_key,
    );
    assert_eq!(
        rv, CKR_OK,
        "EC P-256 key generation (with pairwise test) should succeed"
    );

    // Sign/verify roundtrip
    let mut sign_mechanism = CK_MECHANISM {
        mechanism: CKM_ECDSA_SHA256,
        p_parameter: std::ptr::null_mut(),
        parameter_len: 0,
    };

    let data = b"ecdsa pairwise roundtrip";

    let rv = functions::C_SignInit(session, &mut sign_mechanism, priv_key);
    assert_eq!(rv, CKR_OK);

    let mut sig = [0u8; 256];
    let mut sig_len: CK_ULONG = 256;
    let rv = functions::C_Sign(
        session,
        data.as_ptr() as *mut _,
        data.len() as CK_ULONG,
        sig.as_mut_ptr(),
        &mut sig_len,
    );
    assert_eq!(rv, CKR_OK);

    let rv = functions::C_VerifyInit(session, &mut sign_mechanism, pub_key);
    assert_eq!(rv, CKR_OK);

    let rv = functions::C_Verify(
        session,
        data.as_ptr() as *mut _,
        data.len() as CK_ULONG,
        sig.as_mut_ptr(),
        sig_len,
    );
    assert_eq!(
        rv, CKR_OK,
        "ECDSA P-256 signature verification should succeed"
    );

    let _ = functions::C_DestroyObject(session, pub_key);
    let _ = functions::C_DestroyObject(session, priv_key);
    cleanup(session);
}

/// Generate ECDSA P-384 key pair → pairwise test runs → sign/verify roundtrip succeeds.
#[test]
fn ecdsa_p384_keygen_with_pairwise_test() {
    let session = init_and_login();

    // P-384 OID: 1.3.132.0.34
    let ec_params: Vec<u8> = vec![0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
    let true_val: CK_BBOOL = CK_TRUE;

    let mut pub_template = [
        CK_ATTRIBUTE {
            attr_type: CKA_EC_PARAMS,
            p_value: ec_params.as_ptr() as *mut _,
            value_len: ec_params.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_VERIFY,
            p_value: &true_val as *const _ as *mut _,
            value_len: 1,
        },
    ];

    let mut priv_template = [CK_ATTRIBUTE {
        attr_type: CKA_SIGN,
        p_value: &true_val as *const _ as *mut _,
        value_len: 1,
    }];

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_EC_KEY_PAIR_GEN,
        p_parameter: std::ptr::null_mut(),
        parameter_len: 0,
    };

    let mut pub_key: CK_OBJECT_HANDLE = 0;
    let mut priv_key: CK_OBJECT_HANDLE = 0;
    let rv = functions::C_GenerateKeyPair(
        session,
        &mut mechanism,
        pub_template.as_mut_ptr(),
        pub_template.len() as CK_ULONG,
        priv_template.as_mut_ptr(),
        priv_template.len() as CK_ULONG,
        &mut pub_key,
        &mut priv_key,
    );
    assert_eq!(
        rv, CKR_OK,
        "EC P-384 key generation (with pairwise test) should succeed"
    );

    // Sign/verify roundtrip
    let mut sign_mechanism = CK_MECHANISM {
        mechanism: CKM_ECDSA_SHA384,
        p_parameter: std::ptr::null_mut(),
        parameter_len: 0,
    };

    let data = b"ecdsa p384 pairwise roundtrip";

    let rv = functions::C_SignInit(session, &mut sign_mechanism, priv_key);
    assert_eq!(rv, CKR_OK);

    let mut sig = [0u8; 256];
    let mut sig_len: CK_ULONG = 256;
    let rv = functions::C_Sign(
        session,
        data.as_ptr() as *mut _,
        data.len() as CK_ULONG,
        sig.as_mut_ptr(),
        &mut sig_len,
    );
    assert_eq!(rv, CKR_OK);

    let rv = functions::C_VerifyInit(session, &mut sign_mechanism, pub_key);
    assert_eq!(rv, CKR_OK);

    let rv = functions::C_Verify(
        session,
        data.as_ptr() as *mut _,
        data.len() as CK_ULONG,
        sig.as_mut_ptr(),
        sig_len,
    );
    assert_eq!(
        rv, CKR_OK,
        "ECDSA P-384 signature verification should succeed"
    );

    let _ = functions::C_DestroyObject(session, pub_key);
    let _ = functions::C_DestroyObject(session, priv_key);
    cleanup(session);
}

/// Generate Ed25519 key pair → pairwise test runs → sign/verify roundtrip succeeds.
#[test]
fn ed25519_keygen_with_pairwise_test() {
    let session = init_and_login();

    let true_val: CK_BBOOL = CK_TRUE;

    let mut pub_template = [CK_ATTRIBUTE {
        attr_type: CKA_VERIFY,
        p_value: &true_val as *const _ as *mut _,
        value_len: 1,
    }];

    let mut priv_template = [CK_ATTRIBUTE {
        attr_type: CKA_SIGN,
        p_value: &true_val as *const _ as *mut _,
        value_len: 1,
    }];

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_EDDSA,
        p_parameter: std::ptr::null_mut(),
        parameter_len: 0,
    };

    let mut pub_key: CK_OBJECT_HANDLE = 0;
    let mut priv_key: CK_OBJECT_HANDLE = 0;
    let rv = functions::C_GenerateKeyPair(
        session,
        &mut mechanism,
        pub_template.as_mut_ptr(),
        pub_template.len() as CK_ULONG,
        priv_template.as_mut_ptr(),
        priv_template.len() as CK_ULONG,
        &mut pub_key,
        &mut priv_key,
    );
    assert_eq!(
        rv, CKR_OK,
        "Ed25519 key generation (with pairwise test) should succeed"
    );

    // Sign/verify roundtrip
    let mut sign_mechanism = CK_MECHANISM {
        mechanism: CKM_EDDSA,
        p_parameter: std::ptr::null_mut(),
        parameter_len: 0,
    };

    let data = b"ed25519 pairwise roundtrip";

    let rv = functions::C_SignInit(session, &mut sign_mechanism, priv_key);
    assert_eq!(rv, CKR_OK);

    let mut sig = [0u8; 128];
    let mut sig_len: CK_ULONG = 128;
    let rv = functions::C_Sign(
        session,
        data.as_ptr() as *mut _,
        data.len() as CK_ULONG,
        sig.as_mut_ptr(),
        &mut sig_len,
    );
    assert_eq!(rv, CKR_OK);

    let rv = functions::C_VerifyInit(session, &mut sign_mechanism, pub_key);
    assert_eq!(rv, CKR_OK);

    let rv = functions::C_Verify(
        session,
        data.as_ptr() as *mut _,
        data.len() as CK_ULONG,
        sig.as_mut_ptr(),
        sig_len,
    );
    assert_eq!(rv, CKR_OK, "Ed25519 signature verification should succeed");

    let _ = functions::C_DestroyObject(session, pub_key);
    let _ = functions::C_DestroyObject(session, priv_key);
    cleanup(session);
}

/// Generate ML-DSA-44 key pair → pairwise test runs → sign/verify roundtrip succeeds.
#[test]
fn ml_dsa_keygen_with_pairwise_test() {
    let session = init_and_login();

    let true_val: CK_BBOOL = CK_TRUE;

    let mut pub_template = [CK_ATTRIBUTE {
        attr_type: CKA_VERIFY,
        p_value: &true_val as *const _ as *mut _,
        value_len: 1,
    }];

    let mut priv_template = [CK_ATTRIBUTE {
        attr_type: CKA_SIGN,
        p_value: &true_val as *const _ as *mut _,
        value_len: 1,
    }];

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_ML_DSA_44,
        p_parameter: std::ptr::null_mut(),
        parameter_len: 0,
    };

    let mut pub_key: CK_OBJECT_HANDLE = 0;
    let mut priv_key: CK_OBJECT_HANDLE = 0;
    let rv = functions::C_GenerateKeyPair(
        session,
        &mut mechanism,
        pub_template.as_mut_ptr(),
        pub_template.len() as CK_ULONG,
        priv_template.as_mut_ptr(),
        priv_template.len() as CK_ULONG,
        &mut pub_key,
        &mut priv_key,
    );
    assert_eq!(
        rv, CKR_OK,
        "ML-DSA-44 key generation (with pairwise test) should succeed"
    );

    // Sign/verify roundtrip
    let mut sign_mechanism = CK_MECHANISM {
        mechanism: CKM_ML_DSA_44,
        p_parameter: std::ptr::null_mut(),
        parameter_len: 0,
    };

    let data = b"ml-dsa pairwise roundtrip test data";

    let rv = functions::C_SignInit(session, &mut sign_mechanism, priv_key);
    assert_eq!(rv, CKR_OK);

    let mut sig = [0u8; 4096];
    let mut sig_len: CK_ULONG = 4096;
    let rv = functions::C_Sign(
        session,
        data.as_ptr() as *mut _,
        data.len() as CK_ULONG,
        sig.as_mut_ptr(),
        &mut sig_len,
    );
    assert_eq!(rv, CKR_OK);

    let rv = functions::C_VerifyInit(session, &mut sign_mechanism, pub_key);
    assert_eq!(rv, CKR_OK);

    let rv = functions::C_Verify(
        session,
        data.as_ptr() as *mut _,
        data.len() as CK_ULONG,
        sig.as_mut_ptr(),
        sig_len,
    );
    assert_eq!(
        rv, CKR_OK,
        "ML-DSA-44 signature verification should succeed"
    );

    let _ = functions::C_DestroyObject(session, pub_key);
    let _ = functions::C_DestroyObject(session, priv_key);
    cleanup(session);
}

/// Verify is_post_failed() reports false after successful key generations.
#[test]
fn post_failed_not_set_after_successful_keygen() {
    let session = init_and_login();

    // Generate an EC key pair — pairwise test should pass
    let ec_params: Vec<u8> = vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    let true_val: CK_BBOOL = CK_TRUE;

    let mut pub_template = [
        CK_ATTRIBUTE {
            attr_type: CKA_EC_PARAMS,
            p_value: ec_params.as_ptr() as *mut _,
            value_len: ec_params.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_VERIFY,
            p_value: &true_val as *const _ as *mut _,
            value_len: 1,
        },
    ];

    let mut priv_template = [CK_ATTRIBUTE {
        attr_type: CKA_SIGN,
        p_value: &true_val as *const _ as *mut _,
        value_len: 1,
    }];

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_EC_KEY_PAIR_GEN,
        p_parameter: std::ptr::null_mut(),
        parameter_len: 0,
    };

    let mut pub_key: CK_OBJECT_HANDLE = 0;
    let mut priv_key: CK_OBJECT_HANDLE = 0;
    let rv = functions::C_GenerateKeyPair(
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

    // POST_FAILED should not be set
    assert!(
        !functions::is_post_failed(),
        "POST should not have failed after successful keygen"
    );

    let _ = functions::C_DestroyObject(session, pub_key);
    let _ = functions::C_DestroyObject(session, priv_key);
    cleanup(session);
}
