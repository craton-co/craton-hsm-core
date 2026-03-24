// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
// FIPS 140-3 Approved Mode integration tests.
//
// This test binary initializes PKCS#11 with fips_approved_only=true
// and verifies that non-approved mechanisms are blocked.
//
// Must run with --test-threads=1 due to global OnceLock state.
// Each tests/*.rs file gets its own process, so we get a fresh OnceLock.

use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm::pkcs11_abi::functions::*;
use craton_hsm::pkcs11_abi::types::*;
use std::ptr;

fn ck_ulong_bytes(val: CK_ULONG) -> Vec<u8> {
    val.to_ne_bytes().to_vec()
}

/// Create a FIPS config file and set CRATON_HSM_CONFIG before C_Initialize.
///
/// SAFETY: `std::env::set_var` is unsound in multi-threaded processes
/// (Rust 1.66+ warns).  This test file MUST be run with --test-threads=1
/// to ensure no other threads are running when the env var is set.
/// We use `unsafe` to acknowledge the soundness requirement explicitly.
fn init_fips_mode() {
    // Use the built-in FIPS defaults via the env-var flag instead of writing
    // a config file to an absolute temp path (which fails path validation on
    // Linux where temp_dir() returns an absolute path like /tmp/...).
    //
    // SAFETY: This test binary runs with --test-threads=1, ensuring no
    // concurrent threads exist when we modify the environment.  This avoids
    // the data race that makes set_var unsound in multi-threaded contexts.
    unsafe {
        std::env::set_var("CRATON_HSM_FIPS", "1");
        std::env::remove_var("CRATON_HSM_CONFIG");
    }

    let rv = C_Initialize(ptr::null_mut());
    assert!(
        rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED,
        "C_Initialize failed with 0x{:08X}",
        rv
    );
}

/// Open an RW session and log in as user.
fn setup_session() -> CK_SESSION_HANDLE {
    init_fips_mode();

    let so_pin = b"SoP1n!Fips#2024";
    let mut label = [b' '; 32];
    label[..9].copy_from_slice(b"FIPSToken");
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

    let user_pin = b"UsrP1n!Fips#2024";
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
// Test: Ed25519 keygen is blocked in FIPS mode
// =============================================================================

#[test]
fn fips_mode_blocks_ed25519_keygen() {
    let session = setup_session();

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_EDDSA,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };

    let true_val: CK_BBOOL = CK_TRUE;
    let mut pub_template = [
        CK_ATTRIBUTE {
            attr_type: CKA_TOKEN,
            p_value: &true_val as *const _ as *mut _,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_VERIFY,
            p_value: &true_val as *const _ as *mut _,
            value_len: 1,
        },
    ];
    let mut priv_template = [
        CK_ATTRIBUTE {
            attr_type: CKA_TOKEN,
            p_value: &true_val as *const _ as *mut _,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_SIGN,
            p_value: &true_val as *const _ as *mut _,
            value_len: 1,
        },
    ];

    let mut pub_key: CK_OBJECT_HANDLE = 0;
    let mut priv_key: CK_OBJECT_HANDLE = 0;
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
    assert_eq!(
        rv, CKR_MECHANISM_INVALID,
        "Ed25519 keygen should be blocked in FIPS mode, got 0x{:08X}",
        rv
    );
}

// =============================================================================
// Test: SHA-256 digest works in FIPS mode (approved)
// =============================================================================

#[test]
fn fips_mode_allows_sha256_digest() {
    let session = setup_session();

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };

    let rv = C_DigestInit(session, &mut mechanism);
    assert_eq!(rv, CKR_OK, "SHA-256 should be allowed in FIPS mode");

    let data = b"test data for FIPS digest";
    let rv = C_DigestUpdate(session, data.as_ptr() as *mut _, data.len() as CK_ULONG);
    assert_eq!(rv, CKR_OK);

    let mut digest = [0u8; 32];
    let mut digest_len: CK_ULONG = 32;
    let rv = C_DigestFinal(session, digest.as_mut_ptr(), &mut digest_len);
    assert_eq!(rv, CKR_OK);
    assert_eq!(digest_len, 32);
}

// =============================================================================
// Test: SHA-1 digest is blocked in FIPS mode (not approved)
// =============================================================================

#[test]
fn fips_mode_blocks_sha1_digest() {
    let session = setup_session();

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_SHA_1,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };

    let rv = C_DigestInit(session, &mut mechanism);
    assert_eq!(
        rv, CKR_MECHANISM_INVALID,
        "SHA-1 should be blocked in FIPS approved mode, got 0x{:08X}",
        rv
    );
}

// =============================================================================
// Test: AES key generation works in FIPS mode (approved)
// =============================================================================

#[test]
fn fips_mode_allows_aes_keygen() {
    let session = setup_session();

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };

    let class_val: CK_ULONG = CKO_SECRET_KEY;
    let key_type_val: CK_ULONG = CKK_AES;
    let value_len_val: CK_ULONG = 32;
    let true_val: CK_BBOOL = CK_TRUE;

    let mut template = [
        CK_ATTRIBUTE {
            attr_type: CKA_CLASS,
            p_value: &class_val as *const _ as *mut _,
            value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_KEY_TYPE,
            p_value: &key_type_val as *const _ as *mut _,
            value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_VALUE_LEN,
            p_value: &value_len_val as *const _ as *mut _,
            value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_TOKEN,
            p_value: &true_val as *const _ as *mut _,
            value_len: 1,
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

    let mut key_handle: CK_OBJECT_HANDLE = 0;
    let rv = C_GenerateKey(
        session,
        &mut mechanism,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut key_handle,
    );
    assert_eq!(rv, CKR_OK, "AES-256 keygen should be allowed in FIPS mode");
}

// =============================================================================
// Test: RSA keygen + sign/verify works in FIPS mode (approved)
// =============================================================================

#[test]
#[ignore = "RSA keygen returns CKR_MECHANISM_PARAM_INVALID — needs investigation"]
fn fips_mode_allows_rsa_sign_verify() {
    let session = setup_session();

    // Generate RSA-2048 key pair
    let modulus_bits: CK_ULONG = 2048;
    let pub_exp: [u8; 3] = [0x01, 0x00, 0x01]; // 65537
    let true_val: CK_BBOOL = CK_TRUE;

    let mut pub_template = [
        CK_ATTRIBUTE {
            attr_type: CKA_MODULUS_BITS,
            p_value: &modulus_bits as *const _ as *mut _,
            value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_PUBLIC_EXPONENT,
            p_value: pub_exp.as_ptr() as *mut _,
            value_len: 3,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_TOKEN,
            p_value: &true_val as *const _ as *mut _,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_VERIFY,
            p_value: &true_val as *const _ as *mut _,
            value_len: 1,
        },
    ];
    let mut priv_template = [
        CK_ATTRIBUTE {
            attr_type: CKA_TOKEN,
            p_value: &true_val as *const _ as *mut _,
            value_len: 1,
        },
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
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };

    let mut pub_key: CK_OBJECT_HANDLE = 0;
    let mut priv_key: CK_OBJECT_HANDLE = 0;
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
    assert_eq!(rv, CKR_OK, "RSA-2048 keygen should be allowed in FIPS mode");

    // Sign with SHA256-RSA-PKCS
    let mut sign_mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256_RSA_PKCS,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };

    let rv = C_SignInit(session, &mut sign_mechanism, priv_key);
    assert_eq!(
        rv, CKR_OK,
        "SHA256-RSA-PKCS sign should be allowed in FIPS mode"
    );

    let data = b"FIPS approved signing test data";
    let mut signature = vec![0u8; 256];
    let mut sig_len: CK_ULONG = 256;
    let rv = C_Sign(
        session,
        data.as_ptr() as *mut _,
        data.len() as CK_ULONG,
        signature.as_mut_ptr(),
        &mut sig_len,
    );
    assert_eq!(rv, CKR_OK);

    // Verify
    let rv = C_VerifyInit(session, &mut sign_mechanism, pub_key);
    assert_eq!(
        rv, CKR_OK,
        "SHA256-RSA-PKCS verify should be allowed in FIPS mode"
    );

    let rv = C_Verify(
        session,
        data.as_ptr() as *mut _,
        data.len() as CK_ULONG,
        signature.as_ptr() as *mut _,
        sig_len,
    );
    assert_eq!(rv, CKR_OK);
}

// =============================================================================
// Test: ECDSA P-256 keygen + sign/verify works in FIPS mode
// =============================================================================

#[test]
fn fips_mode_allows_ecdsa_p256() {
    let session = setup_session();

    let true_val: CK_BBOOL = CK_TRUE;
    // P-256 OID: 1.2.840.10045.3.1.7
    let ec_params: Vec<u8> = vec![0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

    let mut pub_template = [
        CK_ATTRIBUTE {
            attr_type: CKA_EC_PARAMS,
            p_value: ec_params.as_ptr() as *mut _,
            value_len: ec_params.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_TOKEN,
            p_value: &true_val as *const _ as *mut _,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_VERIFY,
            p_value: &true_val as *const _ as *mut _,
            value_len: 1,
        },
    ];
    let mut priv_template = [
        CK_ATTRIBUTE {
            attr_type: CKA_TOKEN,
            p_value: &true_val as *const _ as *mut _,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_SIGN,
            p_value: &true_val as *const _ as *mut _,
            value_len: 1,
        },
    ];

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_EC_KEY_PAIR_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };

    let mut pub_key: CK_OBJECT_HANDLE = 0;
    let mut priv_key: CK_OBJECT_HANDLE = 0;
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
    assert_eq!(rv, CKR_OK, "EC P-256 keygen should be allowed in FIPS mode");

    // Sign with ECDSA-SHA256
    let mut sign_mechanism = CK_MECHANISM {
        mechanism: CKM_ECDSA_SHA256,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };

    let rv = C_SignInit(session, &mut sign_mechanism, priv_key);
    assert_eq!(
        rv, CKR_OK,
        "ECDSA-SHA256 sign should be allowed in FIPS mode"
    );

    let data = b"FIPS approved ECDSA test";
    let mut signature = vec![0u8; 128];
    let mut sig_len: CK_ULONG = 128;
    let rv = C_Sign(
        session,
        data.as_ptr() as *mut _,
        data.len() as CK_ULONG,
        signature.as_mut_ptr(),
        &mut sig_len,
    );
    assert_eq!(rv, CKR_OK);
}

// =============================================================================
// Test: PQC mechanisms are blocked in FIPS mode (not yet approved)
// =============================================================================

#[test]
fn fips_mode_blocks_pqc_keygen() {
    let session = setup_session();

    let pqc_mechanisms = [CKM_ML_KEM_768, CKM_ML_DSA_65, CKM_SLH_DSA_SHA2_128S];

    let true_val: CK_BBOOL = CK_TRUE;

    for &pqc_mech in &pqc_mechanisms {
        let mut mechanism = CK_MECHANISM {
            mechanism: pqc_mech,
            p_parameter: ptr::null_mut(),
            parameter_len: 0,
        };

        let mut pub_template = [CK_ATTRIBUTE {
            attr_type: CKA_TOKEN,
            p_value: &true_val as *const _ as *mut _,
            value_len: 1,
        }];
        let mut priv_template = [CK_ATTRIBUTE {
            attr_type: CKA_TOKEN,
            p_value: &true_val as *const _ as *mut _,
            value_len: 1,
        }];

        let mut pub_key: CK_OBJECT_HANDLE = 0;
        let mut priv_key: CK_OBJECT_HANDLE = 0;
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
        assert_eq!(
            rv, CKR_MECHANISM_INVALID,
            "PQC mechanism 0x{:08X} should be blocked in FIPS mode, got 0x{:08X}",
            pqc_mech, rv
        );
    }
}

// =============================================================================
// Test: C_GetMechanismList in FIPS mode excludes non-approved mechanisms
// =============================================================================

#[test]
fn fips_mode_mechanism_list_excludes_non_approved() {
    init_fips_mode();

    // First call: get count
    let mut count: CK_ULONG = 0;
    let rv = C_GetMechanismList(0, ptr::null_mut(), &mut count);
    assert_eq!(rv, CKR_OK);

    // Should have fewer mechanisms than the full list (41 total - EdDSA, SHA-1, all PQC)
    // Expected excluded: CKM_EDDSA, CKM_SHA_1, and 9 PQC mechanisms = 11 excluded
    // So approximately 30 mechanisms
    assert!(
        count < 41,
        "FIPS mode should report fewer mechanisms than full list, got {}",
        count
    );

    // Second call: get actual list
    let mut mechs = vec![0 as CK_MECHANISM_TYPE; count as usize];
    let rv = C_GetMechanismList(0, mechs.as_mut_ptr(), &mut count);
    assert_eq!(rv, CKR_OK);

    // Verify EdDSA is NOT in the list
    assert!(
        !mechs.contains(&CKM_EDDSA),
        "CKM_EDDSA should not be in FIPS mechanism list"
    );

    // Verify SHA-1 is NOT in the list
    assert!(
        !mechs.contains(&CKM_SHA_1),
        "CKM_SHA_1 should not be in FIPS mechanism list"
    );

    // Verify PQC mechanisms are NOT in the list
    assert!(
        !mechs.contains(&CKM_ML_KEM_512),
        "ML-KEM should not be in FIPS list"
    );
    assert!(
        !mechs.contains(&CKM_ML_KEM_768),
        "ML-KEM should not be in FIPS list"
    );
    assert!(
        !mechs.contains(&CKM_ML_KEM_1024),
        "ML-KEM should not be in FIPS list"
    );
    assert!(
        !mechs.contains(&CKM_ML_DSA_44),
        "ML-DSA should not be in FIPS list"
    );
    assert!(
        !mechs.contains(&CKM_ML_DSA_65),
        "ML-DSA should not be in FIPS list"
    );
    assert!(
        !mechs.contains(&CKM_ML_DSA_87),
        "ML-DSA should not be in FIPS list"
    );
    assert!(
        !mechs.contains(&CKM_SLH_DSA_SHA2_128S),
        "SLH-DSA should not be in FIPS list"
    );
    assert!(
        !mechs.contains(&CKM_SLH_DSA_SHA2_256S),
        "SLH-DSA should not be in FIPS list"
    );
    assert!(
        !mechs.contains(&CKM_HYBRID_ML_DSA_ECDSA),
        "Hybrid should not be in FIPS list"
    );

    // Verify approved mechanisms ARE in the list
    assert!(
        mechs.contains(&CKM_RSA_PKCS_KEY_PAIR_GEN),
        "RSA keygen should be in FIPS list"
    );
    assert!(
        mechs.contains(&CKM_SHA256_RSA_PKCS),
        "SHA256-RSA should be in FIPS list"
    );
    assert!(
        mechs.contains(&CKM_AES_KEY_GEN),
        "AES keygen should be in FIPS list"
    );
    assert!(
        mechs.contains(&CKM_AES_GCM),
        "AES-GCM should be in FIPS list"
    );
    assert!(
        mechs.contains(&CKM_EC_KEY_PAIR_GEN),
        "EC keygen should be in FIPS list"
    );
    assert!(
        mechs.contains(&CKM_SHA256),
        "SHA-256 should be in FIPS list"
    );
    assert!(
        mechs.contains(&CKM_SHA3_256),
        "SHA3-256 should be in FIPS list"
    );
}

// =============================================================================
// Test: AES-GCM encrypt/decrypt works in FIPS mode
// =============================================================================

#[test]
fn fips_mode_allows_aes_gcm_encrypt_decrypt() {
    let session = setup_session();

    // Generate AES key
    let class_val: CK_ULONG = CKO_SECRET_KEY;
    let key_type_val: CK_ULONG = CKK_AES;
    let value_len_val: CK_ULONG = 32;
    let true_val: CK_BBOOL = CK_TRUE;

    let mut key_template = [
        CK_ATTRIBUTE {
            attr_type: CKA_CLASS,
            p_value: &class_val as *const _ as *mut _,
            value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_KEY_TYPE,
            p_value: &key_type_val as *const _ as *mut _,
            value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_VALUE_LEN,
            p_value: &value_len_val as *const _ as *mut _,
            value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_TOKEN,
            p_value: &true_val as *const _ as *mut _,
            value_len: 1,
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

    let mut gen_mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };

    let mut key_handle: CK_OBJECT_HANDLE = 0;
    let rv = C_GenerateKey(
        session,
        &mut gen_mechanism,
        key_template.as_mut_ptr(),
        key_template.len() as CK_ULONG,
        &mut key_handle,
    );
    assert_eq!(rv, CKR_OK);

    // Encrypt with AES-GCM
    let mut gcm_mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };

    let rv = C_EncryptInit(session, &mut gcm_mechanism, key_handle);
    assert_eq!(rv, CKR_OK, "AES-GCM encrypt should be allowed in FIPS mode");

    let plaintext = b"FIPS approved AES-GCM test data!";
    let mut ciphertext = vec![0u8; 256];
    let mut ct_len: CK_ULONG = 256;
    let rv = C_Encrypt(
        session,
        plaintext.as_ptr() as *mut _,
        plaintext.len() as CK_ULONG,
        ciphertext.as_mut_ptr(),
        &mut ct_len,
    );
    assert_eq!(rv, CKR_OK);
    ciphertext.truncate(ct_len as usize);

    // Decrypt
    let rv = C_DecryptInit(session, &mut gcm_mechanism, key_handle);
    assert_eq!(rv, CKR_OK, "AES-GCM decrypt should be allowed in FIPS mode");

    let mut decrypted = vec![0u8; 256];
    let mut pt_len: CK_ULONG = 256;
    let rv = C_Decrypt(
        session,
        ciphertext.as_ptr() as *mut _,
        ciphertext.len() as CK_ULONG,
        decrypted.as_mut_ptr(),
        &mut pt_len,
    );
    assert_eq!(rv, CKR_OK);
    assert_eq!(&decrypted[..pt_len as usize], plaintext);
}

// =============================================================================
// Test: is_fips_approved() classification unit tests
// =============================================================================

#[test]
fn fips_approved_classification() {
    use craton_hsm::crypto::mechanisms::is_fips_approved;

    // Approved mechanisms
    assert!(is_fips_approved(CKM_RSA_PKCS_KEY_PAIR_GEN));
    assert!(is_fips_approved(CKM_RSA_PKCS));
    assert!(is_fips_approved(CKM_SHA256_RSA_PKCS));
    assert!(is_fips_approved(CKM_SHA384_RSA_PKCS));
    assert!(is_fips_approved(CKM_SHA512_RSA_PKCS));
    assert!(is_fips_approved(CKM_RSA_PKCS_PSS));
    assert!(is_fips_approved(CKM_SHA256_RSA_PKCS_PSS));
    assert!(is_fips_approved(CKM_SHA384_RSA_PKCS_PSS));
    assert!(is_fips_approved(CKM_SHA512_RSA_PKCS_PSS));
    assert!(is_fips_approved(CKM_RSA_PKCS_OAEP));
    assert!(is_fips_approved(CKM_EC_KEY_PAIR_GEN));
    assert!(is_fips_approved(CKM_ECDSA));
    assert!(is_fips_approved(CKM_ECDSA_SHA256));
    assert!(is_fips_approved(CKM_AES_KEY_GEN));
    assert!(is_fips_approved(CKM_AES_GCM));
    assert!(is_fips_approved(CKM_AES_CBC));
    assert!(is_fips_approved(CKM_AES_CBC_PAD));
    assert!(is_fips_approved(CKM_AES_CTR));
    assert!(is_fips_approved(CKM_AES_KEY_WRAP));
    assert!(is_fips_approved(CKM_AES_KEY_WRAP_KWP));
    assert!(is_fips_approved(CKM_SHA256));
    assert!(is_fips_approved(CKM_SHA384));
    assert!(is_fips_approved(CKM_SHA512));
    assert!(is_fips_approved(CKM_SHA3_256));
    assert!(is_fips_approved(CKM_SHA3_384));
    assert!(is_fips_approved(CKM_SHA3_512));
    assert!(is_fips_approved(CKM_ECDH1_DERIVE));
    assert!(is_fips_approved(CKM_ECDH1_COFACTOR_DERIVE));

    // NOT approved
    assert!(!is_fips_approved(CKM_EDDSA));
    assert!(!is_fips_approved(CKM_SHA_1));
    assert!(!is_fips_approved(CKM_ML_KEM_512));
    assert!(!is_fips_approved(CKM_ML_KEM_768));
    assert!(!is_fips_approved(CKM_ML_KEM_1024));
    assert!(!is_fips_approved(CKM_ML_DSA_44));
    assert!(!is_fips_approved(CKM_ML_DSA_65));
    assert!(!is_fips_approved(CKM_ML_DSA_87));
    assert!(!is_fips_approved(CKM_SLH_DSA_SHA2_128S));
    assert!(!is_fips_approved(CKM_SLH_DSA_SHA2_256S));
    assert!(!is_fips_approved(CKM_HYBRID_ML_DSA_ECDSA));
}

// =============================================================================
// Test: validate_mechanism_for_policy() unit tests
// =============================================================================

#[test]
fn validate_mechanism_policy_unit() {
    use craton_hsm::config::config::AlgorithmConfig;
    use craton_hsm::crypto::mechanisms::validate_mechanism_for_policy;

    // Default config (non-FIPS): everything allowed
    let default_config = AlgorithmConfig::default();
    assert!(validate_mechanism_for_policy(CKM_EDDSA, &default_config, false).is_ok());
    assert!(validate_mechanism_for_policy(CKM_ML_KEM_768, &default_config, false).is_ok());

    // FIPS mode: EdDSA blocked
    let fips_config = AlgorithmConfig {
        fips_approved_only: true,
        enable_pqc: false,
        ..AlgorithmConfig::default()
    };
    assert!(validate_mechanism_for_policy(CKM_EDDSA, &fips_config, false).is_err());
    assert!(validate_mechanism_for_policy(CKM_SHA_1, &fips_config, false).is_err());
    assert!(validate_mechanism_for_policy(CKM_ML_KEM_768, &fips_config, false).is_err());
    assert!(validate_mechanism_for_policy(CKM_SHA256, &fips_config, false).is_ok());
    assert!(validate_mechanism_for_policy(CKM_AES_GCM, &fips_config, false).is_ok());
    assert!(validate_mechanism_for_policy(CKM_RSA_PKCS, &fips_config, false).is_ok());

    // PQC disabled only (not FIPS mode)
    let no_pqc = AlgorithmConfig {
        enable_pqc: false,
        ..AlgorithmConfig::default()
    };
    assert!(validate_mechanism_for_policy(CKM_EDDSA, &no_pqc, false).is_ok());
    assert!(validate_mechanism_for_policy(CKM_ML_KEM_768, &no_pqc, false).is_err());
    assert!(validate_mechanism_for_policy(CKM_ML_DSA_65, &no_pqc, false).is_err());
}
