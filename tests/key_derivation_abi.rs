// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
// Key Derivation ABI tests — exercises C_DeriveKey (ECDH) through the PKCS#11 C ABI.

use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm::pkcs11_abi::functions::*;
use craton_hsm::pkcs11_abi::types::*;
use std::ptr;

mod common;

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

fn setup_user_session() -> CK_SESSION_HANDLE {
    ensure_init();
    let so_pin = b"sopin123";
    let mut label = [b' '; 32];
    label[..8].copy_from_slice(b"DervTest");
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

/// P-256 OID (DER-encoded)
const P256_OID: [u8; 10] = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
/// P-384 OID (DER-encoded)
const P384_OID: [u8; 7] = [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22];

fn generate_ec_keypair(
    session: CK_SESSION_HANDLE,
    oid: &[u8],
) -> (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) {
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_EC_KEY_PAIR_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let ck_true: CK_BBOOL = CK_TRUE;

    let mut pub_template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_EC_PARAMS,
            p_value: oid.as_ptr() as CK_VOID_PTR,
            value_len: oid.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_VERIFY,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
    ];
    let mut priv_template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_SIGN,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_DERIVE,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_SENSITIVE,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
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
    assert_eq!(rv, CKR_OK, "EC keygen failed: 0x{:08X}", rv);
    (pub_key, priv_key)
}

/// Read CKA_EC_POINT from a public key handle.
fn read_ec_point(session: CK_SESSION_HANDLE, pub_key: CK_OBJECT_HANDLE) -> Vec<u8> {
    // First call to get size
    let mut template = [CK_ATTRIBUTE {
        attr_type: CKA_EC_POINT,
        p_value: ptr::null_mut(),
        value_len: 0,
    }];
    let rv = C_GetAttributeValue(session, pub_key, template.as_mut_ptr(), 1);
    assert_eq!(
        rv, CKR_OK,
        "GetAttributeValue(EC_POINT) size failed: 0x{:08X}",
        rv
    );
    let size = template[0].value_len as usize;

    let mut buf = vec![0u8; size];
    template[0].p_value = buf.as_mut_ptr() as CK_VOID_PTR;
    template[0].value_len = size as CK_ULONG;
    let rv = C_GetAttributeValue(session, pub_key, template.as_mut_ptr(), 1);
    assert_eq!(
        rv, CKR_OK,
        "GetAttributeValue(EC_POINT) data failed: 0x{:08X}",
        rv
    );
    buf.truncate(template[0].value_len as usize);
    buf
}

/// Derive a shared secret via ECDH1_DERIVE.
/// `base_key` is our private key handle, `peer_public_data` is the other party's EC_POINT.
fn do_ecdh_derive(
    session: CK_SESSION_HANDLE,
    base_key: CK_OBJECT_HANDLE,
    peer_public_data: &[u8],
) -> CK_OBJECT_HANDLE {
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_ECDH1_DERIVE,
        p_parameter: peer_public_data.as_ptr() as CK_VOID_PTR,
        parameter_len: peer_public_data.len() as CK_ULONG,
    };

    let ck_true: CK_BBOOL = CK_TRUE;
    let key_len_bytes = ck_ulong_bytes(32);
    let class_bytes = ck_ulong_bytes(CKO_SECRET_KEY);
    let key_type_bytes = ck_ulong_bytes(CKK_AES);

    let mut derive_template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_CLASS,
            p_value: class_bytes.as_ptr() as CK_VOID_PTR,
            value_len: class_bytes.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_KEY_TYPE,
            p_value: key_type_bytes.as_ptr() as CK_VOID_PTR,
            value_len: key_type_bytes.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_VALUE_LEN,
            p_value: key_len_bytes.as_ptr() as CK_VOID_PTR,
            value_len: key_len_bytes.len() as CK_ULONG,
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

    let mut derived_key: CK_OBJECT_HANDLE = 0;
    let rv = C_DeriveKey(
        session,
        &mut mechanism,
        base_key,
        derive_template.as_mut_ptr(),
        derive_template.len() as CK_ULONG,
        &mut derived_key,
    );
    assert_eq!(rv, CKR_OK, "C_DeriveKey failed: 0x{:08X}", rv);
    derived_key
}

// ============================================================================
// ECDH P-256 derivation
// ============================================================================

#[test]
fn test_ecdh_p256_derive_succeeds() {
    let session = setup_user_session();
    let (_pub_a, priv_a) = generate_ec_keypair(session, &P256_OID);
    let (pub_b, _priv_b) = generate_ec_keypair(session, &P256_OID);

    let ec_point_b = read_ec_point(session, pub_b);
    let _derived = do_ecdh_derive(session, priv_a, &ec_point_b);
}

#[test]
fn test_ecdh_p256_derived_key_is_secret() {
    let session = setup_user_session();
    let (_pub_a, priv_a) = generate_ec_keypair(session, &P256_OID);
    let (pub_b, _priv_b) = generate_ec_keypair(session, &P256_OID);

    let ec_point_b = read_ec_point(session, pub_b);
    let derived = do_ecdh_derive(session, priv_a, &ec_point_b);

    let mut class_val: CK_ULONG = 0;
    let mut template = [CK_ATTRIBUTE {
        attr_type: CKA_CLASS,
        p_value: &mut class_val as *mut _ as CK_VOID_PTR,
        value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
    }];
    let rv = C_GetAttributeValue(session, derived, template.as_mut_ptr(), 1);
    assert_eq!(rv, CKR_OK);
    assert_eq!(
        class_val, CKO_SECRET_KEY,
        "Derived key should be CKO_SECRET_KEY"
    );
}

#[test]
fn test_ecdh_p256_derived_key_usable() {
    let session = setup_user_session();
    let (_pub_a, priv_a) = generate_ec_keypair(session, &P256_OID);
    let (pub_b, _priv_b) = generate_ec_keypair(session, &P256_OID);

    let ec_point_b = read_ec_point(session, pub_b);
    let derived = do_ecdh_derive(session, priv_a, &ec_point_b);

    // Use derived key for AES-GCM encrypt
    let iv = [0u8; 12];
    let mut mech = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: iv.as_ptr() as CK_VOID_PTR,
        parameter_len: iv.len() as CK_ULONG,
    };
    let rv = C_EncryptInit(session, &mut mech, derived);
    assert_eq!(rv, CKR_OK, "Derived key should be usable for encryption");
}

#[test]
fn test_ecdh_p256_both_sides_derive_same() {
    let session = setup_user_session();
    let (_pub_a, priv_a) = generate_ec_keypair(session, &P256_OID);
    let (pub_b, _priv_b) = generate_ec_keypair(session, &P256_OID);

    let ec_point_b = read_ec_point(session, pub_b);

    // Derive the same key twice to verify determinism
    let derived_1 = do_ecdh_derive(session, priv_a, &ec_point_b);
    let derived_2 = do_ecdh_derive(session, priv_a, &ec_point_b);

    // Verify determinism: encrypt with derived_1, decrypt with derived_2
    // (same inputs must produce the same derived key)
    let plaintext = b"ecdh determinism test";
    let iv = [0u8; 12];

    let mut mech = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: iv.as_ptr() as CK_VOID_PTR,
        parameter_len: iv.len() as CK_ULONG,
    };
    let rv = C_EncryptInit(session, &mut mech, derived_1);
    assert_eq!(rv, CKR_OK);
    let mut ciphertext = vec![0u8; 256];
    let mut ct_len: CK_ULONG = ciphertext.len() as CK_ULONG;
    let rv = C_Encrypt(
        session,
        plaintext.as_ptr() as *mut _,
        plaintext.len() as CK_ULONG,
        ciphertext.as_mut_ptr(),
        &mut ct_len,
    );
    assert_eq!(rv, CKR_OK);

    // Decrypt with the second derived key — should recover plaintext
    let rv = C_DecryptInit(session, &mut mech, derived_2);
    assert_eq!(rv, CKR_OK, "DecryptInit with derived_2 should succeed");
    let mut recovered = vec![0u8; 256];
    let mut rec_len: CK_ULONG = recovered.len() as CK_ULONG;
    let rv = C_Decrypt(
        session,
        ciphertext.as_mut_ptr(),
        ct_len,
        recovered.as_mut_ptr(),
        &mut rec_len,
    );
    assert_eq!(
        rv, CKR_OK,
        "Same ECDH inputs must derive the same key (cross-decrypt must succeed)"
    );
    assert_eq!(
        &recovered[..rec_len as usize],
        plaintext,
        "Decrypted plaintext should match original"
    );
}

// ============================================================================
// CKA_EC_POINT encoding (PKCS#11: DER OCTET STRING around the X9.62 point)
// ============================================================================

#[test]
fn test_ec_point_p256_is_der_octet_string() {
    let session = setup_user_session();
    let (pub_key, _priv_key) = generate_ec_keypair(session, &P256_OID);
    let ec_point = read_ec_point(session, pub_key);
    assert_eq!(ec_point.len(), 2 + 65, "P-256 EC_POINT must be 67 bytes");
    assert_eq!(
        &ec_point[..3],
        &[0x04, 0x41, 0x04],
        "P-256 EC_POINT must be OCTET STRING(65) wrapping an uncompressed point"
    );
}

#[test]
fn test_ec_point_p384_is_der_octet_string() {
    let session = setup_user_session();
    let (pub_key, _priv_key) = generate_ec_keypair(session, &P384_OID);
    let ec_point = read_ec_point(session, pub_key);
    assert_eq!(ec_point.len(), 2 + 97, "P-384 EC_POINT must be 99 bytes");
    assert_eq!(
        &ec_point[..3],
        &[0x04, 0x61, 0x04],
        "P-384 EC_POINT must be OCTET STRING(97) wrapping an uncompressed point"
    );
}

#[test]
fn test_ecdh_accepts_raw_and_der_peer_point() {
    let session = setup_user_session();
    let (_pub_a, priv_a) = generate_ec_keypair(session, &P256_OID);
    let (pub_b, _priv_b) = generate_ec_keypair(session, &P256_OID);

    let der_point = read_ec_point(session, pub_b);
    let raw_point = &der_point[2..];

    let from_der = do_ecdh_derive(session, priv_a, &der_point);
    let from_raw = do_ecdh_derive(session, priv_a, raw_point);

    // Both encodings of the same peer key must yield the same secret:
    // encrypt under one derived key, decrypt under the other.
    let plaintext = b"ecdh raw/der equivalence";
    let iv = [0u8; 12];
    let mut mech = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: iv.as_ptr() as CK_VOID_PTR,
        parameter_len: iv.len() as CK_ULONG,
    };
    let rv = C_EncryptInit(session, &mut mech, from_der);
    assert_eq!(rv, CKR_OK);
    let mut ciphertext = vec![0u8; 256];
    let mut ct_len: CK_ULONG = ciphertext.len() as CK_ULONG;
    let rv = C_Encrypt(
        session,
        plaintext.as_ptr() as *mut _,
        plaintext.len() as CK_ULONG,
        ciphertext.as_mut_ptr(),
        &mut ct_len,
    );
    assert_eq!(rv, CKR_OK);

    let rv = C_DecryptInit(session, &mut mech, from_raw);
    assert_eq!(rv, CKR_OK);
    let mut recovered = vec![0u8; 256];
    let mut rec_len: CK_ULONG = recovered.len() as CK_ULONG;
    let rv = C_Decrypt(
        session,
        ciphertext.as_mut_ptr(),
        ct_len,
        recovered.as_mut_ptr(),
        &mut rec_len,
    );
    assert_eq!(
        rv, CKR_OK,
        "raw and DER peer points must derive the same key"
    );
    assert_eq!(&recovered[..rec_len as usize], plaintext);
}

// ============================================================================
// ECDH P-384 derivation
// ============================================================================

#[test]
fn test_ecdh_p384_derive_succeeds() {
    let session = setup_user_session();
    let (_pub_a, priv_a) = generate_ec_keypair(session, &P384_OID);
    let (pub_b, _priv_b) = generate_ec_keypair(session, &P384_OID);

    let ec_point_b = read_ec_point(session, pub_b);
    let _derived = do_ecdh_derive(session, priv_a, &ec_point_b);
}

#[test]
fn test_ecdh_p384_derived_key_usable() {
    let session = setup_user_session();
    let (_pub_a, priv_a) = generate_ec_keypair(session, &P384_OID);
    let (pub_b, _priv_b) = generate_ec_keypair(session, &P384_OID);

    let ec_point_b = read_ec_point(session, pub_b);
    let derived = do_ecdh_derive(session, priv_a, &ec_point_b);

    let iv = [0u8; 12];
    let mut mech = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: iv.as_ptr() as CK_VOID_PTR,
        parameter_len: iv.len() as CK_ULONG,
    };
    let rv = C_EncryptInit(session, &mut mech, derived);
    assert_eq!(rv, CKR_OK, "Derived P-384 key should be usable");
}

// ============================================================================
// Error cases
// ============================================================================

#[test]
fn test_derive_invalid_base_key() {
    let session = setup_user_session();
    let (pub_b, _priv_b) = generate_ec_keypair(session, &P256_OID);
    let ec_point_b = read_ec_point(session, pub_b);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_ECDH1_DERIVE,
        p_parameter: ec_point_b.as_ptr() as CK_VOID_PTR,
        parameter_len: ec_point_b.len() as CK_ULONG,
    };
    let ck_true: CK_BBOOL = CK_TRUE;
    let key_len_bytes = ck_ulong_bytes(32);
    let class_bytes = ck_ulong_bytes(CKO_SECRET_KEY);
    let key_type_bytes = ck_ulong_bytes(CKK_AES);
    let mut template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_CLASS,
            p_value: class_bytes.as_ptr() as CK_VOID_PTR,
            value_len: class_bytes.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_KEY_TYPE,
            p_value: key_type_bytes.as_ptr() as CK_VOID_PTR,
            value_len: key_type_bytes.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_VALUE_LEN,
            p_value: key_len_bytes.as_ptr() as CK_VOID_PTR,
            value_len: key_len_bytes.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_ENCRYPT,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
    ];
    let mut derived: CK_OBJECT_HANDLE = 0;
    let rv = C_DeriveKey(
        session,
        &mut mechanism,
        0xFFFFFFFF,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut derived,
    );
    assert_ne!(rv, CKR_OK, "Invalid base key handle should fail");
}

#[test]
fn test_derive_with_aes_key_fails() {
    let session = setup_user_session();
    // Generate an AES key (wrong type for ECDH derive)
    let mut aes_mech = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let value_len = ck_ulong_bytes(32);
    let ck_true: CK_BBOOL = CK_TRUE;
    let mut aes_tmpl = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_VALUE_LEN,
            p_value: value_len.as_ptr() as CK_VOID_PTR,
            value_len: value_len.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_DERIVE,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
    ];
    let mut aes_key: CK_OBJECT_HANDLE = 0;
    let rv = C_GenerateKey(
        session,
        &mut aes_mech,
        aes_tmpl.as_mut_ptr(),
        aes_tmpl.len() as CK_ULONG,
        &mut aes_key,
    );
    assert_eq!(rv, CKR_OK);

    // Try ECDH derive with AES key
    let fake_point = [0u8; 65]; // random bytes
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_ECDH1_DERIVE,
        p_parameter: fake_point.as_ptr() as CK_VOID_PTR,
        parameter_len: fake_point.len() as CK_ULONG,
    };
    let class_bytes = ck_ulong_bytes(CKO_SECRET_KEY);
    let key_type_bytes = ck_ulong_bytes(CKK_AES);
    let key_len_bytes = ck_ulong_bytes(32);
    let mut template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_CLASS,
            p_value: class_bytes.as_ptr() as CK_VOID_PTR,
            value_len: class_bytes.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_KEY_TYPE,
            p_value: key_type_bytes.as_ptr() as CK_VOID_PTR,
            value_len: key_type_bytes.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_VALUE_LEN,
            p_value: key_len_bytes.as_ptr() as CK_VOID_PTR,
            value_len: key_len_bytes.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_ENCRYPT,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
    ];
    let mut derived: CK_OBJECT_HANDLE = 0;
    let rv = C_DeriveKey(
        session,
        &mut mechanism,
        aes_key,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut derived,
    );
    assert_ne!(rv, CKR_OK, "ECDH derive with AES key should fail");
}

#[test]
fn test_derive_null_mechanism() {
    let session = setup_user_session();
    let (_pub, priv_key) = generate_ec_keypair(session, &P256_OID);
    let ck_true: CK_BBOOL = CK_TRUE;
    let class_bytes = ck_ulong_bytes(CKO_SECRET_KEY);
    let key_type_bytes = ck_ulong_bytes(CKK_AES);
    let key_len_bytes = ck_ulong_bytes(32);
    let mut template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_CLASS,
            p_value: class_bytes.as_ptr() as CK_VOID_PTR,
            value_len: class_bytes.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_KEY_TYPE,
            p_value: key_type_bytes.as_ptr() as CK_VOID_PTR,
            value_len: key_type_bytes.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_VALUE_LEN,
            p_value: key_len_bytes.as_ptr() as CK_VOID_PTR,
            value_len: key_len_bytes.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_ENCRYPT,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
    ];
    let mut derived: CK_OBJECT_HANDLE = 0;
    let rv = C_DeriveKey(
        session,
        ptr::null_mut(),
        priv_key,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut derived,
    );
    assert_eq!(
        rv, CKR_ARGUMENTS_BAD,
        "Null mechanism should return CKR_ARGUMENTS_BAD"
    );
}

#[test]
fn test_derive_without_login() {
    ensure_init();
    let so_pin = b"sopin123";
    let mut label = [b' '; 32];
    label[..8].copy_from_slice(b"NoLgDerv");
    C_InitToken(
        0,
        so_pin.as_ptr() as *mut _,
        so_pin.len() as CK_ULONG,
        label.as_ptr() as *mut _,
    );

    let mut session: CK_SESSION_HANDLE = 0;
    C_OpenSession(
        0,
        CKF_RW_SESSION | CKF_SERIAL_SESSION,
        ptr::null_mut(),
        None,
        &mut session,
    );
    // Don't login

    let fake_point = [0u8; 65];
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_ECDH1_DERIVE,
        p_parameter: fake_point.as_ptr() as CK_VOID_PTR,
        parameter_len: fake_point.len() as CK_ULONG,
    };
    let ck_true: CK_BBOOL = CK_TRUE;
    let class_bytes = ck_ulong_bytes(CKO_SECRET_KEY);
    let key_type_bytes = ck_ulong_bytes(CKK_AES);
    let key_len_bytes = ck_ulong_bytes(32);
    let mut template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_CLASS,
            p_value: class_bytes.as_ptr() as CK_VOID_PTR,
            value_len: class_bytes.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_KEY_TYPE,
            p_value: key_type_bytes.as_ptr() as CK_VOID_PTR,
            value_len: key_type_bytes.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_VALUE_LEN,
            p_value: key_len_bytes.as_ptr() as CK_VOID_PTR,
            value_len: key_len_bytes.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_ENCRYPT,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
    ];
    let mut derived: CK_OBJECT_HANDLE = 0;
    let rv = C_DeriveKey(
        session,
        &mut mechanism,
        1,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut derived,
    );
    assert_ne!(rv, CKR_OK, "DeriveKey without login should fail");
}

#[test]
fn test_derive_invalid_mechanism() {
    let session = setup_user_session();
    let (_pub, priv_key) = generate_ec_keypair(session, &P256_OID);
    let (pub_b, _) = generate_ec_keypair(session, &P256_OID);
    let ec_point_b = read_ec_point(session, pub_b);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256, // Wrong mechanism for derive
        p_parameter: ec_point_b.as_ptr() as CK_VOID_PTR,
        parameter_len: ec_point_b.len() as CK_ULONG,
    };
    let ck_true: CK_BBOOL = CK_TRUE;
    let class_bytes = ck_ulong_bytes(CKO_SECRET_KEY);
    let key_type_bytes = ck_ulong_bytes(CKK_AES);
    let key_len_bytes = ck_ulong_bytes(32);
    let mut template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_CLASS,
            p_value: class_bytes.as_ptr() as CK_VOID_PTR,
            value_len: class_bytes.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_KEY_TYPE,
            p_value: key_type_bytes.as_ptr() as CK_VOID_PTR,
            value_len: key_type_bytes.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_VALUE_LEN,
            p_value: key_len_bytes.as_ptr() as CK_VOID_PTR,
            value_len: key_len_bytes.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_ENCRYPT,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
    ];
    let mut derived: CK_OBJECT_HANDLE = 0;
    let rv = C_DeriveKey(
        session,
        &mut mechanism,
        priv_key,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut derived,
    );
    assert_ne!(rv, CKR_OK, "Invalid derive mechanism should fail");
}

#[test]
fn test_derive_without_derive_permission() {
    let session = setup_user_session();
    // Generate EC key WITHOUT derive permission
    let ck_false: CK_BBOOL = CK_FALSE;
    let ck_true: CK_BBOOL = CK_TRUE;
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_EC_KEY_PAIR_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let mut pub_template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_EC_PARAMS,
            p_value: P256_OID.as_ptr() as CK_VOID_PTR,
            value_len: P256_OID.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_VERIFY,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
    ];
    let mut priv_template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_SIGN,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_DERIVE,
            p_value: &ck_false as *const _ as CK_VOID_PTR,
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
    assert_eq!(rv, CKR_OK);

    let (peer_pub, _) = generate_ec_keypair(session, &P256_OID);
    let ec_point = read_ec_point(session, peer_pub);

    let mut derive_mech = CK_MECHANISM {
        mechanism: CKM_ECDH1_DERIVE,
        p_parameter: ec_point.as_ptr() as CK_VOID_PTR,
        parameter_len: ec_point.len() as CK_ULONG,
    };
    let class_bytes = ck_ulong_bytes(CKO_SECRET_KEY);
    let key_type_bytes = ck_ulong_bytes(CKK_AES);
    let key_len_bytes = ck_ulong_bytes(32);
    let mut template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_CLASS,
            p_value: class_bytes.as_ptr() as CK_VOID_PTR,
            value_len: class_bytes.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_KEY_TYPE,
            p_value: key_type_bytes.as_ptr() as CK_VOID_PTR,
            value_len: key_type_bytes.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_VALUE_LEN,
            p_value: key_len_bytes.as_ptr() as CK_VOID_PTR,
            value_len: key_len_bytes.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_ENCRYPT,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
    ];
    let mut derived: CK_OBJECT_HANDLE = 0;
    let rv = C_DeriveKey(
        session,
        &mut derive_mech,
        priv_key,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut derived,
    );
    assert_ne!(
        rv, CKR_OK,
        "Derive without CKA_DERIVE permission should fail"
    );
}

// ============================================================================
// Derived key value len
// ============================================================================

#[test]
fn test_derived_key_value_len() {
    let session = setup_user_session();
    let (_pub_a, priv_a) = generate_ec_keypair(session, &P256_OID);
    let (pub_b, _) = generate_ec_keypair(session, &P256_OID);
    let ec_point_b = read_ec_point(session, pub_b);
    let derived = do_ecdh_derive(session, priv_a, &ec_point_b);

    let mut val_len: CK_ULONG = 0;
    let mut template = [CK_ATTRIBUTE {
        attr_type: CKA_VALUE_LEN,
        p_value: &mut val_len as *mut _ as CK_VOID_PTR,
        value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
    }];
    let rv = C_GetAttributeValue(session, derived, template.as_mut_ptr(), 1);
    assert_eq!(rv, CKR_OK);
    assert_eq!(
        val_len, 32,
        "Derived key should have VALUE_LEN=32 (AES-256)"
    );
}

#[test]
fn test_derived_key_type() {
    let session = setup_user_session();
    let (_pub_a, priv_a) = generate_ec_keypair(session, &P256_OID);
    let (pub_b, _) = generate_ec_keypair(session, &P256_OID);
    let ec_point_b = read_ec_point(session, pub_b);
    let derived = do_ecdh_derive(session, priv_a, &ec_point_b);

    let mut kt: CK_ULONG = 0;
    let mut template = [CK_ATTRIBUTE {
        attr_type: CKA_KEY_TYPE,
        p_value: &mut kt as *mut _ as CK_VOID_PTR,
        value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
    }];
    let rv = C_GetAttributeValue(session, derived, template.as_mut_ptr(), 1);
    assert_eq!(rv, CKR_OK);
    assert_eq!(kt, CKK_AES, "Derived key should have type CKK_AES");
}

// ============================================================================
// Multiple derivations with same key pair
// ============================================================================

#[test]
fn test_derive_twice_same_keys_same_result() {
    let session = setup_user_session();
    let (_pub_a, priv_a) = generate_ec_keypair(session, &P256_OID);
    let (pub_b, _) = generate_ec_keypair(session, &P256_OID);
    let ec_point_b = read_ec_point(session, pub_b);

    let derived1 = do_ecdh_derive(session, priv_a, &ec_point_b);
    let derived2 = do_ecdh_derive(session, priv_a, &ec_point_b);

    // Different handles but same key material
    assert_ne!(derived1, derived2, "Should get different handles");

    // Verify same key material: encrypt with derived1, decrypt with derived2
    let plaintext = b"consistency check";
    let iv = [0u8; 12];

    let mut mech = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: iv.as_ptr() as CK_VOID_PTR,
        parameter_len: iv.len() as CK_ULONG,
    };
    let rv = C_EncryptInit(session, &mut mech, derived1);
    assert_eq!(rv, CKR_OK);
    let mut ciphertext = vec![0u8; 256];
    let mut ct_len: CK_ULONG = ciphertext.len() as CK_ULONG;
    let rv = C_Encrypt(
        session,
        plaintext.as_ptr() as *mut _,
        plaintext.len() as CK_ULONG,
        ciphertext.as_mut_ptr(),
        &mut ct_len,
    );
    assert_eq!(rv, CKR_OK);

    // Decrypt with derived2 — should succeed since both have same key material
    let rv = C_DecryptInit(session, &mut mech, derived2);
    assert_eq!(rv, CKR_OK);
    let mut recovered = vec![0u8; 256];
    let mut rec_len: CK_ULONG = recovered.len() as CK_ULONG;
    let rv = C_Decrypt(
        session,
        ciphertext.as_mut_ptr(),
        ct_len,
        recovered.as_mut_ptr(),
        &mut rec_len,
    );
    assert_eq!(
        rv, CKR_OK,
        "Same ECDH derivation should produce same key (cross-decrypt must succeed)"
    );
    assert_eq!(
        &recovered[..rec_len as usize],
        plaintext,
        "Decrypted plaintext should match original"
    );
}

#[test]
fn test_derive_different_peers_different_keys() {
    let session = setup_user_session();
    let (_pub_a, priv_a) = generate_ec_keypair(session, &P256_OID);
    let (pub_b, _) = generate_ec_keypair(session, &P256_OID);
    let (pub_c, _) = generate_ec_keypair(session, &P256_OID);
    let ec_point_b = read_ec_point(session, pub_b);
    let ec_point_c = read_ec_point(session, pub_c);

    let derived_ab = do_ecdh_derive(session, priv_a, &ec_point_b);
    let derived_ac = do_ecdh_derive(session, priv_a, &ec_point_c);

    // Encrypt same plaintext with different derived keys — should differ
    let plaintext = b"different peers";
    let iv = [0u8; 12];

    let mut mech = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: iv.as_ptr() as CK_VOID_PTR,
        parameter_len: iv.len() as CK_ULONG,
    };
    let rv = C_EncryptInit(session, &mut mech, derived_ab);
    assert_eq!(rv, CKR_OK);
    let mut ct1 = vec![0u8; 256];
    let mut ct1_len: CK_ULONG = ct1.len() as CK_ULONG;
    let rv = C_Encrypt(
        session,
        plaintext.as_ptr() as *mut _,
        plaintext.len() as CK_ULONG,
        ct1.as_mut_ptr(),
        &mut ct1_len,
    );
    assert_eq!(rv, CKR_OK);

    let rv = C_EncryptInit(session, &mut mech, derived_ac);
    assert_eq!(rv, CKR_OK);
    let mut ct2 = vec![0u8; 256];
    let mut ct2_len: CK_ULONG = ct2.len() as CK_ULONG;
    let rv = C_Encrypt(
        session,
        plaintext.as_ptr() as *mut _,
        plaintext.len() as CK_ULONG,
        ct2.as_mut_ptr(),
        &mut ct2_len,
    );
    assert_eq!(rv, CKR_OK);

    assert_ne!(
        &ct1[..ct1_len as usize],
        &ct2[..ct2_len as usize],
        "Different ECDH peers should produce different keys"
    );
}

// ============================================================================
// Destroy derived key
// ============================================================================

#[test]
fn test_destroy_derived_key() {
    let session = setup_user_session();
    let (_pub_a, priv_a) = generate_ec_keypair(session, &P256_OID);
    let (pub_b, _) = generate_ec_keypair(session, &P256_OID);
    let ec_point_b = read_ec_point(session, pub_b);
    let derived = do_ecdh_derive(session, priv_a, &ec_point_b);

    let rv = C_DestroyObject(session, derived);
    assert_eq!(rv, CKR_OK, "Should be able to destroy derived key");

    // Verify destroyed key can't be used
    let iv = [0u8; 12];
    let mut mech = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: iv.as_ptr() as CK_VOID_PTR,
        parameter_len: iv.len() as CK_ULONG,
    };
    let rv = C_EncryptInit(session, &mut mech, derived);
    assert_ne!(rv, CKR_OK, "Destroyed derived key should be unusable");
}

#[test]
fn test_derive_on_ro_session_fails() {
    ensure_init();
    let so_pin = b"sopin123";
    let mut label = [b' '; 32];
    label[..8].copy_from_slice(b"RODrvTst");
    C_InitToken(
        0,
        so_pin.as_ptr() as *mut _,
        so_pin.len() as CK_ULONG,
        label.as_ptr() as *mut _,
    );

    let mut session: CK_SESSION_HANDLE = 0;
    // RW session for SO setup
    C_OpenSession(
        0,
        CKF_RW_SESSION | CKF_SERIAL_SESSION,
        ptr::null_mut(),
        None,
        &mut session,
    );
    C_Login(
        session,
        CKU_SO,
        so_pin.as_ptr() as *mut _,
        so_pin.len() as CK_ULONG,
    );
    let user_pin = b"userpin1";
    C_InitPIN(
        session,
        user_pin.as_ptr() as *mut _,
        user_pin.len() as CK_ULONG,
    );
    C_Logout(session);
    C_CloseSession(session);

    // Open RO session
    let mut ro_session: CK_SESSION_HANDLE = 0;
    C_OpenSession(
        0,
        CKF_SERIAL_SESSION,
        ptr::null_mut(),
        None,
        &mut ro_session,
    );
    C_Login(
        ro_session,
        CKU_USER,
        user_pin.as_ptr() as *mut _,
        user_pin.len() as CK_ULONG,
    );

    // Try to generate key (needed for derive) on RO session
    let mut ec_mech = CK_MECHANISM {
        mechanism: CKM_EC_KEY_PAIR_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let ck_true: CK_BBOOL = CK_TRUE;
    let mut pub_tmpl = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_EC_PARAMS,
            p_value: P256_OID.as_ptr() as CK_VOID_PTR,
            value_len: P256_OID.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_VERIFY,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
    ];
    let mut priv_tmpl = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_SIGN,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_DERIVE,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
    ];
    let mut pub_key: CK_OBJECT_HANDLE = 0;
    let mut priv_key: CK_OBJECT_HANDLE = 0;
    let rv = C_GenerateKeyPair(
        ro_session,
        &mut ec_mech,
        pub_tmpl.as_mut_ptr(),
        pub_tmpl.len() as CK_ULONG,
        priv_tmpl.as_mut_ptr(),
        priv_tmpl.len() as CK_ULONG,
        &mut pub_key,
        &mut priv_key,
    );
    assert_ne!(rv, CKR_OK, "Key generation on RO session should fail");
}

#[test]
fn test_derive_get_object_size() {
    let session = setup_user_session();
    let (_pub_a, priv_a) = generate_ec_keypair(session, &P256_OID);
    let (pub_b, _) = generate_ec_keypair(session, &P256_OID);
    let ec_point_b = read_ec_point(session, pub_b);
    let derived = do_ecdh_derive(session, priv_a, &ec_point_b);

    let mut size: CK_ULONG = 0;
    let rv = C_GetObjectSize(session, derived, &mut size);
    assert_eq!(rv, CKR_OK, "GetObjectSize on derived key should succeed");
    assert!(size > 0, "Derived key size should be > 0");
}

// ============================================================================
// Standard CK_ECDH1_DERIVE_PARAMS mechanism parameter
// ============================================================================

/// Generate an EC key pair whose private key is non-sensitive, so tests can
/// read CKA_VALUE and cross-check the token's derivation independently.
fn generate_exportable_ec_keypair(
    session: CK_SESSION_HANDLE,
    oid: &[u8],
) -> (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) {
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_EC_KEY_PAIR_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let ck_true: CK_BBOOL = CK_TRUE;
    let ck_false: CK_BBOOL = CK_FALSE;
    let mut pub_template = vec![CK_ATTRIBUTE {
        attr_type: CKA_EC_PARAMS,
        p_value: oid.as_ptr() as CK_VOID_PTR,
        value_len: oid.len() as CK_ULONG,
    }];
    let mut priv_template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_DERIVE,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_SENSITIVE,
            p_value: &ck_false as *const _ as CK_VOID_PTR,
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
    assert_eq!(rv, CKR_OK, "EC keygen failed: 0x{:08X}", rv);
    (pub_key, priv_key)
}

fn read_attr(
    session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    attr_type: CK_ATTRIBUTE_TYPE,
) -> Vec<u8> {
    let mut template = [CK_ATTRIBUTE {
        attr_type,
        p_value: ptr::null_mut(),
        value_len: 0,
    }];
    let rv = C_GetAttributeValue(session, object, template.as_mut_ptr(), 1);
    assert_eq!(rv, CKR_OK, "GetAttributeValue size failed: 0x{:08X}", rv);
    let mut buf = vec![0u8; template[0].value_len as usize];
    template[0].p_value = buf.as_mut_ptr() as CK_VOID_PTR;
    let rv = C_GetAttributeValue(session, object, template.as_mut_ptr(), 1);
    assert_eq!(rv, CKR_OK, "GetAttributeValue data failed: 0x{:08X}", rv);
    buf.truncate(template[0].value_len as usize);
    buf
}

/// C_DeriveKey with a standard CK_ECDH1_DERIVE_PARAMS. The derived AES key
/// is non-sensitive when the base key is, so its value can be read back.
fn derive_with_params(
    session: CK_SESSION_HANDLE,
    base_key: CK_OBJECT_HANDLE,
    kdf: CK_ULONG,
    shared_data: &[u8],
    public_data: &[u8],
    key_len: CK_ULONG,
) -> Result<CK_OBJECT_HANDLE, CK_RV> {
    let mut params = CK_ECDH1_DERIVE_PARAMS {
        kdf,
        shared_data_len: shared_data.len() as CK_ULONG,
        p_shared_data: if shared_data.is_empty() {
            ptr::null_mut()
        } else {
            shared_data.as_ptr() as CK_BYTE_PTR
        },
        public_data_len: public_data.len() as CK_ULONG,
        p_public_data: if public_data.is_empty() {
            ptr::null_mut()
        } else {
            public_data.as_ptr() as CK_BYTE_PTR
        },
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_ECDH1_DERIVE,
        p_parameter: &mut params as *mut _ as CK_VOID_PTR,
        parameter_len: std::mem::size_of::<CK_ECDH1_DERIVE_PARAMS>() as CK_ULONG,
    };
    let ck_false: CK_BBOOL = CK_FALSE;
    let key_len_bytes = ck_ulong_bytes(key_len);
    let class_bytes = ck_ulong_bytes(CKO_SECRET_KEY);
    let key_type_bytes = ck_ulong_bytes(CKK_AES);
    let mut template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_CLASS,
            p_value: class_bytes.as_ptr() as CK_VOID_PTR,
            value_len: class_bytes.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_KEY_TYPE,
            p_value: key_type_bytes.as_ptr() as CK_VOID_PTR,
            value_len: key_type_bytes.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_VALUE_LEN,
            p_value: key_len_bytes.as_ptr() as CK_VOID_PTR,
            value_len: key_len_bytes.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_SENSITIVE,
            p_value: &ck_false as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
    ];
    let mut derived: CK_OBJECT_HANDLE = 0;
    let rv = C_DeriveKey(
        session,
        &mut mechanism,
        base_key,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut derived,
    );
    if rv == CKR_OK {
        Ok(derived)
    } else {
        Err(rv)
    }
}

fn x963_kdf<D: sha2::Digest>(z: &[u8], shared_info: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut counter: u32 = 1;
    while out.len() < len {
        let mut h = D::new();
        h.update(z);
        h.update(counter.to_be_bytes());
        h.update(shared_info);
        out.extend_from_slice(&h.finalize());
        counter += 1;
    }
    out.truncate(len);
    out
}

#[test]
fn test_ecdh_params_ckd_null_p256_matches_raw_shared_secret() {
    let session = setup_user_session();
    let (_pub_a, priv_a) = generate_exportable_ec_keypair(session, &P256_OID);
    let (pub_b, _priv_b) = generate_ec_keypair(session, &P256_OID);

    let peer_point = read_ec_point(session, pub_b);
    let derived = derive_with_params(session, priv_a, CKD_NULL, &[], &peer_point, 32)
        .expect("CKD_NULL derive failed");
    let token_key = read_attr(session, derived, CKA_VALUE);

    let sk = p256::SecretKey::from_slice(&read_attr(session, priv_a, CKA_VALUE)).unwrap();
    let pk = p256::PublicKey::from_sec1_bytes(&peer_point[2..]).unwrap();
    let z = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
    assert_eq!(token_key, z.raw_secret_bytes().to_vec());
}

#[test]
fn test_ecdh_params_ckd_null_p384_truncates_to_rightmost_bytes() {
    let session = setup_user_session();
    let (_pub_a, priv_a) = generate_exportable_ec_keypair(session, &P384_OID);
    let (pub_b, _priv_b) = generate_ec_keypair(session, &P384_OID);

    let peer_point = read_ec_point(session, pub_b);
    let derived = derive_with_params(session, priv_a, CKD_NULL, &[], &peer_point, 32)
        .expect("CKD_NULL derive failed");
    let token_key = read_attr(session, derived, CKA_VALUE);

    let sk = p384::SecretKey::from_slice(&read_attr(session, priv_a, CKA_VALUE)).unwrap();
    let pk = p384::PublicKey::from_sec1_bytes(&peer_point[2..]).unwrap();
    let z = p384::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
    assert_eq!(token_key, z.raw_secret_bytes()[48 - 32..].to_vec());
}

#[test]
fn test_ecdh_params_sha384_kdf_with_shared_data_matches_x963() {
    let session = setup_user_session();
    let (_pub_a, priv_a) = generate_exportable_ec_keypair(session, &P384_OID);
    let (pub_b, _priv_b) = generate_ec_keypair(session, &P384_OID);

    let peer_point = read_ec_point(session, pub_b);
    let shared_info = b"craton ecdh shared info";
    let derived = derive_with_params(
        session,
        priv_a,
        CKD_SHA384_KDF,
        shared_info,
        &peer_point,
        24,
    )
    .expect("CKD_SHA384_KDF derive failed");
    let token_key = read_attr(session, derived, CKA_VALUE);

    let sk = p384::SecretKey::from_slice(&read_attr(session, priv_a, CKA_VALUE)).unwrap();
    let pk = p384::PublicKey::from_sec1_bytes(&peer_point[2..]).unwrap();
    let z = p384::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
    let expected = x963_kdf::<sha2::Sha384>(z.raw_secret_bytes(), shared_info, 24);
    assert_eq!(token_key, expected);
}

#[test]
fn test_ecdh_params_both_parties_agree() {
    let session = setup_user_session();
    let (pub_a, priv_a) = generate_exportable_ec_keypair(session, &P256_OID);
    let (pub_b, priv_b) = generate_exportable_ec_keypair(session, &P256_OID);
    let point_a = read_ec_point(session, pub_a);
    let point_b = read_ec_point(session, pub_b);

    for kdf in [CKD_NULL, CKD_SHA256_KDF, CKD_SHA512_KDF] {
        let ab = derive_with_params(session, priv_a, kdf, &[], &point_b, 32).unwrap();
        let ba = derive_with_params(session, priv_b, kdf, &[], &point_a, 32).unwrap();
        assert_eq!(
            read_attr(session, ab, CKA_VALUE),
            read_attr(session, ba, CKA_VALUE),
            "kdf {kdf:#x}: both sides must derive the same key"
        );
    }
}

#[test]
fn test_ecdh_params_accepts_raw_public_data() {
    let session = setup_user_session();
    let (_pub_a, priv_a) = generate_exportable_ec_keypair(session, &P256_OID);
    let (pub_b, _priv_b) = generate_ec_keypair(session, &P256_OID);
    let der_point = read_ec_point(session, pub_b);

    let from_der = derive_with_params(session, priv_a, CKD_NULL, &[], &der_point, 32).unwrap();
    let from_raw = derive_with_params(session, priv_a, CKD_NULL, &[], &der_point[2..], 32).unwrap();
    assert_eq!(
        read_attr(session, from_der, CKA_VALUE),
        read_attr(session, from_raw, CKA_VALUE)
    );
}

#[test]
fn test_ecdh_params_rejects_invalid_parameters() {
    let session = setup_user_session();
    let (_pub_a, priv_a) = generate_ec_keypair(session, &P256_OID);
    let (pub_b, _priv_b) = generate_ec_keypair(session, &P256_OID);
    let point = read_ec_point(session, pub_b);

    // CKD_NULL does not take shared data.
    assert_eq!(
        derive_with_params(session, priv_a, CKD_NULL, b"info", &point, 32),
        Err(CKR_MECHANISM_PARAM_INVALID)
    );
    // SHA-1 and unknown KDFs are refused.
    for kdf in [CKD_SHA1_KDF, 0x7777] {
        assert_eq!(
            derive_with_params(session, priv_a, kdf, &[], &point, 32),
            Err(CKR_MECHANISM_PARAM_INVALID),
            "kdf {kdf:#x}"
        );
    }
    // Missing public data.
    assert_eq!(
        derive_with_params(session, priv_a, CKD_NULL, &[], &[], 32),
        Err(CKR_MECHANISM_PARAM_INVALID)
    );
    // A point that is not on the curve.
    let mut bogus = point[2..].to_vec();
    bogus[10] ^= 0xff;
    assert_eq!(
        derive_with_params(session, priv_a, CKD_NULL, &[], &bogus, 32),
        Err(CKR_MECHANISM_PARAM_INVALID)
    );
}
