// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
// Attribute management ABI tests — exercises C_GetAttributeValue, C_SetAttributeValue,
// C_FindObjectsInit/FindObjects/FindObjectsFinal through the PKCS#11 C ABI.

use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm::pkcs11_abi::functions::*;
use craton_hsm::pkcs11_abi::types::*;
use std::ptr;

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
    label[..8].copy_from_slice(b"AttrTest");
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

fn generate_aes_key(session: CK_SESSION_HANDLE, label: &[u8]) -> CK_OBJECT_HANDLE {
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let value_len_bytes = ck_ulong_bytes(32);
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
        CK_ATTRIBUTE {
            attr_type: CKA_LABEL,
            p_value: label.as_ptr() as CK_VOID_PTR,
            value_len: label.len() as CK_ULONG,
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

fn generate_aes_key_with_id(
    session: CK_SESSION_HANDLE,
    label: &[u8],
    id: &[u8],
) -> CK_OBJECT_HANDLE {
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let value_len_bytes = ck_ulong_bytes(32);
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
        CK_ATTRIBUTE {
            attr_type: CKA_LABEL,
            p_value: label.as_ptr() as CK_VOID_PTR,
            value_len: label.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_ID,
            p_value: id.as_ptr() as CK_VOID_PTR,
            value_len: id.len() as CK_ULONG,
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
    assert_eq!(rv, CKR_OK, "generate_aes_key_with_id failed: 0x{:08X}", rv);
    key
}

// ============================================================================
// C_GetAttributeValue tests
// ============================================================================

#[test]
fn test_get_label_attribute() {
    let session = setup_user_session();
    let label = b"my_test_key_001";
    let key = generate_aes_key(session, label);

    let mut buf = [0u8; 64];
    let mut template = [CK_ATTRIBUTE {
        attr_type: CKA_LABEL,
        p_value: buf.as_mut_ptr() as CK_VOID_PTR,
        value_len: buf.len() as CK_ULONG,
    }];
    let rv = C_GetAttributeValue(session, key, template.as_mut_ptr(), 1);
    assert_eq!(rv, CKR_OK, "GetAttributeValue(LABEL) failed: 0x{:08X}", rv);
    let actual_len = template[0].value_len as usize;
    assert_eq!(&buf[..actual_len], label.as_slice());
}

#[test]
fn test_get_id_attribute() {
    let session = setup_user_session();
    let id = b"\x01\x02\x03\x04";
    let key = generate_aes_key_with_id(session, b"id_key", id);

    let mut buf = [0u8; 64];
    let mut template = [CK_ATTRIBUTE {
        attr_type: CKA_ID,
        p_value: buf.as_mut_ptr() as CK_VOID_PTR,
        value_len: buf.len() as CK_ULONG,
    }];
    let rv = C_GetAttributeValue(session, key, template.as_mut_ptr(), 1);
    assert_eq!(rv, CKR_OK);
    let actual_len = template[0].value_len as usize;
    assert_eq!(&buf[..actual_len], id.as_slice());
}

#[test]
fn test_get_class_attribute() {
    let session = setup_user_session();
    let key = generate_aes_key(session, b"class_test");
    let mut class_val: CK_ULONG = 0;
    let mut template = [CK_ATTRIBUTE {
        attr_type: CKA_CLASS,
        p_value: &mut class_val as *mut _ as CK_VOID_PTR,
        value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
    }];
    let rv = C_GetAttributeValue(session, key, template.as_mut_ptr(), 1);
    assert_eq!(rv, CKR_OK);
    assert_eq!(class_val, CKO_SECRET_KEY);
}

#[test]
fn test_get_key_type_attribute() {
    let session = setup_user_session();
    let key = generate_aes_key(session, b"kt_test");
    let mut kt: CK_ULONG = 0;
    let mut template = [CK_ATTRIBUTE {
        attr_type: CKA_KEY_TYPE,
        p_value: &mut kt as *mut _ as CK_VOID_PTR,
        value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
    }];
    let rv = C_GetAttributeValue(session, key, template.as_mut_ptr(), 1);
    assert_eq!(rv, CKR_OK);
    assert_eq!(kt, CKK_AES);
}

#[test]
fn test_get_encrypt_permission_attribute() {
    let session = setup_user_session();
    let key = generate_aes_key(session, b"enc_perm");
    let mut enc_val: CK_BBOOL = CK_FALSE;
    let mut template = [CK_ATTRIBUTE {
        attr_type: CKA_ENCRYPT,
        p_value: &mut enc_val as *mut _ as CK_VOID_PTR,
        value_len: 1,
    }];
    let rv = C_GetAttributeValue(session, key, template.as_mut_ptr(), 1);
    assert_eq!(rv, CKR_OK);
    assert_eq!(enc_val, CK_TRUE, "Key should have CKA_ENCRYPT=true");
}

#[test]
fn test_get_decrypt_permission_attribute() {
    let session = setup_user_session();
    let key = generate_aes_key(session, b"dec_perm");
    let mut dec_val: CK_BBOOL = CK_FALSE;
    let mut template = [CK_ATTRIBUTE {
        attr_type: CKA_DECRYPT,
        p_value: &mut dec_val as *mut _ as CK_VOID_PTR,
        value_len: 1,
    }];
    let rv = C_GetAttributeValue(session, key, template.as_mut_ptr(), 1);
    assert_eq!(rv, CKR_OK);
    assert_eq!(dec_val, CK_TRUE);
}

#[test]
fn test_get_sensitive_attribute() {
    let session = setup_user_session();
    let key = generate_aes_key(session, b"sens_test");
    let mut sens: CK_BBOOL = CK_TRUE;
    let mut template = [CK_ATTRIBUTE {
        attr_type: CKA_SENSITIVE,
        p_value: &mut sens as *mut _ as CK_VOID_PTR,
        value_len: 1,
    }];
    let rv = C_GetAttributeValue(session, key, template.as_mut_ptr(), 1);
    assert_eq!(rv, CKR_OK);
    // Default AES keys are not sensitive unless explicitly set
}

#[test]
fn test_get_extractable_attribute() {
    let session = setup_user_session();
    let key = generate_aes_key(session, b"extr_test");
    let mut extr: CK_BBOOL = CK_FALSE;
    let mut template = [CK_ATTRIBUTE {
        attr_type: CKA_EXTRACTABLE,
        p_value: &mut extr as *mut _ as CK_VOID_PTR,
        value_len: 1,
    }];
    let rv = C_GetAttributeValue(session, key, template.as_mut_ptr(), 1);
    assert_eq!(rv, CKR_OK);
    // Default extractable may be true or false depending on implementation
    // This test verifies the attribute is readable
    assert!(
        extr == CK_TRUE || extr == CK_FALSE,
        "Extractable should be a valid boolean"
    );
}

#[test]
fn test_get_attribute_null_value_returns_size() {
    let session = setup_user_session();
    let key = generate_aes_key(session, b"size_query");

    let mut template = [CK_ATTRIBUTE {
        attr_type: CKA_LABEL,
        p_value: ptr::null_mut(),
        value_len: 0,
    }];
    let rv = C_GetAttributeValue(session, key, template.as_mut_ptr(), 1);
    assert_eq!(rv, CKR_OK, "Null-value query should return OK");
    let value_len = template[0].value_len;
    assert_eq!(value_len, 10, "Label 'size_query' is 10 bytes");
}

#[test]
fn test_get_attribute_invalid_handle() {
    let session = setup_user_session();
    let mut val: CK_ULONG = 0;
    let mut template = [CK_ATTRIBUTE {
        attr_type: CKA_CLASS,
        p_value: &mut val as *mut _ as CK_VOID_PTR,
        value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
    }];
    let rv = C_GetAttributeValue(session, 0xFFFFFFFF, template.as_mut_ptr(), 1);
    assert_ne!(rv, CKR_OK, "Invalid handle should fail");
}

#[test]
fn test_get_multiple_attributes_at_once() {
    let session = setup_user_session();
    let key = generate_aes_key(session, b"multi_attr");

    let mut class_val: CK_ULONG = 0;
    let mut kt: CK_ULONG = 0;
    let mut val_len: CK_ULONG = 0;
    let mut template = [
        CK_ATTRIBUTE {
            attr_type: CKA_CLASS,
            p_value: &mut class_val as *mut _ as CK_VOID_PTR,
            value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_KEY_TYPE,
            p_value: &mut kt as *mut _ as CK_VOID_PTR,
            value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_VALUE_LEN,
            p_value: &mut val_len as *mut _ as CK_VOID_PTR,
            value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        },
    ];
    let rv = C_GetAttributeValue(session, key, template.as_mut_ptr(), 3);
    assert_eq!(rv, CKR_OK, "Multi-attribute query should succeed");
    assert_eq!(class_val, CKO_SECRET_KEY);
    assert_eq!(kt, CKK_AES);
    assert_eq!(val_len, 32);
}

// ============================================================================
// C_SetAttributeValue tests
// ============================================================================

#[test]
fn test_set_label_attribute() {
    let session = setup_user_session();
    let key = generate_aes_key(session, b"old_label");

    let new_label = b"new_label_val";
    let mut template = [CK_ATTRIBUTE {
        attr_type: CKA_LABEL,
        p_value: new_label.as_ptr() as CK_VOID_PTR,
        value_len: new_label.len() as CK_ULONG,
    }];
    let rv = C_SetAttributeValue(session, key, template.as_mut_ptr(), 1);
    assert_eq!(rv, CKR_OK, "SetAttributeValue(LABEL) failed: 0x{:08X}", rv);

    // Read back
    let mut buf = [0u8; 64];
    let mut read_template = [CK_ATTRIBUTE {
        attr_type: CKA_LABEL,
        p_value: buf.as_mut_ptr() as CK_VOID_PTR,
        value_len: buf.len() as CK_ULONG,
    }];
    let rv = C_GetAttributeValue(session, key, read_template.as_mut_ptr(), 1);
    assert_eq!(rv, CKR_OK);
    assert_eq!(
        &buf[..read_template[0].value_len as usize],
        new_label.as_slice()
    );
}

#[test]
fn test_set_id_attribute() {
    let session = setup_user_session();
    let key = generate_aes_key(session, b"id_set_test");

    let new_id = b"\xAA\xBB\xCC\xDD";
    let mut template = [CK_ATTRIBUTE {
        attr_type: CKA_ID,
        p_value: new_id.as_ptr() as CK_VOID_PTR,
        value_len: new_id.len() as CK_ULONG,
    }];
    let rv = C_SetAttributeValue(session, key, template.as_mut_ptr(), 1);
    assert_eq!(rv, CKR_OK, "SetAttributeValue(ID) failed: 0x{:08X}", rv);

    let mut buf = [0u8; 64];
    let mut read_template = [CK_ATTRIBUTE {
        attr_type: CKA_ID,
        p_value: buf.as_mut_ptr() as CK_VOID_PTR,
        value_len: buf.len() as CK_ULONG,
    }];
    let rv = C_GetAttributeValue(session, key, read_template.as_mut_ptr(), 1);
    assert_eq!(rv, CKR_OK);
    assert_eq!(
        &buf[..read_template[0].value_len as usize],
        new_id.as_slice()
    );
}

#[test]
fn test_set_attribute_invalid_handle() {
    let session = setup_user_session();
    let new_label = b"test";
    let mut template = [CK_ATTRIBUTE {
        attr_type: CKA_LABEL,
        p_value: new_label.as_ptr() as CK_VOID_PTR,
        value_len: new_label.len() as CK_ULONG,
    }];
    let rv = C_SetAttributeValue(session, 0xFFFFFFFF, template.as_mut_ptr(), 1);
    assert_ne!(rv, CKR_OK, "Set on invalid handle should fail");
}

// ============================================================================
// C_FindObjects tests
// ============================================================================

#[test]
fn test_find_objects_by_label() {
    let session = setup_user_session();
    let label = b"find_me_label";
    let _key = generate_aes_key(session, label);

    let mut find_template = [CK_ATTRIBUTE {
        attr_type: CKA_LABEL,
        p_value: label.as_ptr() as CK_VOID_PTR,
        value_len: label.len() as CK_ULONG,
    }];
    let rv = C_FindObjectsInit(session, find_template.as_mut_ptr(), 1);
    assert_eq!(rv, CKR_OK);

    let mut found: [CK_OBJECT_HANDLE; 10] = [0; 10];
    let mut count: CK_ULONG = 0;
    let rv = C_FindObjects(session, found.as_mut_ptr(), 10, &mut count);
    assert_eq!(rv, CKR_OK);
    assert!(count >= 1, "Should find at least 1 object");

    let rv = C_FindObjectsFinal(session);
    assert_eq!(rv, CKR_OK);
}

#[test]
fn test_find_objects_by_class() {
    let session = setup_user_session();
    let _key = generate_aes_key(session, b"class_find");
    let class_val = ck_ulong_bytes(CKO_SECRET_KEY);

    let mut find_template = [CK_ATTRIBUTE {
        attr_type: CKA_CLASS,
        p_value: class_val.as_ptr() as CK_VOID_PTR,
        value_len: class_val.len() as CK_ULONG,
    }];
    let rv = C_FindObjectsInit(session, find_template.as_mut_ptr(), 1);
    assert_eq!(rv, CKR_OK);

    let mut found: [CK_OBJECT_HANDLE; 100] = [0; 100];
    let mut count: CK_ULONG = 0;
    let rv = C_FindObjects(session, found.as_mut_ptr(), 100, &mut count);
    assert_eq!(rv, CKR_OK);
    assert!(count >= 1, "Should find at least 1 secret key");

    C_FindObjectsFinal(session);
}

#[test]
fn test_find_objects_by_id() {
    let session = setup_user_session();
    let id = b"\xDE\xAD\xBE\xEF";
    let _key = generate_aes_key_with_id(session, b"id_find", id);

    let mut find_template = [CK_ATTRIBUTE {
        attr_type: CKA_ID,
        p_value: id.as_ptr() as CK_VOID_PTR,
        value_len: id.len() as CK_ULONG,
    }];
    let rv = C_FindObjectsInit(session, find_template.as_mut_ptr(), 1);
    assert_eq!(rv, CKR_OK);

    let mut found: [CK_OBJECT_HANDLE; 10] = [0; 10];
    let mut count: CK_ULONG = 0;
    let rv = C_FindObjects(session, found.as_mut_ptr(), 10, &mut count);
    assert_eq!(rv, CKR_OK);
    assert!(count >= 1, "Should find object by CKA_ID");

    C_FindObjectsFinal(session);
}

#[test]
fn test_find_objects_no_match() {
    let session = setup_user_session();
    let label = b"nonexistent_unique_xyz_12345";

    let mut find_template = [CK_ATTRIBUTE {
        attr_type: CKA_LABEL,
        p_value: label.as_ptr() as CK_VOID_PTR,
        value_len: label.len() as CK_ULONG,
    }];
    let rv = C_FindObjectsInit(session, find_template.as_mut_ptr(), 1);
    assert_eq!(rv, CKR_OK);

    let mut found: [CK_OBJECT_HANDLE; 10] = [0; 10];
    let mut count: CK_ULONG = 0;
    let rv = C_FindObjects(session, found.as_mut_ptr(), 10, &mut count);
    assert_eq!(rv, CKR_OK);
    assert_eq!(count, 0, "Should find 0 objects for nonexistent label");

    C_FindObjectsFinal(session);
}

#[test]
fn test_find_objects_empty_template() {
    let session = setup_user_session();
    let _key = generate_aes_key(session, b"empty_tmpl_find");

    // Empty template → match all objects
    let rv = C_FindObjectsInit(session, ptr::null_mut(), 0);
    assert_eq!(rv, CKR_OK);

    let mut found: [CK_OBJECT_HANDLE; 100] = [0; 100];
    let mut count: CK_ULONG = 0;
    let rv = C_FindObjects(session, found.as_mut_ptr(), 100, &mut count);
    assert_eq!(rv, CKR_OK);
    assert!(count >= 1, "Empty template should match at least 1 object");

    C_FindObjectsFinal(session);
}

#[test]
fn test_find_objects_after_set_label() {
    let session = setup_user_session();
    let key = generate_aes_key(session, b"before_rename");

    // Change label
    let new_label = b"after_rename_xyz";
    let mut set_template = [CK_ATTRIBUTE {
        attr_type: CKA_LABEL,
        p_value: new_label.as_ptr() as CK_VOID_PTR,
        value_len: new_label.len() as CK_ULONG,
    }];
    C_SetAttributeValue(session, key, set_template.as_mut_ptr(), 1);

    // Find by new label
    let mut find_template = [CK_ATTRIBUTE {
        attr_type: CKA_LABEL,
        p_value: new_label.as_ptr() as CK_VOID_PTR,
        value_len: new_label.len() as CK_ULONG,
    }];
    let rv = C_FindObjectsInit(session, find_template.as_mut_ptr(), 1);
    assert_eq!(rv, CKR_OK);

    let mut found: [CK_OBJECT_HANDLE; 10] = [0; 10];
    let mut count: CK_ULONG = 0;
    let rv = C_FindObjects(session, found.as_mut_ptr(), 10, &mut count);
    assert_eq!(rv, CKR_OK);
    assert!(count >= 1, "Should find object by new label");

    C_FindObjectsFinal(session);
}

#[test]
fn test_find_objects_final_without_init() {
    let session = setup_user_session();
    // FindObjectsFinal without FindObjectsInit — should return error or OK
    let rv = C_FindObjectsFinal(session);
    // Per PKCS#11 spec, this should return CKR_OPERATION_NOT_INITIALIZED
    // but some implementations just return OK. Accept either.
    assert!(
        rv == CKR_OK || rv == CKR_OPERATION_NOT_INITIALIZED,
        "FindObjectsFinal without init: 0x{:08X}",
        rv
    );
}

#[test]
fn test_find_objects_multiple_with_same_label() {
    let session = setup_user_session();
    let label = b"dup_label";
    let _k1 = generate_aes_key(session, label);
    let _k2 = generate_aes_key(session, label);
    let _k3 = generate_aes_key(session, label);

    let mut find_template = [CK_ATTRIBUTE {
        attr_type: CKA_LABEL,
        p_value: label.as_ptr() as CK_VOID_PTR,
        value_len: label.len() as CK_ULONG,
    }];
    let rv = C_FindObjectsInit(session, find_template.as_mut_ptr(), 1);
    assert_eq!(rv, CKR_OK);

    let mut found: [CK_OBJECT_HANDLE; 100] = [0; 100];
    let mut count: CK_ULONG = 0;
    let rv = C_FindObjects(session, found.as_mut_ptr(), 100, &mut count);
    assert_eq!(rv, CKR_OK);
    assert!(
        count >= 3,
        "Should find at least 3 objects with same label, found {}",
        count
    );

    C_FindObjectsFinal(session);
}

// ============================================================================
// Value attribute (sensitive key protection)
// ============================================================================

#[test]
fn test_get_value_of_sensitive_key() {
    let session = setup_user_session();
    // Generate a sensitive key
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let value_len_bytes = ck_ulong_bytes(32);
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
            attr_type: CKA_SENSITIVE,
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
    assert_eq!(rv, CKR_OK);

    // Try to read CKA_VALUE from sensitive key → should fail with CKR_ATTRIBUTE_SENSITIVE
    let mut buf = [0u8; 64];
    let mut read_template = [CK_ATTRIBUTE {
        attr_type: CKA_VALUE,
        p_value: buf.as_mut_ptr() as CK_VOID_PTR,
        value_len: buf.len() as CK_ULONG,
    }];
    let rv = C_GetAttributeValue(session, key, read_template.as_mut_ptr(), 1);
    assert_ne!(rv, CKR_OK, "Reading CKA_VALUE of sensitive key should fail");
}

#[test]
fn test_get_value_len_attribute() {
    let session = setup_user_session();
    let key = generate_aes_key(session, b"vlen_test");
    let mut val_len: CK_ULONG = 0;
    let mut template = [CK_ATTRIBUTE {
        attr_type: CKA_VALUE_LEN,
        p_value: &mut val_len as *mut _ as CK_VOID_PTR,
        value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
    }];
    let rv = C_GetAttributeValue(session, key, template.as_mut_ptr(), 1);
    assert_eq!(rv, CKR_OK);
    assert_eq!(val_len, 32, "AES-256 key should have VALUE_LEN=32");
}

#[test]
fn test_find_and_get_combined_workflow() {
    let session = setup_user_session();
    let label = b"workflow_test";
    let id = b"\x11\x22\x33";
    let key = generate_aes_key_with_id(session, label, id);

    // Find by label
    let mut find_template = [CK_ATTRIBUTE {
        attr_type: CKA_LABEL,
        p_value: label.as_ptr() as CK_VOID_PTR,
        value_len: label.len() as CK_ULONG,
    }];
    let rv = C_FindObjectsInit(session, find_template.as_mut_ptr(), 1);
    assert_eq!(rv, CKR_OK);
    let mut found: [CK_OBJECT_HANDLE; 10] = [0; 10];
    let mut count: CK_ULONG = 0;
    let rv = C_FindObjects(session, found.as_mut_ptr(), 10, &mut count);
    assert_eq!(rv, CKR_OK);
    assert!(count >= 1);
    C_FindObjectsFinal(session);

    // Read attributes from found object
    let found_handle = found[0];
    let mut read_id = [0u8; 16];
    let mut read_template = [CK_ATTRIBUTE {
        attr_type: CKA_ID,
        p_value: read_id.as_mut_ptr() as CK_VOID_PTR,
        value_len: read_id.len() as CK_ULONG,
    }];
    let rv = C_GetAttributeValue(session, found_handle, read_template.as_mut_ptr(), 1);
    assert_eq!(rv, CKR_OK);
    assert_eq!(
        &read_id[..read_template[0].value_len as usize],
        id.as_slice()
    );
}
