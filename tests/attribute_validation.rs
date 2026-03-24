// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
// Attribute validation tests — exercises object store attribute handling,
// sensitivity enforcement, CKA_PRIVATE visibility, template matching,
// and modifiability/destroyability directly on internal structs.

use craton_hsm::error::HsmError;
use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm::pkcs11_abi::types::*;
use craton_hsm::store::attributes::{read_attribute, ObjectStore};
use craton_hsm::store::key_material::RawKeyMaterial;
use craton_hsm::store::object::StoredObject;

fn ck_ulong_bytes(val: CK_ULONG) -> Vec<u8> {
    val.to_ne_bytes().to_vec()
}

// ============================================================================
// Sensitivity enforcement: CKA_VALUE reads
// ============================================================================

#[test]
fn test_sensitive_non_extractable_blocks_value_read() {
    let mut obj = StoredObject::new(1, CKO_SECRET_KEY);
    obj.sensitive = true;
    obj.extractable = false;
    obj.key_material = Some(RawKeyMaterial::new(vec![0xAA; 32]));

    let result = read_attribute(&obj, CKA_VALUE);
    assert!(matches!(result, Err(HsmError::AttributeSensitive)));
}

#[test]
fn test_sensitive_extractable_allows_value_read() {
    let mut obj = StoredObject::new(1, CKO_SECRET_KEY);
    obj.sensitive = true;
    obj.extractable = true;
    obj.key_material = Some(RawKeyMaterial::new(vec![0xBB; 32]));

    let result = read_attribute(&obj, CKA_VALUE).unwrap();
    assert_eq!(result, Some(vec![0xBB; 32]));
}

#[test]
fn test_non_sensitive_allows_value_read() {
    let mut obj = StoredObject::new(1, CKO_SECRET_KEY);
    obj.sensitive = false;
    obj.extractable = true;
    obj.key_material = Some(RawKeyMaterial::new(vec![0xCC; 32]));

    let result = read_attribute(&obj, CKA_VALUE).unwrap();
    assert_eq!(result, Some(vec![0xCC; 32]));
}

#[test]
fn test_non_sensitive_non_extractable_allows_value_read() {
    // Per PKCS#11: CKA_SENSITIVE is the primary guard, EXTRACTABLE gates wrap/export
    let mut obj = StoredObject::new(1, CKO_SECRET_KEY);
    obj.sensitive = false;
    obj.extractable = false;
    obj.key_material = Some(RawKeyMaterial::new(vec![0xDD; 32]));

    let result = read_attribute(&obj, CKA_VALUE).unwrap();
    assert_eq!(result, Some(vec![0xDD; 32]));
}

// ============================================================================
// CKA_PRIVATE enforcement (find_objects visibility)
// ============================================================================

#[test]
fn test_private_object_invisible_without_login() {
    let store = ObjectStore::new();
    let template = vec![
        (CKA_CLASS, ck_ulong_bytes(CKO_SECRET_KEY)),
        (CKA_PRIVATE, vec![CK_TRUE]),
    ];
    let handle = store.create_object(&template).unwrap();

    let found = store.find_objects(&[], false); // not logged in
    assert!(
        !found.contains(&handle),
        "Private object should not be found without login"
    );
}

#[test]
fn test_private_object_visible_with_login() {
    let store = ObjectStore::new();
    let template = vec![
        (CKA_CLASS, ck_ulong_bytes(CKO_SECRET_KEY)),
        (CKA_PRIVATE, vec![CK_TRUE]),
    ];
    let handle = store.create_object(&template).unwrap();

    let found = store.find_objects(&[], true); // logged in
    assert!(
        found.contains(&handle),
        "Private object should be found when logged in"
    );
}

#[test]
fn test_public_object_always_visible() {
    let store = ObjectStore::new();
    let template = vec![
        (CKA_CLASS, ck_ulong_bytes(CKO_SECRET_KEY)),
        (CKA_PRIVATE, vec![CK_FALSE]),
    ];
    let handle = store.create_object(&template).unwrap();

    let found_no_login = store.find_objects(&[], false);
    let found_with_login = store.find_objects(&[], true);
    assert!(found_no_login.contains(&handle));
    assert!(found_with_login.contains(&handle));
}

// ============================================================================
// Template validation (create_object)
// ============================================================================

#[test]
fn test_create_object_without_class_fails() {
    let store = ObjectStore::new();
    let template = vec![(CKA_LABEL, b"no-class".to_vec())];
    let err = store.create_object(&template).unwrap_err();
    assert!(matches!(err, HsmError::TemplateIncomplete));
}

#[test]
fn test_create_object_with_class_succeeds() {
    let store = ObjectStore::new();
    let template = vec![
        (CKA_CLASS, ck_ulong_bytes(CKO_DATA)),
        (CKA_LABEL, b"test-data".to_vec()),
    ];
    let handle = store.create_object(&template).unwrap();
    let obj = store.get_object(handle).unwrap();
    let obj = obj.read();
    assert_eq!(obj.class, CKO_DATA);
    assert_eq!(obj.label, b"test-data");
}

// ============================================================================
// Template matching (find_objects)
// ============================================================================

#[test]
fn test_find_by_label_exact_match() {
    let store = ObjectStore::new();
    let template1 = vec![
        (CKA_CLASS, ck_ulong_bytes(CKO_DATA)),
        (CKA_LABEL, b"alpha".to_vec()),
        (CKA_PRIVATE, vec![CK_FALSE]),
    ];
    let template2 = vec![
        (CKA_CLASS, ck_ulong_bytes(CKO_DATA)),
        (CKA_LABEL, b"beta".to_vec()),
        (CKA_PRIVATE, vec![CK_FALSE]),
    ];
    let h1 = store.create_object(&template1).unwrap();
    let _h2 = store.create_object(&template2).unwrap();

    let search = vec![(CKA_LABEL, b"alpha".to_vec())];
    let found = store.find_objects(&search, true);
    assert!(found.contains(&h1));
    assert_eq!(found.len(), 1);
}

#[test]
fn test_find_by_label_no_match() {
    let store = ObjectStore::new();
    let template = vec![
        (CKA_CLASS, ck_ulong_bytes(CKO_DATA)),
        (CKA_LABEL, b"exists".to_vec()),
        (CKA_PRIVATE, vec![CK_FALSE]),
    ];
    let _h = store.create_object(&template).unwrap();

    let search = vec![(CKA_LABEL, b"nonexistent".to_vec())];
    let found = store.find_objects(&search, true);
    assert!(found.is_empty());
}

#[test]
fn test_find_by_class() {
    let store = ObjectStore::new();
    let t1 = vec![
        (CKA_CLASS, ck_ulong_bytes(CKO_SECRET_KEY)),
        (CKA_PRIVATE, vec![CK_FALSE]),
    ];
    let t2 = vec![
        (CKA_CLASS, ck_ulong_bytes(CKO_DATA)),
        (CKA_PRIVATE, vec![CK_FALSE]),
    ];
    let h1 = store.create_object(&t1).unwrap();
    let _h2 = store.create_object(&t2).unwrap();

    let search = vec![(CKA_CLASS, ck_ulong_bytes(CKO_SECRET_KEY))];
    let found = store.find_objects(&search, true);
    assert!(found.contains(&h1));
    assert_eq!(found.len(), 1);
}

#[test]
fn test_find_by_key_type() {
    let store = ObjectStore::new();
    let t1 = vec![
        (CKA_CLASS, ck_ulong_bytes(CKO_SECRET_KEY)),
        (CKA_KEY_TYPE, ck_ulong_bytes(CKK_AES)),
        (CKA_PRIVATE, vec![CK_FALSE]),
    ];
    let t2 = vec![
        (CKA_CLASS, ck_ulong_bytes(CKO_SECRET_KEY)),
        (CKA_KEY_TYPE, ck_ulong_bytes(0x00000010)),
        (CKA_PRIVATE, vec![CK_FALSE]),
    ];
    let h1 = store.create_object(&t1).unwrap();
    let _h2 = store.create_object(&t2).unwrap();

    let search = vec![(CKA_KEY_TYPE, ck_ulong_bytes(CKK_AES))];
    let found = store.find_objects(&search, true);
    assert!(found.contains(&h1));
    assert_eq!(found.len(), 1);
}

#[test]
fn test_find_empty_template_returns_all_public() {
    let store = ObjectStore::new();
    let t1 = vec![
        (CKA_CLASS, ck_ulong_bytes(CKO_DATA)),
        (CKA_PRIVATE, vec![CK_FALSE]),
    ];
    let t2 = vec![
        (CKA_CLASS, ck_ulong_bytes(CKO_DATA)),
        (CKA_PRIVATE, vec![CK_FALSE]),
    ];
    let h1 = store.create_object(&t1).unwrap();
    let h2 = store.create_object(&t2).unwrap();

    let found = store.find_objects(&[], false);
    assert!(found.contains(&h1));
    assert!(found.contains(&h2));
}

// ============================================================================
// Destroyability
// ============================================================================

#[test]
fn test_destroy_valid_handle() {
    let store = ObjectStore::new();
    let template = vec![(CKA_CLASS, ck_ulong_bytes(CKO_DATA))];
    let handle = store.create_object(&template).unwrap();
    store.destroy_object(handle).unwrap();
    let err = store.get_object(handle).unwrap_err();
    assert!(matches!(err, HsmError::ObjectHandleInvalid));
}

#[test]
fn test_destroy_invalid_handle() {
    let store = ObjectStore::new();
    let err = store.destroy_object(999999).unwrap_err();
    assert!(matches!(err, HsmError::ObjectHandleInvalid));
}

#[test]
fn test_get_object_invalid_handle() {
    let store = ObjectStore::new();
    let err = store.get_object(999999).unwrap_err();
    assert!(matches!(err, HsmError::ObjectHandleInvalid));
}

// ============================================================================
// Object size
// ============================================================================

#[test]
fn test_object_size_increases_with_key_material() {
    let store = ObjectStore::new();
    let t1 = vec![(CKA_CLASS, ck_ulong_bytes(CKO_DATA))];
    let h1 = store.create_object(&t1).unwrap();
    let size_no_key = store.get_object_size(h1).unwrap();

    // Insert an object with key material
    let mut obj = StoredObject::new(store.next_handle().unwrap(), CKO_SECRET_KEY);
    obj.key_material = Some(RawKeyMaterial::new(vec![0xAA; 256]));
    let h2 = store.insert_object(obj).unwrap();
    let size_with_key = store.get_object_size(h2).unwrap();

    assert!(size_with_key > size_no_key);
}

// ============================================================================
// Read various attributes
// ============================================================================

#[test]
fn test_read_boolean_attributes() {
    let mut obj = StoredObject::new(1, CKO_SECRET_KEY);
    obj.can_encrypt = true;
    obj.can_decrypt = false;
    obj.can_sign = true;
    obj.modifiable = false;

    assert_eq!(read_attribute(&obj, CKA_ENCRYPT).unwrap(), Some(vec![1]));
    assert_eq!(read_attribute(&obj, CKA_DECRYPT).unwrap(), Some(vec![0]));
    assert_eq!(read_attribute(&obj, CKA_SIGN).unwrap(), Some(vec![1]));
    assert_eq!(read_attribute(&obj, CKA_MODIFIABLE).unwrap(), Some(vec![0]));
}

#[test]
fn test_read_class_and_key_type() {
    let mut obj = StoredObject::new(1, CKO_SECRET_KEY);
    obj.key_type = Some(CKK_AES);

    let class_bytes = read_attribute(&obj, CKA_CLASS).unwrap().unwrap();
    assert_eq!(
        CK_ULONG::from_ne_bytes(class_bytes.try_into().unwrap()),
        CKO_SECRET_KEY
    );

    let kt_bytes = read_attribute(&obj, CKA_KEY_TYPE).unwrap().unwrap();
    assert_eq!(
        CK_ULONG::from_ne_bytes(kt_bytes.try_into().unwrap()),
        CKK_AES
    );
}

#[test]
fn test_read_label_and_id() {
    let mut obj = StoredObject::new(1, CKO_DATA);
    obj.label = b"my-key".to_vec();
    obj.id = b"\x01\x02\x03".to_vec();

    assert_eq!(
        read_attribute(&obj, CKA_LABEL).unwrap(),
        Some(b"my-key".to_vec())
    );
    assert_eq!(
        read_attribute(&obj, CKA_ID).unwrap(),
        Some(vec![0x01, 0x02, 0x03])
    );
}

#[test]
fn test_read_unknown_attribute_returns_none() {
    let obj = StoredObject::new(1, CKO_DATA);
    // CKA with a vendor-defined type that doesn't exist
    let result = read_attribute(&obj, 0x80000001).unwrap();
    assert_eq!(result, None);
}

// ============================================================================
// Template matching edge cases
// ============================================================================

#[test]
fn test_matches_template_with_boolean_attributes() {
    let mut obj = StoredObject::new(1, CKO_SECRET_KEY);
    obj.can_sign = true;
    obj.can_verify = false;

    let search_sign = vec![(CKA_SIGN, vec![CK_TRUE])];
    assert!(obj.matches_template(&search_sign));

    let search_no_sign = vec![(CKA_SIGN, vec![CK_FALSE])];
    assert!(!obj.matches_template(&search_no_sign));

    let search_verify = vec![(CKA_VERIFY, vec![CK_TRUE])];
    assert!(!obj.matches_template(&search_verify));
}

#[test]
fn test_matches_template_multi_attribute() {
    let mut obj = StoredObject::new(1, CKO_SECRET_KEY);
    obj.key_type = Some(CKK_AES);
    obj.can_encrypt = true;

    let search = vec![
        (CKA_CLASS, ck_ulong_bytes(CKO_SECRET_KEY)),
        (CKA_KEY_TYPE, ck_ulong_bytes(CKK_AES)),
        (CKA_ENCRYPT, vec![CK_TRUE]),
    ];
    assert!(obj.matches_template(&search));

    // Change one attribute to mismatch
    let search_bad = vec![
        (CKA_CLASS, ck_ulong_bytes(CKO_SECRET_KEY)),
        (CKA_KEY_TYPE, ck_ulong_bytes(0x00000010)),
    ];
    assert!(!obj.matches_template(&search_bad));
}
