// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Persistence integration tests for ObjectStore + EncryptedStore.
//!
//! Tests verify that token objects survive across ObjectStore instances
//! (simulating process restart), session objects are NOT persisted,
//! C_InitToken clearing works, and file locking prevents dual access.
//!
//! Run with: cargo test --test persistence -- --test-threads=1

use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm::store::attributes::ObjectStore;
use craton_hsm::store::encrypted_store::{derive_key_from_pin, EncryptedStore};
use craton_hsm::store::key_material::RawKeyMaterial;
use craton_hsm::store::object::StoredObject;

fn make_db_path(dir: &std::path::Path) -> String {
    dir.join("test.redb").to_str().unwrap().to_string()
}

#[test]
fn test_token_objects_survive_restart() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = make_db_path(dir.path());
    let (enc_key, _) = derive_key_from_pin(b"test-pin", None, None);

    // Phase 1: Create objects and persist them
    let handle = {
        let store = EncryptedStore::new(Some(&db_path)).unwrap();
        let obj_store = ObjectStore::with_persistence(store);
        obj_store.set_persist_key(*enc_key);

        // Create a token object (CKA_TOKEN = true)
        let template = vec![
            (CKA_CLASS, CKO_SECRET_KEY.to_ne_bytes().to_vec()),
            (CKA_TOKEN, vec![1u8]), // token object
            (CKA_LABEL, b"persist-test-key".to_vec()),
            (CKA_VALUE, vec![0xAB; 32]), // AES-256 key
            (CKA_ENCRYPT, vec![1]),
        ];
        let handle = obj_store.create_object(&template).unwrap();

        // Verify we can read it back
        let obj = obj_store.get_object(handle).unwrap();
        let obj = obj.read();
        assert_eq!(obj.label, b"persist-test-key");
        assert!(obj.token_object);
        handle
    };
    // obj_store and EncryptedStore dropped here (simulates process exit)

    // Phase 2: Reopen the store and verify objects survived
    {
        let store = EncryptedStore::new(Some(&db_path)).unwrap();
        let obj_store = ObjectStore::with_persistence(store);
        obj_store.set_persist_key(*enc_key);

        let loaded = obj_store.load_from_store().unwrap();
        assert_eq!(loaded, 1, "Should have loaded 1 persisted object");

        // Verify we can find the object
        let obj = obj_store.get_object(handle).unwrap();
        let obj = obj.read();
        assert_eq!(obj.label, b"persist-test-key");
        assert!(obj.token_object);
        assert!(obj.can_encrypt);
        assert_eq!(obj.key_material.as_ref().unwrap().as_bytes(), &[0xAB; 32]);
    }
}

#[test]
fn test_session_objects_not_persisted() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = make_db_path(dir.path());
    let (enc_key, _) = derive_key_from_pin(b"test-pin", None, None);

    // Phase 1: Create a session object (CKA_TOKEN = false)
    {
        let store = EncryptedStore::new(Some(&db_path)).unwrap();
        let obj_store = ObjectStore::with_persistence(store);
        obj_store.set_persist_key(*enc_key);

        let template = vec![
            (CKA_CLASS, CKO_SECRET_KEY.to_ne_bytes().to_vec()),
            (CKA_TOKEN, vec![0u8]), // session object (NOT token)
            (CKA_LABEL, b"session-key".to_vec()),
            (CKA_VALUE, vec![0xCD; 16]),
        ];
        obj_store.create_object(&template).unwrap();
    }

    // Phase 2: Reopen - session object should NOT be there
    {
        let store = EncryptedStore::new(Some(&db_path)).unwrap();
        let obj_store = ObjectStore::with_persistence(store);
        obj_store.set_persist_key(*enc_key);

        let loaded = obj_store.load_from_store().unwrap();
        assert_eq!(loaded, 0, "Session objects should not be persisted");
    }
}

#[test]
fn test_clear_removes_persisted_objects() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = make_db_path(dir.path());
    let (enc_key, _) = derive_key_from_pin(b"test-pin", None, None);

    // Phase 1: Create token objects then clear (simulates C_InitToken)
    {
        let store = EncryptedStore::new(Some(&db_path)).unwrap();
        let obj_store = ObjectStore::with_persistence(store);
        obj_store.set_persist_key(*enc_key);

        for i in 0..3 {
            let template = vec![
                (CKA_CLASS, CKO_SECRET_KEY.to_ne_bytes().to_vec()),
                (CKA_TOKEN, vec![1u8]),
                (CKA_LABEL, format!("key-{}", i).into_bytes()),
                (CKA_VALUE, vec![0xEE; 32]),
            ];
            obj_store.create_object(&template).unwrap();
        }

        // Clear all (C_InitToken)
        obj_store.clear();
    }

    // Phase 2: Reopen - nothing should be there
    {
        let store = EncryptedStore::new(Some(&db_path)).unwrap();
        let obj_store = ObjectStore::with_persistence(store);
        obj_store.set_persist_key(*enc_key);

        let loaded = obj_store.load_from_store().unwrap();
        assert_eq!(loaded, 0, "Clear should have removed all persisted objects");
    }
}

#[test]
fn test_destroy_removes_from_persistent_store() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = make_db_path(dir.path());
    let (enc_key, _) = derive_key_from_pin(b"test-pin", None, None);

    // Phase 1: Create then destroy a token object
    {
        let store = EncryptedStore::new(Some(&db_path)).unwrap();
        let obj_store = ObjectStore::with_persistence(store);
        obj_store.set_persist_key(*enc_key);

        let template = vec![
            (CKA_CLASS, CKO_SECRET_KEY.to_ne_bytes().to_vec()),
            (CKA_TOKEN, vec![1u8]),
            (CKA_LABEL, b"to-destroy".to_vec()),
            (CKA_VALUE, vec![0xFF; 32]),
        ];
        let handle = obj_store.create_object(&template).unwrap();
        obj_store.destroy_object(handle).unwrap();
    }

    // Phase 2: Reopen - destroyed object should be gone
    {
        let store = EncryptedStore::new(Some(&db_path)).unwrap();
        let obj_store = ObjectStore::with_persistence(store);
        obj_store.set_persist_key(*enc_key);

        let loaded = obj_store.load_from_store().unwrap();
        assert_eq!(loaded, 0, "Destroyed objects should not persist");
    }
}

#[test]
fn test_file_lock_prevents_dual_open() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = make_db_path(dir.path());

    // Open store 1 (acquires lock)
    let _store1 = EncryptedStore::new(Some(&db_path)).unwrap();

    // Attempting to open store 2 should fail with lock contention
    let result = EncryptedStore::new(Some(&db_path));
    assert!(
        result.is_err(),
        "Second process opening same database should fail due to file lock"
    );
}

#[test]
fn test_wrong_pin_cannot_load_objects() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = make_db_path(dir.path());
    let (enc_key1, _) = derive_key_from_pin(b"correct-pin", None, None);
    let (enc_key2, _) = derive_key_from_pin(b"wrong-pin", None, None);

    // Phase 1: Create with correct PIN
    {
        let store = EncryptedStore::new(Some(&db_path)).unwrap();
        let obj_store = ObjectStore::with_persistence(store);
        obj_store.set_persist_key(*enc_key1);

        let template = vec![
            (CKA_CLASS, CKO_SECRET_KEY.to_ne_bytes().to_vec()),
            (CKA_TOKEN, vec![1u8]),
            (CKA_LABEL, b"secret-key".to_vec()),
            (CKA_VALUE, vec![0x42; 32]),
        ];
        obj_store.create_object(&template).unwrap();
    }

    // Phase 2: Try to load with wrong PIN
    {
        let store = EncryptedStore::new(Some(&db_path)).unwrap();
        let obj_store = ObjectStore::with_persistence(store);
        obj_store.set_persist_key(*enc_key2);

        // load_from_store should fail or return 0 (decrypt fails)
        let result = obj_store.load_from_store();
        // The decryption with wrong key should either error or skip the object
        match result {
            Ok(count) => assert_eq!(count, 0, "Wrong PIN should not load any objects"),
            Err(_) => {} // Also acceptable - decrypt failure
        }
    }
}

#[test]
fn test_insert_object_persists() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = make_db_path(dir.path());
    let (enc_key, _) = derive_key_from_pin(b"test-pin", None, None);

    let handle;
    // Phase 1: Insert a pre-built object (keygen path)
    {
        let store = EncryptedStore::new(Some(&db_path)).unwrap();
        let obj_store = ObjectStore::with_persistence(store);
        obj_store.set_persist_key(*enc_key);

        let h = obj_store.next_handle().unwrap();
        let mut obj = StoredObject::new(h, CKO_SECRET_KEY);
        obj.token_object = true;
        obj.label = b"keygen-key".to_vec();
        obj.key_material = Some(RawKeyMaterial::new(vec![0x99; 32]));
        obj.can_sign = true;

        handle = obj_store.insert_object(obj).unwrap();
    }

    // Phase 2: Verify it survived
    {
        let store = EncryptedStore::new(Some(&db_path)).unwrap();
        let obj_store = ObjectStore::with_persistence(store);
        obj_store.set_persist_key(*enc_key);

        let loaded = obj_store.load_from_store().unwrap();
        assert_eq!(loaded, 1);

        let obj = obj_store.get_object(handle).unwrap();
        let obj = obj.read();
        assert_eq!(obj.label, b"keygen-key");
        assert!(obj.can_sign);
    }
}

#[test]
fn test_no_persistence_by_default() {
    // Default ObjectStore (no persistence) should work as before
    let obj_store = ObjectStore::new();
    assert!(!obj_store.has_persistence());

    let template = vec![
        (CKA_CLASS, CKO_SECRET_KEY.to_ne_bytes().to_vec()),
        (CKA_TOKEN, vec![1u8]),
        (CKA_LABEL, b"mem-only".to_vec()),
        (CKA_VALUE, vec![0x11; 16]),
    ];
    let handle = obj_store.create_object(&template).unwrap();
    let obj = obj_store.get_object(handle).unwrap();
    assert_eq!(obj.read().label, b"mem-only");
}

#[test]
fn test_multiple_objects_persist() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = make_db_path(dir.path());
    let (enc_key, _) = derive_key_from_pin(b"test-pin", None, None);

    // Phase 1: Create multiple token objects
    {
        let store = EncryptedStore::new(Some(&db_path)).unwrap();
        let obj_store = ObjectStore::with_persistence(store);
        obj_store.set_persist_key(*enc_key);

        for i in 0u8..5 {
            let template = vec![
                (CKA_CLASS, CKO_SECRET_KEY.to_ne_bytes().to_vec()),
                (CKA_TOKEN, vec![1u8]),
                (CKA_LABEL, format!("key-{}", i).into_bytes()),
                (CKA_VALUE, vec![i; 32]),
            ];
            obj_store.create_object(&template).unwrap();
        }
    }

    // Phase 2: All 5 should survive
    {
        let store = EncryptedStore::new(Some(&db_path)).unwrap();
        let obj_store = ObjectStore::with_persistence(store);
        obj_store.set_persist_key(*enc_key);

        let loaded = obj_store.load_from_store().unwrap();
        assert_eq!(loaded, 5, "All 5 token objects should persist");
    }
}
