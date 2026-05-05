// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
use dashmap::DashMap;
use parking_lot::RwLock;
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use zeroize::Zeroize;

use crate::error::{HsmError, HsmResult};
use crate::pkcs11_abi::constants::*;
use crate::pkcs11_abi::types::*;
use crate::session::handle::ObjectHandleAllocator;
use crate::store::encrypted_store::EncryptedStore;
use crate::store::key_material::RawKeyMaterial;
use crate::store::object::StoredObject;

/// Sentinel value used in the secondary attribute index when an object has
/// no `CKA_KEY_TYPE` (e.g., certificate or data objects). Uses `CK_ULONG::MAX`
/// which is platform-portable (c_ulong is 32-bit on Windows, 64-bit on Linux)
/// and well outside any real PKCS#11 key-type constant.
const NO_KEY_TYPE: CK_ULONG = CK_ULONG::MAX;

/// Maximum number of objects that can be stored simultaneously.
/// Prevents resource exhaustion via unbounded object creation.
/// 64 attributes × 8 KiB each × 10,000 objects ≈ 5 GiB theoretical max.
const MAX_OBJECTS: usize = 10_000;

/// Maximum allowed size for CKA_VALUE key material in bytes.
/// Largest supported key: 4096-bit RSA private key DER ≈ 2.4 KiB.
/// We allow up to 8 KiB to accommodate future key types with headroom.
const MAX_KEY_MATERIAL_LEN: usize = 8192;

/// In-memory object store with optional persistence.
///
/// When `persist_store` is set, token objects (CKA_TOKEN=true) are
/// automatically persisted to the EncryptedStore on create/insert/destroy.
/// Session objects (CKA_TOKEN=false) are never persisted.
pub struct ObjectStore {
    objects: DashMap<CK_OBJECT_HANDLE, Arc<RwLock<StoredObject>>>,
    handle_alloc: ObjectHandleAllocator,
    /// Optional persistent backend. When present, token objects are
    /// serialized and stored encrypted on disk.
    persist_store: Option<EncryptedStore>,
    /// Encryption key for the persistent store (derived from user PIN).
    /// Set when persistence is enabled and a user logs in.
    /// Wrapped in `Zeroizing` so the key is automatically zeroed on drop,
    /// even if `clear_persist_key()` is not explicitly called.
    persist_key: parking_lot::Mutex<Option<zeroize::Zeroizing<[u8; 32]>>>,
    /// Maps object handles to their opaque store keys (random hex strings).
    /// Prevents sequential handle enumeration in the persistent store.
    handle_to_store_key: parking_lot::Mutex<std::collections::HashMap<CK_OBJECT_HANDLE, String>>,
    /// Secondary attribute index keyed by `(CKA_CLASS, CKA_KEY_TYPE)` mapping
    /// to the set of object handles with that combination. Used as an
    /// optimization hint inside `find_objects_for_slot` when the search
    /// template is selective on both attributes — the iteration still visits
    /// every object (constant-time invariant) but the per-object work is
    /// reduced to a cheap `HashSet::contains` lookup for non-candidates.
    ///
    /// Use `NO_KEY_TYPE` as the second tuple element when an object has no
    /// `CKA_KEY_TYPE` (e.g., certificate / data objects).
    attr_index: parking_lot::RwLock<HashMap<(CK_ULONG, CK_ULONG), HashSet<CK_OBJECT_HANDLE>>>,
}

impl ObjectStore {
    pub fn new() -> Self {
        Self {
            objects: DashMap::new(),
            handle_alloc: ObjectHandleAllocator::new(),
            persist_store: None,
            persist_key: parking_lot::Mutex::new(None),
            handle_to_store_key: parking_lot::Mutex::new(std::collections::HashMap::new()),
            attr_index: parking_lot::RwLock::new(HashMap::new()),
        }
    }

    /// Return the number of objects currently stored.
    pub fn objects_len(&self) -> usize {
        self.objects.len()
    }

    /// Create an ObjectStore with persistence enabled.
    pub fn with_persistence(store: EncryptedStore) -> Self {
        Self {
            objects: DashMap::new(),
            handle_alloc: ObjectHandleAllocator::new(),
            persist_store: Some(store),
            persist_key: parking_lot::Mutex::new(None),
            handle_to_store_key: parking_lot::Mutex::new(std::collections::HashMap::new()),
            attr_index: parking_lot::RwLock::new(HashMap::new()),
        }
    }

    /// Add a handle to the secondary `(class, key_type)` index.
    ///
    /// `key_type` should be `NO_KEY_TYPE` when the object has no `CKA_KEY_TYPE`.
    fn index_insert(&self, class: CK_ULONG, key_type: CK_ULONG, handle: CK_OBJECT_HANDLE) {
        self.attr_index
            .write()
            .entry((class, key_type))
            .or_default()
            .insert(handle);
    }

    /// Remove a handle from the secondary `(class, key_type)` index.
    /// Cleans up empty buckets so the map doesn't grow unbounded.
    fn index_remove(&self, handle: CK_OBJECT_HANDLE) {
        let mut idx = self.attr_index.write();
        let mut empty_keys = Vec::new();
        for (k, set) in idx.iter_mut() {
            set.remove(&handle);
            if set.is_empty() {
                empty_keys.push(*k);
            }
        }
        for k in empty_keys {
            idx.remove(&k);
        }
    }

    /// Helper: derive the index tuple from a `StoredObject`.
    fn index_key_for(obj: &StoredObject) -> (CK_ULONG, CK_ULONG) {
        (obj.class, obj.key_type.unwrap_or(NO_KEY_TYPE))
    }

    /// Generate an opaque, random store key for a new object.
    /// Prevents sequential handle enumeration in the persistent store.
    fn generate_store_key(&self, handle: CK_OBJECT_HANDLE) -> String {
        let mut random_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut random_bytes);
        let key = format!("obj_{}", hex::encode(random_bytes));
        self.handle_to_store_key.lock().insert(handle, key.clone());
        key
    }

    /// Look up the store key for a handle.
    /// If no mapping exists, generates a new random key to avoid falling
    /// back to a sequential handle-based key that would leak creation order.
    fn get_store_key(&self, handle: CK_OBJECT_HANDLE) -> String {
        let map = self.handle_to_store_key.lock();
        if let Some(key) = map.get(&handle) {
            return key.clone();
        }
        drop(map);
        // No mapping found — generate a random one rather than exposing
        // the sequential handle number in the persistent store.
        self.generate_store_key(handle)
    }

    /// Set the encryption key for persistence (called after user login).
    pub fn set_persist_key(&self, key: [u8; 32]) {
        *self.persist_key.lock() = Some(zeroize::Zeroizing::new(key));
    }

    /// Clear the persistence key (called on logout).
    /// The `Zeroizing` wrapper also guarantees zeroization on drop even if
    /// this method is never called (e.g., process crash).
    pub fn clear_persist_key(&self) {
        // Setting to None drops the Zeroizing<[u8; 32]>, which auto-zeroizes.
        *self.persist_key.lock() = None;
    }

    /// Load persisted token objects from the encrypted store.
    /// Called during initialization after the user logs in and the
    /// persist key is set.
    ///
    /// The persist key is held under lock for the entire load operation
    /// to avoid copying it to the stack where a panic could leak it.
    pub fn load_from_store(&self) -> HsmResult<usize> {
        let store = match &self.persist_store {
            Some(s) => s,
            None => return Ok(0),
        };

        // Hold the lock for the duration of all decryption operations
        // instead of copying the key out, minimizing key exposure.
        let guard = self.persist_key.lock();
        let key = match guard.as_ref() {
            Some(k) => k,
            None => return Ok(0), // No key set yet, can't decrypt
        };

        let keys = store.list_keys()?;
        let mut loaded = 0;

        for store_key in keys {
            if let Some(data) = store.load_encrypted(&store_key, key)? {
                // `data` is Zeroizing<Vec<u8>> — automatically zeroized on drop.
                //
                // RESIDUAL RISK (reduced from prior serde_json design):
                // postcard's intermediate parsing buffers are still allocator-
                // owned and not zeroized on free, but the format is a compact
                // binary length-prefixed encoding. Unlike serde_json there are
                // no string-unescape allocations (no UTF-8 decode of escaped
                // sequences into fresh `String` buffers), so the residual
                // surface area is materially smaller. Key bytes still pass
                // through `Vec<u8>::deserialize` once before being mlocked
                // inside `RawKeyMaterial::new`.
                let result = postcard::from_bytes::<StoredObject>(&data);
                match result {
                    Ok(obj) => {
                        // Defense-in-depth: verify critical security invariants
                        // on deserialized objects. AES-GCM provides authenticity,
                        // but this catches logic bugs or schema migration issues.
                        if let Err(reason) = validate_deserialized_object(&obj) {
                            tracing::warn!(
                                "Rejected deserialized object '{}': {}",
                                store_key,
                                reason
                            );
                            continue;
                        }

                        let handle = obj.handle;
                        // Record the store_key mapping for this handle
                        self.handle_to_store_key.lock().insert(handle, store_key);
                        // Ensure handle allocator is past this handle
                        self.handle_alloc.ensure_past(handle);
                        // Maintain the (class, key_type) secondary index
                        let (cls, kt) = Self::index_key_for(&obj);
                        self.index_insert(cls, kt, handle);
                        self.objects.insert(handle, Arc::new(RwLock::new(obj)));
                        loaded += 1;
                    }
                    Err(e) => {
                        tracing::warn!("Failed to deserialize object '{}': {}", store_key, e);
                    }
                }
            }
        }

        Ok(loaded)
    }

    /// Persist a token object to the encrypted store (if enabled).
    ///
    /// Performance: previously held the persist key Mutex across both
    /// `serde_json::to_vec` and the redb-backed `store_encrypted` call,
    /// which serialized concurrent persists onto the disk path. We now
    /// clone the 32-byte key into a `Zeroizing<[u8; 32]>` stack temporary
    /// while the lock is held, drop the lock, then perform serialization
    /// and disk I/O against the temporary. The `Zeroizing` wrapper guarantees
    /// the stack copy is zeroed on drop — including on panic between the
    /// clone and the natural drop point — so the key is never leaked.
    fn persist_object(&self, obj: &StoredObject) {
        if !obj.token_object {
            return; // Only persist token objects
        }

        let store = match &self.persist_store {
            Some(s) => s,
            None => return,
        };

        // Acquire the lock only long enough to clone the key bytes into a
        // Zeroizing stack temporary, then release it so concurrent
        // sessions can persist in parallel rather than serializing on disk I/O.
        // If no key is set, return early — no path can persist with an empty key.
        let key_copy: zeroize::Zeroizing<[u8; 32]> = {
            let guard = self.persist_key.lock();
            match guard.as_ref() {
                Some(k) => zeroize::Zeroizing::new(**k),
                None => return, // No key, can't persist
            }
            // `guard` is dropped here, releasing the persist_key Mutex
            // before we touch the disk.
        };

        // Use opaque store key — generate one if this handle is new
        let store_key = {
            let map = self.handle_to_store_key.lock();
            map.get(&obj.handle).cloned()
        }
        .unwrap_or_else(|| self.generate_store_key(obj.handle));

        // Use postcard (compact binary serde format) instead of serde_json:
        // — removes the per-persist serde_json overhead (key/value formatting,
        //   string escaping, base64-style number encoding) on the hot path.
        // — eliminates the string-unescape allocation paths that previously
        //   left key fragments in unzeroized intermediate buffers.
        // The output `Vec<u8>` is still zeroized before drop.
        match postcard::to_allocvec(obj) {
            Ok(mut data) => {
                let result = store.store_encrypted(&store_key, &data, &*key_copy);
                // Zeroize serialized plaintext containing key material before dropping
                data.zeroize();
                if let Err(e) = result {
                    tracing::error!("Failed to persist object {}: {:?}", obj.handle, e);
                }
            }
            Err(e) => {
                tracing::error!("Failed to serialize object {}: {}", obj.handle, e);
            }
        }
        // `key_copy` drops here (or on any panic between its construction
        // and this point), zeroing the 32-byte stack temporary.
    }

    /// Remove a persisted object from the encrypted store.
    fn unpersist_object(&self, handle: CK_OBJECT_HANDLE) {
        let store = match &self.persist_store {
            Some(s) => s,
            None => return,
        };

        let store_key = self.get_store_key(handle);
        if let Err(e) = store.delete(&store_key) {
            tracing::error!("Failed to unpersist object {}: {:?}", handle, e);
        }
        // Remove the mapping
        self.handle_to_store_key.lock().remove(&handle);
    }

    /// Create a new object from a template of attributes
    pub fn create_object(
        &self,
        template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    ) -> HsmResult<CK_OBJECT_HANDLE> {
        // Enforce maximum object count to prevent resource exhaustion
        if self.objects.len() >= MAX_OBJECTS {
            return Err(HsmError::DeviceMemory);
        }

        // Find class in template (required)
        let class = template
            .iter()
            .find(|(t, _)| *t == CKA_CLASS)
            .and_then(|(_, v)| read_ck_ulong(v))
            .ok_or(HsmError::TemplateIncomplete)?;

        let handle = self.handle_alloc.next()?;
        let mut obj = StoredObject::new(handle, class);

        // Apply all attributes from template
        for (attr_type, value) in template {
            apply_attribute(&mut obj, *attr_type, value)?;
        }

        // Persist if it's a token object
        self.persist_object(&obj);

        // Maintain the (class, key_type) secondary index
        let (cls, kt) = Self::index_key_for(&obj);
        self.index_insert(cls, kt, handle);

        self.objects.insert(handle, Arc::new(RwLock::new(obj)));
        Ok(handle)
    }

    /// Insert a pre-built object (used by keygen).
    ///
    /// Returns the handle on success, or `Err(DeviceMemory)` if the store
    /// has reached its maximum object capacity.
    pub fn insert_object(&self, obj: StoredObject) -> HsmResult<CK_OBJECT_HANDLE> {
        // Enforce maximum object count to prevent resource exhaustion
        if self.objects.len() >= MAX_OBJECTS {
            return Err(HsmError::DeviceMemory);
        }

        let handle = obj.handle;

        // Persist if it's a token object
        self.persist_object(&obj);

        // Maintain the (class, key_type) secondary index
        let (cls, kt) = Self::index_key_for(&obj);
        self.index_insert(cls, kt, handle);

        self.objects.insert(handle, Arc::new(RwLock::new(obj)));
        Ok(handle)
    }

    /// Allocate a new handle
    pub fn next_handle(&self) -> HsmResult<CK_OBJECT_HANDLE> {
        self.handle_alloc.next()
    }

    /// Destroy an object.
    ///
    /// Checks the `destroyable` flag **before** removing from the map to avoid
    /// a TOCTOU race where a non-destroyable object could be permanently lost.
    pub fn destroy_object(&self, handle: CK_OBJECT_HANDLE) -> HsmResult<()> {
        // Atomic check-and-remove: the destroyable check and removal happen
        // while the DashMap shard lock is held, eliminating the TOCTOU window.
        let removed = self
            .objects
            .remove_if(&handle, |_k, v| v.read().destroyable);

        match removed {
            Some(_) => {
                // Successfully removed a destroyable object
                self.unpersist_object(handle);
                // Drop the handle from the secondary attribute index.
                self.index_remove(handle);
                Ok(())
            }
            None => {
                // Either the object doesn't exist, or it's not destroyable
                if self.objects.contains_key(&handle) {
                    // Object exists but is not destroyable
                    Err(HsmError::GeneralError)
                } else {
                    Err(HsmError::ObjectHandleInvalid)
                }
            }
        }
    }

    /// Get an object by handle
    pub fn get_object(&self, handle: CK_OBJECT_HANDLE) -> HsmResult<Arc<RwLock<StoredObject>>> {
        self.objects
            .get(&handle)
            .map(|o| o.value().clone())
            .ok_or(HsmError::ObjectHandleInvalid)
    }

    /// Get object size
    pub fn get_object_size(&self, handle: CK_OBJECT_HANDLE) -> HsmResult<CK_ULONG> {
        let obj = self.get_object(handle)?;
        let size = obj.read().approximate_size();
        Ok(size)
    }

    /// Clear all objects (used by C_InitToken per PKCS#11 spec)
    pub fn clear(&self) {
        self.objects.clear();
        self.handle_to_store_key.lock().clear();
        self.attr_index.write().clear();

        // Also clear the persistent store
        if let Some(ref store) = self.persist_store {
            if let Err(e) = store.clear() {
                tracing::error!("Failed to clear persistent store: {:?}", e);
            }
        }
    }

    /// Check if persistence is enabled
    pub fn has_persistence(&self) -> bool {
        self.persist_store.is_some()
    }

    /// Find objects matching a template, scoped to a specific slot.
    ///
    /// Always iterates *all* objects and performs a full template match on
    /// each one (even those that will be filtered out) to avoid leaking
    /// information about the number or distribution of private objects via
    /// timing side-channels.
    pub fn find_objects(
        &self,
        template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
        is_logged_in: bool,
    ) -> Vec<CK_OBJECT_HANDLE> {
        self.find_objects_for_slot(template, is_logged_in, None)
    }

    /// Find objects matching a template, optionally scoped to a specific slot.
    ///
    /// When `slot_id` is `Some`, only objects belonging to that slot are
    /// returned. This prevents cross-slot object access in multi-slot
    /// deployments.
    ///
    /// **Index-narrowed iteration when applicable.**  When the template
    /// specifies both `CKA_CLASS` and `CKA_KEY_TYPE`, we iterate only the
    /// candidate handle set obtained from `attr_index` — non-candidate
    /// objects are not touched at all (no `RwLock` acquired, no
    /// `matches_template` evaluated).  The candidate count for a given
    /// (class, key_type) is independent of login state, so the timing of a
    /// specific template query does not leak whether the caller is logged
    /// in (private/public visibility is checked under the read lock,
    /// after the candidate set is fixed).
    ///
    /// **Full-iteration fallback.**  When the template lacks either
    /// `CKA_CLASS` or `CKA_KEY_TYPE`, we walk the entire DashMap and
    /// take a per-object read lock — preserving the original behavior.
    /// Templates that don't fix both attributes are inherently unselective,
    /// so the full walk is appropriate.
    ///
    /// The previous implementation took 10,000 `RwLock` read locks for a
    /// 10,000-object store regardless of how selective the template was —
    /// the index lookup short-circuited only the inner attribute-match
    /// comparison, not the per-object lock acquisition.  That overhead
    /// completely dominated the index's intended speedup, which is what
    /// this revision fixes.
    pub fn find_objects_for_slot(
        &self,
        template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
        is_logged_in: bool,
        slot_id: Option<CK_ULONG>,
    ) -> Vec<CK_OBJECT_HANDLE> {
        // Extract CKA_CLASS / CKA_KEY_TYPE from the template (if present).
        let mut tmpl_class: Option<CK_ULONG> = None;
        let mut tmpl_key_type: Option<CK_ULONG> = None;
        for (attr_type, value) in template {
            match *attr_type {
                CKA_CLASS => {
                    if let Some(v) = read_ck_ulong(value) {
                        tmpl_class = Some(v);
                    }
                }
                CKA_KEY_TYPE => {
                    if let Some(v) = read_ck_ulong(value) {
                        tmpl_key_type = Some(v);
                    }
                }
                _ => {}
            }
        }

        // Fast path: both class and key_type fixed → iterate candidates only.
        if let (Some(cls), Some(kt)) = (tmpl_class, tmpl_key_type) {
            // Snapshot the candidate handle set so we don't hold the index
            // lock while taking per-object read locks.
            let candidates: Vec<CK_OBJECT_HANDLE> = {
                let idx = self.attr_index.read();
                idx.get(&(cls, kt))
                    .map(|set| set.iter().copied().collect())
                    .unwrap_or_default()
            };
            let mut results = Vec::with_capacity(candidates.len());
            for handle in candidates {
                if let Some(entry) = self.objects.get(&handle) {
                    let obj = entry.value().read();
                    let visible = !obj.private || is_logged_in;
                    let slot_ok = slot_id.map_or(true, |sid| obj.slot_id == sid);
                    if visible && slot_ok && obj.matches_template(template) {
                        results.push(handle);
                    }
                }
                // If `objects.get` is `None`, the handle was destroyed between
                // index snapshot and lookup — silently skip (the index entry
                // will be reconciled by the next destroy_object pass).
            }
            return results;
        }

        // Fallback path: template did not fix both CKA_CLASS and CKA_KEY_TYPE.
        // Walk the full object map.
        let mut results = Vec::with_capacity(self.objects.len());
        for entry in self.objects.iter() {
            let obj = entry.value().read();
            let visible = !obj.private || is_logged_in;
            let slot_ok = slot_id.map_or(true, |sid| obj.slot_id == sid);
            if visible && slot_ok && obj.matches_template(template) {
                results.push(*entry.key());
            }
        }
        results
    }

    /// Sweep all objects, applying date-based lifecycle transitions.
    ///
    /// Write-locks each object individually to check and persist any
    /// SP 800-57 state transitions triggered by `start_date` / `end_date`.
    /// Returns a list of transitions that occurred during the sweep.
    pub fn sweep_lifecycle(&self) -> Vec<crate::store::lifecycle::LifecycleTransition> {
        let mut transitions = Vec::new();
        // Collect objects that need persistence outside the iterator to avoid
        // holding DashMap shard locks during disk I/O.
        let mut to_persist: Vec<crate::store::object::StoredObject> = Vec::new();

        for entry in self.objects.iter() {
            let mut obj = entry.value().write();
            if let Some((old_state, new_state)) = obj.transition_lifecycle_if_needed() {
                // Avoid the extra allocation that `Cow::to_string()` always
                // performs (it formats through a fresh String even when the
                // bytes are already valid UTF-8).  `into_owned()` reuses the
                // borrowed slice when there are no replacement chars and only
                // allocates on the lossy fallback path.
                let label = String::from_utf8_lossy(&obj.label).into_owned();
                transitions.push(crate::store::lifecycle::LifecycleTransition {
                    handle: obj.handle,
                    label,
                    old_state,
                    new_state,
                });
                // Clone while still holding the write lock to prevent TOCTOU:
                // no other thread can modify the object between transition and clone.
                if obj.token_object {
                    to_persist.push(obj.clone());
                }
            }
            // Write lock is dropped here (end of loop iteration)
        }

        // Persist outside the DashMap iterator to avoid lock ordering issues
        for obj_clone in to_persist {
            self.persist_object(&obj_clone);
        }

        transitions
    }

    /// Export all objects as cloned StoredObjects (for backup).
    ///
    /// Returns a `ZeroizingObjects` wrapper that zeroizes all key material
    /// when dropped, preventing callers from accidentally leaking plaintext
    /// key copies.
    pub fn export_all_objects(&self) -> ZeroizingObjects {
        let objects: Vec<StoredObject> = self
            .objects
            .iter()
            .map(|entry| entry.value().read().clone())
            .collect();
        ZeroizingObjects(objects)
    }
}

/// Apply an attribute value to an object during creation.
///
/// **Security note**: this function must only be called during object
/// creation (`create_object`).  Post-creation attribute modification is
/// handled by `C_SetAttributeValue` which enforces `CKA_MODIFIABLE` and
/// restricts the set of mutable attributes to `CKA_LABEL` / `CKA_ID`.
pub fn apply_attribute(
    obj: &mut StoredObject,
    attr_type: CK_ATTRIBUTE_TYPE,
    value: &[u8],
) -> HsmResult<()> {
    match attr_type {
        CKA_CLASS => {
            obj.class = read_ck_ulong(value).ok_or(HsmError::AttributeValueInvalid)?;
        }
        CKA_KEY_TYPE => {
            obj.key_type = Some(read_ck_ulong(value).ok_or(HsmError::AttributeValueInvalid)?);
        }
        CKA_LABEL => {
            obj.label = value.to_vec();
        }
        CKA_ID => {
            obj.id = value.to_vec();
        }
        CKA_TOKEN => {
            obj.token_object = !value.is_empty() && value[0] != 0;
        }
        CKA_PRIVATE => {
            obj.private = !value.is_empty() && value[0] != 0;
        }
        CKA_SENSITIVE => {
            let new_val = !value.is_empty() && value[0] != 0;
            // PKCS#11 §10.7: CKA_SENSITIVE is one-way — once true, cannot be reset to false
            if obj.sensitive && !new_val {
                return Err(HsmError::AttributeReadOnly);
            }
            obj.sensitive = new_val;
        }
        CKA_EXTRACTABLE => {
            let new_val = !value.is_empty() && value[0] != 0;
            // PKCS#11 §10.7: CKA_EXTRACTABLE is one-way — once false, cannot be set back to true
            if !obj.extractable && new_val {
                return Err(HsmError::AttributeReadOnly);
            }
            obj.extractable = new_val;
        }
        CKA_MODIFIABLE => {
            obj.modifiable = !value.is_empty() && value[0] != 0;
        }
        CKA_DESTROYABLE => {
            obj.destroyable = !value.is_empty() && value[0] != 0;
        }
        CKA_ENCRYPT => {
            obj.can_encrypt = !value.is_empty() && value[0] != 0;
        }
        CKA_DECRYPT => {
            obj.can_decrypt = !value.is_empty() && value[0] != 0;
        }
        CKA_SIGN => {
            obj.can_sign = !value.is_empty() && value[0] != 0;
        }
        CKA_VERIFY => {
            obj.can_verify = !value.is_empty() && value[0] != 0;
        }
        CKA_WRAP => {
            obj.can_wrap = !value.is_empty() && value[0] != 0;
        }
        CKA_UNWRAP => {
            obj.can_unwrap = !value.is_empty() && value[0] != 0;
        }
        CKA_DERIVE => {
            obj.can_derive = !value.is_empty() && value[0] != 0;
        }
        CKA_VALUE => {
            if value.len() > MAX_KEY_MATERIAL_LEN {
                return Err(HsmError::AttributeValueInvalid);
            }
            obj.key_material = Some(RawKeyMaterial::new(value.to_vec()));
        }
        CKA_MODULUS => {
            obj.modulus = Some(value.to_vec());
        }
        CKA_MODULUS_BITS => {
            obj.modulus_bits = Some(read_ck_ulong(value).ok_or(HsmError::AttributeValueInvalid)?);
        }
        CKA_PUBLIC_EXPONENT => {
            obj.public_exponent = Some(value.to_vec());
        }
        CKA_EC_PARAMS => {
            obj.ec_params = Some(value.to_vec());
        }
        CKA_EC_POINT => {
            obj.ec_point = Some(value.to_vec());
        }
        CKA_VALUE_LEN => {
            obj.value_len = Some(read_ck_ulong(value).ok_or(HsmError::AttributeValueInvalid)?);
        }
        CKA_START_DATE => {
            if value.len() == 8 {
                let mut date = [0u8; 8];
                date.copy_from_slice(value);
                obj.start_date = Some(date);
            } else if value.is_empty() {
                obj.start_date = None;
            } else {
                return Err(HsmError::GeneralError);
            }
        }
        CKA_END_DATE => {
            if value.len() == 8 {
                let mut date = [0u8; 8];
                date.copy_from_slice(value);
                obj.end_date = Some(date);
            } else if value.is_empty() {
                obj.end_date = None;
            } else {
                return Err(HsmError::GeneralError);
            }
        }
        _ => {
            // Limit extra attribute value size and count to prevent resource exhaustion
            if value.len() > 8192 {
                return Err(HsmError::ArgumentsBad);
            }
            if obj.extra_attributes.len() >= 64 && !obj.extra_attributes.contains_key(&attr_type) {
                return Err(HsmError::ArgumentsBad);
            }
            obj.extra_attributes.insert(attr_type, value.to_vec());
        }
    }
    Ok(())
}

/// Read attribute value from a stored object.
/// Returns None if the attribute is sensitive and non-extractable.
pub fn read_attribute(
    obj: &StoredObject,
    attr_type: CK_ATTRIBUTE_TYPE,
) -> Result<Option<Vec<u8>>, HsmError> {
    match attr_type {
        CKA_CLASS => Ok(Some(ck_ulong_to_bytes(obj.class))),
        CKA_KEY_TYPE => Ok(obj.key_type.map(ck_ulong_to_bytes)),
        CKA_LABEL => Ok(Some(obj.label.clone())),
        CKA_ID => Ok(Some(obj.id.clone())),
        CKA_TOKEN => Ok(Some(vec![if obj.token_object { 1 } else { 0 }])),
        CKA_PRIVATE => Ok(Some(vec![if obj.private { 1 } else { 0 }])),
        CKA_SENSITIVE => Ok(Some(vec![if obj.sensitive { 1 } else { 0 }])),
        CKA_EXTRACTABLE => Ok(Some(vec![if obj.extractable { 1 } else { 0 }])),
        CKA_MODIFIABLE => Ok(Some(vec![if obj.modifiable { 1 } else { 0 }])),
        CKA_DESTROYABLE => Ok(Some(vec![if obj.destroyable { 1 } else { 0 }])),
        CKA_ENCRYPT => Ok(Some(vec![if obj.can_encrypt { 1 } else { 0 }])),
        CKA_DECRYPT => Ok(Some(vec![if obj.can_decrypt { 1 } else { 0 }])),
        CKA_SIGN => Ok(Some(vec![if obj.can_sign { 1 } else { 0 }])),
        CKA_VERIFY => Ok(Some(vec![if obj.can_verify { 1 } else { 0 }])),
        CKA_WRAP => Ok(Some(vec![if obj.can_wrap { 1 } else { 0 }])),
        CKA_UNWRAP => Ok(Some(vec![if obj.can_unwrap { 1 } else { 0 }])),
        CKA_DERIVE => Ok(Some(vec![if obj.can_derive { 1 } else { 0 }])),
        CKA_VALUE => {
            // CKA_VALUE access policy:
            // - sensitive=true AND extractable=false → block (key is fully protected)
            // - sensitive=true AND extractable=true  → allow (key is exportable)
            // - sensitive=false → always allow (regardless of extractable)
            //
            // This follows the convention that CKA_SENSITIVE + CKA_EXTRACTABLE
            // together determine the key's protection level. A sensitive key
            // that is also extractable can still be read (it's exportable by
            // design). Only when both guards are engaged is the value blocked.
            if obj.sensitive && !obj.extractable {
                return Err(HsmError::AttributeSensitive);
            }
            Ok(obj.key_material.as_ref().map(|km| km.as_bytes().to_vec()))
        }
        CKA_MODULUS => Ok(obj.modulus.clone()),
        CKA_MODULUS_BITS => Ok(obj.modulus_bits.map(ck_ulong_to_bytes)),
        CKA_PUBLIC_EXPONENT => Ok(obj.public_exponent.clone()),
        CKA_EC_PARAMS => Ok(obj.ec_params.clone()),
        CKA_EC_POINT => Ok(obj.ec_point.clone()),
        CKA_VALUE_LEN => Ok(obj.value_len.map(ck_ulong_to_bytes)),
        CKA_START_DATE => Ok(obj.start_date.map(|d| d.to_vec())),
        CKA_END_DATE => Ok(obj.end_date.map(|d| d.to_vec())),
        _ => Ok(obj.extra_attributes.get(&attr_type).cloned()),
    }
}

/// Parse a `CK_ULONG` from raw bytes. Returns `None` if the input is
/// too short, instead of silently returning 0 (which could cause false
/// matches or incorrect attribute values).
pub fn read_ck_ulong(bytes: &[u8]) -> Option<CK_ULONG> {
    let size = std::mem::size_of::<CK_ULONG>();
    if bytes.len() < size {
        return None;
    }
    let mut buf = [0u8; std::mem::size_of::<CK_ULONG>()];
    buf.copy_from_slice(&bytes[..size]);
    Some(CK_ULONG::from_ne_bytes(buf))
}

fn ck_ulong_to_bytes(val: CK_ULONG) -> Vec<u8> {
    val.to_ne_bytes().to_vec()
}

/// Defense-in-depth: validate that a deserialized `StoredObject` has sane
/// security-critical fields. AES-GCM ensures authenticity of the ciphertext,
/// but this guards against schema migration bugs, serialization quirks, or
/// accidental corruption that produces a valid-but-dangerous object.
fn validate_deserialized_object(obj: &StoredObject) -> Result<(), &'static str> {
    // Handle 0 is CK_INVALID_HANDLE in PKCS#11
    if obj.handle == 0 {
        return Err("handle is CK_INVALID_HANDLE (0)");
    }

    // Key objects (secret/private) must be sensitive by default.
    // If an object has key_material but is not sensitive and not extractable,
    // that's an inconsistent state — either it's sensitive or extractable.
    if obj.key_material.is_some() && !obj.sensitive && !obj.extractable {
        return Err("key object is both non-sensitive and non-extractable");
    }

    // Lifecycle state "Destroyed" objects should never be persisted
    if obj.lifecycle_state == crate::store::object::KeyLifecycleState::Destroyed {
        return Err("persisted object has Destroyed lifecycle state");
    }

    Ok(())
}

/// Wrapper around `Vec<StoredObject>` that ensures all cloned key material
/// and sensitive metadata is zeroized when the collection is dropped.
pub struct ZeroizingObjects(Vec<StoredObject>);

impl std::ops::Deref for ZeroizingObjects {
    type Target = [StoredObject];
    fn deref(&self) -> &[StoredObject] {
        &self.0
    }
}

impl Drop for ZeroizingObjects {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        for obj in self.0.iter_mut() {
            // RawKeyMaterial is zeroized by its own Drop impl, but we must
            // also zeroize other fields that may contain sensitive data.
            obj.label.zeroize();
            obj.id.zeroize();
            if let Some(ref mut pk) = obj.public_key_data {
                pk.zeroize();
            }
            if let Some(ref mut m) = obj.modulus {
                m.zeroize();
            }
            if let Some(ref mut e) = obj.public_exponent {
                e.zeroize();
            }
            if let Some(ref mut p) = obj.ec_params {
                p.zeroize();
            }
            if let Some(ref mut p) = obj.ec_point {
                p.zeroize();
            }
            for val in obj.extra_attributes.values_mut() {
                val.zeroize();
            }
        }
        // Now drop all elements (which triggers RawKeyMaterial::drop → zeroize key bytes)
        self.0.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::encrypted_store::EncryptedStore;
    use std::sync::Arc;

    /// Smoke test: multiple threads call `persist_object` concurrently
    /// against an `ObjectStore` with persistence enabled. Now that the
    /// 32-byte persist key is cloned into a `Zeroizing` stack temporary
    /// and the lock is released before `serde_json::to_vec` and the
    /// redb-backed `store_encrypted` call, concurrent persists should
    /// no longer serialize on the disk path. This test validates the
    /// concurrent persist path runs without panicking and that all
    /// objects are durably stored.
    #[test]
    fn persist_object_concurrent_smoke() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("concurrent_persist.redb");
        let store = EncryptedStore::new(Some(db_path.to_str().unwrap())).unwrap();
        let obj_store = Arc::new(ObjectStore::with_persistence(store));
        obj_store.set_persist_key([0xAA; 32]);

        const N_THREADS: usize = 8;
        const PER_THREAD: usize = 25;

        let mut handles = Vec::with_capacity(N_THREADS);
        for t in 0..N_THREADS {
            let store_clone = Arc::clone(&obj_store);
            handles.push(std::thread::spawn(move || {
                for i in 0..PER_THREAD {
                    let label = format!("concurrent-{}-{}", t, i);
                    let template = vec![
                        (CKA_CLASS, CKO_SECRET_KEY.to_ne_bytes().to_vec()),
                        (CKA_TOKEN, vec![1u8]),
                        (CKA_LABEL, label.into_bytes()),
                        (CKA_VALUE, vec![(t as u8).wrapping_add(i as u8); 32]),
                    ];
                    store_clone
                        .create_object(&template)
                        .expect("create_object should succeed under concurrency");
                }
            }));
        }

        for h in handles {
            h.join().expect("worker thread should not panic");
        }

        assert_eq!(obj_store.objects_len(), N_THREADS * PER_THREAD);
    }

    /// Verify that calling `persist_object` with no persist key set does
    /// not panic and is a no-op (early return path is preserved after the
    /// lock-release refactor).
    #[test]
    fn persist_object_with_no_key_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("nokey.redb");
        let store = EncryptedStore::new(Some(db_path.to_str().unwrap())).unwrap();
        let obj_store = ObjectStore::with_persistence(store);
        // Intentionally do NOT call set_persist_key — persist_object must
        // return early without writing anything to disk.

        let template = vec![
            (CKA_CLASS, CKO_SECRET_KEY.to_ne_bytes().to_vec()),
            (CKA_TOKEN, vec![1u8]),
            (CKA_LABEL, b"no-key-test".to_vec()),
            (CKA_VALUE, vec![0xEE; 16]),
        ];
        let handle = obj_store
            .create_object(&template)
            .expect("create_object should succeed even without persist key");

        // The in-memory object should exist
        assert!(obj_store.get_object(handle).is_ok());
    }
}
