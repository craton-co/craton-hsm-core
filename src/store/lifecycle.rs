// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company

//! Key lifecycle automation per SP 800-57 Part 1.
//!
//! Provides [`KeyLifecycleManager`] which sweeps the object store and
//! persists any date-triggered state transitions (e.g., PreActivation → Active
//! when `start_date` is reached, or Active → Deactivated when `end_date`
//! passes).

use crate::pkcs11_abi::types::CK_OBJECT_HANDLE;
use crate::store::attributes::ObjectStore;
use crate::store::object::KeyLifecycleState;

/// Record of a single lifecycle state transition detected during a sweep.
#[derive(Debug, Clone)]
pub struct LifecycleTransition {
    /// PKCS#11 object handle
    pub handle: CK_OBJECT_HANDLE,
    /// Human-readable label (CKA_LABEL) of the object
    pub label: String,
    /// State before the transition
    pub old_state: KeyLifecycleState,
    /// State after the transition
    pub new_state: KeyLifecycleState,
}

impl std::fmt::Display for LifecycleTransition {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "handle={} label={:?}: {} -> {}",
            self.handle, self.label, self.old_state, self.new_state
        )
    }
}

/// Manages automated key lifecycle transitions for the object store.
///
/// Designed to be called periodically (e.g., on every `C_FindObjects`,
/// on token initialization, or from a background timer) to detect keys
/// whose dates have crossed activation/deactivation boundaries and
/// persist the resulting state changes.
pub struct KeyLifecycleManager;

impl KeyLifecycleManager {
    /// Sweep all objects in the store, applying date-based lifecycle
    /// transitions and returning a list of any transitions that occurred.
    ///
    /// Each object is individually write-locked, so this method does not
    /// block the entire store. Token objects whose state changed are
    /// automatically re-persisted to the encrypted store.
    pub fn sweep_objects(object_store: &ObjectStore) -> Vec<LifecycleTransition> {
        let transitions = object_store.sweep_lifecycle();

        for t in &transitions {
            tracing::info!(
                handle = t.handle,
                label = %t.label,
                old_state = %t.old_state,
                new_state = %t.new_state,
                "SP 800-57 lifecycle transition"
            );
        }

        transitions
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::object::StoredObject;

    /// Helper: build a date string N days from now (positive = future, negative = past).
    fn date_offset_days(days: i64) -> [u8; 8] {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let target = (now as i64 + days * 86400) as u64;
        epoch_to_ck_date(target)
    }

    fn epoch_to_ck_date(epoch: u64) -> [u8; 8] {
        let total_days = epoch / 86400;
        let mut y = 1970u64;
        let mut remaining = total_days;
        loop {
            let days_in_year = if is_leap(y) { 366 } else { 365 };
            if remaining < days_in_year {
                break;
            }
            remaining -= days_in_year;
            y += 1;
        }
        let month_days: [u64; 12] = [
            31,
            if is_leap(y) { 29 } else { 28 },
            31,
            30,
            31,
            30,
            31,
            31,
            30,
            31,
            30,
            31,
        ];
        let mut m = 1u64;
        for &md in &month_days {
            if remaining < md {
                break;
            }
            remaining -= md;
            m += 1;
        }
        let d = remaining + 1;
        let s = format!("{:04}{:02}{:02}", y, m, d);
        let mut buf = [0u8; 8];
        buf.copy_from_slice(s.as_bytes());
        buf
    }

    fn is_leap(y: u64) -> bool {
        (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
    }

    fn make_object(
        handle: CK_OBJECT_HANDLE,
        label: &str,
        state: KeyLifecycleState,
    ) -> StoredObject {
        let mut obj = StoredObject::new(handle, 0);
        obj.label = label.as_bytes().to_vec();
        obj.lifecycle_state = state;
        obj
    }

    #[test]
    fn sweep_mixed_objects() {
        let store = ObjectStore::new();

        // Object 1: Active with expired end_date → should transition to Deactivated
        let mut obj1 = make_object(1, "expired-key", KeyLifecycleState::Active);
        obj1.end_date = Some(date_offset_days(-5));
        store.insert_object(obj1).unwrap();

        // Object 2: Active with future start_date → effective is PreActivation
        // but stored state is Active, so effective_lifecycle_state returns PreActivation
        let mut obj2 = make_object(2, "future-key", KeyLifecycleState::Active);
        obj2.start_date = Some(date_offset_days(30));
        store.insert_object(obj2).unwrap();

        // Object 3: Already Compromised — should NOT change
        let mut obj3 = make_object(3, "compromised-key", KeyLifecycleState::Compromised);
        obj3.start_date = Some(date_offset_days(-30));
        obj3.end_date = Some(date_offset_days(30));
        store.insert_object(obj3).unwrap();

        // Object 4: Active with no dates — no change
        let obj4 = make_object(4, "normal-key", KeyLifecycleState::Active);
        store.insert_object(obj4).unwrap();

        let transitions = KeyLifecycleManager::sweep_objects(&store);

        // Should have exactly 2 transitions: obj1 and obj2
        assert_eq!(transitions.len(), 2);

        // Verify the transitions (order is not guaranteed with DashMap)
        let t1 = transitions
            .iter()
            .find(|t| t.handle == 1)
            .expect("transition for handle 1");
        assert_eq!(t1.old_state, KeyLifecycleState::Active);
        assert_eq!(t1.new_state, KeyLifecycleState::Deactivated);
        assert_eq!(t1.label, "expired-key");

        let t2 = transitions
            .iter()
            .find(|t| t.handle == 2)
            .expect("transition for handle 2");
        assert_eq!(t2.old_state, KeyLifecycleState::Active);
        assert_eq!(t2.new_state, KeyLifecycleState::PreActivation);
        assert_eq!(t2.label, "future-key");

        // Verify no transition for handles 3 and 4
        assert!(transitions.iter().all(|t| t.handle != 3));
        assert!(transitions.iter().all(|t| t.handle != 4));
    }

    #[test]
    fn sweep_empty_store() {
        let store = ObjectStore::new();
        let transitions = KeyLifecycleManager::sweep_objects(&store);
        assert!(transitions.is_empty());
    }

    #[test]
    fn sweep_no_transitions_needed() {
        let store = ObjectStore::new();

        // All objects already in correct state
        let obj = make_object(1, "active-key", KeyLifecycleState::Active);
        store.insert_object(obj).unwrap();

        let obj2 = make_object(2, "compromised", KeyLifecycleState::Compromised);
        store.insert_object(obj2).unwrap();

        let transitions = KeyLifecycleManager::sweep_objects(&store);
        assert!(transitions.is_empty());
    }

    #[test]
    fn sweep_persists_state_change() {
        let store = ObjectStore::new();

        let mut obj = make_object(1, "expiring", KeyLifecycleState::Active);
        obj.end_date = Some(date_offset_days(-1));
        store.insert_object(obj).unwrap();

        let _transitions = KeyLifecycleManager::sweep_objects(&store);

        // Verify the stored state was actually updated
        let arc = store.get_object(1).unwrap();
        let obj = arc.read();
        assert_eq!(obj.lifecycle_state, KeyLifecycleState::Deactivated);
    }

    #[test]
    fn lifecycle_transition_display() {
        let t = LifecycleTransition {
            handle: 42,
            label: "my-key".to_string(),
            old_state: KeyLifecycleState::Active,
            new_state: KeyLifecycleState::Deactivated,
        };
        let s = format!("{}", t);
        assert!(s.contains("42"));
        assert!(s.contains("my-key"));
        assert!(s.contains("Active"));
        assert!(s.contains("Deactivated"));
    }
}
