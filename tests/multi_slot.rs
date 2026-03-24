// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Tests for multi-slot support (Phase 10E).
//! Run with: cargo test --test multi_slot -- --test-threads=1

use craton_hsm::config::config::HsmConfig;
use craton_hsm::core::HsmCore;

fn config_with_slots(count: usize) -> HsmConfig {
    let mut config = HsmConfig::default();
    config.token.slot_count = count;
    config
}

#[test]
fn test_default_single_slot() {
    let config = HsmConfig::default();
    let hsm = HsmCore::new(&config);
    let ids = hsm.slot_manager().get_slot_ids();
    assert_eq!(ids, vec![0]);
    assert_eq!(hsm.slot_manager().slot_count(), 1);
}

#[test]
fn test_multi_slot_creation() {
    let config = config_with_slots(4);
    let hsm = HsmCore::new(&config);
    let ids = hsm.slot_manager().get_slot_ids();
    assert_eq!(ids, vec![0, 1, 2, 3]);
    assert_eq!(hsm.slot_manager().slot_count(), 4);
}

#[test]
fn test_slot_validation_valid() {
    let config = config_with_slots(3);
    let hsm = HsmCore::new(&config);
    assert!(hsm.slot_manager().validate_slot(0).is_ok());
    assert!(hsm.slot_manager().validate_slot(1).is_ok());
    assert!(hsm.slot_manager().validate_slot(2).is_ok());
}

#[test]
fn test_slot_validation_invalid() {
    let config = config_with_slots(2);
    let hsm = HsmCore::new(&config);
    assert!(hsm.slot_manager().validate_slot(2).is_err());
    assert!(hsm.slot_manager().validate_slot(99).is_err());
}

#[test]
fn test_independent_tokens_per_slot() {
    let config = config_with_slots(3);
    let hsm = HsmCore::new(&config);

    // Initialize only slot 0's token
    let token0 = hsm.slot_manager().get_token(0).unwrap();
    token0
        .init_token(b"so-pin-1234", b"Slot0 Token                     ")
        .unwrap();
    assert!(token0.is_initialized());

    // Slot 1's token should still be uninitialized
    let token1 = hsm.slot_manager().get_token(1).unwrap();
    assert!(!token1.is_initialized());

    // Slot 2's token should also be uninitialized
    let token2 = hsm.slot_manager().get_token(2).unwrap();
    assert!(!token2.is_initialized());
}

#[test]
fn test_get_token_invalid_slot() {
    let config = config_with_slots(1);
    let hsm = HsmCore::new(&config);
    let result = hsm.slot_manager().get_token(5);
    assert!(result.is_err());
}

#[test]
fn test_minimum_one_slot() {
    // Even if slot_count is 0, we should get at least 1 slot
    let mut config = HsmConfig::default();
    config.token.slot_count = 0;
    let hsm = HsmCore::new(&config);
    assert_eq!(hsm.slot_manager().slot_count(), 1);
    assert!(hsm.slot_manager().get_token(0).is_ok());
}

#[test]
fn test_slot_ids_sorted() {
    let config = config_with_slots(5);
    let hsm = HsmCore::new(&config);
    let ids = hsm.slot_manager().get_slot_ids();
    assert_eq!(ids, vec![0, 1, 2, 3, 4]);
    // Verify sorted
    for i in 1..ids.len() {
        assert!(ids[i] > ids[i - 1]);
    }
}
