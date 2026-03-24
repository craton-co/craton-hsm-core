// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Fuzz target for attribute parsing and object template matching.
//!
//! Exercises ObjectStore::create_object(), read_attribute(), and
//! StoredObject::matches_template() with random attribute types
//! and payloads.

#![no_main]

use libfuzzer_sys::fuzz_target;
use craton_hsm::store::object::StoredObject;
use craton_hsm::store::attributes::{read_attribute, ObjectStore};
use craton_hsm::pkcs11_abi::types::*;
use craton_hsm::pkcs11_abi::constants::*;

fuzz_target!(|data: &[u8]| {
    if data.len() < 12 {
        return;
    }

    let selector = data[0] % 3;
    let payload = &data[1..];

    match selector {
        0 => fuzz_create_with_random_template(payload),
        1 => fuzz_read_random_attributes(payload),
        2 => fuzz_template_matching(payload),
        _ => {}
    }
});

fn fuzz_create_with_random_template(data: &[u8]) {
    if data.len() < 16 {
        return;
    }

    let mut template: Vec<(CK_ATTRIBUTE_TYPE, Vec<u8>)> = Vec::new();
    let mut offset = 0;

    // Always include CKA_CLASS so create_object doesn't fail on missing class
    // FIX #9: Use to_le_bytes for reproducible corpus across platforms (was to_ne_bytes)
    template.push((CKA_CLASS, CKO_SECRET_KEY.to_le_bytes().to_vec()));

    while offset + 12 < data.len() && template.len() < 15 {
        // FIX: Use from_le_bytes for reproducible corpus across platforms
        let attr_type = u64::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
            data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
        ]) as CK_ATTRIBUTE_TYPE;
        offset += 8;

        let value_len = (u32::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        ]) % 256) as usize;
        offset += 4;

        let value_end = (offset + value_len).min(data.len());
        let value = data[offset..value_end].to_vec();
        offset = value_end;

        template.push((attr_type, value));
    }

    let store = ObjectStore::new();
    // This should handle any template gracefully (return error, not panic)
    let _ = store.create_object(&template);
}

fn fuzz_read_random_attributes(data: &[u8]) {
    if data.len() < 8 {
        return;
    }

    let obj = StoredObject::new(1, CKO_SECRET_KEY);

    let mut offset = 0;
    while offset + 8 <= data.len() {
        // FIX: Use from_le_bytes for reproducible corpus across platforms
        let attr_type = u64::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
            data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
        ]) as CK_ATTRIBUTE_TYPE;
        offset += 8;

        // Should never panic
        let _ = read_attribute(&obj, attr_type);
    }
}

fn fuzz_template_matching(data: &[u8]) {
    if data.len() < 16 {
        return;
    }

    let obj = StoredObject::new(1, CKO_SECRET_KEY);

    let mut template: Vec<(CK_ATTRIBUTE_TYPE, Vec<u8>)> = Vec::new();
    let mut offset = 0;

    while offset + 9 < data.len() && template.len() < 10 {
        // FIX: Use from_le_bytes for reproducible corpus across platforms
        let attr_type = u64::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
            data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
        ]) as CK_ATTRIBUTE_TYPE;
        offset += 8;

        let value_len = (data[offset] as usize) % 64;
        offset += 1;

        let value_end = (offset + value_len).min(data.len());
        let value = data[offset..value_end].to_vec();
        offset = value_end;

        template.push((attr_type, value));
    }

    // Should never panic
    let _ = obj.matches_template(&template);
}
