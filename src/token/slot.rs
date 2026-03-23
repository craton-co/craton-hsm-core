// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
#![forbid(unsafe_code)]

use crate::error::{HsmError, HsmResult};
use crate::pkcs11_abi::types::CK_SLOT_ID;
use crate::token::token::Token;
use std::collections::HashMap;
use std::sync::Arc;

/// SlotManager manages a configurable set of slots.
/// Each slot contains an independent token. Default: 1 slot (slot 0).
///
/// This struct is immutable after construction — the slot map is built once
/// in `new()` / `new_with_config()` and never modified. Individual tokens
/// are accessed via `Arc<Token>` and handle their own internal synchronization.
pub struct SlotManager {
    tokens: HashMap<CK_SLOT_ID, Arc<Token>>,
}

impl SlotManager {
    pub fn new() -> Self {
        let mut tokens = HashMap::new();
        tokens.insert(0, Arc::new(Token::new()));
        Self { tokens }
    }

    pub fn new_with_config(config: &crate::config::config::HsmConfig) -> Self {
        let count = config.token.slot_count.max(1);
        // Clamp to CK_SLOT_ID range to prevent silent truncation / duplicate keys.
        let max_slots = CK_SLOT_ID::MAX as usize;
        let count = count.min(max_slots);
        let mut tokens = HashMap::new();
        for i in 0..count {
            tokens.insert(
                i as CK_SLOT_ID,
                Arc::new(Token::new_with_config(Some(config))),
            );
        }
        Self { tokens }
    }

    pub fn get_slot_ids(&self) -> Vec<CK_SLOT_ID> {
        let mut ids: Vec<_> = self.tokens.keys().copied().collect();
        ids.sort();
        ids
    }

    pub fn get_token(&self, slot_id: CK_SLOT_ID) -> HsmResult<Arc<Token>> {
        self.tokens
            .get(&slot_id)
            .cloned()
            .ok_or(HsmError::SlotIdInvalid)
    }

    pub fn validate_slot(&self, slot_id: CK_SLOT_ID) -> HsmResult<()> {
        if self.tokens.contains_key(&slot_id) {
            Ok(())
        } else {
            Err(HsmError::SlotIdInvalid)
        }
    }

    pub fn slot_count(&self) -> usize {
        self.tokens.len()
    }
}
