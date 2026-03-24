// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
// deny(unsafe_code) instead of forbid: the Windows ACL code in
// encrypted_store.rs requires a single targeted #[allow(unsafe_code)]
// for FFI calls to SetNamedSecurityInfoW. All other code remains
// safe and will trigger a compile error if unsafe is used.
#![deny(unsafe_code)]

pub mod attributes;
pub mod backup;
pub mod encrypted_store;
pub mod key_material;
pub mod lockout_store;
pub mod object;
