// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Craton HSM — a PKCS#11 v3.0-compliant Software HSM in pure Rust.
//!
//! This crate provides a complete software HSM implementation with classical
//! and post-quantum cryptography, FIPS 140-3 readiness, and a C ABI compatible
//! with any PKCS#11 consumer.

#![warn(missing_docs)]

/// Tamper-evident audit logging with chained SHA-256.
pub mod audit;
/// Configuration — TOML-based `HsmConfig` with algorithm policy.
pub mod config;
/// Core HSM state — the central `HsmCore` struct shared by all entry points.
pub mod core;
/// Cryptographic operations — keygen, sign, encrypt, digest, PQC, DRBG, self-tests, backends.
pub mod crypto;
/// Error types — `HsmError` enum with `CK_RV` mapping.
pub mod error;
/// PKCS#11 C ABI layer — types, constants, and 70+ `#[no_mangle]` function exports.
///
/// This module uses PKCS#11 naming conventions (e.g., `CK_RV`, `CKR_OK`, `C_Initialize`)
/// which require `non_camel_case_types`, `non_snake_case`, and `non_upper_case_globals`.
#[allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]
pub mod pkcs11_abi;
/// Platform-specific file ACL helpers (Windows DACL restriction).
#[cfg(windows)]
pub(crate) mod platform_acl;
/// Session management — `SessionManager`, session state machine, handle allocation.
pub mod session;
/// Object storage — in-memory `ObjectStore`, encrypted persistence, key material, backups.
pub mod store;
/// Token and slot management — PIN hashing, login state, multi-slot support.
pub mod token;
