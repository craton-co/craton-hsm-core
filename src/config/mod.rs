// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
#![forbid(unsafe_code)]

#[allow(clippy::module_inception)]
pub mod config;

// Re-export key types to avoid `config::config::HsmConfig` stutter.
pub use config::{AlgorithmConfig, HsmConfig};
