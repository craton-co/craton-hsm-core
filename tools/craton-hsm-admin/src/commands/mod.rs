// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
pub mod audit;
pub mod backup;
pub mod key;
pub mod pin;
pub mod token;

use craton_hsm::config::config::HsmConfig;

/// Load and validate an HSM config from disk.
///
/// Errors if the file is missing, malformed, or fails validation.
pub fn load_config(path: &str) -> Result<HsmConfig, Box<dyn std::error::Error>> {
    let config = HsmConfig::load_from_path(path)?;
    config
        .validate()
        .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?;
    Ok(config)
}
