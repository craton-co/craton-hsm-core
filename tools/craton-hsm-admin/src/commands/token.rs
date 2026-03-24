// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
use crate::output;
use craton_hsm::config::config::HsmConfig;
use craton_hsm::core::HsmCore;
use zeroize::Zeroizing;

type CliResult = Result<(), Box<dyn std::error::Error>>;

/// Initialize a new token with the given label.
pub fn init(config_path: &str, label: &str) -> CliResult {
    let config = load_config_strict(config_path)?;
    let hsm = HsmCore::new(&config);
    let token = hsm
        .slot_manager()
        .get_token(0)
        .map_err(|_| "Failed to access token.")?;

    // Prompt for SO PIN (zeroized on drop)
    let so_pin = Zeroizing::new(rpassword::prompt_password("Enter new SO PIN: ")?);
    let so_pin_confirm = Zeroizing::new(rpassword::prompt_password("Confirm SO PIN: ")?);
    if *so_pin != *so_pin_confirm {
        return Err("SO PINs do not match.".into());
    }
    if so_pin.len() < config.security.pin_min_length
        || so_pin.len() > config.security.pin_max_length
    {
        return Err("SO PIN does not meet length requirements.".into());
    }

    if let Err(reason) = super::pin::validate_pin_complexity(&so_pin) {
        return Err(reason.into());
    }

    // Pad or truncate label to 32 bytes (PKCS#11 spec)
    let mut label_bytes = [b' '; 32];
    let copy_len = label.len().min(32);
    label_bytes[..copy_len].copy_from_slice(&label.as_bytes()[..copy_len]);

    token
        .init_token(so_pin.as_bytes(), &label_bytes)
        .map_err(|_| "Token initialization failed.")?;

    println!("Token initialized successfully.");
    println!("  Label: {}", label);
    Ok(())
}

/// Display token information.
pub fn info(config_path: &str, json: bool) -> CliResult {
    let config = load_config(config_path)?;
    let hsm = HsmCore::new(&config);
    let token = hsm
        .slot_manager()
        .get_token(0)
        .map_err(|_| "Failed to access token.")?;

    let initialized = token.is_initialized();
    let user_pin_init = token.is_user_pin_initialized();
    let login_state = format!("{:?}", token.login_state());
    let flags = token.flags();

    if json {
        let value = serde_json::json!({
            "slot_id": 0,
            "initialized": initialized,
            "user_pin_initialized": user_pin_init,
            "login_state": login_state,
            "session_count": token.session_count(),
            "rw_session_count": token.rw_session_count(),
            "max_sessions": token.max_sessions(),
            "max_rw_sessions": token.max_rw_sessions(),
            "pin_min_len": token.pin_min_len(),
            "pin_max_len": token.pin_max_len(),
            "flags": format!("0x{:08x}", flags),
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        println!("Token Information");
        println!("=================");
        output::print_table(&[
            ("Slot ID:", "0".to_string()),
            ("Initialized:", initialized.to_string()),
            ("User PIN Init:", user_pin_init.to_string()),
            ("Login State:", login_state),
            (
                "Sessions:",
                format!("{}/{}", token.session_count(), token.max_sessions()),
            ),
            (
                "RW Sessions:",
                format!("{}/{}", token.rw_session_count(), token.max_rw_sessions()),
            ),
            (
                "PIN Length:",
                format!("{}-{}", token.pin_min_len(), token.pin_max_len()),
            ),
            ("Flags:", format!("0x{:08x}", flags)),
        ]);
    }

    Ok(())
}

/// Show overall HSM status.
pub fn status(config_path: &str, json: bool) -> CliResult {
    let config = load_config(config_path)?;
    let hsm = HsmCore::new(&config);
    let token = hsm
        .slot_manager()
        .get_token(0)
        .map_err(|_| "Failed to access token.")?;

    let obj_count = hsm.object_store().find_objects(&[], true).len();
    let audit_count = hsm.audit_log().entry_count();

    if json {
        let value = serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "token_initialized": token.is_initialized(),
            "object_count": obj_count,
            "audit_entries": audit_count,
            "config": {
                "max_sessions": config.token.max_sessions,
                "pqc_enabled": config.algorithms.enable_pqc,
            }
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        println!("Craton HSM Status");
        println!("==============");
        output::print_table(&[
            ("Version:", env!("CARGO_PKG_VERSION").to_string()),
            ("Token Init:", token.is_initialized().to_string()),
            ("Objects:", obj_count.to_string()),
            ("Audit Entries:", audit_count.to_string()),
            ("Max Sessions:", config.token.max_sessions.to_string()),
            ("PQC Enabled:", config.algorithms.enable_pqc.to_string()),
        ]);
    }

    Ok(())
}

fn load_config(path: &str) -> Result<HsmConfig, Box<dyn std::error::Error>> {
    let config = HsmConfig::load_from_path(path)?;
    config
        .validate()
        .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?;
    Ok(config)
}

/// Strict config loading for mutating operations — fails if config is missing.
fn load_config_strict(path: &str) -> Result<HsmConfig, Box<dyn std::error::Error>> {
    let config = HsmConfig::load_from_path(path)?;
    config
        .validate()
        .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?;
    Ok(config)
}
