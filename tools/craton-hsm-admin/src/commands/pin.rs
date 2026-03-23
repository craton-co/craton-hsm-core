// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
use craton_hsm::config::config::HsmConfig;
use craton_hsm::core::HsmCore;
use craton_hsm::pkcs11_abi::constants::*;
use zeroize::Zeroizing;

type CliResult = Result<(), Box<dyn std::error::Error>>;

/// Validate PIN complexity beyond just length.
/// Rejects trivially weak PINs that would be vulnerable to brute-force.
pub fn validate_pin_complexity(pin: &str) -> Result<(), &'static str> {
    // Reject all-identical characters (e.g., "000000", "aaaaaa")
    if pin.len() > 1 {
        let first = pin.as_bytes()[0];
        if pin.bytes().all(|b| b == first) {
            return Err("PIN must not consist of a single repeated character.");
        }
    }

    // Reject ascending/descending sequential patterns (e.g., "123456", "abcdef", "654321")
    if pin.len() >= 4 {
        let bytes = pin.as_bytes();
        let all_ascending = bytes.windows(2).all(|w| w[1] == w[0].wrapping_add(1));
        let all_descending = bytes.windows(2).all(|w| w[0] == w[1].wrapping_add(1));
        if all_ascending || all_descending {
            return Err("PIN must not be a sequential pattern (e.g., 123456).");
        }
    }

    // Require at least 2 distinct characters
    let mut seen = [false; 256];
    let mut distinct = 0usize;
    for &b in pin.as_bytes() {
        if !seen[b as usize] {
            seen[b as usize] = true;
            distinct += 1;
        }
    }
    if distinct < 2 {
        return Err("PIN must contain at least 2 distinct characters.");
    }

    Ok(())
}

/// Change user or SO PIN.
pub fn change(config_path: &str, user_type: &str) -> CliResult {
    let config = load_config(config_path)?;
    let hsm = HsmCore::new(&config);
    let token = hsm
        .slot_manager()
        .get_token(0)
        .map_err(|_| "Failed to access token.")?;

    if !token.is_initialized() {
        return Err("Token is not initialized. Run 'token init' first.".into());
    }

    let ck_user = match user_type.to_uppercase().as_str() {
        "USER" => CKU_USER,
        "SO" => CKU_SO,
        other => return Err(format!("Invalid user type: '{}'. Use USER or SO", other).into()),
    };

    // Prompt for current PIN with retry and backoff (zeroized on drop)
    let old_pin = {
        const MAX_ATTEMPTS: u32 = 3;
        let mut authenticated_pin = None;
        for attempt in 1..=MAX_ATTEMPTS {
            let pin = Zeroizing::new(rpassword::prompt_password(&format!(
                "Enter current {} PIN: ",
                user_type.to_uppercase()
            ))?);
            match token.login(ck_user, pin.as_bytes()) {
                Ok(_) => {
                    authenticated_pin = Some(pin);
                    break;
                }
                Err(_) => {
                    let remaining = MAX_ATTEMPTS - attempt;
                    if remaining == 0 {
                        std::thread::sleep(std::time::Duration::from_secs(2));
                        return Err("Login failed. Maximum attempts reached. \
                            Note: too many failed attempts may lock the PIN."
                            .into());
                    }
                    let delay = std::time::Duration::from_secs(attempt as u64);
                    eprintln!(
                        "Login failed. {} attempt(s) remaining. Retrying in {}s...",
                        remaining,
                        delay.as_secs()
                    );
                    std::thread::sleep(delay);
                }
            }
        }
        authenticated_pin.ok_or("Login failed.")?
    };

    // Prompt for new PIN (zeroized on drop)
    let new_pin = Zeroizing::new(rpassword::prompt_password(&format!(
        "Enter new {} PIN: ",
        user_type.to_uppercase()
    ))?);
    let new_pin_confirm = Zeroizing::new(rpassword::prompt_password("Confirm new PIN: ")?);

    if *new_pin != *new_pin_confirm {
        token.logout().ok();
        return Err("PINs do not match.".into());
    }

    if new_pin.len() < config.security.pin_min_length
        || new_pin.len() > config.security.pin_max_length
    {
        token.logout().ok();
        return Err("PIN does not meet length requirements.".into());
    }

    if let Err(reason) = validate_pin_complexity(&new_pin) {
        token.logout().ok();
        return Err(reason.into());
    }

    token
        .set_pin(old_pin.as_bytes(), new_pin.as_bytes())
        .map_err(|_| {
            token.logout().ok();
            "PIN change failed."
        })?;

    token.logout().ok();
    println!("{} PIN changed successfully.", user_type.to_uppercase());
    Ok(())
}

/// Reset user PIN (requires SO authentication).
pub fn reset(config_path: &str) -> CliResult {
    let config = load_config(config_path)?;
    let hsm = HsmCore::new(&config);
    let token = hsm
        .slot_manager()
        .get_token(0)
        .map_err(|_| "Failed to access token.")?;

    if !token.is_initialized() {
        return Err("Token is not initialized. Run 'token init' first.".into());
    }

    // SO must authenticate with retry and backoff (zeroized on drop)
    {
        const MAX_ATTEMPTS: u32 = 3;
        let mut authenticated = false;
        for attempt in 1..=MAX_ATTEMPTS {
            let so_pin = Zeroizing::new(rpassword::prompt_password("Enter SO PIN: ")?);
            match token.login(CKU_SO, so_pin.as_bytes()) {
                Ok(_) => {
                    authenticated = true;
                    break;
                }
                Err(_) => {
                    let remaining = MAX_ATTEMPTS - attempt;
                    if remaining == 0 {
                        std::thread::sleep(std::time::Duration::from_secs(2));
                        return Err("SO login failed. Maximum attempts reached. \
                            Note: too many failed attempts may lock the PIN."
                            .into());
                    }
                    let delay = std::time::Duration::from_secs(attempt as u64);
                    eprintln!(
                        "SO login failed. {} attempt(s) remaining. Retrying in {}s...",
                        remaining,
                        delay.as_secs()
                    );
                    std::thread::sleep(delay);
                }
            }
        }
        if !authenticated {
            return Err("SO login failed.".into());
        }
    }

    // New user PIN (zeroized on drop)
    let new_pin = Zeroizing::new(rpassword::prompt_password("Enter new User PIN: ")?);
    let new_pin_confirm = Zeroizing::new(rpassword::prompt_password("Confirm new User PIN: ")?);

    if *new_pin != *new_pin_confirm {
        token.logout().ok();
        return Err("PINs do not match.".into());
    }

    if new_pin.len() < config.security.pin_min_length
        || new_pin.len() > config.security.pin_max_length
    {
        token.logout().ok();
        return Err("PIN does not meet length requirements.".into());
    }

    if let Err(reason) = validate_pin_complexity(&new_pin) {
        token.logout().ok();
        return Err(reason.into());
    }

    // SO initializes user PIN (reset)
    token.init_pin(new_pin.as_bytes()).map_err(|_| {
        token.logout().ok();
        "PIN reset failed."
    })?;

    token.logout().ok();
    println!("User PIN reset successfully.");
    Ok(())
}

fn load_config(path: &str) -> Result<HsmConfig, Box<dyn std::error::Error>> {
    let config = HsmConfig::load_from_path(path)?;
    config
        .validate()
        .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?;
    Ok(config)
}
