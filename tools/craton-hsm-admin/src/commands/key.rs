// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
use crate::output;
use craton_hsm::config::config::HsmConfig;
use craton_hsm::core::HsmCore;
use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm::pkcs11_abi::types::{CK_ATTRIBUTE_TYPE, CK_OBJECT_HANDLE};
use zeroize::Zeroizing;

type CliResult = Result<(), Box<dyn std::error::Error>>;

/// Maximum authentication attempts before the CLI refuses further tries.
const MAX_AUTH_ATTEMPTS: u32 = 3;

/// Authenticate as SO or USER before performing key operations.
/// Enforces a delay between failed attempts as defense-in-depth against
/// brute-force, even if the underlying token has its own lockout.
fn authenticate_user(hsm: &HsmCore) -> CliResult {
    let token = hsm
        .slot_manager()
        .get_token(0)
        .map_err(|_| "Failed to access token.")?;

    if !token.is_initialized() {
        return Err("Token is not initialized. Run 'token init' first.".into());
    }

    // Ask the user which role to authenticate as — never silently try both,
    // as that doubles brute-force surface and can escalate privileges.
    eprint!("Authenticate as [U]ser or [S]O? [U/S] ");
    let mut role_input = String::new();
    std::io::stdin().read_line(&mut role_input)?;
    let ck_user = match role_input.trim().to_uppercase().as_str() {
        "S" | "SO" => CKU_SO,
        _ => CKU_USER,
    };

    let role_name = if ck_user == CKU_SO { "SO" } else { "User" };

    for attempt in 1..=MAX_AUTH_ATTEMPTS {
        let pin = Zeroizing::new(rpassword::prompt_password(&format!(
            "Enter {} PIN: ",
            role_name
        ))?);

        match token.login(ck_user, pin.as_bytes()) {
            Ok(_) => return Ok(()),
            Err(_) => {
                let remaining = MAX_AUTH_ATTEMPTS - attempt;
                if remaining == 0 {
                    // Enforce a final delay to slow down scripted retry loops
                    std::thread::sleep(std::time::Duration::from_secs(2));
                    return Err("Authentication failed. Maximum attempts reached.".into());
                }
                // Exponential backoff: 1s, 2s between retries
                let delay = std::time::Duration::from_secs(attempt as u64);
                eprintln!(
                    "Authentication failed. {} attempt(s) remaining. Retrying in {}s...",
                    remaining,
                    delay.as_secs()
                );
                std::thread::sleep(delay);
            }
        }
    }

    Err("Authentication failed.".into())
}

/// Logout after operation.
fn logout(hsm: &HsmCore) {
    if let Ok(token) = hsm.slot_manager().get_token(0) {
        token.logout().ok();
    }
}

/// List all keys in the object store.
pub fn list(config_path: &str, json: bool) -> CliResult {
    let config = load_config(config_path)?;
    let hsm = HsmCore::new(&config);

    // Require authentication to view private objects
    authenticate_user(&hsm)?;

    let handles = hsm.object_store().find_objects(&[], true);

    if json {
        let mut objects = Vec::new();
        for handle in &handles {
            if let Ok(obj_lock) = hsm.object_store().get_object(*handle) {
                let obj = obj_lock.read();
                let label = String::from_utf8_lossy(&obj.label).trim().to_string();
                objects.push(serde_json::json!({
                    "handle": obj.handle,
                    "class": output::object_class_name(obj.class as u64),
                    "key_type": obj.key_type.map(|kt| output::key_type_name(kt as u64)),
                    "label": label,
                    "size_bits": obj.modulus_bits.or(obj.value_len.map(|v| v * 8)),
                    "sensitive": obj.sensitive,
                    "extractable": obj.extractable,
                }));
            }
        }
        println!("{}", serde_json::to_string_pretty(&objects)?);
    } else {
        let mut table = output::ObjectTable::new(vec![
            "Handle",
            "Class",
            "Type",
            "Label",
            "Size",
            "Sensitive",
            "Extractable",
        ]);

        for handle in &handles {
            if let Ok(obj_lock) = hsm.object_store().get_object(*handle) {
                let obj = obj_lock.read();
                let label = String::from_utf8_lossy(&obj.label).trim().to_string();
                let class = output::object_class_name(obj.class as u64);
                let key_type = obj
                    .key_type
                    .map(|kt| output::key_type_name(kt as u64))
                    .unwrap_or("-");
                let size = obj
                    .modulus_bits
                    .or(obj.value_len.map(|v| v * 8))
                    .map(|s| format!("{}", s))
                    .unwrap_or_else(|| "-".to_string());

                table.add_row(vec![
                    format!("{}", obj.handle),
                    class.to_string(),
                    key_type.to_string(),
                    label,
                    size,
                    obj.sensitive.to_string(),
                    obj.extractable.to_string(),
                ]);
            }
        }

        println!("Key Objects");
        println!("===========");
        if table.is_empty() {
            println!("  (no objects found)");
        } else {
            print!("{}", table);
        }
        println!("\nTotal: {} object(s)", handles.len());
    }

    logout(&hsm);
    Ok(())
}

/// Import a key from file (PEM or DER).
pub fn import(config_path: &str, file: &str, label: &str, key_type: &str) -> CliResult {
    let config = load_config(config_path)?;
    let hsm = HsmCore::new(&config);

    // Require authentication before importing keys
    authenticate_user(&hsm)?;

    // Wrap key data in Zeroizing so it is scrubbed from memory after use.
    // Without this, the raw key bytes from std::fs::read persist in freed
    // heap memory until the allocator reuses the pages.
    let key_data = Zeroizing::new(std::fs::read(file).map_err(|_| "Failed to read key file.")?);

    // Determine CKA_KEY_TYPE and CKA_CLASS based on --type argument
    let (ck_key_type, ck_class) = match key_type.to_uppercase().as_str() {
        "RSA" => (CKK_RSA, CKO_PRIVATE_KEY),
        "EC" => (CKK_EC, CKO_PRIVATE_KEY),
        "AES" => (CKK_AES, CKO_SECRET_KEY),
        other => {
            return Err(format!("Unsupported key type: '{}'. Use RSA, EC, or AES", other).into())
        }
    };

    // Build attribute template.
    // SECURITY: key_data.to_vec() creates an unprotected copy of the raw key bytes.
    // We must explicitly zeroize the template after create_object consumes it.
    let mut template: Vec<(CK_ATTRIBUTE_TYPE, Vec<u8>)> = vec![
        (CKA_CLASS, (ck_class as u64).to_le_bytes().to_vec()),
        (CKA_KEY_TYPE, (ck_key_type as u64).to_le_bytes().to_vec()),
        (CKA_LABEL, label.as_bytes().to_vec()),
        (CKA_TOKEN, vec![1u8]), // token object
        (CKA_PRIVATE, vec![1u8]),
        (CKA_SENSITIVE, vec![1u8]),
        (CKA_VALUE, key_data.to_vec()),
    ];
    // key_data (Zeroizing<Vec<u8>>) is dropped here, scrubbing the file contents.

    let handle = hsm
        .object_store()
        .create_object(&template)
        .map_err(|e| format!("Failed to import key: {:?}", e));

    // Zeroize all template value buffers — especially CKA_VALUE which contains
    // the raw key material that was copied out of the Zeroizing wrapper.
    for (_attr, ref mut value) in &mut template {
        zeroize::Zeroize::zeroize(value.as_mut_slice());
    }
    drop(template);

    let handle = handle?;

    println!("Key imported successfully.");
    println!("  Handle: {}", handle);
    println!("  Label:  {}", label);
    println!("  Type:   {}", key_type.to_uppercase());

    logout(&hsm);
    Ok(())
}

/// Delete a key by handle.
pub fn delete(config_path: &str, handle: u64, force: bool) -> CliResult {
    let config = load_config(config_path)?;
    let hsm = HsmCore::new(&config);

    // Require authentication before deleting keys
    authenticate_user(&hsm)?;

    let handle = handle as CK_OBJECT_HANDLE;

    // Capture object identity before prompting for confirmation
    let (label, orig_class, orig_key_type, orig_sensitive) = {
        let obj_lock = hsm
            .object_store()
            .get_object(handle)
            .map_err(|_| format!("Object handle {} not found", handle))?;
        let obj = obj_lock.read();
        (
            String::from_utf8_lossy(&obj.label).trim().to_string(),
            obj.class,
            obj.key_type,
            obj.sensitive,
        )
    };

    if !force {
        eprint!("Delete object {} (label: '{}')? [y/N] ", handle, label);
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            logout(&hsm);
            return Ok(());
        }
    }

    // Re-verify object still exists and matches before destroying (mitigate TOCTOU).
    // Check label, class, key_type, and sensitive flag to detect object swaps.
    {
        let obj_lock = hsm
            .object_store()
            .get_object(handle)
            .map_err(|_| format!("Object handle {} no longer exists", handle))?;
        let obj = obj_lock.read();
        let current_label = String::from_utf8_lossy(&obj.label).trim().to_string();
        let current_class = obj.class;
        let current_key_type = obj.key_type;
        let current_sensitive = obj.sensitive;
        if current_label != label
            || current_class != orig_class
            || current_key_type != orig_key_type
            || current_sensitive != orig_sensitive
        {
            logout(&hsm);
            return Err(format!(
                "Object at handle {} changed since confirmation. Aborting for safety.",
                handle
            )
            .into());
        }
    }

    hsm.object_store()
        .destroy_object(handle)
        .map_err(|e| format!("Failed to destroy object: {:?}", e))?;

    println!("Object {} deleted.", handle);
    logout(&hsm);
    Ok(())
}

fn load_config(path: &str) -> Result<HsmConfig, Box<dyn std::error::Error>> {
    let config = HsmConfig::load_from_path(path)?;
    config
        .validate()
        .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?;
    Ok(config)
}
