// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
use crate::output;
use craton_hsm::config::config::HsmConfig;
use craton_hsm::core::HsmCore;
use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm::pkcs11_abi::types::{CK_ATTRIBUTE_TYPE, CK_OBJECT_HANDLE, CK_ULONG};
use zeroize::{Zeroize, Zeroizing};

use super::import_parse::ParsedKey;

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

/// Encode a `CK_ULONG`-typed attribute value the way the lib expects.
/// The store uses `from_ne_bytes::<CK_ULONG>` when reading these attrs, so
/// we MUST emit native-endian bytes sized to the platform's `c_ulong`.
fn ck_ulong_bytes(val: CK_ULONG) -> Vec<u8> {
    val.to_ne_bytes().to_vec()
}

/// Import a key from a PEM or DER file.
///
/// Parses the input first (PKCS#8, PKCS#1, SPKI, SEC1) so the import emits
/// the correct PKCS#11 attribute template for the key form. The object class
/// is inferred from the parsed structure: `--class`, when supplied, only
/// confirms that inference and triggers a clear error on mismatch — it never
/// overrides the parser. For AES, `--class` is ignored (always secret key).
pub fn import(
    config_path: &str,
    file: &str,
    label: &str,
    key_type: &str,
    class: Option<&str>,
    yes: bool,
) -> CliResult {
    let upper_type = key_type.to_uppercase();

    // Wrap raw file bytes in Zeroizing — without it the bytes (and any
    // intermediate copies) persist in freed heap until the allocator reuses
    // the pages.
    let key_data = Zeroizing::new(std::fs::read(file).map_err(|_| "Failed to read key file.")?);

    // Parse the input and build the attribute template. AES is special-cased:
    // there is no standard PEM/DER container for raw AES key bytes, so we
    // keep the historical "file contents are the key bytes" behaviour for
    // it but enforce CKO_SECRET_KEY.
    let (mut template, display): (Vec<(CK_ATTRIBUTE_TYPE, Vec<u8>)>, String) = match upper_type
        .as_str()
    {
        "AES" => {
            if class.is_some_and(|c| !c.eq_ignore_ascii_case("secret")) {
                return Err(format!(
                    "AES keys are always class=secret; got --class {}",
                    class.unwrap()
                )
                .into());
            }
            // Defense-in-depth: refuse obviously-wrong AES key sizes.
            // PKCS#11 requires CKA_VALUE_LEN in bytes for secret keys.
            let len = key_data.len();
            if !matches!(len, 16 | 24 | 32) {
                return Err(format!(
                    "AES key file must contain 16, 24, or 32 raw bytes; got {}",
                    len
                )
                .into());
            }
            let mut tpl: Vec<(CK_ATTRIBUTE_TYPE, Vec<u8>)> = vec![
                (CKA_CLASS, ck_ulong_bytes(CKO_SECRET_KEY)),
                (CKA_KEY_TYPE, ck_ulong_bytes(CKK_AES)),
                (CKA_LABEL, label.as_bytes().to_vec()),
                (CKA_TOKEN, vec![1u8]),
                (CKA_PRIVATE, vec![1u8]),
                (CKA_SENSITIVE, vec![1u8]),
                (CKA_VALUE_LEN, ck_ulong_bytes(len as CK_ULONG)),
                (CKA_VALUE, key_data.as_slice().to_vec()),
            ];
            // Sanity: nothing in `tpl` should outlive the function. The
            // outer for-loop at the end will zeroize each value buffer.
            let _ = &mut tpl;
            (tpl, format!("AES (secret, {} bits)", len * 8))
        }
        "RSA" | "EC" => {
            // Parse — fails fast on garbage input rather than silently
            // creating an unusable HSM object.
            let parsed = ParsedKey::from_bytes(&key_data).map_err(|e| {
                format!(
                    "Failed to parse key file as PEM/DER: {}. \
                     Supported: PKCS#8 PRIVATE KEY, SPKI PUBLIC KEY, \
                     PKCS#1 RSA PRIVATE/PUBLIC KEY, SEC1 EC PRIVATE KEY.",
                    e
                )
            })?;

            // Enforce --type matches the parsed structure.
            let parsed_type = parsed.key_type_name();
            if parsed_type != upper_type {
                return Err(format!(
                    "--type {} does not match parsed key (got {}). Refusing to import.",
                    upper_type, parsed_type
                )
                .into());
            }

            // Infer class from structure; reject if --class disagrees.
            // The parser is authoritative; --class is merely a confirmation.
            parsed
                .confirm_class(class)
                .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?;

            let display = parsed.display_summary();
            let template = parsed.into_template(label);
            (template, display)
        }
        other => {
            return Err(format!("Unsupported key type: '{}'. Use RSA, EC, or AES", other).into())
        }
    };

    // Show what we're about to import and require explicit confirmation
    // (or --yes). Importing a private key is irreversible and visible to
    // everyone with token access, so we make the user agree to the parsed
    // identity, not just the on-disk file name.
    eprintln!("About to import key:");
    eprintln!("  File:   {}", file);
    eprintln!("  Label:  {}", label);
    eprintln!("  {}", display);
    if !yes {
        eprint!("Proceed with import? [y/N] ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            // Zero out the staged template before we bail.
            for (_attr, ref mut value) in &mut template {
                value.zeroize();
            }
            return Err("Import cancelled.".into());
        }
    }

    // Now authenticate. We deliberately parse and confirm BEFORE prompting
    // for the PIN — there is no reason to harvest a PIN when we already
    // know the input is bogus or the user changed their mind.
    let config = load_config(config_path)?;
    let hsm = HsmCore::new(&config);
    if let Err(e) = authenticate_user(&hsm) {
        for (_attr, ref mut value) in &mut template {
            value.zeroize();
        }
        return Err(e);
    }

    let handle = hsm
        .object_store()
        .create_object(&template)
        .map_err(|e| format!("Failed to import key: {:?}", e));

    // Zero all template value buffers — especially CKA_VALUE / CKA_PRIVATE_EXPONENT
    // / CKA_PRIME_* which contain unprotected copies of the secret material.
    for (_attr, ref mut value) in &mut template {
        value.zeroize();
    }
    drop(template);

    let handle = handle?;

    println!("Key imported successfully.");
    println!("  Handle: {}", handle);
    println!("  Label:  {}", label);
    println!("  {}", display);

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
