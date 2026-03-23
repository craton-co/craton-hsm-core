// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
use craton_hsm::config::config::HsmConfig;
use craton_hsm::core::HsmCore;
use craton_hsm::store::backup;
use std::path::Path;
use zeroize::Zeroizing;

const MIN_PASSPHRASE_LENGTH: usize = 12;

/// Prompt for a passphrase with confirmation, returning a zeroizing wrapper.
fn prompt_passphrase(confirm: bool) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    let passphrase = Zeroizing::new(rpassword::prompt_password("Enter backup passphrase: ")?);
    if passphrase.is_empty() {
        return Err("Passphrase must not be empty.".into());
    }
    if confirm && passphrase.len() < MIN_PASSPHRASE_LENGTH {
        return Err(format!(
            "Passphrase too short. Minimum {} characters required to protect key material.",
            MIN_PASSPHRASE_LENGTH
        )
        .into());
    }
    if confirm {
        let confirm = Zeroizing::new(rpassword::prompt_password("Confirm backup passphrase: ")?);
        if *passphrase != *confirm {
            return Err("Passphrases do not match.".into());
        }
    }
    Ok(passphrase)
}

/// Set restrictive file permissions (owner-only read/write).
#[cfg(unix)]
fn set_restrictive_permissions(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms)
        .map_err(|e| format!("Failed to set file permissions: {}", e))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_restrictive_permissions(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    // On Windows, use icacls to strip inherited ACEs and grant access only to
    // the current user.  This ensures backup files containing key material
    // are not readable by other users on the same machine.
    //
    // SECURITY: Use `whoami` to get the actual current username instead of the
    // %USERNAME% environment variable, which is user-controllable and could be
    // set to "Everyone" to grant world-readable permissions.
    let whoami_output = std::process::Command::new("whoami")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("Cannot determine current Windows user via whoami: {}", e))?;
    if !whoami_output.status.success() {
        return Err(
            "whoami command failed — cannot determine current user for ACL restriction".into(),
        );
    }
    let username = String::from_utf8_lossy(&whoami_output.stdout)
        .trim()
        .to_string();
    if username.is_empty() {
        return Err("whoami returned empty username — cannot set restrictive ACLs".into());
    }

    let status = std::process::Command::new("icacls")
        .args([
            path,
            "/inheritance:r",
            "/grant:r",
            &format!("{}:(R,W)", username),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    match status {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => {
            eprintln!(
                "Warning: icacls exited with code {} — backup file may have default ACLs",
                s.code().unwrap_or(-1)
            );
            Ok(())
        }
        Err(e) => {
            eprintln!(
                "Warning: could not run icacls to restrict backup permissions: {}",
                e
            );
            Ok(())
        }
    }
}

fn load_config(path: &str) -> Result<HsmConfig, Box<dyn std::error::Error>> {
    let config = HsmConfig::load_from_path(path)?;
    config
        .validate()
        .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?;
    Ok(config)
}

pub fn create_backup(config_path: &str, output: &str) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config(config_path)?;
    let hsm = HsmCore::new(&config);

    // Prompt for passphrase interactively (never via CLI arg)
    let passphrase = prompt_passphrase(true)?;

    // Export all objects from the object store
    let objects = hsm.object_store().export_all_objects();
    let token_serial = config.token.serial_number.clone();
    let backup_data = backup::create_backup(&objects, &passphrase, &token_serial, None)
        .map_err(|e| format!("Backup creation failed: {:?}", e))?;

    // Write backup file with restrictive permissions from the start (no race window).
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(output)
            .map_err(|e| format!("Failed to create backup file: {}", e))?;
        std::io::Write::write_all(&mut file, &backup_data)
            .map_err(|e| format!("Failed to write backup file: {}", e))?;
    }
    #[cfg(not(unix))]
    {
        // SECURITY: Write to a temporary file in the same directory first, set
        // restrictive ACLs on it, then rename to the final path. This avoids
        // the race window where the backup is world-readable between creation
        // and ACL restriction.
        let output_path = std::path::Path::new(output);
        let parent = output_path.parent().unwrap_or(std::path::Path::new("."));
        let tmp_name = format!(".craton_hsm-backup-{}.tmp", std::process::id());
        let tmp_path = parent.join(&tmp_name);
        let tmp_str = tmp_path.to_string_lossy().to_string();

        // Write to temp file
        std::fs::write(&tmp_path, &backup_data)
            .map_err(|e| format!("Failed to write temporary backup file: {}", e))?;

        // Restrict permissions on temp file before it becomes visible at final path
        if let Err(e) = set_restrictive_permissions(&tmp_str) {
            // Clean up temp file on ACL failure
            let _ = std::fs::remove_file(&tmp_path);
            return Err(format!("Failed to set backup file permissions: {}", e).into());
        }

        // Atomic rename to final destination
        if let Err(e) = std::fs::rename(&tmp_path, output) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(format!("Failed to move backup file to final location: {}", e).into());
        }
    }

    println!(
        "Backup created: {} ({} objects, {} bytes)",
        output,
        objects.len(),
        backup_data.len()
    );
    Ok(())
}

pub fn restore_backup(config_path: &str, input: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !Path::new(input).exists() {
        return Err("Backup file not found at specified path.".into());
    }

    let backup_data = std::fs::read(input).map_err(|_| "Failed to read backup file.")?;

    // Prompt for passphrase interactively
    let passphrase = prompt_passphrase(false)?;

    let config = load_config(config_path)?;
    let token_serial = config.token.serial_number.clone();

    // Use persistent replay protection to prevent re-importing the same backup
    // across daemon restarts. The replay guard file is stored alongside the
    // config file directory.
    let replay_guard_path = std::path::Path::new(config_path)
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .join(".craton_hsm_replay_guard");
    let mut replay_guard = backup::PersistentReplayGuard::new(replay_guard_path);

    // Extract the guard's consumed IDs into a mutable HashSet for restore_backup.
    // After restore, any newly inserted ID is persisted back to the guard file.
    let mut consumed_ids = replay_guard.consumed_ids_clone();

    let objects = backup::restore_backup(
        &backup_data,
        &passphrase,
        &token_serial,
        None, // use default 30-day max age
        None, // default PBKDF2 iterations
        Some(&mut consumed_ids),
    )
    .map_err(|e| {
        format!(
            "Backup restore failed (wrong passphrase or corrupt file): {:?}",
            e
        )
    })?;

    // Persist any newly consumed backup IDs to the guard file
    for id in &consumed_ids {
        if !replay_guard.is_consumed(id) {
            replay_guard
                .record(id.clone())
                .map_err(|e| format!("Failed to persist replay guard: {:?}", e))?;
        }
    }
    let hsm = HsmCore::new(&config);

    // Check for handle conflicts before inserting
    let mut skipped = 0usize;
    let mut restored = 0usize;
    for obj in objects {
        let handle = obj.handle;
        if hsm.object_store().get_object(handle).is_ok() {
            eprintln!(
                "Warning: object handle {} already exists, skipping to avoid overwrite.",
                handle
            );
            skipped += 1;
            continue;
        }
        match hsm.object_store().insert_object(obj) {
            Ok(_) => restored += 1,
            Err(e) => {
                eprintln!("Warning: failed to insert object {}: {:?}", handle, e);
                skipped += 1;
            }
        }
    }

    println!("Restored {} objects from backup.", restored);
    if skipped > 0 {
        eprintln!("{} objects skipped due to existing handles.", skipped);
    }
    Ok(())
}
