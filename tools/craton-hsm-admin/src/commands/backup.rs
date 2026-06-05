// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
use crate::commands::{authenticate_so, logout};
use craton_hsm::config::config::HsmConfig;
use craton_hsm::core::HsmCore;
use craton_hsm::pkcs11_abi::types::CK_SLOT_ID;
use craton_hsm::store::backup;
use craton_hsm::store::object::StoredObject;
use std::path::Path;
use zeroize::Zeroizing;

/// Slot id administered by every admin CLI command (single-slot model).
const ADMIN_SLOT_ID: CK_SLOT_ID = 0;

/// Outcome of staging-and-committing a batch of restored objects.
///
/// `restored` and `skipped` are reported on both success and partial-failure
/// paths so the operator can audit what actually landed in the store.
#[derive(Debug, Default)]
pub(crate) struct RestoreOutcome {
    /// Number of objects successfully inserted into the live store.
    pub restored: usize,
    /// Number of objects skipped during pre-validation (e.g. handle
    /// conflicts) before any insert was attempted.
    pub skipped: usize,
}

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

    // Prompt for the backup *passphrase* (file-encryption secret).
    let passphrase = prompt_passphrase(false)?;

    let config = load_config(config_path)?;
    let hsm = HsmCore::new(&config);

    // In the binary, authentication is the real interactive SO PIN prompt.
    restore_backup_core(&hsm, &config, config_path, &backup_data, &passphrase, |hsm| {
        authenticate_so(hsm, ADMIN_SLOT_ID)
    })
}

/// Core orchestration for `backup restore`, parameterised over the SO
/// authentication step.
///
/// The binary always passes the interactive `authenticate_so` prompt;
/// tests inject a deterministic closure to exercise the auth-bypass and
/// authenticated paths.
///
/// SECURITY INVARIANT: the auth callback runs **before** any state
/// mutation.  If it returns an error the replay guard is unchanged and
/// the live object store is untouched.
pub(crate) fn restore_backup_core<F>(
    hsm: &HsmCore,
    config: &HsmConfig,
    config_path: &str,
    backup_data: &[u8],
    passphrase: &str,
    authenticate: F,
) -> Result<(), Box<dyn std::error::Error>>
where
    F: FnOnce(&HsmCore) -> Result<(), Box<dyn std::error::Error>>,
{
    // Authenticate *first* — this is the gate that protects every
    // subsequent side effect.  Any failure here must propagate before we
    // touch the replay guard or the object store.
    authenticate(hsm)?;

    let token_serial = config.token.serial_number.clone();
    let result = restore_backup_authenticated(
        hsm,
        config_path,
        backup_data,
        passphrase,
        &token_serial,
    );
    logout(hsm, ADMIN_SLOT_ID);
    result
}

/// Body of `restore_backup` that runs *after* SO authentication has
/// succeeded. Split out so the SO-session logout can be performed
/// unconditionally on every exit path.
fn restore_backup_authenticated(
    hsm: &HsmCore,
    config_path: &str,
    backup_data: &[u8],
    passphrase: &str,
    token_serial: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Use persistent replay protection to prevent re-importing the same
    // backup across daemon restarts. The replay guard file is stored
    // alongside the config file directory.
    let replay_guard_path = std::path::Path::new(config_path)
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .join(".craton_hsm_replay_guard");
    let mut replay_guard = backup::PersistentReplayGuard::new(replay_guard_path);

    // Extract the guard's consumed IDs into a mutable HashSet for
    // restore_backup. After restore, any newly inserted ID is persisted
    // back to the guard file.
    let mut consumed_ids = replay_guard.consumed_ids_clone();

    let objects = backup::restore_backup(
        backup_data,
        passphrase,
        token_serial,
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

    // Persist any newly consumed backup IDs to the guard file BEFORE we
    // insert anything. If we crash mid-insert the replay guard already
    // marks the backup as consumed, so a retry can't re-run the same
    // backup over a partially-populated store and create duplicates.
    for id in &consumed_ids {
        if !replay_guard.is_consumed(id) {
            replay_guard
                .record(id.clone())
                .map_err(|e| format!("Failed to persist replay guard: {:?}", e))?;
        }
    }

    let outcome = stage_and_commit_objects(hsm, objects)?;
    println!("Restored {} objects from backup.", outcome.restored);
    if outcome.skipped > 0 {
        eprintln!(
            "{} objects skipped due to existing handles.",
            outcome.skipped
        );
    }
    Ok(())
}

/// Stage decoded objects, validate the whole batch, then commit them to
/// the live object store in a single pass.
///
/// Pre-validation walks every object and filters out ones whose handles
/// already exist in the store (the previous in-line behaviour, preserved
/// for backwards compatibility — this is a non-fatal skip).  Any other
/// pre-validation failure aborts before *any* object is inserted.
///
/// The commit phase then inserts every staged object.  The underlying
/// object store does not currently expose a transactional API, so a
/// failure partway through the commit cannot fully roll back.  When that
/// happens we surface a precise error message reporting exactly how many
/// objects were inserted before the failure, so the operator can audit
/// the resulting store state.
pub(crate) fn stage_and_commit_objects(
    hsm: &HsmCore,
    objects: Vec<StoredObject>,
) -> Result<RestoreOutcome, Box<dyn std::error::Error>> {
    // --- Stage + validate -------------------------------------------------
    // Collect objects we will actually insert.  Skip handle-conflicts up
    // front (non-fatal) so we never even attempt to overwrite an existing
    // object.  Any duplicate handle *within* the staged batch is a hard
    // error: it indicates a corrupt or hostile backup payload.
    let mut staged: Vec<StoredObject> = Vec::with_capacity(objects.len());
    let mut staged_handles: std::collections::HashSet<u64> =
        std::collections::HashSet::with_capacity(objects.len());
    let mut skipped: usize = 0;

    for obj in objects {
        let handle = obj.handle as u64;
        if hsm.object_store().get_object(obj.handle).is_ok() {
            eprintln!(
                "Warning: object handle {} already exists, skipping to avoid overwrite.",
                handle
            );
            skipped += 1;
            continue;
        }
        if !staged_handles.insert(handle) {
            // Two staged objects share a handle — refuse to commit *any*
            // of them.  This protects against a backup payload that would
            // otherwise leave the store in an unpredictable state
            // depending on insert order.
            return Err(format!(
                "Backup payload is invalid: duplicate handle {} appears more than once. \
                 No objects were inserted.",
                handle
            )
            .into());
        }
        staged.push(obj);
    }

    // --- Commit -----------------------------------------------------------
    // Insert every staged object.  If a mid-batch failure occurs we cannot
    // roll back already-inserted objects (the object store has no
    // transaction API yet), so report exactly which objects were inserted
    // before bailing.
    let mut restored: usize = 0;
    for obj in staged {
        let handle = obj.handle as u64;
        match hsm.object_store().insert_object(obj) {
            Ok(_) => restored += 1,
            Err(e) => {
                return Err(format!(
                    "Failed to insert object {} after {} of the batch had already \
                     been committed: {:?}. The object store does not support \
                     transactional rollback; the already-inserted objects remain \
                     in the live store.",
                    handle, restored, e
                )
                .into());
            }
        }
    }

    Ok(RestoreOutcome { restored, skipped })
}

// ============================================================================
// Unit tests
// ============================================================================
//
// These tests focus on the security-critical behaviour of `backup restore`:
//
// 1. A failed SO authentication MUST NOT mutate the object store or the
//    replay guard.  Without this gate anyone who knew the backup passphrase
//    could forge a backup file and inject objects (CVE-class issue this
//    change fixes).
// 2. A successful SO authentication restores every object in the backup.
// 3. Stage-then-commit semantics: a malformed batch is rejected up front
//    and leaves the store untouched.
//
// The interactive `restore_backup` entry point is exercised indirectly via
// `restore_backup_core`, which accepts the SO-auth step as a closure so
// tests can drive it without a TTY.
#[cfg(test)]
mod tests {
    use super::*;
    use craton_hsm::config::config::HsmConfig;
    use craton_hsm::core::HsmCore;
    use craton_hsm::pkcs11_abi::constants::CKO_DATA;
    use craton_hsm::store::backup;
    use craton_hsm::store::object::StoredObject;

    /// Passphrase that satisfies both the length floor (16 chars) and the
    /// complexity policy enforced by `backup::create_backup`.
    const TEST_PASSPHRASE: &str = "V3ry-Secret-Backup-Passphrase!";

    fn make_test_object(handle: u64) -> StoredObject {
        // CK_OBJECT_HANDLE is `c_ulong` (u32 on Windows, u64 on Linux);
        // truncating here is safe for the small handles we use in tests.
        let mut obj = StoredObject::new(
            handle as craton_hsm::pkcs11_abi::types::CK_OBJECT_HANDLE,
            CKO_DATA,
        );
        obj.label = format!("test-obj-{}", handle).into_bytes();
        obj
    }

    /// Build a fresh in-memory HSM config wired to a temp dir.  Disables
    /// object persistence so each test starts with an empty store.
    fn make_test_config(tmp_dir: &std::path::Path) -> HsmConfig {
        let mut config = HsmConfig::default();
        config.token.storage_path = tmp_dir.join("store");
        config.token.persist_objects = false;
        config.token.serial_number = "TEST000000000001".to_string();
        // Speed up PBKDF2 in tests; the default already drops to 1 round
        // in debug builds, but be explicit so this doesn't slow CI.
        config.security.pbkdf2_iterations = 1;
        config
    }

    /// Build a backup blob containing the provided objects, encrypted with
    /// `TEST_PASSPHRASE` and bound to the config's token serial.
    fn make_backup_blob(config: &HsmConfig, objects: &[StoredObject]) -> Vec<u8> {
        backup::create_backup(
            objects,
            TEST_PASSPHRASE,
            &config.token.serial_number,
            Some(1),
        )
        .expect("create_backup")
    }

    /// Write a minimal config TOML to disk so `restore_backup_core` can
    /// derive a replay-guard path from its parent directory.
    fn write_dummy_config(tmp_dir: &std::path::Path) -> std::path::PathBuf {
        let path = tmp_dir.join("craton_hsm.toml");
        // The TOML contents are not parsed by `restore_backup_core` — it
        // only uses the path's parent for the replay-guard location.
        std::fs::write(&path, b"# test config\n").unwrap();
        path
    }

    /// SECURITY: Failed SO authentication MUST leave the object store
    /// untouched. This is the regression test for the issue this commit
    /// fixes: a caller who only knows the backup passphrase must NOT be
    /// able to inject objects.
    #[test]
    fn restore_rejects_without_so_auth_and_does_not_mutate_store() {
        let tmp = tempfile::tempdir().unwrap();
        let config = make_test_config(tmp.path());
        let hsm = HsmCore::new(&config);
        let config_path = write_dummy_config(tmp.path());

        let objects = vec![make_test_object(1001), make_test_object(1002)];
        let blob = make_backup_blob(&config, &objects);

        let pre_handles = hsm.object_store().find_objects(&[], true);
        assert_eq!(
            pre_handles.len(),
            0,
            "test must start with an empty object store"
        );

        // Simulate a failed SO PIN attempt — the closure returns an error
        // before any state mutation is allowed.
        let result = restore_backup_core(
            &hsm,
            &config,
            config_path.to_str().unwrap(),
            &blob,
            TEST_PASSPHRASE,
            |_| Err("SO authentication failed.".into()),
        );

        assert!(result.is_err(), "restore must fail without SO auth");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("SO authentication failed"),
            "error should surface the SO auth failure, got: {}",
            err_msg
        );

        // The object store MUST be untouched.
        let post_handles = hsm.object_store().find_objects(&[], true);
        assert_eq!(
            post_handles.len(),
            0,
            "no objects should have been inserted when SO auth failed"
        );

        // The replay guard MUST be untouched.  If the file exists at all,
        // it must not contain the backup_id.  In practice no file should
        // be created — but tolerate an empty file in case the underlying
        // helper touches it.
        let guard_path = tmp.path().join(".craton_hsm_replay_guard");
        if guard_path.exists() {
            let contents = std::fs::read_to_string(&guard_path).unwrap_or_default();
            assert!(
                contents.trim().is_empty(),
                "replay guard must not record an ID when SO auth fails, got: {:?}",
                contents
            );
        }
    }

    /// With a successful SO auth, every object in the backup must end up
    /// in the live store.
    #[test]
    fn restore_with_successful_so_auth_inserts_all_objects() {
        let tmp = tempfile::tempdir().unwrap();
        let config = make_test_config(tmp.path());
        let hsm = HsmCore::new(&config);
        let config_path = write_dummy_config(tmp.path());

        let objects = vec![
            make_test_object(2001),
            make_test_object(2002),
            make_test_object(2003),
        ];
        let blob = make_backup_blob(&config, &objects);

        let result = restore_backup_core(
            &hsm,
            &config,
            config_path.to_str().unwrap(),
            &blob,
            TEST_PASSPHRASE,
            |_| Ok(()), // SO auth succeeded
        );
        assert!(result.is_ok(), "restore should succeed: {:?}", result.err());

        for handle in &[2001u64, 2002, 2003] {
            let h = *handle as craton_hsm::pkcs11_abi::types::CK_OBJECT_HANDLE;
            assert!(
                hsm.object_store().get_object(h).is_ok(),
                "object with handle {} should be present after restore",
                handle
            );
        }
    }

    /// Stage-then-commit: a backup payload with a duplicate handle inside
    /// the *same* batch is rejected up front and leaves the store empty.
    /// This proves the new validation pass runs before any insert.
    #[test]
    fn restore_rejects_duplicate_handles_in_batch_atomically() {
        let tmp = tempfile::tempdir().unwrap();
        let config = make_test_config(tmp.path());
        let hsm = HsmCore::new(&config);

        // Two objects sharing the same handle — the staging pass must
        // refuse the batch and insert neither.
        let objects = vec![make_test_object(3001), make_test_object(3001)];

        let outcome = stage_and_commit_objects(&hsm, objects);
        assert!(
            outcome.is_err(),
            "duplicate handles in the staged batch must fail validation"
        );
        let err = outcome.unwrap_err().to_string();
        assert!(
            err.contains("duplicate handle 3001"),
            "error should identify the duplicate handle, got: {}",
            err
        );
        assert!(
            err.contains("No objects were inserted"),
            "error should reassure operator no partial insert happened, got: {}",
            err
        );

        // Store is untouched — no object with handle 3001 exists.
        let handle = 3001u64 as craton_hsm::pkcs11_abi::types::CK_OBJECT_HANDLE;
        assert!(
            hsm.object_store().get_object(handle).is_err(),
            "no objects should have been inserted"
        );
    }

    /// Pre-existing handles in the live store are *skipped* rather than
    /// failing the whole batch — this preserves the previous user-facing
    /// behaviour where a partial restore over an existing store is
    /// allowed.  The remaining objects must still be inserted in the
    /// same single committed pass.
    #[test]
    fn restore_skips_existing_handles_and_inserts_rest() {
        let tmp = tempfile::tempdir().unwrap();
        let config = make_test_config(tmp.path());
        let hsm = HsmCore::new(&config);

        // Pre-insert an object so handle 4001 is already taken.
        let existing = make_test_object(4001);
        hsm.object_store()
            .insert_object(existing)
            .expect("pre-insert");

        let batch = vec![
            make_test_object(4001), // conflicts, must be skipped
            make_test_object(4002), // must be inserted
        ];

        let outcome = stage_and_commit_objects(&hsm, batch).expect("commit");
        assert_eq!(outcome.restored, 1, "only the non-conflicting object should be inserted");
        assert_eq!(outcome.skipped, 1, "the conflicting object should be skipped");

        // Both handles now exist (4001 was pre-existing, 4002 newly
        // restored).
        let h1 = 4001u64 as craton_hsm::pkcs11_abi::types::CK_OBJECT_HANDLE;
        let h2 = 4002u64 as craton_hsm::pkcs11_abi::types::CK_OBJECT_HANDLE;
        assert!(hsm.object_store().get_object(h1).is_ok());
        assert!(hsm.object_store().get_object(h2).is_ok());
    }
}
