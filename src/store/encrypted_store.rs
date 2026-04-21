// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use std::fs::File;
use std::path::PathBuf;

use zeroize::Zeroizing;

use crate::crypto::drbg::HmacDrbg;
use crate::error::{HsmError, HsmResult};

/// PBKDF2 iteration count per OWASP 2024 guidance (minimum 1,000,000).
const PBKDF2_ITERATIONS: u32 = 1_000_000;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

/// redb table definition for encrypted object blobs.
/// Key: UTF-8 string (object identifier), Value: nonce || ciphertext bytes.
const OBJECTS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("objects");

/// Encrypted persistent store backed by redb.
///
/// Objects are encrypted with AES-256-GCM using a key derived from
/// the user PIN via PBKDF2-HMAC-SHA256. The database file is protected
/// by an exclusive file lock (via `fs2`) to prevent concurrent access
/// from multiple processes.
pub struct EncryptedStore {
    db: Option<Database>,
    /// Hold the lock file open for the lifetime of the store.
    /// The exclusive lock is released when this file handle is dropped.
    _lock_file: Option<File>,
}

impl Drop for EncryptedStore {
    fn drop(&mut self) {
        // Release the exclusive lock by dropping the file handle.
        // We intentionally do NOT delete the lock file — removing it after
        // releasing the lock creates a TOCTOU race where another process
        // could acquire the (about-to-be-deleted) lock, only to have it
        // deleted out from under it, allowing a third process in.
        // The lock file is harmless on disk and will be reused next time.
        self._lock_file.take();
    }
}

impl EncryptedStore {
    /// Create a new encrypted store. If path is None, operates in memory-only mode.
    ///
    /// When a path is provided, acquires an exclusive file lock on
    /// `<path>.lock` to prevent concurrent access from another process.
    /// Returns an error if the database is already locked.
    pub fn new(path: Option<&str>) -> HsmResult<Self> {
        match path {
            Some(p) => {
                // Acquire exclusive file lock before opening the database
                let lock_path = PathBuf::from(format!("{}.lock", p));
                let lock_file = File::create(&lock_path).map_err(|e| {
                    tracing::error!(
                        "Failed to create lock file '{}': {}",
                        lock_path.display(),
                        e
                    );
                    HsmError::GeneralError
                })?;

                // Set restrictive permissions on the lock file to prevent
                // other users from observing HSM operation timing.
                // Failure here is fatal — see set_restrictive_permissions docs.
                set_restrictive_permissions(&lock_path)?;

                use fs2::FileExt;
                lock_file.try_lock_exclusive().map_err(|e| {
                    tracing::error!("Database at '{}' is locked by another process: {}", p, e);
                    HsmError::GeneralError
                })?;

                let db = Database::create(p).map_err(|e| {
                    tracing::error!("Failed to open database at '{}': {}", p, e);
                    HsmError::GeneralError
                })?;

                // Set restrictive permissions on the database file itself.
                // Failure here is fatal — refuse to open a world-readable HSM DB.
                set_restrictive_permissions(&PathBuf::from(p))?;

                Ok(Self {
                    db: Some(db),
                    _lock_file: Some(lock_file),
                })
            }
            None => Ok(Self {
                db: None,
                _lock_file: None,
            }),
        }
    }

    /// Check if persistent storage is available
    pub fn is_available(&self) -> bool {
        self.db.is_some()
    }

    /// Store an encrypted blob under a key
    pub fn store_encrypted(
        &self,
        store_key: &str,
        plaintext: &[u8],
        encryption_key: &[u8; KEY_LEN],
    ) -> HsmResult<()> {
        let db = self.db.as_ref().ok_or(HsmError::GeneralError)?;

        let mut nonce_bytes = [0u8; NONCE_LEN];
        // Route nonce generation through DRBG for health testing & prediction resistance,
        // consistent with all other randomness in the HSM (see drbg.rs architecture).
        let mut drbg = HmacDrbg::new()?;
        drbg.generate(&mut nonce_bytes)?;

        let aes_key = Key::<Aes256Gcm>::from_slice(encryption_key);
        let cipher = Aes256Gcm::new(aes_key);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, plaintext).map_err(|e| {
            tracing::error!("AES-GCM encryption failed for key '{}': {}", store_key, e);
            HsmError::GeneralError
        })?;

        // Store as: nonce || ciphertext
        let mut stored = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        stored.extend_from_slice(&nonce_bytes);
        stored.extend_from_slice(&ciphertext);

        let write_txn = db.begin_write().map_err(|e| {
            tracing::error!("Failed to begin write transaction: {}", e);
            HsmError::GeneralError
        })?;
        {
            let mut table = write_txn.open_table(OBJECTS_TABLE).map_err(|e| {
                tracing::error!("Failed to open objects table for write: {}", e);
                HsmError::GeneralError
            })?;
            table.insert(store_key, stored.as_slice()).map_err(|e| {
                tracing::error!("Failed to insert key '{}': {}", store_key, e);
                HsmError::GeneralError
            })?;
        }
        write_txn.commit().map_err(|e| {
            tracing::error!("Failed to commit write transaction: {}", e);
            HsmError::GeneralError
        })?;

        Ok(())
    }

    /// Load and decrypt a blob.
    ///
    /// The returned buffer is wrapped in `Zeroizing` so that decrypted
    /// plaintext (which may contain key material) is automatically zeroed
    /// when dropped — callers no longer need to remember to zeroize manually.
    pub fn load_encrypted(
        &self,
        store_key: &str,
        encryption_key: &[u8; KEY_LEN],
    ) -> HsmResult<Option<Zeroizing<Vec<u8>>>> {
        let db = self.db.as_ref().ok_or(HsmError::GeneralError)?;

        let read_txn = db.begin_read().map_err(|e| {
            tracing::error!("Failed to begin read transaction: {}", e);
            HsmError::GeneralError
        })?;

        // The table may not exist yet if nothing has been stored
        let table = match read_txn.open_table(OBJECTS_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => {
                tracing::error!("Failed to open objects table for read: {}", e);
                return Err(HsmError::GeneralError);
            }
        };

        let stored = match table.get(store_key).map_err(|e| {
            tracing::error!("Failed to get key '{}': {}", store_key, e);
            HsmError::GeneralError
        })? {
            Some(data) => data.value().to_vec(),
            None => return Ok(None),
        };

        if stored.len() < NONCE_LEN {
            return Err(HsmError::EncryptedDataInvalid);
        }

        let nonce = Nonce::from_slice(&stored[..NONCE_LEN]);
        let ciphertext = &stored[NONCE_LEN..];

        let aes_key = Key::<Aes256Gcm>::from_slice(encryption_key);
        let cipher = Aes256Gcm::new(aes_key);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| HsmError::EncryptedDataInvalid)?;

        Ok(Some(Zeroizing::new(plaintext)))
    }

    /// Delete a stored key
    pub fn delete(&self, store_key: &str) -> HsmResult<()> {
        let db = self.db.as_ref().ok_or(HsmError::GeneralError)?;

        let write_txn = db.begin_write().map_err(|e| {
            tracing::error!("Failed to begin write transaction for delete: {}", e);
            HsmError::GeneralError
        })?;
        {
            let mut table = write_txn.open_table(OBJECTS_TABLE).map_err(|e| {
                tracing::error!("Failed to open objects table for delete: {}", e);
                HsmError::GeneralError
            })?;
            table.remove(store_key).map_err(|e| {
                tracing::error!("Failed to remove key '{}': {}", store_key, e);
                HsmError::GeneralError
            })?;
        }
        write_txn.commit().map_err(|e| {
            tracing::error!("Failed to commit delete transaction: {}", e);
            HsmError::GeneralError
        })?;
        Ok(())
    }

    /// List all keys in the store
    pub fn list_keys(&self) -> HsmResult<Vec<String>> {
        let db = self.db.as_ref().ok_or(HsmError::GeneralError)?;

        let read_txn = db.begin_read().map_err(|e| {
            tracing::error!("Failed to begin read transaction for list_keys: {}", e);
            HsmError::GeneralError
        })?;

        let table = match read_txn.open_table(OBJECTS_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => {
                tracing::error!("Failed to open objects table for list_keys: {}", e);
                return Err(HsmError::GeneralError);
            }
        };

        let mut keys = Vec::new();
        let iter = table.iter().map_err(|e| {
            tracing::error!("Failed to iterate objects table: {}", e);
            HsmError::GeneralError
        })?;
        for entry in iter {
            if let Ok(entry) = entry {
                keys.push(entry.0.value().to_string());
            }
        }
        Ok(keys)
    }

    /// Clear all data from the store (used by C_InitToken)
    pub fn clear(&self) -> HsmResult<()> {
        let db = self.db.as_ref().ok_or(HsmError::GeneralError)?;

        let write_txn = db.begin_write().map_err(|e| {
            tracing::error!("Failed to begin write transaction for clear: {}", e);
            HsmError::GeneralError
        })?;
        {
            // Delete the entire table. A new one will be created on next write.
            let _ = write_txn.delete_table(OBJECTS_TABLE);
        }
        write_txn.commit().map_err(|e| {
            tracing::error!("Failed to commit clear transaction: {}", e);
            HsmError::GeneralError
        })?;
        Ok(())
    }
}

/// Set restrictive file permissions (owner-only read/write) on a path.
/// On Unix, sets mode 0o600. On Windows, sets a DACL granting only the
/// current user GENERIC_ALL access (removing inherited ACEs).
///
/// Failures are treated as **fatal**: a permission setting that silently
/// no-ops would leave HSM-managed files (database, lock, replay guard)
/// readable to other local users — exactly the threat this function
/// exists to defend against. Callers that need to tolerate environments
/// where permission changes cannot succeed (e.g., constrained containers,
/// network filesystems without ACL support) should explicitly opt into
/// the permissive path via [`set_restrictive_permissions_or_warn`].
pub fn set_restrictive_permissions(path: &std::path::Path) -> HsmResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|e| {
            tracing::error!(
                "Failed to set restrictive permissions on '{}': {} — refusing to continue with \
                 a potentially world-readable HSM file. Set explicit permissive mode if your \
                 environment cannot honor 0o600.",
                path.display(),
                e
            );
            HsmError::GeneralError
        })?;
        Ok(())
    }
    #[cfg(windows)]
    {
        set_restrictive_permissions_windows(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        // No supported permission model on this target; refuse rather than
        // silently leave the file world-accessible.
        tracing::error!(
            "No restrictive-permission backend for this target; cannot protect '{}'",
            path.display()
        );
        Err(HsmError::GeneralError)
    }
}

/// Permissive variant of [`set_restrictive_permissions`]. Logs a warning
/// on failure and continues. Use **only** when the caller has made an
/// informed choice that running with potentially loose permissions is
/// acceptable (e.g., test harnesses, opt-in deployment configurations).
#[allow(dead_code)]
pub fn set_restrictive_permissions_or_warn(path: &std::path::Path) {
    if let Err(_e) = set_restrictive_permissions(path) {
        tracing::warn!(
            "Continuing despite failure to restrict permissions on '{}' — file may be \
             accessible to other local users",
            path.display()
        );
    }
}

/// Windows implementation: set a DACL that grants only the current user
/// GENERIC_ALL, removing any inherited permissions from parent directories.
///
/// Returns `Err(HsmError::GeneralError)` on any FFI failure — silently
/// succeeding here would leave the file with whatever inherited ACEs the
/// parent directory has, which on a multi-user Windows host can include
/// `Users` or `Authenticated Users` reads.
#[cfg(windows)]
#[allow(unsafe_code)]
fn set_restrictive_permissions_windows(path: &std::path::Path) -> HsmResult<()> {
    use std::os::windows::ffi::OsStrExt;

    // Convert path to null-terminated wide string
    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: All FFI calls operate on valid handles and buffers with lengths
    // checked before use. The token handle is closed in all code paths.
    unsafe {
        use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, GENERIC_ALL};
        use windows_sys::Win32::Security::Authorization::{
            SetEntriesInAclW, SetNamedSecurityInfoW, EXPLICIT_ACCESS_W, SET_ACCESS, SE_FILE_OBJECT,
            TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
        };
        use windows_sys::Win32::Security::{
            GetTokenInformation, TokenUser, ACL, DACL_SECURITY_INFORMATION, NO_INHERITANCE,
            PROTECTED_DACL_SECURITY_INFORMATION, PSID, TOKEN_QUERY, TOKEN_USER,
        };
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        // Get current user's SID from the process token
        let mut token_handle = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle) == 0 {
            tracing::error!(
                "Failed to open process token for ACL setup on '{}'",
                path.display()
            );
            return Err(HsmError::GeneralError);
        }

        // Query token user info size
        let mut needed: u32 = 0;
        GetTokenInformation(
            token_handle,
            TokenUser,
            std::ptr::null_mut(),
            0,
            &mut needed,
        );
        if needed == 0 {
            CloseHandle(token_handle);
            tracing::error!("Failed to query token user size for '{}'", path.display());
            return Err(HsmError::GeneralError);
        }

        let mut token_buf: Vec<u8> = vec![0u8; needed as usize];
        if GetTokenInformation(
            token_handle,
            TokenUser,
            token_buf.as_mut_ptr() as *mut _,
            needed,
            &mut needed,
        ) == 0
        {
            CloseHandle(token_handle);
            tracing::error!("Failed to get token user info for '{}'", path.display());
            return Err(HsmError::GeneralError);
        }
        CloseHandle(token_handle);

        let token_user = &*(token_buf.as_ptr() as *const TOKEN_USER);
        let user_sid: PSID = token_user.User.Sid;

        // Build an EXPLICIT_ACCESS entry granting only the current user GENERIC_ALL
        let mut ea: EXPLICIT_ACCESS_W = std::mem::zeroed();
        ea.grfAccessPermissions = GENERIC_ALL;
        ea.grfAccessMode = SET_ACCESS;
        ea.grfInheritance = NO_INHERITANCE;
        ea.Trustee = TRUSTEE_W {
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation: 0,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_USER,
            ptstrName: user_sid as *mut u16,
        };

        // Create the new ACL
        let mut new_acl: *mut ACL = std::ptr::null_mut();
        let result = SetEntriesInAclW(1, &ea, std::ptr::null(), &mut new_acl);
        if result != 0 {
            tracing::error!(
                "SetEntriesInAclW failed ({}) for '{}'",
                result,
                path.display()
            );
            return Err(HsmError::GeneralError);
        }

        // Apply the DACL to the file with PROTECTED flag to block inheritance
        let result = SetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            new_acl,
            std::ptr::null_mut(),
        );
        let apply_err = if result != 0 {
            tracing::error!(
                "SetNamedSecurityInfoW failed ({}) for '{}'",
                result,
                path.display()
            );
            Some(HsmError::GeneralError)
        } else {
            None
        };

        if !new_acl.is_null() {
            LocalFree(new_acl as *mut _);
        }

        match apply_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

/// Derive an encryption key from a PIN using PBKDF2-HMAC-SHA256.
/// Returns (derived_key, salt). If salt is None, generates a new random salt.
/// The derived key is wrapped in `Zeroizing` so it is cleared on drop.
///
/// `iterations` controls the PBKDF2 work factor. Pass the value from
/// `HsmConfig::security.pbkdf2_iterations` so that runtime config is honored.
/// Falls back to `PBKDF2_ITERATIONS` if `None`.
pub fn derive_key_from_pin(
    pin: &[u8],
    salt: Option<&[u8]>,
    iterations: Option<u32>,
) -> (Zeroizing<[u8; KEY_LEN]>, Vec<u8>) {
    let salt_bytes = if let Some(s) = salt {
        s.to_vec()
    } else {
        let mut s = vec![0u8; SALT_LEN];
        // Route through DRBG for health testing & prediction resistance
        if let Ok(mut drbg) = HmacDrbg::new() {
            let _ = drbg.generate(&mut s);
        } else {
            // Fallback to OsRng if DRBG instantiation fails (should not happen)
            use rand::rngs::OsRng;
            use rand::RngCore;
            OsRng.fill_bytes(&mut s);
        }
        s
    };

    let iters = iterations.unwrap_or(PBKDF2_ITERATIONS);
    let mut derived_key = Zeroizing::new([0u8; KEY_LEN]);
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(pin, &salt_bytes, iters, derived_key.as_mut());

    (derived_key, salt_bytes)
}

/// Verify a PIN against a stored PBKDF2 hash.
/// The stored_hash format is: salt (32 bytes) || derived_key (32 bytes)
pub fn verify_pin_pbkdf2(stored_hash: &[u8], pin: &[u8], iterations: Option<u32>) -> bool {
    if stored_hash.len() != SALT_LEN + KEY_LEN {
        return false;
    }
    let salt = &stored_hash[..SALT_LEN];
    let stored_key = &stored_hash[SALT_LEN..];

    let (derived_key, _) = derive_key_from_pin(pin, Some(salt), iterations);

    use subtle::ConstantTimeEq;
    stored_key.ct_eq(derived_key.as_ref()).into()
}

/// Hash a PIN for storage using PBKDF2.
/// Returns `Zeroizing<Vec<u8>>` containing salt (32 bytes) || derived_key (32 bytes).
/// The wrapper ensures the derived key bytes are zeroized when dropped.
pub fn hash_pin_pbkdf2(pin: &[u8], iterations: Option<u32>) -> Zeroizing<Vec<u8>> {
    let (derived_key, salt) = derive_key_from_pin(pin, None, iterations);
    let mut result = Vec::with_capacity(SALT_LEN + KEY_LEN);
    result.extend_from_slice(&salt);
    result.extend_from_slice(derived_key.as_ref());
    Zeroizing::new(result)
}
