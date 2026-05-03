// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use parking_lot::Mutex;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

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

/// Default threshold of pending operations before an automatic flush in
/// batched mode. `0` means "no automatic flush — caller must call
/// `flush()` explicitly", which is the default behavior of
/// [`EncryptedStore::enable_batched_writes`].
const DEFAULT_BATCH_THRESHOLD: usize = 0;

/// Encrypted persistent store backed by redb.
///
/// Objects are encrypted with AES-256-GCM using a key derived from
/// the user PIN via PBKDF2-HMAC-SHA256. The database file is protected
/// by an exclusive file lock (via `fs2`) to prevent concurrent access
/// from multiple processes.
///
/// # Batched commits (optional)
///
/// By default every [`store_encrypted`](Self::store_encrypted) and
/// [`delete`](Self::delete) call opens its own redb write transaction and
/// fsyncs on commit. For bulk-provisioning workloads this is the dominant
/// cost. Calling [`enable_batched_writes`](Self::enable_batched_writes)
/// switches the store into a mode where mutations are accumulated in
/// memory and only persisted on [`flush`](Self::flush) (or when the
/// configured threshold is reached). Reads transparently consult the
/// pending buffer first so callers see their own writes regardless of
/// mode.
///
/// **Crash-recovery note**: in batched mode any writes that have not
/// been flushed are lost on a crash or abrupt process exit. This is the
/// intended trade-off — the caller takes responsibility for choosing a
/// natural sync point (e.g., `C_Finalize`, end of bulk import).
pub struct EncryptedStore {
    db: Option<Database>,
    /// Hold the lock file open for the lifetime of the store.
    /// The exclusive lock is released when this file handle is dropped.
    _lock_file: Option<File>,
    /// When `true`, mutations are buffered in `pending_writes` /
    /// `pending_deletes` until `flush()` is called or the threshold is
    /// reached. See type-level documentation for crash-recovery caveats.
    batch_writes: AtomicBool,
    /// Auto-flush threshold (0 = manual flush only). Counts pending
    /// writes plus pending deletes — when the sum reaches this value,
    /// the next mutation triggers an implicit `flush()`.
    batch_flush_threshold: AtomicUsize,
    /// Encrypted blobs awaiting commit. Key = store_key, value =
    /// `nonce || ciphertext` (the same on-disk format used in redb).
    pending_writes: Mutex<HashMap<String, Vec<u8>>>,
    /// Store keys awaiting deletion. A delete shadows any pending write
    /// for the same key — see `delete()` for the precise semantics.
    pending_deletes: Mutex<HashSet<String>>,
}

impl Drop for EncryptedStore {
    fn drop(&mut self) {
        // Best-effort flush of any batched writes before releasing the
        // database. Failures are logged but not propagated — Drop cannot
        // return errors and we shouldn't panic.
        //
        // Callers that care about durability should call `flush()`
        // explicitly before drop; relying on Drop is best-effort because
        // a panic, abort, or process kill bypasses Drop entirely.
        if self.batch_writes.load(Ordering::Acquire)
            && (!self.pending_writes.lock().is_empty()
                || !self.pending_deletes.lock().is_empty())
        {
            if let Err(e) = self.flush() {
                tracing::error!(
                    "Best-effort flush during EncryptedStore drop failed: {:?} — \
                     pending writes were lost",
                    e
                );
            }
        }
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
                    batch_writes: AtomicBool::new(false),
                    batch_flush_threshold: AtomicUsize::new(DEFAULT_BATCH_THRESHOLD),
                    pending_writes: Mutex::new(HashMap::new()),
                    pending_deletes: Mutex::new(HashSet::new()),
                })
            }
            None => Ok(Self {
                db: None,
                _lock_file: None,
                batch_writes: AtomicBool::new(false),
                batch_flush_threshold: AtomicUsize::new(DEFAULT_BATCH_THRESHOLD),
                pending_writes: Mutex::new(HashMap::new()),
                pending_deletes: Mutex::new(HashSet::new()),
            }),
        }
    }

    /// Enable batched-commit mode.
    ///
    /// In batched mode, [`store_encrypted`](Self::store_encrypted) and
    /// [`delete`](Self::delete) accumulate operations in an in-memory
    /// buffer instead of opening a redb write transaction (and fsyncing)
    /// on every call. The buffered operations are committed atomically
    /// on the next [`flush`](Self::flush) call, when the
    /// `flush_threshold` is reached, when [`clear`](Self::clear) is
    /// called, or when this store is dropped.
    ///
    /// `flush_threshold` is the maximum number of pending operations
    /// (writes + deletes) the store will accumulate before performing an
    /// implicit flush. Pass `0` to require an explicit `flush()` call
    /// (most predictable behavior — recommended for bulk-import jobs
    /// where the caller knows the exact sync point).
    ///
    /// **Security / durability**: in batched mode, a crash, kernel
    /// panic, power loss, or abrupt process termination before the next
    /// flush will lose any token-object writes accumulated since the
    /// last successful flush. Callers must therefore reserve this mode
    /// for workloads where the lost-data window is acceptable —
    /// typical examples include initial provisioning, bulk key import,
    /// or test fixtures. For interactive HSM operation each
    /// `C_CreateObject` / `C_DestroyObject` should still hit the
    /// per-call commit path so the spec's durability guarantees hold.
    pub fn enable_batched_writes(&self, flush_threshold: usize) {
        self.batch_flush_threshold
            .store(flush_threshold, Ordering::Release);
        self.batch_writes.store(true, Ordering::Release);
    }

    /// Disable batched-commit mode and immediately flush any pending
    /// writes. Subsequent mutations will commit per-call as in normal
    /// mode.
    pub fn disable_batched_writes(&self) -> HsmResult<()> {
        // Flush first so we don't drop already-accepted writes when the
        // mode flag flips.
        self.flush()?;
        self.batch_writes.store(false, Ordering::Release);
        Ok(())
    }

    /// Returns `true` if batched-commit mode is currently active.
    pub fn is_batched(&self) -> bool {
        self.batch_writes.load(Ordering::Acquire)
    }

    /// Number of currently buffered operations (pending writes + pending
    /// deletes). Useful for callers that want to monitor flush pressure.
    pub fn pending_op_count(&self) -> usize {
        self.pending_writes.lock().len() + self.pending_deletes.lock().len()
    }

    /// Commit any pending writes / deletes accumulated in batched mode.
    ///
    /// All buffered operations are applied in a single redb write
    /// transaction so the on-disk view transitions atomically. After
    /// successful commit the in-memory buffers are cleared.
    ///
    /// Calling `flush()` when no operations are pending is a cheap
    /// no-op. Calling it when batched mode has never been enabled is
    /// also fine — buffers are empty.
    pub fn flush(&self) -> HsmResult<()> {
        let db = match self.db.as_ref() {
            Some(d) => d,
            // In-memory mode: nothing to persist, just drop the buffers.
            None => {
                self.pending_writes.lock().clear();
                self.pending_deletes.lock().clear();
                return Ok(());
            }
        };

        // Snapshot the buffers under their respective locks, then drop
        // the locks before doing the redb commit (which performs disk
        // I/O). This avoids blocking new writes for the duration of the
        // fsync.
        let writes = std::mem::take(&mut *self.pending_writes.lock());
        let deletes = std::mem::take(&mut *self.pending_deletes.lock());

        if writes.is_empty() && deletes.is_empty() {
            return Ok(());
        }

        let write_txn = db.begin_write().map_err(|e| {
            tracing::error!("Failed to begin write transaction for flush: {}", e);
            HsmError::GeneralError
        })?;
        {
            let mut table = write_txn.open_table(OBJECTS_TABLE).map_err(|e| {
                tracing::error!("Failed to open objects table for flush: {}", e);
                HsmError::GeneralError
            })?;

            for (k, v) in &writes {
                table.insert(k.as_str(), v.as_slice()).map_err(|e| {
                    tracing::error!("Failed to insert key '{}' during flush: {}", k, e);
                    HsmError::GeneralError
                })?;
            }
            for k in &deletes {
                // Ignore "not found" — a delete after a never-committed
                // write simply has no effect, which is what callers expect.
                table.remove(k.as_str()).map_err(|e| {
                    tracing::error!("Failed to remove key '{}' during flush: {}", k, e);
                    HsmError::GeneralError
                })?;
            }
        }
        write_txn.commit().map_err(|e| {
            tracing::error!("Failed to commit flush transaction: {}", e);
            HsmError::GeneralError
        })?;

        Ok(())
    }

    /// Check if persistent storage is available
    pub fn is_available(&self) -> bool {
        self.db.is_some()
    }

    /// Store an encrypted blob under a key.
    ///
    /// In batched-commit mode (see [`enable_batched_writes`](Self::enable_batched_writes))
    /// the encrypted blob is buffered in memory and is *not* fsynced to
    /// disk until [`flush`](Self::flush) is called or the configured
    /// auto-flush threshold is reached. In normal mode each call opens
    /// its own redb write transaction and commits synchronously.
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

        // Batched mode: buffer the encrypted blob and (possibly) flush.
        if self.batch_writes.load(Ordering::Acquire) {
            {
                let mut writes = self.pending_writes.lock();
                // A subsequent write to the same key supersedes any prior pending one.
                writes.insert(store_key.to_string(), stored);
                // A new write to a key supersedes a prior pending delete.
                self.pending_deletes.lock().remove(store_key);
            }
            self.maybe_auto_flush()?;
            return Ok(());
        }

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

    /// If batched mode is on and the buffer has reached the configured
    /// threshold, perform an implicit flush. A threshold of `0` means
    /// "flush only on explicit `flush()` calls".
    fn maybe_auto_flush(&self) -> HsmResult<()> {
        let threshold = self.batch_flush_threshold.load(Ordering::Acquire);
        if threshold == 0 {
            return Ok(());
        }
        let pending = self.pending_writes.lock().len() + self.pending_deletes.lock().len();
        if pending >= threshold {
            self.flush()?;
        }
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

        // In batched mode the in-memory buffer is the authoritative view
        // for keys it shadows: a pending delete hides the on-disk value,
        // a pending write supersedes it. Read-after-write must always
        // see the buffered state regardless of whether flush() has run.
        let pending: Option<Vec<u8>> = if self.batch_writes.load(Ordering::Acquire) {
            if self.pending_deletes.lock().contains(store_key) {
                return Ok(None);
            }
            self.pending_writes.lock().get(store_key).cloned()
        } else {
            None
        };

        let stored = if let Some(p) = pending {
            p
        } else {
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

            match table.get(store_key).map_err(|e| {
                tracing::error!("Failed to get key '{}': {}", store_key, e);
                HsmError::GeneralError
            })? {
                Some(data) => data.value().to_vec(),
                None => return Ok(None),
            }
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

    /// Delete a stored key.
    ///
    /// In batched-commit mode the deletion is buffered until
    /// [`flush`](Self::flush). A delete that arrives while a pending
    /// write for the same key is still buffered cancels both — the key
    /// will simply not be present after flush, matching the on-disk
    /// effect of a write-then-delete sequence.
    pub fn delete(&self, store_key: &str) -> HsmResult<()> {
        let db = self.db.as_ref().ok_or(HsmError::GeneralError)?;

        if self.batch_writes.load(Ordering::Acquire) {
            // Cancel any pending write for this key. If the key only
            // existed in the buffer (never flushed) we need not record
            // a delete tombstone — there's nothing on disk to remove.
            let had_pending_write = self.pending_writes.lock().remove(store_key).is_some();
            if !had_pending_write {
                self.pending_deletes.lock().insert(store_key.to_string());
            }
            self.maybe_auto_flush()?;
            return Ok(());
        }

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

    /// List all keys in the store.
    ///
    /// In batched-commit mode the returned list reflects the merged
    /// view of on-disk keys plus pending writes minus pending deletes,
    /// so callers always see the same set the next [`flush`](Self::flush)
    /// would produce.
    pub fn list_keys(&self) -> HsmResult<Vec<String>> {
        let db = self.db.as_ref().ok_or(HsmError::GeneralError)?;

        let read_txn = db.begin_read().map_err(|e| {
            tracing::error!("Failed to begin read transaction for list_keys: {}", e);
            HsmError::GeneralError
        })?;

        let table = match read_txn.open_table(OBJECTS_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => {
                // No on-disk table yet — return only pending writes (if any).
                if self.batch_writes.load(Ordering::Acquire) {
                    return Ok(self.pending_writes.lock().keys().cloned().collect());
                }
                return Ok(Vec::new());
            }
            Err(e) => {
                tracing::error!("Failed to open objects table for list_keys: {}", e);
                return Err(HsmError::GeneralError);
            }
        };

        let mut keys: HashSet<String> = HashSet::new();
        let iter = table.iter().map_err(|e| {
            tracing::error!("Failed to iterate objects table: {}", e);
            HsmError::GeneralError
        })?;
        for entry in iter {
            if let Ok(entry) = entry {
                keys.insert(entry.0.value().to_string());
            }
        }

        // Merge in pending writes / strip pending deletes when batched.
        if self.batch_writes.load(Ordering::Acquire) {
            let pending_writes = self.pending_writes.lock();
            for k in pending_writes.keys() {
                keys.insert(k.clone());
            }
            let pending_deletes = self.pending_deletes.lock();
            for k in pending_deletes.iter() {
                keys.remove(k);
            }
        }

        Ok(keys.into_iter().collect())
    }

    /// Clear all data from the store (used by C_InitToken).
    ///
    /// This always commits synchronously regardless of batched mode —
    /// `C_InitToken` is a destructive admin operation that must reach
    /// disk immediately. Any pending batched mutations are dropped
    /// (they would have been wiped anyway).
    pub fn clear(&self) -> HsmResult<()> {
        let db = self.db.as_ref().ok_or(HsmError::GeneralError)?;

        // Discard any unflushed writes/deletes — `clear()` makes them moot.
        self.pending_writes.lock().clear();
        self.pending_deletes.lock().clear();

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

#[cfg(test)]
mod tests {
    use super::*;

    /// Open a fresh `EncryptedStore` against a temp file and return the
    /// store plus the tempdir guard (drop the dir last to clean up).
    fn fresh_store() -> (EncryptedStore, tempfile::TempDir, [u8; KEY_LEN]) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.redb");
        let store = EncryptedStore::new(Some(path.to_str().unwrap())).unwrap();
        let (key, _) = derive_key_from_pin(b"test-pin", None, None);
        (store, dir, *key)
    }

    /// Spawn a fresh `EncryptedStore` reusing the existing on-disk file
    /// from `dir`. Used to simulate a process restart without losing the
    /// path.
    fn reopen_store(dir: &tempfile::TempDir) -> EncryptedStore {
        let path = dir.path().join("test.redb");
        EncryptedStore::new(Some(path.to_str().unwrap())).unwrap()
    }

    #[test]
    fn batched_writes_not_visible_on_disk_until_flush() {
        // Phase 1: write 5 objects in batched mode but DO NOT flush.
        let (store, dir, key) = fresh_store();
        store.enable_batched_writes(0); // explicit-flush only
        for i in 0..5 {
            store
                .store_encrypted(&format!("k{}", i), &[i as u8; 16], &key)
                .unwrap();
        }

        // Within the same store, batched reads see their own writes.
        for i in 0..5 {
            let got = store
                .load_encrypted(&format!("k{}", i), &key)
                .unwrap()
                .expect("write should be visible to its own store before flush");
            assert_eq!(got.as_slice(), &[i as u8; 16]);
        }
        assert_eq!(store.pending_op_count(), 5);

        // Drop the store WITHOUT calling flush. The Drop impl best-effort
        // flushes — to actually demonstrate "not yet on disk" we
        // explicitly forget the pending buffers first.
        store.pending_writes.lock().clear();
        store.pending_deletes.lock().clear();
        drop(store);

        // Phase 2: reopen the redb file from a fresh process-equivalent
        // state. Nothing should be there because we cleared the buffers
        // before drop.
        let store2 = reopen_store(&dir);
        for i in 0..5 {
            let got = store2.load_encrypted(&format!("k{}", i), &key).unwrap();
            assert!(got.is_none(), "key k{} unexpectedly persisted", i);
        }
    }

    #[test]
    fn batched_writes_appear_on_disk_after_flush() {
        let (store, dir, key) = fresh_store();
        store.enable_batched_writes(0);
        for i in 0..5 {
            store
                .store_encrypted(&format!("k{}", i), &[i as u8; 16], &key)
                .unwrap();
        }
        assert_eq!(store.pending_op_count(), 5);
        store.flush().unwrap();
        assert_eq!(store.pending_op_count(), 0);

        // Reopen and confirm all 5 are persisted.
        drop(store);
        let store2 = reopen_store(&dir);
        for i in 0..5 {
            let got = store2
                .load_encrypted(&format!("k{}", i), &key)
                .unwrap()
                .expect("post-flush keys must be on disk");
            assert_eq!(got.as_slice(), &[i as u8; 16]);
        }
    }

    #[test]
    fn batched_threshold_triggers_auto_flush() {
        let (store, dir, key) = fresh_store();
        // Threshold of 3 — the 3rd pending write should trigger flush.
        store.enable_batched_writes(3);

        store.store_encrypted("a", &[1; 4], &key).unwrap();
        assert_eq!(store.pending_op_count(), 1);
        store.store_encrypted("b", &[2; 4], &key).unwrap();
        assert_eq!(store.pending_op_count(), 2);
        // 3rd write hits threshold → auto-flushes immediately afterwards.
        store.store_encrypted("c", &[3; 4], &key).unwrap();
        assert_eq!(store.pending_op_count(), 0);

        // All three are now on disk.
        drop(store);
        let store2 = reopen_store(&dir);
        for k in ["a", "b", "c"] {
            assert!(store2.load_encrypted(k, &key).unwrap().is_some());
        }
    }

    #[test]
    fn batched_delete_cancels_pending_write() {
        let (store, _dir, key) = fresh_store();
        store.enable_batched_writes(0);
        store.store_encrypted("a", &[1; 4], &key).unwrap();
        store.delete("a").unwrap();
        // Both the pending write and pending delete should now be empty.
        assert_eq!(store.pending_op_count(), 0);
        // load_encrypted reflects the cancellation.
        assert!(store.load_encrypted("a", &key).unwrap().is_none());
    }

    #[test]
    fn batched_delete_after_flush_buffers_tombstone() {
        let (store, dir, key) = fresh_store();
        store.enable_batched_writes(0);
        store.store_encrypted("a", &[1; 4], &key).unwrap();
        store.flush().unwrap();
        store.delete("a").unwrap();
        // The write is on disk but the delete is buffered.
        assert_eq!(store.pending_op_count(), 1);
        // Read sees the tombstone.
        assert!(store.load_encrypted("a", &key).unwrap().is_none());

        // Without flush, drop and reopen — the row is still present
        // because the delete tombstone was never persisted.
        store.pending_writes.lock().clear();
        store.pending_deletes.lock().clear();
        drop(store);
        let store2 = reopen_store(&dir);
        assert!(store2.load_encrypted("a", &key).unwrap().is_some());
    }

    #[test]
    fn list_keys_merges_pending() {
        let (store, _dir, key) = fresh_store();
        // Start with one on-disk key (commit normally).
        store.store_encrypted("on_disk", &[9; 4], &key).unwrap();
        // Switch to batched mode and add a pending one + delete the on-disk one.
        store.enable_batched_writes(0);
        store
            .store_encrypted("only_pending", &[1; 4], &key)
            .unwrap();
        store.delete("on_disk").unwrap();

        let mut keys = store.list_keys().unwrap();
        keys.sort();
        assert_eq!(keys, vec!["only_pending".to_string()]);
    }

    #[test]
    fn disable_batched_writes_flushes() {
        let (store, dir, key) = fresh_store();
        store.enable_batched_writes(0);
        store.store_encrypted("a", &[1; 4], &key).unwrap();
        assert_eq!(store.pending_op_count(), 1);
        // disable_batched_writes() must flush before flipping the flag.
        store.disable_batched_writes().unwrap();
        assert_eq!(store.pending_op_count(), 0);
        assert!(!store.is_batched());

        drop(store);
        let store2 = reopen_store(&dir);
        assert!(store2.load_encrypted("a", &key).unwrap().is_some());
    }
}
