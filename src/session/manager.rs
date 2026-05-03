// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
use dashmap::DashMap;
use parking_lot::{Mutex, RwLock};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::handle::SessionHandleAllocator;
use super::session::Session;
use crate::error::{HsmError, HsmResult};
use crate::pkcs11_abi::constants::*;
use crate::pkcs11_abi::types::*;
use crate::token::token::Token;

thread_local! {
    /// Thread-local cache of the most recently accessed session.
    /// Avoids DashMap shard lock on repeated access to the same session.
    /// The `u64` is the generation counter at the time of caching; a mismatch
    /// against `SessionManager::generation` means sessions were removed and
    /// the cached entry may be stale (use-after-close defense).
    static TLS_SESSION_CACHE: RefCell<Option<(CK_SESSION_HANDLE, u64, Arc<RwLock<Session>>)>> = RefCell::new(None);
}

pub struct SessionManager {
    sessions: DashMap<CK_SESSION_HANDLE, Arc<RwLock<Session>>>,
    handle_alloc: SessionHandleAllocator,
    /// Maximum allowed idle time before a session is eligible for cleanup.
    /// `Duration::ZERO` means idle-timeout is disabled (default).
    idle_timeout: Duration,
    /// Monotonically increasing counter bumped every time one or more sessions
    /// are removed. The TLS cache stores the generation at cache-fill time;
    /// a mismatch forces a DashMap re-lookup, preventing use-after-close races.
    generation: AtomicU64,
    /// Side index: slot_id -> set of session handles open against that slot.
    ///
    /// Maintained alongside `sessions` so that slot-scoped operations
    /// (`logout_all`, `login_all`, `has_ro_sessions`) can find their
    /// sessions in O(handles-on-slot) instead of O(all-sessions).  The
    /// only legal lock ordering is **DashMap first, then `slot_index`**:
    /// callers read or mutate `sessions` first, then update `slot_index`
    /// to reflect the change.  Slot-scoped readers take `slot_index`
    /// briefly, *clone* the handle set, release the lock, and only then
    /// re-enter `sessions` for per-session work.  This avoids deadlock
    /// between the two locks.
    ///
    /// Race note: a session opened concurrently with a slot-scoped
    /// operation may not be visited by that operation if the index update
    /// has not yet completed.  This matches the pre-existing behavior of
    /// `login_all`'s two-phase loop (see the TOCTOU note on `login_all`)
    /// and is safe because freshly-opened sessions inherit token-level
    /// login state from `open_session` directly.
    slot_index: Mutex<HashMap<CK_SLOT_ID, HashSet<CK_SESSION_HANDLE>>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: DashMap::new(),
            handle_alloc: SessionHandleAllocator::new(),
            idle_timeout: Duration::ZERO,
            generation: AtomicU64::new(0),
            slot_index: Mutex::new(HashMap::new()),
        }
    }

    // ---- slot_index helpers ------------------------------------------------
    //
    // Each helper takes the `slot_index` lock briefly and never reaches into
    // `sessions` while holding it.  Callers MUST update `sessions` first and
    // only then call the index helper, to keep the documented lock order
    // (DashMap before slot_index) and avoid deadlocks.

    /// Record `handle` as open against `slot_id`.
    fn slot_index_insert(&self, slot_id: CK_SLOT_ID, handle: CK_SESSION_HANDLE) {
        self.slot_index
            .lock()
            .entry(slot_id)
            .or_default()
            .insert(handle);
    }

    /// Drop `handle` from `slot_id`'s entry, removing the entry entirely if it
    /// becomes empty.  Silently no-ops if the handle is unknown — `close_session`
    /// is the only caller that knows the slot, and other removal paths route
    /// through `slot_index_drop_many`.
    fn slot_index_remove(&self, slot_id: CK_SLOT_ID, handle: CK_SESSION_HANDLE) {
        let mut idx = self.slot_index.lock();
        if let Some(set) = idx.get_mut(&slot_id) {
            set.remove(&handle);
            if set.is_empty() {
                idx.remove(&slot_id);
            }
        }
    }

    /// Drop a batch of handles from the index.  Used by retain-style removals
    /// where the slot per handle isn't known up-front, so we sweep every slot.
    fn slot_index_drop_many(&self, handles: &[CK_SESSION_HANDLE]) {
        if handles.is_empty() {
            return;
        }
        let mut idx = self.slot_index.lock();
        for set in idx.values_mut() {
            for h in handles {
                set.remove(h);
            }
        }
        idx.retain(|_slot, set| !set.is_empty());
    }

    /// Snapshot the handle set for `slot_id`.  Returns an empty `Vec` if no
    /// sessions are open on that slot.  Caller iterates the snapshot against
    /// `sessions` *after* releasing the index lock.
    fn slot_index_snapshot(&self, slot_id: CK_SLOT_ID) -> Vec<CK_SESSION_HANDLE> {
        self.slot_index
            .lock()
            .get(&slot_id)
            .map(|set| set.iter().copied().collect())
            .unwrap_or_default()
    }

    #[cfg(test)]
    fn slot_index_len(&self, slot_id: CK_SLOT_ID) -> usize {
        self.slot_index
            .lock()
            .get(&slot_id)
            .map(|s| s.len())
            .unwrap_or(0)
    }

    /// Return the number of currently open sessions.
    pub fn sessions_len(&self) -> usize {
        self.sessions.len()
    }

    /// Set the idle timeout duration. Sessions that have been idle longer
    /// than this are eligible for removal by `cleanup_idle_sessions()`.
    /// A duration of zero disables idle-timeout (the default).
    pub fn set_idle_timeout(&mut self, timeout: Duration) {
        self.idle_timeout = timeout;
    }

    /// Remove all sessions that have been idle longer than the configured
    /// timeout. Returns the list of closed session handles.
    ///
    /// If idle timeout is disabled (zero), this is a no-op and returns an
    /// empty list.
    ///
    /// Eagerly zeroizes operation state on each removed session before
    /// dropping it (FIPS 140-3 §7.7).
    pub fn cleanup_idle_sessions(&self) -> Vec<CK_SESSION_HANDLE> {
        if self.idle_timeout.is_zero() {
            return Vec::new();
        }

        let mut closed_handles = Vec::new();
        let timeout = self.idle_timeout;

        self.sessions.retain(|&handle, session| {
            let mut s = session.write();
            if s.idle_duration() > timeout {
                // Mark session as closed so any thread still holding an Arc
                // can detect the close (TOCTOU defense).
                s.closed = true;
                // Eagerly zeroize CSPs before the session is dropped.
                s.active_operation = None;
                s.find_context = None;
                closed_handles.push(handle);
                false // remove
            } else {
                true // keep
            }
        });

        if !closed_handles.is_empty() {
            // Drop the closed handles from the slot side index.  We don't
            // know each session's slot_id here (the Session is gone), so
            // sweep all slot entries in one lock acquisition.
            self.slot_index_drop_many(&closed_handles);
            // Bump generation so TLS caches are invalidated (H3).
            self.generation.fetch_add(1, Ordering::Release);
            tracing::debug!(
                "Idle-timeout cleanup: closed {} session(s): {:?}",
                closed_handles.len(),
                closed_handles
            );
        }

        closed_handles
    }

    pub fn open_session(
        &self,
        slot_id: CK_SLOT_ID,
        flags: CK_FLAGS,
        token: &Token,
    ) -> HsmResult<CK_SESSION_HANDLE> {
        // CKF_SERIAL_SESSION is mandatory per PKCS#11 spec
        if (flags & CKF_SERIAL_SESSION) == 0 {
            return Err(HsmError::SessionParallelNotSupported);
        }

        let is_rw = (flags & CKF_RW_SESSION) != 0;

        // Check if SO is logged in — only RW sessions allowed
        if !is_rw {
            if token.login_state() == crate::token::token::LoginState::SoLoggedIn {
                return Err(HsmError::SessionReadWriteSoExists);
            }
        }

        token.increment_session_count(is_rw)?;

        let handle = self.handle_alloc.next()?;
        let mut session = Session::new(handle, slot_id, flags);

        // Inherit login state from token — roll back session count on failure
        let login_result = match token.login_state() {
            crate::token::token::LoginState::UserLoggedIn => session.on_user_login(),
            crate::token::token::LoginState::SoLoggedIn => session.on_so_login(),
            crate::token::token::LoginState::Public => Ok(()),
        };
        if let Err(e) = login_result {
            // Best-effort rollback — log but don't mask the original error
            if let Err(dec_err) = token.decrement_session_count(is_rw) {
                tracing::error!("open_session rollback: decrement failed: {:?}", dec_err);
            }
            return Err(e);
        }

        self.sessions.insert(handle, Arc::new(RwLock::new(session)));
        // DashMap insert is committed; now mirror into the side index.
        self.slot_index_insert(slot_id, handle);
        Ok(handle)
    }

    pub fn close_session(&self, handle: CK_SESSION_HANDLE, token: &Token) -> HsmResult<()> {
        let (_, session) = self
            .sessions
            .remove(&handle)
            .ok_or(HsmError::SessionHandleInvalid)?;
        // Bump generation AFTER removal so TLS caches are invalidated (H3).
        self.generation.fetch_add(1, Ordering::Release);
        // Invalidate TLS cache so stale Arc is not returned after close.
        Self::invalidate_session_cache(handle);
        // Eagerly zeroize CSPs held in active operations rather than
        // relying on Arc refcount reaching zero (another thread may
        // still hold a clone from get_session).
        let slot_id = {
            let mut s = session.write();
            s.closed = true;
            s.active_operation = None;
            s.find_context = None;
            // Propagate decrement errors — a double-close is a caller bug
            token.decrement_session_count(s.is_rw())?;
            s.slot_id
        };
        // Update the side index after the DashMap removal is committed and
        // the per-session lock has been released.
        self.slot_index_remove(slot_id, handle);
        Ok(())
    }

    pub fn close_all_sessions(&self, slot_id: CK_SLOT_ID, token: &Token) {
        // Invalidate TLS cache — any cached session for this slot is about
        // to be removed, and sessions for other slots are cheap to re-cache.
        Self::invalidate_all_session_caches();
        // Use DashMap::retain to atomically remove matching sessions while
        // holding each shard lock, preventing TOCTOU races where new sessions
        // could be opened between collecting handles and closing them.
        //
        // Decrement per-session to maintain accurate counts. Using
        // reset_session_counts() would corrupt counts for sessions on other
        // slots that share the same token.
        let mut closed: Vec<CK_SESSION_HANDLE> = Vec::new();
        self.sessions.retain(|&handle, session| {
            let mut s = session.write();
            if s.slot_id == slot_id {
                s.closed = true;
                // Best-effort: log decrement errors but continue closing
                if let Err(e) = token.decrement_session_count(s.is_rw()) {
                    tracing::error!("close_all_sessions: decrement failed: {:?}", e);
                }
                closed.push(handle);
                false // remove this entry
            } else {
                true // keep entries for other slots
            }
        });
        if !closed.is_empty() {
            // Drop all closed handles from the slot_id entry of the side
            // index in one lock acquisition.
            {
                let mut idx = self.slot_index.lock();
                if let Some(set) = idx.get_mut(&slot_id) {
                    for h in &closed {
                        set.remove(h);
                    }
                    if set.is_empty() {
                        idx.remove(&slot_id);
                    }
                }
            }
            // Bump generation AFTER removal so TLS caches are invalidated (H3).
            self.generation.fetch_add(1, Ordering::Release);
        }
    }

    pub fn get_session(&self, handle: CK_SESSION_HANDLE) -> HsmResult<Arc<RwLock<Session>>> {
        self.sessions
            .get(&handle)
            .map(|s| s.value().clone())
            .ok_or(HsmError::SessionHandleInvalid)
    }

    /// Get a session with thread-local caching.
    /// On cache hit (same handle AND same generation), returns the cached Arc
    /// without DashMap lookup.  A generation mismatch (sessions were removed
    /// since the cache was filled) forces a DashMap re-lookup, preventing
    /// use-after-close races (H3).
    ///
    /// Roadmap Near-Term: TLS session cache — implemented via TLS_SESSION_CACHE
    /// + generation counter.  Used by hot-path PKCS#11 entry points (C_Sign,
    /// C_Verify, C_Encrypt, C_Decrypt, C_Digest, C_GetSessionInfo, C_FindObjects,
    /// C_GenerateRandom) to skip the DashMap shard lock on repeated access.
    pub fn get_session_cached(&self, handle: CK_SESSION_HANDLE) -> HsmResult<Arc<RwLock<Session>>> {
        let current_gen = self.generation.load(Ordering::Acquire);

        // Check TLS cache first
        let cached = TLS_SESSION_CACHE.with(|cache| {
            let borrow = cache.borrow();
            if let Some((cached_handle, cached_gen, ref session)) = *borrow {
                if cached_handle == handle && cached_gen == current_gen {
                    return Some(Arc::clone(session));
                }
            }
            None
        });

        if let Some(session) = cached {
            return Ok(session);
        }

        // Cache miss (or generation mismatch) — look up in DashMap
        let session = self.get_session(handle)?;

        // Update TLS cache with current generation
        TLS_SESSION_CACHE.with(|cache| {
            *cache.borrow_mut() = Some((handle, current_gen, Arc::clone(&session)));
        });

        Ok(session)
    }

    /// Invalidate the TLS session cache for a specific handle.
    /// Called when a session is closed or its state changes significantly.
    pub fn invalidate_session_cache(handle: CK_SESSION_HANDLE) {
        TLS_SESSION_CACHE.with(|cache| {
            let mut borrow = cache.borrow_mut();
            if let Some((cached_handle, _, _)) = &*borrow {
                if *cached_handle == handle {
                    *borrow = None;
                }
            }
        });
    }

    /// Invalidate all TLS session caches.
    pub fn invalidate_all_session_caches() {
        TLS_SESSION_CACHE.with(|cache| {
            *cache.borrow_mut() = None;
        });
    }

    /// Login across all sessions for a given slot.
    ///
    /// Collects matching session handles first, then applies login state
    /// changes in a separate pass. This two-phase approach avoids holding
    /// DashMap shard locks while re-acquiring them during rollback, which
    /// could deadlock if a rollback handle hashes to the same shard.
    ///
    /// **TOCTOU note:** sessions opened between Phase 1 and Phase 2 are
    /// *not* visited by `login_all`, but they inherit login state from the
    /// token (via `open_session`), so they will already be in the correct
    /// state.  Sessions *closed* between phases are harmlessly skipped
    /// (the handle will be absent from the DashMap).  If handle recycling
    /// is ever introduced, the caller must ensure that a recycled handle
    /// cannot appear in Phase 2 pointing to a different session than the
    /// one collected in Phase 1 — the `slot_id` re-check provides a
    /// partial guard against this.
    pub fn login_all(&self, slot_id: CK_SLOT_ID, user_type: CK_ULONG) -> HsmResult<()> {
        if user_type != CKU_USER && user_type != CKU_SO {
            return Err(HsmError::UserTypeInvalid);
        }

        // Phase 1: collect handles via the side index (O(handles-on-slot)
        // instead of O(all-sessions)).  No DashMap shard locks are held
        // during the snapshot — the index Mutex is released immediately.
        let handles: Vec<CK_SESSION_HANDLE> = self.slot_index_snapshot(slot_id);

        // Phase 2: apply login to each session, tracking successes for rollback
        let mut logged_in: Vec<CK_SESSION_HANDLE> = Vec::new();
        for &handle in &handles {
            if let Some(entry) = self.sessions.get(&handle) {
                let mut s = entry.value().write();
                // Re-check slot_id in case session was replaced between phases
                if s.slot_id != slot_id {
                    continue;
                }
                let result = match user_type {
                    CKU_USER => s.on_user_login(),
                    CKU_SO => s.on_so_login(),
                    _ => unreachable!(),
                };
                if let Err(e) = result {
                    // Release current lock before rollback
                    drop(s);
                    drop(entry);
                    // Rollback: logout all sessions we already logged in
                    for &rollback_handle in &logged_in {
                        if let Some(rb_entry) = self.sessions.get(&rollback_handle) {
                            let mut rb = rb_entry.value().write();
                            let _ = rb.on_logout();
                        }
                    }
                    return Err(e);
                }
                logged_in.push(handle);
            }
        }
        Ok(())
    }

    /// Logout across all sessions for a given slot.
    ///
    /// Best-effort: iterates every matching session even if some fail.
    /// Individual failures are logged; the *first* error is propagated
    /// to the caller.  All reachable sessions are attempted regardless
    /// of errors so that partial-logout (some sessions logged in, some
    /// not) is minimised.
    pub fn logout_all(&self, slot_id: CK_SLOT_ID) -> HsmResult<()> {
        // Snapshot the slot's handles via the side index to skip the full
        // DashMap walk.  Sessions opened concurrently with this call may not
        // be visited (matching the pre-existing race window noted on
        // `login_all`); they inherit token-level state via `open_session`.
        let handles = self.slot_index_snapshot(slot_id);
        let mut first_err: Option<HsmError> = None;
        for handle in handles {
            let session = match self.sessions.get(&handle) {
                Some(s) => s.value().clone(),
                // Handle may have been closed between snapshot and lookup.
                None => continue,
            };
            let mut s = session.write();
            // Re-check slot_id as a guard against the (currently impossible)
            // case where handles are recycled between slots.
            if s.slot_id == slot_id && s.state.is_logged_in() {
                if let Err(e) = s.on_logout() {
                    tracing::error!("logout_all: failed to logout session {}: {:?}", s.handle, e);
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Check if a session has exceeded the idle timeout.
    /// Returns Ok(()) if the session is still valid, or Err(SessionClosed) if timed out.
    /// Also touches the session to reset the idle timer on successful check.
    ///
    /// **TOCTOU fix (H4):** When the session is timed out, we mark it as
    /// `closed` under the write lock *before* releasing the lock. This ensures
    /// any other thread that already holds an `Arc<RwLock<Session>>` will see
    /// the closed flag when it next acquires the lock. After marking closed,
    /// we drop the lock and then remove the entry from DashMap.
    pub fn check_and_touch(&self, handle: CK_SESSION_HANDLE) -> HsmResult<()> {
        let session = self.get_session(handle)?;
        let mut s = session.write();

        if !self.idle_timeout.is_zero() && s.idle_duration() > self.idle_timeout {
            // Mark session as closed while we still hold the write lock,
            // so any other thread holding a clone of this Arc sees the flag.
            s.closed = true;
            // Eagerly zeroize CSPs under the lock.
            s.active_operation = None;
            s.find_context = None;
            // Snapshot slot_id before releasing the session lock so we can
            // update the side index without re-locking the (closed) session.
            let slot_id = s.slot_id;
            // Now safe to release the lock — the closed flag protects against
            // concurrent use.
            drop(s);
            drop(session);
            // Remove from DashMap and bump generation for TLS cache invalidation.
            self.sessions.remove(&handle);
            self.slot_index_remove(slot_id, handle);
            self.generation.fetch_add(1, Ordering::Release);
            Self::invalidate_session_cache(handle);
            tracing::debug!("Session {} closed due to idle timeout", handle);
            return Err(HsmError::SessionClosed);
        }

        s.touch();
        Ok(())
    }

    pub fn has_ro_sessions(&self, slot_id: CK_SLOT_ID) -> bool {
        // Snapshot the slot's handle set first so we don't hold the
        // index lock while taking per-session read locks.
        let handles = self.slot_index_snapshot(slot_id);
        for handle in handles {
            if let Some(entry) = self.sessions.get(&handle) {
                let s = entry.value().read();
                if s.slot_id == slot_id && !s.is_rw() {
                    return true;
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn make_token() -> Token {
        Token::new()
    }

    #[test]
    fn cleanup_noop_when_timeout_disabled() {
        let mgr = SessionManager::new(); // idle_timeout = ZERO (default)
        let token = make_token();
        let flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
        let _h = mgr.open_session(0, flags, &token).unwrap();

        let closed = mgr.cleanup_idle_sessions();
        assert!(
            closed.is_empty(),
            "Should not close anything when timeout is disabled"
        );
    }

    #[test]
    fn cleanup_removes_idle_sessions() {
        let mut mgr = SessionManager::new();
        // Set a very short idle timeout so sessions are immediately eligible.
        mgr.set_idle_timeout(Duration::from_millis(1));

        let token = make_token();
        let flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
        let h1 = mgr.open_session(0, flags, &token).unwrap();
        let h2 = mgr.open_session(0, flags, &token).unwrap();

        // Sleep just past the timeout to ensure sessions are idle.
        std::thread::sleep(Duration::from_millis(10));

        let closed = mgr.cleanup_idle_sessions();
        assert_eq!(closed.len(), 2, "Both idle sessions should be closed");
        assert!(closed.contains(&h1));
        assert!(closed.contains(&h2));

        // Verify sessions are actually gone.
        assert!(mgr.get_session(h1).is_err());
        assert!(mgr.get_session(h2).is_err());
    }

    #[test]
    fn cleanup_keeps_active_sessions() {
        let mut mgr = SessionManager::new();
        mgr.set_idle_timeout(Duration::from_secs(60));

        let token = make_token();
        let flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
        let h = mgr.open_session(0, flags, &token).unwrap();

        // Session was just created, so idle_duration < 60s. It should survive cleanup.
        let closed = mgr.cleanup_idle_sessions();
        assert!(closed.is_empty(), "Fresh session should not be cleaned up");
        assert!(mgr.get_session(h).is_ok());
    }

    #[test]
    fn touch_resets_idle_duration() {
        let mut mgr = SessionManager::new();
        // Use generous timeout to avoid flaky failures under parallel CPU load.
        mgr.set_idle_timeout(Duration::from_secs(2));

        let token = make_token();
        let flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
        let h = mgr.open_session(0, flags, &token).unwrap();

        // Wait a bit, then touch to reset the idle timer.
        std::thread::sleep(Duration::from_millis(100));
        {
            let session = mgr.get_session(h).unwrap();
            let mut s = session.write();
            s.touch();
        }

        // Wait again — total wall time > initial sleep but time since touch < timeout.
        std::thread::sleep(Duration::from_millis(100));
        let closed = mgr.cleanup_idle_sessions();
        assert!(
            closed.is_empty(),
            "Touched session should not be cleaned up"
        );
        assert!(mgr.get_session(h).is_ok());
    }

    #[test]
    fn cleanup_zeroizes_active_operation() {
        let mut mgr = SessionManager::new();
        mgr.set_idle_timeout(Duration::from_millis(1));

        let token = make_token();
        let flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
        let h = mgr.open_session(0, flags, &token).unwrap();

        // Set up a dummy active operation on the session.
        {
            let session = mgr.get_session(h).unwrap();
            let mut s = session.write();
            s.active_operation = Some(super::super::session::ActiveOperation::Digest {
                mechanism: 0,
                hasher: None,
                accumulated_input: zeroize::Zeroizing::new(vec![0xAA; 32]),
            });
        }

        std::thread::sleep(Duration::from_millis(10));
        let closed = mgr.cleanup_idle_sessions();
        assert_eq!(closed.len(), 1);
        assert!(closed.contains(&h));
    }

    #[test]
    fn session_idle_duration_increases() {
        use super::super::session::Session;
        let s = Session::new(1, 0, CKF_SERIAL_SESSION | CKF_RW_SESSION);
        std::thread::sleep(Duration::from_millis(10));
        assert!(
            s.idle_duration() >= Duration::from_millis(5),
            "idle_duration should reflect elapsed time"
        );
    }

    #[test]
    fn tls_cache_hit_returns_same_arc() {
        let mgr = SessionManager::new();
        let token = make_token();
        let flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
        let h = mgr.open_session(0, flags, &token).unwrap();

        // First call populates the TLS cache (miss).
        let s1 = mgr.get_session_cached(h).unwrap();
        // Second call should hit the TLS cache.
        let s2 = mgr.get_session_cached(h).unwrap();

        assert!(
            Arc::ptr_eq(&s1, &s2),
            "Cache hit should return the same Arc"
        );
    }

    #[test]
    fn tls_cache_miss_falls_through_to_dashmap() {
        let mgr = SessionManager::new();
        let token = make_token();
        let flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
        let h = mgr.open_session(0, flags, &token).unwrap();

        // Ensure TLS cache is empty, then fetch via cached path.
        SessionManager::invalidate_all_session_caches();
        let session = mgr.get_session_cached(h).unwrap();
        let direct = mgr.get_session(h).unwrap();

        // Both should point to the same underlying session.
        assert!(Arc::ptr_eq(&session, &direct));
    }

    #[test]
    fn tls_cache_invalidation_clears_entry() {
        let mgr = SessionManager::new();
        let token = make_token();
        let flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
        let h = mgr.open_session(0, flags, &token).unwrap();

        // Populate the cache.
        let _ = mgr.get_session_cached(h).unwrap();

        // Invalidate for a different handle — should NOT clear.
        SessionManager::invalidate_session_cache(h + 999);
        let s1 = mgr.get_session_cached(h).unwrap();
        // Still a cache hit (same Arc as DashMap entry).
        let direct = mgr.get_session(h).unwrap();
        assert!(Arc::ptr_eq(&s1, &direct));

        // Invalidate for the correct handle.
        SessionManager::invalidate_session_cache(h);
        // Next call must go through DashMap again (cache miss).
        let s2 = mgr.get_session_cached(h).unwrap();
        // s2 should still resolve to the same session.
        assert!(Arc::ptr_eq(&s2, &direct));
    }

    #[test]
    fn tls_cache_different_handle_replaces_entry() {
        let mgr = SessionManager::new();
        let token = make_token();
        let flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
        let h1 = mgr.open_session(0, flags, &token).unwrap();
        let h2 = mgr.open_session(0, flags, &token).unwrap();

        // Populate cache with h1.
        let s1 = mgr.get_session_cached(h1).unwrap();
        // Now request h2 — should replace h1 in the cache.
        let s2 = mgr.get_session_cached(h2).unwrap();

        assert!(
            !Arc::ptr_eq(&s1, &s2),
            "Different handles should yield different Arcs"
        );

        // Requesting h2 again should be a cache hit.
        let s2_again = mgr.get_session_cached(h2).unwrap();
        assert!(Arc::ptr_eq(&s2, &s2_again));

        // Requesting h1 again is now a cache miss (replaced by h2),
        // but should still work via DashMap fallback.
        let s1_again = mgr.get_session_cached(h1).unwrap();
        assert!(Arc::ptr_eq(&s1, &s1_again));
    }

    #[test]
    fn close_session_invalidates_tls_cache() {
        let mgr = SessionManager::new();
        let token = make_token();
        let flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
        let h = mgr.open_session(0, flags, &token).unwrap();

        // Populate the TLS cache.
        let _ = mgr.get_session_cached(h).unwrap();

        // Close the session — should invalidate the cache.
        mgr.close_session(h, &token).unwrap();

        // Subsequent cached lookup should fail (session gone from DashMap).
        assert!(mgr.get_session_cached(h).is_err());
    }

    #[test]
    fn close_all_sessions_invalidates_tls_cache() {
        let mgr = SessionManager::new();
        let token = make_token();
        let flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
        let h = mgr.open_session(0, flags, &token).unwrap();

        // Populate the TLS cache.
        let _ = mgr.get_session_cached(h).unwrap();

        // Close all sessions for slot 0.
        mgr.close_all_sessions(0, &token);

        // Cached lookup should fail.
        assert!(mgr.get_session_cached(h).is_err());
    }

    #[test]
    fn check_and_touch_no_timeout_always_succeeds() {
        let mgr = SessionManager::new(); // idle_timeout = ZERO (default)
        let token = make_token();
        let flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
        let h = mgr.open_session(0, flags, &token).unwrap();

        // Even after a sleep, check_and_touch should succeed when timeout is disabled.
        std::thread::sleep(Duration::from_millis(10));
        assert!(mgr.check_and_touch(h).is_ok());
        assert!(mgr.get_session(h).is_ok(), "Session should still exist");
    }

    #[test]
    fn check_and_touch_active_session_succeeds() {
        let mut mgr = SessionManager::new();
        mgr.set_idle_timeout(Duration::from_secs(60));
        let token = make_token();
        let flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
        let h = mgr.open_session(0, flags, &token).unwrap();

        // Session was just created — well within timeout.
        assert!(mgr.check_and_touch(h).is_ok());
        assert!(mgr.get_session(h).is_ok());
    }

    #[test]
    fn check_and_touch_expired_session_returns_error() {
        let mut mgr = SessionManager::new();
        mgr.set_idle_timeout(Duration::from_millis(1));
        let token = make_token();
        let flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
        let h = mgr.open_session(0, flags, &token).unwrap();

        // Wait past the timeout.
        std::thread::sleep(Duration::from_millis(10));

        let result = mgr.check_and_touch(h);
        assert!(result.is_err(), "Should return error for expired session");
        // Verify the session was removed.
        assert!(
            mgr.get_session(h).is_err(),
            "Expired session should be removed"
        );
    }

    #[test]
    fn check_and_touch_resets_idle_timer() {
        let mut mgr = SessionManager::new();
        mgr.set_idle_timeout(Duration::from_millis(50));
        let token = make_token();
        let flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
        let h = mgr.open_session(0, flags, &token).unwrap();

        // Wait 30ms (within timeout), then touch.
        std::thread::sleep(Duration::from_millis(30));
        assert!(mgr.check_and_touch(h).is_ok());

        // Wait another 30ms — total wall time 60ms > 50ms timeout,
        // but time since touch is only ~30ms < 50ms.
        std::thread::sleep(Duration::from_millis(30));
        assert!(
            mgr.check_and_touch(h).is_ok(),
            "Session should survive because touch reset the idle timer"
        );
    }

    // ------------------------------------------------------------------
    // slot_index correctness
    // ------------------------------------------------------------------

    #[test]
    fn slot_index_tracks_open_close() {
        let mgr = SessionManager::new();
        let token = make_token();
        let flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

        let a = mgr.open_session(0, flags, &token).unwrap();
        let b = mgr.open_session(0, flags, &token).unwrap();
        let c = mgr.open_session(7, flags, &token).unwrap();

        assert_eq!(mgr.slot_index_len(0), 2);
        assert_eq!(mgr.slot_index_len(7), 1);
        assert_eq!(mgr.slot_index_len(99), 0);

        mgr.close_session(a, &token).unwrap();
        assert_eq!(mgr.slot_index_len(0), 1);

        mgr.close_session(b, &token).unwrap();
        // Empty slot entries are pruned so size goes back to 0.
        assert_eq!(mgr.slot_index_len(0), 0);

        mgr.close_session(c, &token).unwrap();
        assert_eq!(mgr.slot_index_len(7), 0);
    }

    #[test]
    fn slot_index_drops_on_close_all_sessions() {
        let mgr = SessionManager::new();
        let token = make_token();
        let flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

        let _ = mgr.open_session(0, flags, &token).unwrap();
        let _ = mgr.open_session(0, flags, &token).unwrap();
        let keep = mgr.open_session(1, flags, &token).unwrap();

        mgr.close_all_sessions(0, &token);

        assert_eq!(mgr.slot_index_len(0), 0);
        assert_eq!(mgr.slot_index_len(1), 1);
        assert!(mgr.get_session(keep).is_ok());
    }

    #[test]
    fn slot_index_drops_on_idle_cleanup() {
        let mut mgr = SessionManager::new();
        mgr.set_idle_timeout(Duration::from_millis(1));
        let token = make_token();
        let flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

        let _ = mgr.open_session(0, flags, &token).unwrap();
        let _ = mgr.open_session(2, flags, &token).unwrap();

        std::thread::sleep(Duration::from_millis(10));
        let closed = mgr.cleanup_idle_sessions();
        assert_eq!(closed.len(), 2);

        assert_eq!(mgr.slot_index_len(0), 0);
        assert_eq!(mgr.slot_index_len(2), 0);
    }

    #[test]
    fn logout_all_only_touches_target_slot_via_index() {
        let mgr = SessionManager::new();
        let token = make_token();
        // The token starts in Public state; we just verify the iteration
        // visits exactly the right handles by checking the index is empty
        // before / after for the untouched slot.
        let flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
        let _ = mgr.open_session(0, flags, &token).unwrap();
        let _ = mgr.open_session(0, flags, &token).unwrap();
        let other = mgr.open_session(5, flags, &token).unwrap();

        assert_eq!(mgr.slot_index_len(0), 2);
        assert_eq!(mgr.slot_index_len(5), 1);

        // No-op for Public sessions, but exercises the index snapshot path.
        mgr.logout_all(0).unwrap();

        // Sessions on slot 5 untouched.
        assert!(mgr.get_session(other).is_ok());
        assert_eq!(mgr.slot_index_len(5), 1);
    }

    #[test]
    fn has_ro_sessions_uses_index() {
        let mgr = SessionManager::new();
        let token = make_token();

        // RW session on slot 0; RO session on slot 1.
        let _ = mgr
            .open_session(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, &token)
            .unwrap();
        let _ = mgr.open_session(1, CKF_SERIAL_SESSION, &token).unwrap();

        assert!(!mgr.has_ro_sessions(0), "slot 0 has only RW");
        assert!(mgr.has_ro_sessions(1), "slot 1 has an RO session");
        assert!(!mgr.has_ro_sessions(99), "slot 99 has nothing");
    }
}
