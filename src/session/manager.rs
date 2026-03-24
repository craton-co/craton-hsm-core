// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
use dashmap::DashMap;
use parking_lot::RwLock;
use std::sync::Arc;

use super::handle::SessionHandleAllocator;
use super::session::Session;
use crate::error::{HsmError, HsmResult};
use crate::pkcs11_abi::constants::*;
use crate::pkcs11_abi::types::*;
use crate::token::token::Token;

pub struct SessionManager {
    sessions: DashMap<CK_SESSION_HANDLE, Arc<RwLock<Session>>>,
    handle_alloc: SessionHandleAllocator,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: DashMap::new(),
            handle_alloc: SessionHandleAllocator::new(),
        }
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
        Ok(handle)
    }

    pub fn close_session(&self, handle: CK_SESSION_HANDLE, token: &Token) -> HsmResult<()> {
        let (_, session) = self
            .sessions
            .remove(&handle)
            .ok_or(HsmError::SessionHandleInvalid)?;
        // Eagerly zeroize CSPs held in active operations rather than
        // relying on Arc refcount reaching zero (another thread may
        // still hold a clone from get_session).
        {
            let mut s = session.write();
            s.active_operation = None;
            s.find_context = None;
            // Propagate decrement errors — a double-close is a caller bug
            token.decrement_session_count(s.is_rw())?;
        }
        Ok(())
    }

    pub fn close_all_sessions(&self, slot_id: CK_SLOT_ID, token: &Token) {
        // Use DashMap::retain to atomically remove matching sessions while
        // holding each shard lock, preventing TOCTOU races where new sessions
        // could be opened between collecting handles and closing them.
        //
        // Decrement per-session to maintain accurate counts. Using
        // reset_session_counts() would corrupt counts for sessions on other
        // slots that share the same token.
        self.sessions.retain(|_handle, session| {
            let s = session.read();
            if s.slot_id == slot_id {
                // Best-effort: log decrement errors but continue closing
                if let Err(e) = token.decrement_session_count(s.is_rw()) {
                    tracing::error!("close_all_sessions: decrement failed: {:?}", e);
                }
                false // remove this entry
            } else {
                true // keep entries for other slots
            }
        });
    }

    pub fn get_session(&self, handle: CK_SESSION_HANDLE) -> HsmResult<Arc<RwLock<Session>>> {
        self.sessions
            .get(&handle)
            .map(|s| s.value().clone())
            .ok_or(HsmError::SessionHandleInvalid)
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

        // Phase 1: collect handles for matching sessions (releases shard locks)
        let handles: Vec<CK_SESSION_HANDLE> = self
            .sessions
            .iter()
            .filter_map(|entry| {
                let s = entry.value().read();
                if s.slot_id == slot_id {
                    Some(*entry.key())
                } else {
                    None
                }
            })
            .collect();

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
        let mut first_err: Option<HsmError> = None;
        for entry in self.sessions.iter() {
            let session = entry.value();
            let mut s = session.write();
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

    pub fn has_ro_sessions(&self, slot_id: CK_SLOT_ID) -> bool {
        self.sessions.iter().any(|entry| {
            let s = entry.value().read();
            s.slot_id == slot_id && !s.is_rw()
        })
    }
}
