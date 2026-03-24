// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! gRPC HsmService implementation.
//!
//! All mutating operations require a valid session handle and appropriate
//! login state, mirroring the PKCS#11 access control model.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tonic::{Request, Response, Status};
use zeroize::Zeroize;

use craton_hsm::audit::log::{AuditOperation, AuditResult};
use craton_hsm::core::HsmCore;
use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm::pkcs11_abi::types::CK_ULONG;
use craton_hsm::token::token::LoginState;

/// (#5-fix) Maximum number of distinct slot entries in throttle maps before
/// oldest entries are evicted. Prevents memory exhaustion from attackers
/// probing thousands of distinct slot IDs.
const MAX_THROTTLE_ENTRIES: usize = 1024;

use crate::proto::hsm_service_server::HsmService;
use crate::proto::*;

/// Per-slot rate-limiting state for login attempts (#5).
struct LoginThrottle {
    failed_attempts: u32,
    lockout_until: Option<Instant>,
}

pub struct HsmServiceImpl {
    pub hsm: Arc<HsmCore>,
    pub max_random_length: u32,
    /// Maximum data payload for digest requests (#13).
    pub max_digest_length: u32,
    /// Brute-force protection (#5): per-slot login attempt tracking.
    /// NOTE: This state is in-memory only and resets on daemon restart.
    /// THREAT MODEL ASSUMPTION: Token-level PIN retry counters (in the core
    /// crate) provide persistent lockout that survives daemon restarts.
    /// If tokens are purely RAM-backed (no persistent storage), an attacker
    /// who can restart the daemon gets unlimited PIN attempts. Deployments
    /// using RAM-only tokens should configure an external rate limiter or
    /// use OS-level restart throttling (e.g., systemd RestartSec).
    login_attempts: std::sync::Mutex<HashMap<CK_ULONG, LoginThrottle>>,
    /// (#21) Brute-force protection for InitToken SO PIN attempts.
    /// Separate from login_attempts because InitToken does not require a session
    /// and a successful attack reinitializes the token, destroying all keys.
    init_token_attempts: std::sync::Mutex<HashMap<CK_ULONG, LoginThrottle>>,
    max_login_attempts: u32,
    login_cooldown: std::time::Duration,
}

impl HsmServiceImpl {
    pub fn new(
        hsm: Arc<HsmCore>,
        max_random_length: u32,
        max_digest_length: u32,
        max_login_attempts: u32,
        login_cooldown_secs: u64,
    ) -> Self {
        if max_login_attempts > 0 {
            tracing::warn!(
                "Login throttle is in-memory only — state resets on daemon restart. \
                 Token-level PIN retry counters provide persistent lockout."
            );
        }
        Self {
            hsm,
            max_random_length,
            max_digest_length,
            login_attempts: std::sync::Mutex::new(HashMap::new()),
            init_token_attempts: std::sync::Mutex::new(HashMap::new()),
            max_login_attempts,
            login_cooldown: std::time::Duration::from_secs(login_cooldown_secs),
        }
    }

    /// (#3) Acquire the login_attempts lock, recovering from poisoned state.
    /// A poisoned mutex means a thread panicked while holding the lock.
    /// We recover by taking the inner data — the HashMap may be inconsistent
    /// but that's better than crashing the entire daemon (DoS).
    fn lock_login_attempts(&self) -> std::sync::MutexGuard<'_, HashMap<CK_ULONG, LoginThrottle>> {
        self.login_attempts.lock().unwrap_or_else(|poisoned| {
            tracing::error!(
                "Login attempts mutex was poisoned — recovering. \
                 Throttle state may be inconsistent."
            );
            poisoned.into_inner()
        })
    }

    /// Check and enforce login rate limiting for a slot (#5).
    /// (#28) Always acquires the lock and performs a lookup to avoid timing
    /// side-channels that could distinguish first-attempt vs subsequent-attempt slots.
    fn check_login_throttle(&self, slot_id: CK_ULONG) -> Result<(), Status> {
        if self.max_login_attempts == 0 {
            return Ok(()); // Disabled, rely on token-level lockout
        }
        let mut attempts = self.lock_login_attempts();
        // Always do a lookup (even if entry doesn't exist) to keep timing consistent
        let throttle = attempts.get_mut(&slot_id);
        let is_locked = match throttle {
            Some(t) => match t.lockout_until {
                Some(until) if Instant::now() < until => {
                    let remaining = until.duration_since(Instant::now());
                    Some(remaining.as_secs() + 1)
                }
                Some(_) => {
                    // (#8) Cooldown has expired — reset the counter so the user
                    // gets a fresh set of attempts rather than immediately re-locking.
                    t.failed_attempts = 0;
                    t.lockout_until = None;
                    None
                }
                None => None,
            },
            None => None,
        };
        // Release lock before returning error to keep critical section short
        drop(attempts);

        if let Some(retry_secs) = is_locked {
            return Err(Status::resource_exhausted(format!(
                "Too many failed login attempts. Retry after {} seconds.",
                retry_secs
            )));
        }
        Ok(())
    }

    /// Record a failed login attempt for a slot (#5).
    fn record_login_failure(&self, slot_id: CK_ULONG) {
        if self.max_login_attempts == 0 {
            return;
        }
        let mut attempts = self.lock_login_attempts();
        // (#5-fix) Evict expired entries to bound memory growth
        evict_expired_throttle_entries(&mut attempts);
        let throttle = attempts.entry(slot_id).or_insert(LoginThrottle {
            failed_attempts: 0,
            lockout_until: None,
        });
        // (#9-fix) Use saturating_add to prevent u32 overflow
        throttle.failed_attempts = throttle.failed_attempts.saturating_add(1);
        if throttle.failed_attempts >= self.max_login_attempts {
            throttle.lockout_until = Some(Instant::now() + self.login_cooldown);
            tracing::warn!(
                slot_id,
                "Login lockout triggered after {} failed attempts",
                throttle.failed_attempts
            );
        }
    }

    /// (#21) Acquire the init_token_attempts lock, recovering from poisoned state.
    fn lock_init_token_attempts(
        &self,
    ) -> std::sync::MutexGuard<'_, HashMap<CK_ULONG, LoginThrottle>> {
        self.init_token_attempts.lock().unwrap_or_else(|poisoned| {
            tracing::error!(
                "InitToken attempts mutex was poisoned — recovering. \
                 Throttle state may be inconsistent."
            );
            poisoned.into_inner()
        })
    }

    /// (#21) Check and enforce rate limiting for InitToken SO PIN attempts.
    /// (#4-fix) Always acquires the lock and performs a lookup to keep timing
    /// consistent, mirroring check_login_throttle (#28).
    fn check_init_token_throttle(&self, slot_id: CK_ULONG) -> Result<(), Status> {
        if self.max_login_attempts == 0 {
            return Ok(()); // Disabled, rely on token-level lockout
        }
        let mut attempts = self.lock_init_token_attempts();
        // Always do a lookup (even if entry doesn't exist) to keep timing consistent
        let throttle = attempts.get_mut(&slot_id);
        let is_locked = match throttle {
            Some(t) => match t.lockout_until {
                Some(until) if Instant::now() < until => {
                    let remaining = until.duration_since(Instant::now());
                    Some(remaining.as_secs() + 1)
                }
                Some(_) => {
                    // Cooldown has expired — reset the counter
                    t.failed_attempts = 0;
                    t.lockout_until = None;
                    None
                }
                None => None,
            },
            None => None,
        };
        // Release lock before returning error to keep critical section short
        drop(attempts);

        if let Some(retry_secs) = is_locked {
            return Err(Status::resource_exhausted(format!(
                "Too many failed InitToken attempts. Retry after {} seconds.",
                retry_secs
            )));
        }
        Ok(())
    }

    /// (#21) Record a failed InitToken attempt for a slot.
    fn record_init_token_failure(&self, slot_id: CK_ULONG) {
        if self.max_login_attempts == 0 {
            return;
        }
        let mut attempts = self.lock_init_token_attempts();
        // (#5-fix) Evict expired entries to bound memory growth
        evict_expired_throttle_entries(&mut attempts);
        let throttle = attempts.entry(slot_id).or_insert(LoginThrottle {
            failed_attempts: 0,
            lockout_until: None,
        });
        // (#9-fix) Use saturating_add to prevent u32 overflow
        throttle.failed_attempts = throttle.failed_attempts.saturating_add(1);
        if throttle.failed_attempts >= self.max_login_attempts {
            throttle.lockout_until = Some(Instant::now() + self.login_cooldown);
            tracing::warn!(
                slot_id,
                "InitToken lockout triggered after {} failed attempts",
                throttle.failed_attempts
            );
        }
    }

    /// (#21) Clear InitToken attempt counter on success.
    fn clear_init_token_attempts(&self, slot_id: CK_ULONG) {
        if self.max_login_attempts == 0 {
            return;
        }
        let mut attempts = self.lock_init_token_attempts();
        attempts.remove(&slot_id);
    }

    /// Clear login attempt counter on successful login (#5).
    fn clear_login_attempts(&self, slot_id: CK_ULONG) {
        if self.max_login_attempts == 0 {
            return;
        }
        let mut attempts = self.lock_login_attempts();
        attempts.remove(&slot_id);
    }

    /// Record an audit event and propagate failures as gRPC errors.
    /// FIPS 140-3 requires that security-relevant events are recorded; if the
    /// audit log cannot write, the operation must be blocked.
    fn audit(
        &self,
        session_handle: u64,
        operation: AuditOperation,
        result: AuditResult,
        key_id: Option<String>,
    ) -> Result<(), Status> {
        self.hsm
            .audit_log()
            .record(session_handle, operation, result, key_id)
            .map_err(|e| {
                tracing::error!("Audit log write failed: {:?}", e);
                Status::internal("Audit system failure")
            })
    }
}

/// (#12) Safely convert a u64 (from protobuf) to CK_ULONG without silent truncation.
fn to_ck_ulong(value: u64, field_name: &str) -> Result<CK_ULONG, Status> {
    value.try_into().map_err(|_| {
        Status::invalid_argument(format!(
            "{} value {} exceeds platform maximum",
            field_name, value
        ))
    })
}

/// Verify that a valid session exists.
/// Returns the session's slot_id on success.
fn require_session(hsm: &HsmCore, session_handle: u64) -> Result<CK_ULONG, Status> {
    let handle = to_ck_ulong(session_handle, "session_handle")?;
    let sess = hsm
        .session_manager()
        .get_session(handle)
        .map_err(hsm_err_to_status)?;
    let slot_id = sess.read().slot_id;
    Ok(slot_id)
}

/// Verify that the token is logged in (user or SO).
///
/// Uses the atomic `require_login` method instead of the snapshot-based
/// `login_state()` to prevent TOCTOU races where a concurrent `logout()`
/// could occur between the check and the protected operation.
fn require_logged_in(hsm: &HsmCore, slot_id: CK_ULONG) -> Result<(), Status> {
    let token = hsm
        .slot_manager()
        .get_token(slot_id)
        .map_err(hsm_err_to_status)?;
    // Try user login first; if SO is logged in instead, that's also acceptable
    match token.require_login(&LoginState::UserLoggedIn) {
        Ok(()) => Ok(()),
        Err(craton_hsm::error::HsmError::UserAnotherAlreadyLoggedIn) => {
            // SO is logged in — also acceptable for general "logged in" check
            Ok(())
        }
        Err(_) => Err(Status::permission_denied(
            "Not logged in — call Login first",
        )),
    }
}

/// Verify session exists AND token is logged in. Returns slot_id.
fn require_authenticated_session(hsm: &HsmCore, session_handle: u64) -> Result<CK_ULONG, Status> {
    let slot_id = require_session(hsm, session_handle)?;
    require_logged_in(hsm, slot_id)?;
    Ok(slot_id)
}

/// (#24) Slot isolation: `StoredObject` now carries a `slot_id` field.
/// The daemon enforces slot-scoping in find_objects, get_attribute_value,
/// and destroy_object. Objects created on one slot are not visible or
/// accessible from sessions on another slot.
///
/// (#4) Attributes that callers must NOT set directly via GenerateKey.
/// These security-critical attributes must be derived from the mechanism
/// or enforced by policy, not supplied by the caller.
/// Retained for use when mechanism dispatch is implemented (#20).
#[allow(dead_code)]
const FORBIDDEN_TEMPLATE_ATTRS: &[u64] = &[
    CKA_SENSITIVE as u64,
    CKA_EXTRACTABLE as u64,
    CKA_ALWAYS_SENSITIVE as u64,
    CKA_NEVER_EXTRACTABLE as u64,
    CKA_TRUSTED as u64,
];

#[tonic::async_trait]
impl HsmService for HsmServiceImpl {
    async fn open_session(
        &self,
        request: Request<OpenSessionRequest>,
    ) -> Result<Response<OpenSessionResponse>, Status> {
        let req = request.into_inner();
        let slot_id = to_ck_ulong(req.slot_id, "slot_id")?;
        let flags = if req.read_write {
            CKF_SERIAL_SESSION | CKF_RW_SESSION
        } else {
            CKF_SERIAL_SESSION
        };

        let token = self
            .hsm
            .slot_manager()
            .get_token(slot_id)
            .map_err(hsm_err_to_status)?;
        let handle = self
            .hsm
            .session_manager()
            .open_session(slot_id, flags as CK_ULONG, &token)
            .map_err(hsm_err_to_status)?;

        // (#18) Audit session open
        self.audit(
            handle as u64,
            AuditOperation::OpenSession {
                slot_id: slot_id as u64,
            },
            AuditResult::Success,
            None,
        )?;

        Ok(Response::new(OpenSessionResponse {
            session_handle: handle as u64,
        }))
    }

    async fn close_session(
        &self,
        request: Request<CloseSessionRequest>,
    ) -> Result<Response<CloseSessionResponse>, Status> {
        let req = request.into_inner();
        let session_handle = to_ck_ulong(req.session_handle, "session_handle")?;
        // (#2) Derive slot_id from session, not hardcoded 0
        let slot_id = require_session(&self.hsm, req.session_handle)?;
        let token = self
            .hsm
            .slot_manager()
            .get_token(slot_id)
            .map_err(hsm_err_to_status)?;
        self.hsm
            .session_manager()
            .close_session(session_handle, &token)
            .map_err(hsm_err_to_status)?;

        // (#18) Audit session close
        self.audit(
            req.session_handle,
            AuditOperation::CloseSession,
            AuditResult::Success,
            None,
        )?;

        Ok(Response::new(CloseSessionResponse {}))
    }

    async fn login(
        &self,
        request: Request<LoginRequest>,
    ) -> Result<Response<LoginResponse>, Status> {
        let mut req = request.into_inner();

        // (#11-fix) Validate user_type against PKCS#11 constants before passing to core.
        let user_type_ck = to_ck_ulong(req.user_type, "user_type")?;
        if user_type_ck != CKU_USER
            && user_type_ck != CKU_SO
            && user_type_ck != CKU_CONTEXT_SPECIFIC
        {
            return Err(Status::invalid_argument(format!(
                "Invalid user_type {}. Expected CKU_USER (1), CKU_SO (0), or CKU_CONTEXT_SPECIFIC (2)",
                req.user_type
            )));
        }

        // (#3) Validate the session handle — login requires a valid session per PKCS#11
        let slot_id = require_session(&self.hsm, req.session_handle)?;

        // (#5) Check brute-force throttle before attempting login
        self.check_login_throttle(slot_id)?;

        // (#2) Use slot from session, not hardcoded 0
        let token = self
            .hsm
            .slot_manager()
            .get_token(slot_id)
            .map_err(hsm_err_to_status)?;

        // (#2) PIN is now `bytes` in proto — use directly, then zeroize
        let result = token.login(user_type_ck, &req.pin);

        // Zeroize PIN material immediately after use, regardless of outcome
        req.pin.zeroize();

        match result {
            Ok(()) => {
                // (#5) Clear failed attempts on success
                self.clear_login_attempts(slot_id);

                // (#18) Audit successful login
                self.audit(
                    req.session_handle,
                    AuditOperation::Login {
                        user_type: req.user_type,
                    },
                    AuditResult::Success,
                    None,
                )?;

                Ok(Response::new(LoginResponse {}))
            }
            Err(e) => {
                // (#5) Record failed attempt
                self.record_login_failure(slot_id);

                // (#18) Audit failed login — convert to status (which also logs server-side)
                let status = hsm_err_to_status(e);

                // (#30) Log audit failure but return the original login error to the
                // client — otherwise an audit failure would mask the real error and
                // leak internal state (audit failures return a different error code).
                if let Err(audit_err) = self.audit(
                    req.session_handle,
                    AuditOperation::Login {
                        user_type: req.user_type,
                    },
                    AuditResult::Failure(0),
                    None,
                ) {
                    tracing::error!("Audit write failed for login failure: {:?}", audit_err);
                }

                Err(status)
            }
        }
    }

    async fn logout(
        &self,
        request: Request<LogoutRequest>,
    ) -> Result<Response<LogoutResponse>, Status> {
        let req = request.into_inner();

        // (#3) Validate the session handle — logout requires a valid session per PKCS#11
        let slot_id = require_session(&self.hsm, req.session_handle)?;

        // (#2) Use slot from session, not hardcoded 0
        let token = self
            .hsm
            .slot_manager()
            .get_token(slot_id)
            .map_err(hsm_err_to_status)?;

        token.logout().map_err(hsm_err_to_status)?;

        // (#18) Audit logout
        self.audit(
            req.session_handle,
            AuditOperation::Logout,
            AuditResult::Success,
            None,
        )?;

        Ok(Response::new(LogoutResponse {}))
    }

    async fn get_token_info(
        &self,
        request: Request<GetTokenInfoRequest>,
    ) -> Result<Response<GetTokenInfoResponse>, Status> {
        let req = request.into_inner();
        let slot_id = to_ck_ulong(req.slot_id, "slot_id")?;

        // (#26) Require a valid session to prevent unauthenticated slot enumeration.
        // Callers must supply a session_handle to prove they have an open session
        // on this slot. This prevents reconnaissance of token state (login_state,
        // session counts, initialized status) by unauthenticated callers.
        if req.session_handle != 0 {
            let session_slot = require_session(&self.hsm, req.session_handle)?;
            if session_slot != slot_id {
                return Err(Status::permission_denied(
                    "Session does not belong to the requested slot",
                ));
            }
        } else {
            return Err(Status::invalid_argument(
                "session_handle is required — open a session first",
            ));
        }

        let token = self
            .hsm
            .slot_manager()
            .get_token(slot_id)
            .map_err(hsm_err_to_status)?;

        // Only expose non-sensitive fields to unauthenticated callers
        let is_logged_in = !matches!(token.login_state(), LoginState::Public);

        let mut response = GetTokenInfoResponse {
            label: String::new(),
            initialized: token.is_initialized(),
            user_pin_initialized: token.is_user_pin_initialized(),
            // (#5) Redact login state for unauthenticated callers
            login_state: if is_logged_in {
                format!("{:?}", token.login_state())
            } else {
                "Restricted".to_string()
            },
            // (#5) Redact session counts for unauthenticated callers
            session_count: 0,
            max_sessions: token.max_sessions(),
            rw_session_count: 0,
            max_rw_sessions: token.max_rw_sessions(),
        };

        if is_logged_in {
            response.session_count = token.session_count();
            response.rw_session_count = token.rw_session_count();
        }

        Ok(Response::new(response))
    }

    async fn init_token(
        &self,
        request: Request<InitTokenRequest>,
    ) -> Result<Response<InitTokenResponse>, Status> {
        let mut req = request.into_inner();
        let slot_id = to_ck_ulong(req.slot_id, "slot_id")?;

        // (#21) Check brute-force throttle before attempting InitToken.
        // A successful SO PIN brute-force reinitializes the token, destroying all keys.
        self.check_init_token_throttle(slot_id)?;

        let token = self
            .hsm
            .slot_manager()
            .get_token(slot_id)
            .map_err(hsm_err_to_status)?;

        let mut label_bytes = [b' '; 32];
        let copy_len = req.label.len().min(32);
        label_bytes[..copy_len].copy_from_slice(&req.label.as_bytes()[..copy_len]);

        // (#2) SO PIN is now `bytes` in proto — use directly, then zeroize
        let result = token.init_token(&req.so_pin, &label_bytes);

        // Zeroize SO PIN material immediately after use
        req.so_pin.zeroize();

        match result {
            Ok(()) => {
                // (#21) Clear failed attempts on success
                self.clear_init_token_attempts(slot_id);

                // (#18) Audit token initialization
                self.audit(
                    0, // No session for InitToken
                    AuditOperation::InitToken {
                        slot_id: slot_id as u64,
                    },
                    AuditResult::Success,
                    None,
                )?;
                tracing::warn!(slot_id, "Token initialized via gRPC");
                Ok(Response::new(InitTokenResponse {}))
            }
            Err(e) => {
                // (#21) Record failed attempt
                self.record_init_token_failure(slot_id);

                // (#18) Audit failed init attempt
                let status = hsm_err_to_status(e);
                // (#30) Log audit failure but return the original error
                if let Err(audit_err) = self.audit(
                    0,
                    AuditOperation::InitToken {
                        slot_id: slot_id as u64,
                    },
                    AuditResult::Failure(0),
                    None,
                ) {
                    tracing::error!("Audit write failed for InitToken failure: {:?}", audit_err);
                }
                Err(status)
            }
        }
    }

    async fn generate_key(
        &self,
        request: Request<GenerateKeyRequest>,
    ) -> Result<Response<GenerateKeyResponse>, Status> {
        let req = request.into_inner();

        let slot_id = require_authenticated_session(&self.hsm, req.session_handle)?;

        let mech = req
            .mechanism
            .ok_or_else(|| Status::invalid_argument("mechanism required"))?;
        let mech_type = to_ck_ulong(mech.mechanism_type, "mechanism_type")?;

        if !craton_hsm::crypto::mechanisms::is_keygen_mechanism(mech_type) {
            return Err(Status::invalid_argument(
                "Unsupported key generation mechanism",
            ));
        }

        // Validate algorithm policy
        craton_hsm::crypto::mechanisms::validate_mechanism_for_policy(
            mech_type,
            self.hsm.algorithm_config(),
            false,
        )
        .map_err(|_| Status::permission_denied("Mechanism blocked by algorithm policy"))?;

        let fips_mode = self.hsm.algorithm_config().fips_approved_only;
        let fips_approved = craton_hsm::crypto::mechanisms::is_fips_approved(mech_type);

        // Parse template for CKA_VALUE_LEN (key size in bytes)
        let template = proto_attrs_to_template(&req.template)?;
        let key_len = template
            .iter()
            .find(|(t, _)| *t == CKA_VALUE_LEN)
            .and_then(|(_, v)| craton_hsm::store::attributes::read_ck_ulong(v))
            .ok_or_else(|| {
                Status::invalid_argument("CKA_VALUE_LEN required in template for key generation")
            })? as usize;

        // Generate key material based on mechanism
        let key_material = match mech_type {
            CKM_AES_KEY_GEN => craton_hsm::crypto::keygen::generate_aes_key(key_len, fips_mode)
                .map_err(hsm_err_to_status)?,
            _ => return Err(Status::invalid_argument("Unsupported keygen mechanism")),
        };

        // Build StoredObject
        let handle = self
            .hsm
            .object_store()
            .next_handle()
            .map_err(hsm_err_to_status)?;
        let mut obj = craton_hsm::store::object::StoredObject::new(handle, CKO_SECRET_KEY);
        obj.slot_id = slot_id;
        obj.key_type = Some(CKK_AES);
        obj.value_len = Some(key_len as CK_ULONG);
        obj.key_material = Some(key_material);
        obj.can_encrypt = true;
        obj.can_decrypt = true;
        obj.sensitive = true;
        obj.extractable = false;

        // Apply template attributes (label, token, private, etc.)
        for (attr_type, value) in &template {
            if *attr_type == CKA_VALUE_LEN {
                continue; // already handled
            }
            craton_hsm::store::attributes::apply_attribute(&mut obj, *attr_type, value)
                .map_err(hsm_err_to_status)?;
        }

        let key_handle = self
            .hsm
            .object_store()
            .insert_object(obj)
            .map_err(hsm_err_to_status)?;

        self.audit(
            req.session_handle,
            AuditOperation::GenerateKey {
                mechanism: mech_type as u64,
                key_length: key_len as u32,
                fips_approved,
            },
            AuditResult::Success,
            Some(format!("handle={}", key_handle)),
        )?;

        Ok(Response::new(GenerateKeyResponse {
            key_handle: key_handle as u64,
        }))
    }

    async fn generate_key_pair(
        &self,
        request: Request<GenerateKeyPairRequest>,
    ) -> Result<Response<GenerateKeyPairResponse>, Status> {
        let req = request.into_inner();

        let slot_id = require_authenticated_session(&self.hsm, req.session_handle)?;

        let mech = req
            .mechanism
            .ok_or_else(|| Status::invalid_argument("mechanism required"))?;
        let mech_type = to_ck_ulong(mech.mechanism_type, "mechanism_type")?;

        if !craton_hsm::crypto::mechanisms::is_keypair_gen_mechanism(mech_type) {
            return Err(Status::invalid_argument(
                "Unsupported key pair generation mechanism",
            ));
        }

        craton_hsm::crypto::mechanisms::validate_mechanism_for_policy(
            mech_type,
            self.hsm.algorithm_config(),
            false,
        )
        .map_err(|_| Status::permission_denied("Mechanism blocked by algorithm policy"))?;

        let fips_mode = self.hsm.algorithm_config().fips_approved_only;
        let fips_approved = craton_hsm::crypto::mechanisms::is_fips_approved(mech_type);
        let pub_template = proto_attrs_to_template(&req.public_template)?;
        let priv_template = proto_attrs_to_template(&req.private_template)?;

        // Allocate handles upfront
        let pub_handle = self
            .hsm
            .object_store()
            .next_handle()
            .map_err(hsm_err_to_status)?;
        let priv_handle = self
            .hsm
            .object_store()
            .next_handle()
            .map_err(hsm_err_to_status)?;

        let mut pub_obj;
        let mut priv_obj;
        let key_length: u32;

        match mech_type {
            CKM_RSA_PKCS_KEY_PAIR_GEN => {
                // Parse CKA_MODULUS_BITS from public template
                let modulus_bits = pub_template
                    .iter()
                    .find(|(t, _)| *t == CKA_MODULUS_BITS)
                    .and_then(|(_, v)| craton_hsm::store::attributes::read_ck_ulong(v))
                    .ok_or_else(|| {
                        Status::invalid_argument("CKA_MODULUS_BITS required in public template")
                    })? as u32;

                key_length = modulus_bits;

                let (private_key_der, modulus, pub_exponent) =
                    craton_hsm::crypto::keygen::generate_rsa_key_pair(modulus_bits, fips_mode)
                        .map_err(hsm_err_to_status)?;

                pub_obj = craton_hsm::store::object::StoredObject::new(pub_handle, CKO_PUBLIC_KEY);
                pub_obj.slot_id = slot_id;
                pub_obj.key_type = Some(CKK_RSA);
                pub_obj.modulus = Some(modulus.clone());
                pub_obj.modulus_bits = Some(modulus_bits as CK_ULONG);
                pub_obj.public_exponent = Some(pub_exponent.clone());
                pub_obj.can_verify = true;
                pub_obj.can_encrypt = true;

                priv_obj =
                    craton_hsm::store::object::StoredObject::new(priv_handle, CKO_PRIVATE_KEY);
                priv_obj.slot_id = slot_id;
                priv_obj.key_type = Some(CKK_RSA);
                priv_obj.modulus = Some(modulus);
                priv_obj.modulus_bits = Some(modulus_bits as CK_ULONG);
                priv_obj.public_exponent = Some(pub_exponent);
                priv_obj.key_material = Some(private_key_der);
                priv_obj.can_sign = true;
                priv_obj.can_decrypt = true;
                priv_obj.sensitive = true;
                priv_obj.extractable = false;
                priv_obj.private = true;
            }
            CKM_EC_KEY_PAIR_GEN => {
                // Parse CKA_EC_PARAMS from public template to determine curve
                let ec_params_bytes = pub_template
                    .iter()
                    .find(|(t, _)| *t == CKA_EC_PARAMS)
                    .map(|(_, v)| v.clone())
                    .ok_or_else(|| {
                        Status::invalid_argument("CKA_EC_PARAMS required in public template")
                    })?;

                let (private_key_material, public_point) = if is_p384_ec_params(&ec_params_bytes) {
                    key_length = 384;
                    craton_hsm::crypto::keygen::generate_ec_p384_key_pair()
                        .map_err(hsm_err_to_status)?
                } else {
                    key_length = 256;
                    craton_hsm::crypto::keygen::generate_ec_p256_key_pair()
                        .map_err(hsm_err_to_status)?
                };

                pub_obj = craton_hsm::store::object::StoredObject::new(pub_handle, CKO_PUBLIC_KEY);
                pub_obj.slot_id = slot_id;
                pub_obj.key_type = Some(CKK_EC);
                pub_obj.ec_params = Some(ec_params_bytes.clone());
                pub_obj.ec_point = Some(public_point.clone());
                pub_obj.can_verify = true;

                priv_obj =
                    craton_hsm::store::object::StoredObject::new(priv_handle, CKO_PRIVATE_KEY);
                priv_obj.slot_id = slot_id;
                priv_obj.key_type = Some(CKK_EC);
                priv_obj.ec_params = Some(ec_params_bytes);
                priv_obj.ec_point = Some(public_point);
                priv_obj.key_material = Some(private_key_material);
                priv_obj.can_sign = true;
                priv_obj.sensitive = true;
                priv_obj.extractable = false;
                priv_obj.private = true;
            }
            CKM_EDDSA => {
                key_length = 255; // Ed25519

                let (private_key_material, public_key_bytes) =
                    craton_hsm::crypto::keygen::generate_ed25519_key_pair()
                        .map_err(hsm_err_to_status)?;

                pub_obj = craton_hsm::store::object::StoredObject::new(pub_handle, CKO_PUBLIC_KEY);
                pub_obj.slot_id = slot_id;
                pub_obj.key_type = Some(CKK_EC_EDWARDS);
                pub_obj.ec_point = Some(public_key_bytes.clone());
                pub_obj.can_verify = true;

                priv_obj =
                    craton_hsm::store::object::StoredObject::new(priv_handle, CKO_PRIVATE_KEY);
                priv_obj.slot_id = slot_id;
                priv_obj.key_type = Some(CKK_EC_EDWARDS);
                priv_obj.ec_point = Some(public_key_bytes);
                priv_obj.key_material = Some(private_key_material);
                priv_obj.can_sign = true;
                priv_obj.sensitive = true;
                priv_obj.extractable = false;
                priv_obj.private = true;
            }
            _ => {
                return Err(Status::invalid_argument(
                    "Unsupported key pair generation mechanism",
                ));
            }
        }

        // Apply template attributes to public key
        for (attr_type, value) in &pub_template {
            if *attr_type == CKA_MODULUS_BITS || *attr_type == CKA_EC_PARAMS {
                continue; // already handled
            }
            craton_hsm::store::attributes::apply_attribute(&mut pub_obj, *attr_type, value)
                .map_err(hsm_err_to_status)?;
        }

        // Apply template attributes to private key
        for (attr_type, value) in &priv_template {
            craton_hsm::store::attributes::apply_attribute(&mut priv_obj, *attr_type, value)
                .map_err(hsm_err_to_status)?;
        }

        let pub_h = self
            .hsm
            .object_store()
            .insert_object(pub_obj)
            .map_err(hsm_err_to_status)?;
        let priv_h = self
            .hsm
            .object_store()
            .insert_object(priv_obj)
            .map_err(hsm_err_to_status)?;

        self.audit(
            req.session_handle,
            AuditOperation::GenerateKeyPair {
                mechanism: mech_type as u64,
                key_length: key_length,
                fips_approved,
            },
            AuditResult::Success,
            Some(format!("pub={}, priv={}", pub_h, priv_h)),
        )?;

        Ok(Response::new(GenerateKeyPairResponse {
            public_key_handle: pub_h as u64,
            private_key_handle: priv_h as u64,
        }))
    }

    async fn destroy_object(
        &self,
        request: Request<DestroyObjectRequest>,
    ) -> Result<Response<DestroyObjectResponse>, Status> {
        let req = request.into_inner();
        let object_handle = to_ck_ulong(req.object_handle, "object_handle")?;

        // Require a valid, authenticated session
        let slot_id = require_authenticated_session(&self.hsm, req.session_handle)?;

        // Enforce slot isolation: verify object belongs to this session's slot
        {
            let obj_lock = self
                .hsm
                .object_store()
                .get_object(object_handle)
                .map_err(hsm_err_to_status)?;
            let obj = obj_lock.read();
            if obj.slot_id != slot_id {
                return Err(Status::not_found("Object not found"));
            }
        }

        self.hsm
            .object_store()
            .destroy_object(object_handle)
            .map_err(hsm_err_to_status)?;

        // (#18) Audit object destruction
        self.audit(
            req.session_handle,
            AuditOperation::DestroyObject,
            AuditResult::Success,
            Some(format!("handle={}", req.object_handle)),
        )?;

        Ok(Response::new(DestroyObjectResponse {}))
    }

    async fn find_objects(
        &self,
        request: Request<FindObjectsRequest>,
    ) -> Result<Response<FindObjectsResponse>, Status> {
        let req = request.into_inner();

        // (#9) Require a valid, authenticated session for FindObjects.
        // Previously only required a session (not login), which could leak
        // private object handles to unauthenticated callers via TOCTOU races.
        // Per PKCS#11, FindObjects with CKA_PRIVATE=true filtering depends on
        // login state — requiring authentication eliminates the race entirely.
        let slot_id = require_authenticated_session(&self.hsm, req.session_handle)?;

        let template = proto_attrs_to_template(&req.template)?;
        let token = self
            .hsm
            .slot_manager()
            .get_token(slot_id)
            .map_err(hsm_err_to_status)?;

        // Since we require authentication above, is_logged_in is always true here.
        // We keep the check for defense-in-depth in case the requirement is relaxed.
        let is_logged_in = !matches!(token.login_state(), LoginState::Public);

        // Scope to the session's slot to prevent cross-slot object access
        let handles =
            self.hsm
                .object_store()
                .find_objects_for_slot(&template, is_logged_in, Some(slot_id));
        let max = if req.max_count > 0 {
            req.max_count as usize
        } else {
            handles.len()
        };

        let result_handles: Vec<u64> = handles.into_iter().take(max).map(|h| h as u64).collect();

        // (#7-fix) Audit FindObjects for FIPS 140-3 compliance
        self.audit(
            req.session_handle,
            AuditOperation::FindObjects {
                result_count: result_handles.len() as u32,
            },
            AuditResult::Success,
            None,
        )?;

        Ok(Response::new(FindObjectsResponse {
            object_handles: result_handles,
        }))
    }

    async fn get_attribute_value(
        &self,
        request: Request<GetAttributeValueRequest>,
    ) -> Result<Response<GetAttributeValueResponse>, Status> {
        let req = request.into_inner();
        let object_handle = to_ck_ulong(req.object_handle, "object_handle")?;

        // (#8) Require a valid session
        let slot_id = require_session(&self.hsm, req.session_handle)?;

        let obj_lock = self
            .hsm
            .object_store()
            .get_object(object_handle)
            .map_err(hsm_err_to_status)?;

        let obj = obj_lock.read();

        // Enforce slot isolation: reject access to objects from a different slot
        if obj.slot_id != slot_id {
            return Err(Status::not_found("Object not found"));
        }

        // (#8) Check if object is private; if so, require login.
        // Per PKCS#11, private object attributes are only visible to logged-in sessions.
        let is_private =
            craton_hsm::store::attributes::read_attribute(&obj, CKA_PRIVATE as CK_ULONG)
                .ok()
                .flatten()
                .map(|v| !v.is_empty() && v[0] != 0)
                .unwrap_or(false);

        if is_private {
            require_logged_in(&self.hsm, slot_id)?;
        }

        let mut attrs = Vec::new();

        for attr_type in &req.attribute_types {
            let attr_ck = to_ck_ulong(*attr_type, "attribute_type")?;
            match craton_hsm::store::attributes::read_attribute(&obj, attr_ck) {
                Ok(Some(value)) => {
                    attrs.push(Attribute {
                        attr_type: *attr_type,
                        value,
                    });
                }
                Ok(None) => {
                    attrs.push(Attribute {
                        attr_type: *attr_type,
                        value: Vec::new(),
                    });
                }
                Err(_) => {
                    // Sensitive attribute — return empty
                    attrs.push(Attribute {
                        attr_type: *attr_type,
                        value: Vec::new(),
                    });
                }
            }
        }

        // (#7-fix) Audit attribute reads for FIPS 140-3 compliance
        self.audit(
            req.session_handle,
            AuditOperation::GetAttributeValue,
            AuditResult::Success,
            Some(format!("handle={}", req.object_handle)),
        )?;

        Ok(Response::new(GetAttributeValueResponse {
            attributes: attrs,
        }))
    }

    async fn sign(&self, request: Request<SignRequest>) -> Result<Response<SignResponse>, Status> {
        let req = request.into_inner();
        let slot_id = require_authenticated_session(&self.hsm, req.session_handle)?;

        let mech = req
            .mechanism
            .ok_or_else(|| Status::invalid_argument("mechanism required"))?;
        let mech_type = to_ck_ulong(mech.mechanism_type, "mechanism_type")?;

        if !craton_hsm::crypto::mechanisms::is_sign_mechanism(mech_type) {
            return Err(Status::invalid_argument("Unsupported signing mechanism"));
        }

        craton_hsm::crypto::mechanisms::validate_mechanism_for_policy(
            mech_type,
            self.hsm.algorithm_config(),
            true, // signing context
        )
        .map_err(|_| Status::permission_denied("Mechanism blocked by algorithm policy"))?;

        let fips_approved = craton_hsm::crypto::mechanisms::is_fips_approved(mech_type);

        let key_handle = to_ck_ulong(req.key_handle, "key_handle")?;
        let key_obj = self
            .hsm
            .object_store()
            .get_object(key_handle)
            .map_err(hsm_err_to_status)?;
        let key = key_obj.read();

        if key.slot_id != slot_id {
            return Err(Status::not_found("Key not found"));
        }
        if !key.can_sign {
            return Err(Status::permission_denied("Key cannot be used for signing"));
        }

        let key_material = key
            .key_material
            .as_ref()
            .ok_or_else(|| Status::internal("Key has no material"))?;
        let key_bytes = key_material.as_bytes();

        let signature = match key.key_type {
            Some(CKK_RSA) => {
                if craton_hsm::crypto::sign::is_pss_mechanism(mech_type) {
                    let hash_alg = craton_hsm::crypto::sign::pss_mechanism_to_hash(mech_type)
                        .map_err(hsm_err_to_status)?;
                    craton_hsm::crypto::sign::rsa_pss_sign(key_bytes, &req.data, hash_alg)
                        .map_err(hsm_err_to_status)?
                } else {
                    let hash_alg = craton_hsm::crypto::sign::mechanism_to_hash(mech_type);
                    craton_hsm::crypto::sign::rsa_pkcs1v15_sign(key_bytes, &req.data, hash_alg)
                        .map_err(hsm_err_to_status)?
                }
            }
            Some(CKK_EC) => {
                let ec_params = key.ec_params.as_deref().unwrap_or(&[]);
                if is_p384_ec_params(ec_params) {
                    craton_hsm::crypto::sign::ecdsa_p384_sign(key_bytes, &req.data)
                        .map_err(hsm_err_to_status)?
                } else {
                    craton_hsm::crypto::sign::ecdsa_p256_sign(key_bytes, &req.data)
                        .map_err(hsm_err_to_status)?
                }
            }
            Some(CKK_EC_EDWARDS) => craton_hsm::crypto::sign::ed25519_sign(key_bytes, &req.data)
                .map_err(hsm_err_to_status)?,
            _ => {
                return Err(Status::invalid_argument(
                    "Key type does not support signing",
                ));
            }
        };

        // Release the read lock before audit (audit may also take locks)
        drop(key);

        self.audit(
            req.session_handle,
            AuditOperation::Sign {
                mechanism: mech_type as u64,
                fips_approved,
            },
            AuditResult::Success,
            Some(format!("key={}", req.key_handle)),
        )?;

        Ok(Response::new(SignResponse { signature }))
    }

    async fn verify(
        &self,
        request: Request<VerifyRequest>,
    ) -> Result<Response<VerifyResponse>, Status> {
        let req = request.into_inner();
        let slot_id = require_authenticated_session(&self.hsm, req.session_handle)?;

        let mech = req
            .mechanism
            .ok_or_else(|| Status::invalid_argument("mechanism required"))?;
        let mech_type = to_ck_ulong(mech.mechanism_type, "mechanism_type")?;

        if !craton_hsm::crypto::mechanisms::is_sign_mechanism(mech_type) {
            return Err(Status::invalid_argument(
                "Unsupported verification mechanism",
            ));
        }

        craton_hsm::crypto::mechanisms::validate_mechanism_for_policy(
            mech_type,
            self.hsm.algorithm_config(),
            true,
        )
        .map_err(|_| Status::permission_denied("Mechanism blocked by algorithm policy"))?;

        let fips_approved = craton_hsm::crypto::mechanisms::is_fips_approved(mech_type);

        let key_handle = to_ck_ulong(req.key_handle, "key_handle")?;
        let key_obj = self
            .hsm
            .object_store()
            .get_object(key_handle)
            .map_err(hsm_err_to_status)?;
        let key = key_obj.read();

        if key.slot_id != slot_id {
            return Err(Status::not_found("Key not found"));
        }
        if !key.can_verify {
            return Err(Status::permission_denied(
                "Key cannot be used for verification",
            ));
        }

        let valid = match key.key_type {
            Some(CKK_RSA) => {
                let modulus = key
                    .modulus
                    .as_ref()
                    .ok_or_else(|| Status::internal("RSA key missing modulus"))?;
                let pub_exp = key
                    .public_exponent
                    .as_ref()
                    .ok_or_else(|| Status::internal("RSA key missing public exponent"))?;

                if craton_hsm::crypto::sign::is_pss_mechanism(mech_type) {
                    let hash_alg = craton_hsm::crypto::sign::pss_mechanism_to_hash(mech_type)
                        .map_err(hsm_err_to_status)?;
                    craton_hsm::crypto::sign::rsa_pss_verify(
                        modulus,
                        pub_exp,
                        &req.data,
                        &req.signature,
                        hash_alg,
                    )
                    .map_err(hsm_err_to_status)?
                } else {
                    let hash_alg = craton_hsm::crypto::sign::mechanism_to_hash(mech_type);
                    craton_hsm::crypto::sign::rsa_pkcs1v15_verify(
                        modulus,
                        pub_exp,
                        &req.data,
                        &req.signature,
                        hash_alg,
                    )
                    .map_err(hsm_err_to_status)?
                }
            }
            Some(CKK_EC) => {
                let ec_point = key
                    .ec_point
                    .as_ref()
                    .ok_or_else(|| Status::internal("EC key missing public point"))?;
                let ec_params = key.ec_params.as_deref().unwrap_or(&[]);
                if is_p384_ec_params(ec_params) {
                    craton_hsm::crypto::sign::ecdsa_p384_verify(ec_point, &req.data, &req.signature)
                        .map_err(hsm_err_to_status)?
                } else {
                    craton_hsm::crypto::sign::ecdsa_p256_verify(ec_point, &req.data, &req.signature)
                        .map_err(hsm_err_to_status)?
                }
            }
            Some(CKK_EC_EDWARDS) => {
                let pub_key = key
                    .ec_point
                    .as_ref()
                    .ok_or_else(|| Status::internal("Ed25519 key missing public key"))?;
                craton_hsm::crypto::sign::ed25519_verify(pub_key, &req.data, &req.signature)
                    .map_err(hsm_err_to_status)?
            }
            _ => {
                return Err(Status::invalid_argument(
                    "Key type does not support verification",
                ));
            }
        };

        drop(key);

        self.audit(
            req.session_handle,
            AuditOperation::Verify {
                mechanism: mech_type as u64,
                fips_approved,
            },
            AuditResult::Success,
            Some(format!("key={}", req.key_handle)),
        )?;

        Ok(Response::new(VerifyResponse { valid }))
    }

    async fn encrypt(
        &self,
        request: Request<EncryptRequest>,
    ) -> Result<Response<EncryptResponse>, Status> {
        let req = request.into_inner();
        let slot_id = require_authenticated_session(&self.hsm, req.session_handle)?;

        let mech = req
            .mechanism
            .ok_or_else(|| Status::invalid_argument("mechanism required"))?;
        let mech_type = to_ck_ulong(mech.mechanism_type, "mechanism_type")?;

        if !craton_hsm::crypto::mechanisms::is_encrypt_mechanism(mech_type) {
            return Err(Status::invalid_argument("Unsupported encryption mechanism"));
        }

        craton_hsm::crypto::mechanisms::validate_mechanism_for_policy(
            mech_type,
            self.hsm.algorithm_config(),
            false,
        )
        .map_err(|_| Status::permission_denied("Mechanism blocked by algorithm policy"))?;

        let fips_approved = craton_hsm::crypto::mechanisms::is_fips_approved(mech_type);

        let key_handle = to_ck_ulong(req.key_handle, "key_handle")?;
        let key_obj = self
            .hsm
            .object_store()
            .get_object(key_handle)
            .map_err(hsm_err_to_status)?;
        let key = key_obj.read();

        if key.slot_id != slot_id {
            return Err(Status::not_found("Key not found"));
        }
        if !key.can_encrypt {
            return Err(Status::permission_denied(
                "Key cannot be used for encryption",
            ));
        }

        let encrypted_data = match mech_type {
            CKM_AES_GCM => {
                let key_bytes = key
                    .key_material
                    .as_ref()
                    .ok_or_else(|| Status::internal("Key has no material"))?
                    .as_bytes();
                craton_hsm::crypto::encrypt::aes_256_gcm_encrypt(key_bytes, &req.data)
                    .map_err(hsm_err_to_status)?
            }
            CKM_AES_CBC | CKM_AES_CBC_PAD => {
                let iv = &mech.parameter;
                if iv.len() != 16 {
                    return Err(Status::invalid_argument(
                        "AES-CBC requires 16-byte IV in mechanism parameter",
                    ));
                }
                let key_bytes = key
                    .key_material
                    .as_ref()
                    .ok_or_else(|| Status::internal("Key has no material"))?
                    .as_bytes();
                craton_hsm::crypto::encrypt::aes_cbc_encrypt(key_bytes, iv, &req.data)
                    .map_err(hsm_err_to_status)?
            }
            CKM_AES_CTR => {
                let iv = &mech.parameter;
                if iv.len() != 16 {
                    return Err(Status::invalid_argument(
                        "AES-CTR requires 16-byte IV in mechanism parameter",
                    ));
                }
                let key_bytes = key
                    .key_material
                    .as_ref()
                    .ok_or_else(|| Status::internal("Key has no material"))?
                    .as_bytes();
                craton_hsm::crypto::encrypt::aes_ctr_encrypt(key_bytes, iv, &req.data)
                    .map_err(hsm_err_to_status)?
            }
            CKM_RSA_PKCS_OAEP => {
                let modulus = key
                    .modulus
                    .as_ref()
                    .ok_or_else(|| Status::internal("RSA key missing modulus"))?;
                let pub_exp = key
                    .public_exponent
                    .as_ref()
                    .ok_or_else(|| Status::internal("RSA key missing public exponent"))?;
                craton_hsm::crypto::sign::rsa_oaep_encrypt(
                    modulus,
                    pub_exp,
                    &req.data,
                    craton_hsm::crypto::sign::OaepHash::Sha256,
                )
                .map_err(hsm_err_to_status)?
            }
            _ => {
                return Err(Status::invalid_argument("Unsupported encryption mechanism"));
            }
        };

        drop(key);

        self.audit(
            req.session_handle,
            AuditOperation::Encrypt {
                mechanism: mech_type as u64,
                fips_approved,
            },
            AuditResult::Success,
            Some(format!("key={}", req.key_handle)),
        )?;

        Ok(Response::new(EncryptResponse { encrypted_data }))
    }

    async fn decrypt(
        &self,
        request: Request<DecryptRequest>,
    ) -> Result<Response<DecryptResponse>, Status> {
        let req = request.into_inner();
        let slot_id = require_authenticated_session(&self.hsm, req.session_handle)?;

        let mech = req
            .mechanism
            .ok_or_else(|| Status::invalid_argument("mechanism required"))?;
        let mech_type = to_ck_ulong(mech.mechanism_type, "mechanism_type")?;

        if !craton_hsm::crypto::mechanisms::is_encrypt_mechanism(mech_type) {
            return Err(Status::invalid_argument("Unsupported decryption mechanism"));
        }

        craton_hsm::crypto::mechanisms::validate_mechanism_for_policy(
            mech_type,
            self.hsm.algorithm_config(),
            false,
        )
        .map_err(|_| Status::permission_denied("Mechanism blocked by algorithm policy"))?;

        let fips_approved = craton_hsm::crypto::mechanisms::is_fips_approved(mech_type);

        let key_handle = to_ck_ulong(req.key_handle, "key_handle")?;
        let key_obj = self
            .hsm
            .object_store()
            .get_object(key_handle)
            .map_err(hsm_err_to_status)?;
        let key = key_obj.read();

        if key.slot_id != slot_id {
            return Err(Status::not_found("Key not found"));
        }
        if !key.can_decrypt {
            return Err(Status::permission_denied(
                "Key cannot be used for decryption",
            ));
        }

        let data = match mech_type {
            CKM_AES_GCM => {
                let key_bytes = key
                    .key_material
                    .as_ref()
                    .ok_or_else(|| Status::internal("Key has no material"))?
                    .as_bytes();
                craton_hsm::crypto::encrypt::aes_256_gcm_decrypt(key_bytes, &req.encrypted_data)
                    .map_err(hsm_err_to_status)?
            }
            CKM_AES_CBC | CKM_AES_CBC_PAD => {
                let iv = &mech.parameter;
                if iv.len() != 16 {
                    return Err(Status::invalid_argument(
                        "AES-CBC requires 16-byte IV in mechanism parameter",
                    ));
                }
                let key_bytes = key
                    .key_material
                    .as_ref()
                    .ok_or_else(|| Status::internal("Key has no material"))?
                    .as_bytes();
                craton_hsm::crypto::encrypt::aes_cbc_decrypt(key_bytes, iv, &req.encrypted_data)
                    .map_err(hsm_err_to_status)?
            }
            CKM_AES_CTR => {
                let iv = &mech.parameter;
                if iv.len() != 16 {
                    return Err(Status::invalid_argument(
                        "AES-CTR requires 16-byte IV in mechanism parameter",
                    ));
                }
                let key_bytes = key
                    .key_material
                    .as_ref()
                    .ok_or_else(|| Status::internal("Key has no material"))?
                    .as_bytes();
                craton_hsm::crypto::encrypt::aes_ctr_decrypt(key_bytes, iv, &req.encrypted_data)
                    .map_err(hsm_err_to_status)?
            }
            CKM_RSA_PKCS_OAEP => {
                let key_bytes = key
                    .key_material
                    .as_ref()
                    .ok_or_else(|| Status::internal("Key has no material"))?
                    .as_bytes();
                craton_hsm::crypto::sign::rsa_oaep_decrypt(
                    key_bytes,
                    &req.encrypted_data,
                    craton_hsm::crypto::sign::OaepHash::Sha256,
                )
                .map_err(hsm_err_to_status)?
            }
            _ => {
                return Err(Status::invalid_argument("Unsupported decryption mechanism"));
            }
        };

        drop(key);

        self.audit(
            req.session_handle,
            AuditOperation::Decrypt {
                mechanism: mech_type as u64,
                fips_approved,
            },
            AuditResult::Success,
            Some(format!("key={}", req.key_handle)),
        )?;

        Ok(Response::new(DecryptResponse { data }))
    }

    async fn digest(
        &self,
        request: Request<DigestRequest>,
    ) -> Result<Response<DigestResponse>, Status> {
        let req = request.into_inner();

        // (#29) Require authentication for digest to prevent CPU exhaustion by
        // unauthenticated callers. While PKCS#11 only requires a session for C_Digest,
        // the daemon enforces login to limit the attack surface for DoS via large
        // hash payloads (up to max_digest_length).
        require_authenticated_session(&self.hsm, req.session_handle)?;

        // (#13) Bound digest data size to prevent CPU exhaustion
        if req.data.len() > self.max_digest_length as usize {
            return Err(Status::invalid_argument(format!(
                "Digest data size {} bytes exceeds maximum {} bytes",
                req.data.len(),
                self.max_digest_length
            )));
        }

        let mech = req
            .mechanism
            .ok_or_else(|| Status::invalid_argument("mechanism required"))?;

        let mech_type = to_ck_ulong(mech.mechanism_type, "mechanism_type")?;
        let result = craton_hsm::crypto::digest::compute_digest(mech_type, &req.data)
            .map_err(hsm_err_to_status)?;

        Ok(Response::new(DigestResponse { digest: result }))
    }

    async fn generate_random(
        &self,
        request: Request<GenerateRandomRequest>,
    ) -> Result<Response<GenerateRandomResponse>, Status> {
        let req = request.into_inner();

        // (#3-fix) Require authentication to prevent DRBG exhaustion by
        // unauthenticated callers, consistent with digest() (#29).
        require_authenticated_session(&self.hsm, req.session_handle)?;

        // (#19) Validate length fits in u32 before comparison to prevent truncation
        let length: u32 = req.length.try_into().map_err(|_| {
            Status::invalid_argument(format!(
                "Requested length {} exceeds maximum representable size",
                req.length
            ))
        })?;

        // Bound the allocation to prevent DoS
        if length > self.max_random_length {
            return Err(Status::invalid_argument(format!(
                "Requested {} bytes exceeds maximum {} bytes",
                length, self.max_random_length
            )));
        }

        let mut buf = vec![0u8; length as usize];

        // (#25) Use the FIPS-compliant HMAC_DRBG — refuse to serve random data
        // if the DRBG mutex is poisoned. A poisoned mutex means a thread panicked
        // mid-DRBG operation, leaving internal state potentially corrupted.
        // For an HSM, using a corrupted DRBG could produce predictable output.
        // parking_lot::Mutex::lock() does not poison — it always returns a guard.
        let mut drbg = self.hsm.drbg().lock();
        drbg.generate(&mut buf)
            .map_err(|_| Status::internal("DRBG generation failed — health test failure"))?;
        drop(drbg);

        self.audit(
            req.session_handle,
            AuditOperation::GenerateRandom { length },
            AuditResult::Success,
            None,
        )?;

        Ok(Response::new(GenerateRandomResponse { random_data: buf }))
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// (#31) Uses try_into instead of `as` to prevent silent truncation of attribute
/// types on 32-bit platforms, consistent with `to_ck_ulong()`.
fn proto_attrs_to_template(attrs: &[Attribute]) -> Result<Vec<(CK_ULONG, Vec<u8>)>, Status> {
    attrs
        .iter()
        .map(|a| {
            let attr_type: CK_ULONG = a.attr_type.try_into().map_err(|_| {
                Status::invalid_argument(format!(
                    "attribute type 0x{:016X} exceeds platform maximum",
                    a.attr_type
                ))
            })?;
            Ok((attr_type, a.value.clone()))
        })
        .collect()
}

/// (#5-fix) Evict expired throttle entries to bound HashMap memory growth.
/// Removes entries whose lockout has expired and caps total entries at MAX_THROTTLE_ENTRIES
/// by evicting the oldest expired entries first.
fn evict_expired_throttle_entries(map: &mut HashMap<CK_ULONG, LoginThrottle>) {
    let now = Instant::now();
    // Remove entries whose lockout has expired
    map.retain(|_, throttle| {
        match throttle.lockout_until {
            Some(until) if now >= until => false, // Expired lockout — evict
            _ => true,
        }
    });
    // If still over capacity (entries without lockout), evict oldest by lowest attempt count
    while map.len() > MAX_THROTTLE_ENTRIES {
        if let Some(&key) = map
            .iter()
            .min_by_key(|(_, t)| t.failed_attempts)
            .map(|(k, _)| k)
        {
            map.remove(&key);
        } else {
            break;
        }
    }
}

/// Check if EC params correspond to P-384 (secp384r1).
/// OID for secp384r1: 1.3.132.0.34 = 06 05 2B 81 04 00 22
fn is_p384_ec_params(ec_params: &[u8]) -> bool {
    const P384_OID: &[u8] = &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22];
    ec_params == P384_OID || ec_params.windows(P384_OID.len()).any(|w| w == P384_OID)
}

/// (#6, #16) Convert HSM errors to gRPC Status without leaking internal details.
/// Raw CK_RV codes and enum variant names are logged server-side but NOT sent to clients.
///
/// Security principle: PIN/auth errors are deliberately vague to prevent oracle attacks.
/// Operational errors (bad mechanism, invalid template, etc.) are descriptive so clients
/// can diagnose and fix their requests.
fn hsm_err_to_status(e: craton_hsm::error::HsmError) -> Status {
    // Log the full detail server-side for debugging (before moving e)
    tracing::debug!(error = ?e, "HSM operation failed");

    use craton_hsm::error::HsmError;

    // Return sanitized messages to the client
    match e {
        // ── Authentication errors (deliberately vague per #6) ───────────────
        HsmError::PinIncorrect | HsmError::PinLocked => {
            Status::unauthenticated("Authentication failed")
        }
        HsmError::PinInvalid => {
            Status::invalid_argument("PIN does not meet complexity requirements")
        }
        HsmError::PinLenRange => Status::invalid_argument("PIN length out of range"),
        HsmError::PinRateLimited => {
            Status::resource_exhausted("Too many attempts — try again later")
        }
        HsmError::UserNotLoggedIn => Status::permission_denied("Login required"),
        HsmError::UserAlreadyLoggedIn => Status::already_exists("Already logged in"),
        HsmError::UserAnotherAlreadyLoggedIn => {
            Status::failed_precondition("Another user already logged in")
        }
        HsmError::UserTypeInvalid => Status::invalid_argument("Invalid user type"),
        HsmError::UserPinNotInitialized => {
            Status::failed_precondition("User PIN not initialized — SO must call InitPIN first")
        }

        // ── Session errors ──────────────────────────────────────────────────
        HsmError::SessionHandleInvalid => Status::not_found("Session not found"),
        HsmError::SessionCount => Status::resource_exhausted("Session limit reached"),
        HsmError::SessionReadOnly => Status::permission_denied("Session is read-only"),
        HsmError::SessionParallelNotSupported => {
            Status::invalid_argument("Parallel sessions not supported")
        }
        HsmError::SessionExists => Status::already_exists("Session already exists"),
        HsmError::SessionReadOnlyExists => Status::failed_precondition("Read-only session exists"),
        HsmError::SessionReadWriteSoExists => {
            Status::failed_precondition("R/W SO session already exists")
        }

        // ── Token/slot errors ───────────────────────────────────────────────
        HsmError::SlotIdInvalid => Status::not_found("Slot not found"),
        HsmError::TokenNotPresent => Status::not_found("Token not present"),
        HsmError::TokenNotInitialized => {
            Status::failed_precondition("Token not initialized — call InitToken first")
        }
        HsmError::TokenWriteProtected => Status::permission_denied("Token is write-protected"),

        // ── Object/attribute errors ─────────────────────────────────────────
        HsmError::ObjectHandleInvalid => Status::not_found("Object not found"),
        HsmError::AttributeTypeInvalid => Status::invalid_argument("Invalid attribute type"),
        HsmError::AttributeValueInvalid => Status::invalid_argument("Invalid attribute value"),
        HsmError::AttributeReadOnly => Status::permission_denied("Attribute is read-only"),
        HsmError::AttributeSensitive => {
            Status::permission_denied("Attribute is sensitive — cannot read")
        }
        HsmError::TemplateIncomplete => Status::invalid_argument("Template is incomplete"),
        HsmError::TemplateInconsistent => Status::invalid_argument("Template is inconsistent"),

        // ── Crypto/mechanism errors ─────────────────────────────────────────
        HsmError::MechanismInvalid => Status::invalid_argument("Unsupported mechanism"),
        HsmError::MechanismParamInvalid => Status::invalid_argument("Invalid mechanism parameters"),
        HsmError::KeyHandleInvalid => Status::not_found("Key not found"),
        HsmError::KeyTypeInconsistent => {
            Status::invalid_argument("Key type does not match mechanism")
        }
        HsmError::KeySizeRange => Status::invalid_argument("Key size out of range"),
        HsmError::KeyFunctionNotPermitted => {
            Status::permission_denied("Key not permitted for this operation")
        }
        HsmError::OperationActive => {
            Status::failed_precondition("Another operation is already active")
        }
        HsmError::OperationNotInitialized => {
            Status::failed_precondition("No operation initialized — call *Init first")
        }

        // ── Data errors ─────────────────────────────────────────────────────
        HsmError::ArgumentsBad => Status::invalid_argument("Invalid argument"),
        HsmError::DataInvalid => Status::invalid_argument("Invalid input data"),
        HsmError::DataLenRange => Status::invalid_argument("Input data length out of range"),
        HsmError::EncryptedDataInvalid => Status::invalid_argument("Invalid encrypted data"),
        HsmError::EncryptedDataLenRange => {
            Status::invalid_argument("Encrypted data length out of range")
        }
        HsmError::SignatureInvalid => Status::invalid_argument("Signature verification failed"),
        HsmError::SignatureLenRange => Status::invalid_argument("Signature length out of range"),
        HsmError::BufferTooSmall => Status::internal("Buffer too small"),

        // ── Capability errors ───────────────────────────────────────────────
        HsmError::FunctionNotSupported => Status::unimplemented("Operation not supported"),
        HsmError::RandomSeedNotSupported => Status::unimplemented("Random seed not supported"),

        // ── System errors (intentionally vague) ─────────────────────────────
        HsmError::NotInitialized => Status::failed_precondition("Cryptoki not initialized"),
        HsmError::AlreadyInitialized => Status::already_exists("Already initialized"),
        HsmError::GeneralError
        | HsmError::HostMemory
        | HsmError::DeviceMemory
        | HsmError::ConfigError(_)
        | HsmError::AuditChainBroken(_) => Status::internal("Internal error"),
    }
}
