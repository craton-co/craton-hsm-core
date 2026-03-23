// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
#![forbid(unsafe_code)]

use parking_lot::{Mutex, RwLock};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

use crate::error::{HsmError, HsmResult};
use crate::pkcs11_abi::types::CK_ULONG;
use crate::store::encrypted_store::{hash_pin_pbkdf2, verify_pin_pbkdf2};
use crate::store::lockout_store::LockoutStore;

const DEFAULT_MAX_SESSIONS: u64 = 100;
const DEFAULT_MAX_RW_SESSIONS: u64 = 10;
const DEFAULT_PIN_MIN_LEN: usize = 8;
const DEFAULT_PIN_MAX_LEN: usize = 64;
const DEFAULT_MAX_FAILED_LOGINS: u32 = 5;
/// Minimum number of distinct byte values required in a PIN.
const PIN_MIN_DISTINCT_BYTES: usize = 3;
/// Minimum number of character classes (lower, upper, digit, other) required.
/// Only enforced for ASCII-text PINs; binary PINs skip this check.
const PIN_MIN_CHAR_CLASSES: usize = 2;
/// Base delay (ms) after a failed login attempt; doubles with each consecutive failure.
const FAILED_LOGIN_BASE_DELAY_MS: u64 = 100;
/// Maximum delay cap (ms) for exponential backoff on failed logins.
const FAILED_LOGIN_MAX_DELAY_MS: u64 = 5000;

#[derive(Debug, Clone, PartialEq)]
pub enum LoginState {
    Public,
    UserLoggedIn,
    SoLoggedIn,
}

/// Consolidated authentication and initialization state protected by a single
/// mutex. This eliminates lock-ordering hazards: all fields that were previously
/// spread across separate `RwLock`s (`initialized`, `user_pin_initialized`) and
/// the auth `Mutex` are now under one lock. The only remaining `RwLock`s are
/// for PIN hashes and the label, which must always be acquired *after* `auth`.
struct AuthState {
    login: LoginState,
    initialized: bool,
    user_pin_initialized: bool,
    failed_user_logins: u32,
    failed_so_logins: u32,
    /// Failed SO PIN attempts specifically in `init_token` (separate from login).
    failed_init_token_logins: u32,
    user_pin_locked: bool,
    so_pin_locked: bool,
    /// Earliest time the next user login attempt is allowed (per-account rate limit).
    user_next_allowed: Option<Instant>,
    /// Earliest time the next SO login attempt is allowed (per-account rate limit).
    so_next_allowed: Option<Instant>,
    /// Earliest time the next init_token attempt is allowed (rate limit).
    init_token_next_allowed: Option<Instant>,
}

impl AuthState {
    fn new() -> Self {
        Self {
            login: LoginState::Public,
            initialized: false,
            user_pin_initialized: false,
            failed_user_logins: 0,
            failed_so_logins: 0,
            failed_init_token_logins: 0,
            user_pin_locked: false,
            so_pin_locked: false,
            user_next_allowed: None,
            so_next_allowed: None,
            init_token_next_allowed: None,
        }
    }

    /// Reset to fresh state, preserving only the `initialized` flag (set by caller).
    fn reset_for_init(&mut self) {
        self.login = LoginState::Public;
        self.user_pin_initialized = false;
        self.failed_user_logins = 0;
        self.failed_so_logins = 0;
        self.failed_init_token_logins = 0;
        self.user_pin_locked = false;
        self.so_pin_locked = false;
        self.user_next_allowed = None;
        self.so_next_allowed = None;
        self.init_token_next_allowed = None;
    }
}

pub struct Token {
    pub label: RwLock<[u8; 32]>,
    /// SO PIN hash (PBKDF2: salt || derived_key) — wrapped in Zeroizing for auto-clear on drop.
    /// Lock ordering: always acquire `auth` before this RwLock.
    so_pin_hash: RwLock<Option<Zeroizing<Vec<u8>>>>,
    /// User PIN hash (PBKDF2: salt || derived_key) — wrapped in Zeroizing for auto-clear on drop.
    /// Lock ordering: always acquire `auth` before this RwLock.
    user_pin_hash: RwLock<Option<Zeroizing<Vec<u8>>>>,
    /// All authentication and initialization state under one lock.
    ///
    /// **Lock ordering:** always acquire `auth` *before* any `RwLock` on this
    /// struct (`so_pin_hash`, `user_pin_hash`, `label`). This ordering is
    /// enforced structurally — `initialized` and `user_pin_initialized` live
    /// inside `AuthState` so they cannot be read without holding `auth`.
    auth: Mutex<AuthState>,
    session_count: AtomicU64,
    rw_session_count: AtomicU64,
    max_sessions: u64,
    max_rw_sessions: u64,
    pin_min_len: usize,
    pin_max_len: usize,
    max_failed_logins: u32,
    /// PBKDF2 iteration count from config (threaded to hash/verify helpers).
    pbkdf2_iterations: u32,
    /// Optional persistent store for lockout counters. When present, lockout
    /// state survives process restarts, preventing brute-force reset via crash.
    lockout_store: Option<LockoutStore>,
}

impl Token {
    pub fn new() -> Self {
        Self::new_with_config(None)
    }

    pub fn new_with_config(config: Option<&crate::config::config::HsmConfig>) -> Self {
        let mut label = [b' '; 32];
        let label_str = config
            .map(|c| c.token.label.as_str())
            .unwrap_or("Craton HSM Token 0");
        let label_bytes = label_str.as_bytes();
        let copy_len = label_bytes.len().min(32);
        label[..copy_len].copy_from_slice(&label_bytes[..copy_len]);

        let max_sessions = config
            .map(|c| c.token.max_sessions)
            .unwrap_or(DEFAULT_MAX_SESSIONS);
        let max_rw_sessions = config
            .map(|c| c.token.max_rw_sessions)
            .unwrap_or(DEFAULT_MAX_RW_SESSIONS);
        let pin_min_len = config
            .map(|c| c.security.pin_min_length)
            .unwrap_or(DEFAULT_PIN_MIN_LEN);
        let pin_max_len = config
            .map(|c| c.security.pin_max_length)
            .unwrap_or(DEFAULT_PIN_MAX_LEN);
        let max_failed_logins = config
            .map(|c| c.security.max_failed_logins)
            .unwrap_or(DEFAULT_MAX_FAILED_LOGINS);
        let pbkdf2_iterations = config
            .map(|c| c.security.pbkdf2_iterations)
            .unwrap_or(600_000);

        // Create lockout store and restore persisted lockout state if available.
        let lockout_store = config.map(|c| LockoutStore::new(&c.token.storage_path));

        let mut auth_state = AuthState::new();
        if let Some(ref store) = lockout_store {
            let data = store.load();
            auth_state.failed_user_logins = data.failed_user_logins;
            auth_state.failed_so_logins = data.failed_so_logins;
            auth_state.failed_init_token_logins = data.failed_init_token_logins;
            auth_state.user_pin_locked = data.user_pin_locked;
            auth_state.so_pin_locked = data.so_pin_locked;
        }

        Self {
            label: RwLock::new(label),
            so_pin_hash: RwLock::new(None),
            user_pin_hash: RwLock::new(None),
            auth: Mutex::new(auth_state),
            session_count: AtomicU64::new(0),
            rw_session_count: AtomicU64::new(0),
            max_sessions,
            max_rw_sessions,
            pin_min_len,
            pin_max_len,
            max_failed_logins,
            pbkdf2_iterations,
            lockout_store,
        }
    }

    /// Persist the current lockout counters to disk (if a store is configured).
    /// Must be called while `auth` is held by the caller; takes the auth state
    /// by reference to extract the data without re-acquiring the lock.
    fn persist_lockout(&self, auth: &AuthState) {
        if let Some(ref store) = self.lockout_store {
            use crate::store::lockout_store::LockoutData;
            store.save(&LockoutData {
                failed_user_logins: auth.failed_user_logins,
                failed_so_logins: auth.failed_so_logins,
                failed_init_token_logins: auth.failed_init_token_logins,
                user_pin_locked: auth.user_pin_locked,
                so_pin_locked: auth.so_pin_locked,
            });
        }
    }

    fn hash_pin(&self, pin: &[u8]) -> Zeroizing<Vec<u8>> {
        hash_pin_pbkdf2(pin, Some(self.pbkdf2_iterations))
    }

    fn verify_pin(&self, stored_hash: &[u8], provided_pin: &[u8]) -> bool {
        verify_pin_pbkdf2(stored_hash, provided_pin, Some(self.pbkdf2_iterations))
    }

    fn validate_pin(&self, pin: &[u8]) -> HsmResult<()> {
        if pin.len() < self.pin_min_len || pin.len() > self.pin_max_len {
            return Err(HsmError::PinLenRange);
        }
        // PIN complexity: require minimum distinct byte values
        let mut seen = [false; 256];
        let mut distinct = 0usize;
        let mut has_lower = false;
        let mut has_upper = false;
        let mut has_digit = false;
        let mut has_other = false;
        let mut has_non_ascii = false;
        for &b in pin {
            if !seen[b as usize] {
                seen[b as usize] = true;
                distinct += 1;
            }
            match b {
                b'a'..=b'z' => has_lower = true,
                b'A'..=b'Z' => has_upper = true,
                b'0'..=b'9' => has_digit = true,
                0x20..=0x7E => has_other = true,
                _ => has_non_ascii = true,
            }
        }
        if distinct < PIN_MIN_DISTINCT_BYTES {
            return Err(HsmError::PinInvalid);
        }
        // Character-class check only applies to ASCII-text PINs. Binary PINs
        // (containing non-printable-ASCII bytes) have sufficient entropy from
        // the distinct-bytes check alone — requiring ASCII character classes
        // would incorrectly reject valid high-entropy binary PINs.
        if !has_non_ascii {
            let class_count = [has_lower, has_upper, has_digit, has_other]
                .iter()
                .filter(|&&c| c)
                .count();
            if class_count < PIN_MIN_CHAR_CLASSES {
                return Err(HsmError::PinInvalid);
            }
        }
        Ok(())
    }

    /// Compute the exponential backoff duration for a given failure count.
    /// Delay = min(base * 2^(failures-1), max_cap).
    fn backoff_duration(failures: u32) -> Duration {
        if failures == 0 {
            return Duration::ZERO;
        }
        let shift = failures.saturating_sub(1).min(31);
        let delay_ms = FAILED_LOGIN_BASE_DELAY_MS.saturating_mul(1u64 << shift);
        Duration::from_millis(delay_ms.min(FAILED_LOGIN_MAX_DELAY_MS))
    }

    /// Check whether the per-account rate limit is in effect and reject early
    /// if the caller is within the backoff window. This rate-limits the
    /// *account*, not just the calling thread, so concurrent attempts are also
    /// blocked. Returns `PinRateLimited` (distinct from `PinIncorrect`) so
    /// callers and audit logs can distinguish rate-limited rejections.
    fn check_rate_limit(next_allowed: &Option<Instant>) -> HsmResult<()> {
        if let Some(deadline) = next_allowed {
            if Instant::now() < *deadline {
                tracing::warn!("login attempt rejected: rate-limited (backoff window active)");
                return Err(HsmError::PinRateLimited);
            }
        }
        Ok(())
    }

    pub fn is_initialized(&self) -> bool {
        self.auth.lock().initialized
    }

    pub fn is_user_pin_initialized(&self) -> bool {
        self.auth.lock().user_pin_initialized
    }

    /// Returns a snapshot of the current login state.
    ///
    /// **Warning:** The returned value is a point-in-time snapshot. **Never** use
    /// it for authorization gates — the state may change between this call and
    /// the action you intend to protect. Use [`require_login`] instead for
    /// atomic check-and-act authorization.
    pub fn login_state(&self) -> LoginState {
        self.auth.lock().login.clone()
    }

    /// Atomically verify the caller is logged in as the required `expected` state.
    ///
    /// **Note:** The auth lock is released after this check returns. For
    /// operations that must hold the lock across the entire check-and-act
    /// sequence (preventing concurrent logout between check and operation),
    /// use [`with_login_state`] instead.
    pub fn require_login(&self, expected: &LoginState) -> HsmResult<()> {
        let auth = self.auth.lock();
        if auth.login == *expected {
            Ok(())
        } else if auth.login == LoginState::Public {
            Err(HsmError::UserNotLoggedIn)
        } else {
            Err(HsmError::UserAnotherAlreadyLoggedIn)
        }
    }

    /// Atomically verify login state and execute a closure while holding the
    /// auth lock, preventing TOCTOU races where a concurrent logout could
    /// invalidate the authorization between the check and the operation.
    ///
    /// The auth lock is held for the entire duration of `f`.
    pub fn with_login_state<F, T>(&self, expected: &LoginState, f: F) -> HsmResult<T>
    where
        F: FnOnce() -> HsmResult<T>,
    {
        let auth = self.auth.lock();
        if auth.login == *expected {
            // Auth lock held across f() — no concurrent logout possible
            f()
        } else if auth.login == LoginState::Public {
            Err(HsmError::UserNotLoggedIn)
        } else {
            Err(HsmError::UserAnotherAlreadyLoggedIn)
        }
    }

    pub fn session_count(&self) -> u64 {
        self.session_count.load(Ordering::SeqCst)
    }

    pub fn rw_session_count(&self) -> u64 {
        self.rw_session_count.load(Ordering::SeqCst)
    }

    pub fn max_sessions(&self) -> u64 {
        self.max_sessions
    }

    pub fn max_rw_sessions(&self) -> u64 {
        self.max_rw_sessions
    }

    pub fn pin_min_len(&self) -> CK_ULONG {
        self.pin_min_len as CK_ULONG
    }

    pub fn pin_max_len(&self) -> CK_ULONG {
        self.pin_max_len as CK_ULONG
    }

    /// Build the CK_TOKEN_INFO flags word.
    ///
    /// All initialization and lockout flags live inside `AuthState`, so a single
    /// mutex acquisition provides a consistent snapshot — no separate RwLock
    /// ordering concerns.
    pub fn flags(&self) -> CK_ULONG {
        use crate::pkcs11_abi::constants::*;
        let mut flags: CK_ULONG = CKF_RNG | CKF_LOGIN_REQUIRED;

        let auth = self.auth.lock();

        if auth.initialized {
            flags |= CKF_TOKEN_INITIALIZED;
        }
        if auth.user_pin_initialized {
            flags |= CKF_USER_PIN_INITIALIZED;
        }
        if auth.user_pin_locked {
            flags |= CKF_USER_PIN_LOCKED;
        }
        if auth.so_pin_locked {
            flags |= CKF_SO_PIN_LOCKED;
        }
        flags
    }

    /// Initialize the token with an SO PIN and label.
    ///
    /// Holds the auth lock for the entire operation to prevent concurrent
    /// login/logout from observing partially-initialized state. If the token
    /// was previously initialized, verifies the SO PIN first — even when the
    /// SO account is locked, providing a recovery path from SO lockout.
    ///
    /// Failed SO PIN verification attempts are tracked with the same
    /// rate-limiting / lockout policy as `login()`, preventing brute-force
    /// PIN discovery via repeated `C_InitToken` calls.
    ///
    /// # Security note
    ///
    /// `init_token` is the most privileged operation on a token: it resets
    /// **all** auth state, clears the user PIN, and resets session counts.
    /// Per the PKCS#11 spec this is allowed even when the SO account is
    /// locked (as a recovery mechanism), but it means a compromised SO PIN
    /// can wipe the token at any time regardless of lockout. Callers should
    /// gate access to `C_InitToken` at the transport/policy layer if this
    /// risk is unacceptable.
    pub fn init_token(&self, so_pin: &[u8], label: &[u8; 32]) -> HsmResult<()> {
        self.validate_pin(so_pin)?;

        // Hold auth lock for the entire operation to prevent races.
        let mut auth = self.auth.lock();

        // If previously initialized, verify the SO PIN even when locked.
        // This is the SO lockout recovery path: correct PIN clears lockout.
        if auth.initialized {
            // Rate-limit init_token attempts independently of login
            Self::check_rate_limit(&auth.init_token_next_allowed)?;

            let hash_guard = self.so_pin_hash.read();
            if let Some(stored) = hash_guard.as_ref() {
                if !self.verify_pin(stored, so_pin) {
                    auth.failed_init_token_logins += 1;
                    let failures = auth.failed_init_token_logins;
                    auth.init_token_next_allowed =
                        Some(Instant::now() + Self::backoff_duration(failures));
                    self.persist_lockout(&auth);
                    tracing::warn!(
                        "init_token: SO PIN verification failed (attempt {})",
                        failures
                    );
                    return Err(HsmError::PinIncorrect);
                }
            }
            drop(hash_guard);
        }

        let hash = self.hash_pin(so_pin);
        *self.so_pin_hash.write() = Some(hash);
        *self.label.write() = *label;
        *self.user_pin_hash.write() = None;

        // Reset all auth state atomically under one lock
        auth.reset_for_init();
        auth.initialized = true;
        self.persist_lockout(&auth);
        // Clear the persisted lockout file since all state is reset
        if let Some(ref store) = self.lockout_store {
            store.clear();
        }

        self.session_count.store(0, Ordering::SeqCst);
        self.rw_session_count.store(0, Ordering::SeqCst);

        tracing::info!("token initialized (all auth state reset)");
        Ok(())
    }

    /// Initialize the user PIN (must be logged in as SO).
    /// Holds the auth lock across the entire operation to prevent TOCTOU races.
    pub fn init_pin(&self, pin: &[u8]) -> HsmResult<()> {
        let mut auth = self.auth.lock();
        if auth.login != LoginState::SoLoggedIn {
            return Err(HsmError::UserNotLoggedIn);
        }

        self.validate_pin(pin)?;

        let hash = self.hash_pin(pin);
        *self.user_pin_hash.write() = Some(hash);
        auth.user_pin_initialized = true;
        auth.failed_user_logins = 0;
        auth.user_pin_locked = false;
        auth.user_next_allowed = None;
        self.persist_lockout(&auth);

        tracing::info!("user PIN initialized by SO");
        Ok(())
    }

    /// Change PIN (user changes own PIN, or SO changes SO PIN).
    ///
    /// Holds the auth lock across the entire operation. Tracks failed old-PIN
    /// verification attempts and applies the same lockout / rate-limit policy
    /// as `login`, preventing brute-force PIN discovery by a logged-in session.
    pub fn set_pin(&self, old_pin: &[u8], new_pin: &[u8]) -> HsmResult<()> {
        self.validate_pin(new_pin)?;

        let mut auth = self.auth.lock();
        match auth.login {
            LoginState::UserLoggedIn => {
                if auth.user_pin_locked {
                    return Err(HsmError::PinLocked);
                }
                Self::check_rate_limit(&auth.user_next_allowed)?;

                let hash_guard = self.user_pin_hash.read();
                let stored = hash_guard.as_ref().ok_or(HsmError::UserPinNotInitialized)?;
                let correct = self.verify_pin(stored, old_pin);
                drop(hash_guard);

                if !correct {
                    auth.failed_user_logins += 1;
                    let failures = auth.failed_user_logins;
                    auth.user_next_allowed =
                        Some(Instant::now() + Self::backoff_duration(failures));
                    if failures >= self.max_failed_logins {
                        auth.user_pin_locked = true;
                    }
                    self.persist_lockout(&auth);
                    if auth.user_pin_locked {
                        tracing::warn!(
                            "user PIN locked after {} failed set_pin attempts",
                            failures
                        );
                        return Err(HsmError::PinLocked);
                    }
                    tracing::warn!(
                        "set_pin: user old-PIN verification failed (attempt {})",
                        failures
                    );
                    return Err(HsmError::PinIncorrect);
                }

                auth.failed_user_logins = 0;
                auth.user_next_allowed = None;
                self.persist_lockout(&auth);
                *self.user_pin_hash.write() = Some(self.hash_pin(new_pin));
                tracing::info!("user PIN changed");
            }
            LoginState::SoLoggedIn => {
                if auth.so_pin_locked {
                    return Err(HsmError::PinLocked);
                }
                Self::check_rate_limit(&auth.so_next_allowed)?;

                let hash_guard = self.so_pin_hash.read();
                let stored = hash_guard.as_ref().ok_or(HsmError::PinIncorrect)?;
                let correct = self.verify_pin(stored, old_pin);
                drop(hash_guard);

                if !correct {
                    auth.failed_so_logins += 1;
                    let failures = auth.failed_so_logins;
                    auth.so_next_allowed = Some(Instant::now() + Self::backoff_duration(failures));
                    if failures >= self.max_failed_logins {
                        auth.so_pin_locked = true;
                    }
                    self.persist_lockout(&auth);
                    if auth.so_pin_locked {
                        tracing::warn!("SO PIN locked after {} failed set_pin attempts", failures);
                        return Err(HsmError::PinLocked);
                    }
                    tracing::warn!(
                        "set_pin: SO old-PIN verification failed (attempt {})",
                        failures
                    );
                    return Err(HsmError::PinIncorrect);
                }

                auth.failed_so_logins = 0;
                auth.so_next_allowed = None;
                self.persist_lockout(&auth);
                *self.so_pin_hash.write() = Some(self.hash_pin(new_pin));
                tracing::info!("SO PIN changed");
            }
            LoginState::Public => {
                return Err(HsmError::UserNotLoggedIn);
            }
        }
        Ok(())
    }

    /// Login as user type (CKU_USER or CKU_SO).
    ///
    /// Always performs the full PBKDF2 verification before checking lockout state,
    /// preventing timing side-channels that would leak whether an account is locked.
    /// Enforces per-account rate limiting: after each failed attempt an exponential
    /// backoff deadline is stored in `AuthState`; any attempt arriving before the
    /// deadline is rejected immediately, blocking concurrent brute-force threads.
    pub fn login(&self, user_type: CK_ULONG, pin: &[u8]) -> HsmResult<()> {
        use crate::pkcs11_abi::constants::*;

        let mut auth = self.auth.lock();

        if !auth.initialized {
            return Err(HsmError::TokenNotInitialized);
        }

        match user_type {
            CKU_USER => {
                if auth.login == LoginState::UserLoggedIn {
                    return Err(HsmError::UserAlreadyLoggedIn);
                }
                if auth.login == LoginState::SoLoggedIn {
                    return Err(HsmError::UserAnotherAlreadyLoggedIn);
                }
                if !auth.user_pin_initialized {
                    return Err(HsmError::UserPinNotInitialized);
                }

                // Per-account rate limit: reject if within backoff window
                Self::check_rate_limit(&auth.user_next_allowed)?;

                // Always perform the full PBKDF2 verification to prevent
                // timing side-channels that leak lockout state.
                let hash_guard = self.user_pin_hash.read();
                let stored = hash_guard.as_ref().ok_or(HsmError::UserPinNotInitialized)?;
                let pin_correct = self.verify_pin(stored, pin);
                drop(hash_guard);

                // Check lockout AFTER verification to keep timing constant
                if auth.user_pin_locked {
                    return Err(HsmError::PinLocked);
                }

                if !pin_correct {
                    auth.failed_user_logins += 1;
                    let failures = auth.failed_user_logins;
                    auth.user_next_allowed =
                        Some(Instant::now() + Self::backoff_duration(failures));
                    if failures >= self.max_failed_logins {
                        auth.user_pin_locked = true;
                    }
                    self.persist_lockout(&auth);
                    if auth.user_pin_locked {
                        tracing::warn!("user PIN locked after {} failed attempts", failures);
                        return Err(HsmError::PinLocked);
                    }
                    tracing::warn!("user login failed (attempt {})", failures);
                    return Err(HsmError::PinIncorrect);
                }

                auth.failed_user_logins = 0;
                auth.user_next_allowed = None;
                self.persist_lockout(&auth);
                auth.login = LoginState::UserLoggedIn;
                tracing::info!("user login succeeded");
            }
            CKU_SO => {
                if auth.login == LoginState::SoLoggedIn {
                    return Err(HsmError::UserAlreadyLoggedIn);
                }
                if auth.login == LoginState::UserLoggedIn {
                    return Err(HsmError::UserAnotherAlreadyLoggedIn);
                }

                // Per-account rate limit: reject if within backoff window
                Self::check_rate_limit(&auth.so_next_allowed)?;

                // Always perform verification before checking lockout
                let hash_guard = self.so_pin_hash.read();
                let stored = hash_guard.as_ref().ok_or(HsmError::PinIncorrect)?;
                let pin_correct = self.verify_pin(stored, pin);
                drop(hash_guard);

                // Check lockout AFTER verification
                if auth.so_pin_locked {
                    return Err(HsmError::PinLocked);
                }

                if !pin_correct {
                    auth.failed_so_logins += 1;
                    let failures = auth.failed_so_logins;
                    auth.so_next_allowed = Some(Instant::now() + Self::backoff_duration(failures));
                    if failures >= self.max_failed_logins {
                        auth.so_pin_locked = true;
                    }
                    self.persist_lockout(&auth);
                    if auth.so_pin_locked {
                        tracing::warn!("SO PIN locked after {} failed attempts", failures);
                        return Err(HsmError::PinLocked);
                    }
                    tracing::warn!("SO login failed (attempt {})", failures);
                    return Err(HsmError::PinIncorrect);
                }

                auth.failed_so_logins = 0;
                auth.so_next_allowed = None;
                self.persist_lockout(&auth);
                auth.login = LoginState::SoLoggedIn;
                tracing::info!("SO login succeeded");
            }
            _ => {
                return Err(HsmError::UserTypeInvalid);
            }
        }
        Ok(())
    }

    pub fn logout(&self) -> HsmResult<()> {
        let mut auth = self.auth.lock();
        if auth.login == LoginState::Public {
            return Err(HsmError::UserNotLoggedIn);
        }
        tracing::info!("logout from {:?}", auth.login);
        auth.login = LoginState::Public;
        Ok(())
    }

    /// Atomically increment session count.
    ///
    /// Acquires the auth lock to serialize against `reset_session_counts` and
    /// prevent the race where a concurrent reset could interleave with the CAS,
    /// causing counter drift.
    pub fn increment_session_count(&self, rw: bool) -> HsmResult<()> {
        let _auth = self.auth.lock();

        let current = self.session_count.load(Ordering::SeqCst);
        if current >= self.max_sessions {
            return Err(HsmError::SessionCount);
        }
        self.session_count.store(current + 1, Ordering::SeqCst);

        if rw {
            let rw_current = self.rw_session_count.load(Ordering::SeqCst);
            if rw_current >= self.max_rw_sessions {
                // Roll back total count
                self.session_count.store(current, Ordering::SeqCst);
                return Err(HsmError::SessionCount);
            }
            self.rw_session_count
                .store(rw_current + 1, Ordering::SeqCst);
        }

        Ok(())
    }

    /// Atomically decrement session count.
    ///
    /// Acquires the auth lock to serialize against `reset_session_counts` and
    /// `increment_session_count`, preventing counter drift from interleaved
    /// operations. Returns `Err` on underflow (double-close) instead of
    /// silently saturating, allowing callers to detect the bug.
    pub fn decrement_session_count(&self, rw: bool) -> HsmResult<()> {
        let _auth = self.auth.lock();

        let current = self.session_count.load(Ordering::SeqCst);
        if current == 0 {
            tracing::error!(
                "decrement_session_count: total count already 0 — possible double-close bug"
            );
            return Err(HsmError::GeneralError);
        }
        self.session_count.store(current - 1, Ordering::SeqCst);

        if rw {
            let rw_current = self.rw_session_count.load(Ordering::SeqCst);
            if rw_current == 0 {
                tracing::error!(
                    "decrement_session_count: rw count already 0 — possible double-close bug"
                );
                return Err(HsmError::GeneralError);
            }
            self.rw_session_count
                .store(rw_current - 1, Ordering::SeqCst);
        }

        Ok(())
    }

    /// Reset both session counters to zero.
    ///
    /// Resets the RW counter first to avoid a transient state where
    /// `rw_session_count > session_count`, which could allow an extra RW
    /// session to be opened past the limit. The auth lock serializes this
    /// against concurrent `increment`/`decrement` operations (which also
    /// acquire `auth`), eliminating counter-drift races.
    pub fn reset_session_counts(&self) {
        let _auth = self.auth.lock();
        self.rw_session_count.store(0, Ordering::SeqCst);
        self.session_count.store(0, Ordering::SeqCst);
    }
}
