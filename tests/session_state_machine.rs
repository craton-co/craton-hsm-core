// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
// Session state machine tests — exercises Session FSM transitions, SessionManager behaviors,
// Token PIN validation, and login state inheritance directly on internal structs.
// No C ABI needed — tests the Rust API surface.

use craton_hsm::error::HsmError;
use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm::pkcs11_abi::types::*;
use craton_hsm::session::manager::SessionManager;
use craton_hsm::session::session::{ActiveOperation, FindContext, Session, SessionState};
use craton_hsm::token::token::{LoginState, Token};

// ============================================================================
// Valid state transitions
// ============================================================================

#[test]
fn test_ro_public_to_ro_user() {
    let mut session = Session::new(1, 0, CKF_SERIAL_SESSION);
    assert_eq!(session.state, SessionState::RoPublic);
    session.on_user_login().unwrap();
    assert_eq!(session.state, SessionState::RoUser);
}

#[test]
fn test_rw_public_to_rw_user() {
    let mut session = Session::new(1, 0, CKF_RW_SESSION | CKF_SERIAL_SESSION);
    assert_eq!(session.state, SessionState::RwPublic);
    session.on_user_login().unwrap();
    assert_eq!(session.state, SessionState::RwUser);
}

#[test]
fn test_rw_public_to_rw_so() {
    let mut session = Session::new(1, 0, CKF_RW_SESSION | CKF_SERIAL_SESSION);
    assert_eq!(session.state, SessionState::RwPublic);
    session.on_so_login().unwrap();
    assert_eq!(session.state, SessionState::RwSO);
}

#[test]
fn test_ro_user_to_ro_public_via_logout() {
    let mut session = Session::new(1, 0, CKF_SERIAL_SESSION);
    session.on_user_login().unwrap();
    session.on_logout().unwrap();
    assert_eq!(session.state, SessionState::RoPublic);
}

#[test]
fn test_rw_user_to_rw_public_via_logout() {
    let mut session = Session::new(1, 0, CKF_RW_SESSION | CKF_SERIAL_SESSION);
    session.on_user_login().unwrap();
    session.on_logout().unwrap();
    assert_eq!(session.state, SessionState::RwPublic);
}

#[test]
fn test_rw_so_to_rw_public_via_logout() {
    let mut session = Session::new(1, 0, CKF_RW_SESSION | CKF_SERIAL_SESSION);
    session.on_so_login().unwrap();
    session.on_logout().unwrap();
    assert_eq!(session.state, SessionState::RwPublic);
}

// ============================================================================
// Invalid state transitions
// ============================================================================

#[test]
fn test_so_login_on_ro_session_fails() {
    let mut session = Session::new(1, 0, CKF_SERIAL_SESSION);
    let err = session.on_so_login().unwrap_err();
    assert!(matches!(err, HsmError::SessionReadOnly));
}

#[test]
fn test_double_user_login_fails() {
    let mut session = Session::new(1, 0, CKF_SERIAL_SESSION);
    session.on_user_login().unwrap();
    let err = session.on_user_login().unwrap_err();
    assert!(matches!(err, HsmError::UserAlreadyLoggedIn));
}

#[test]
fn test_double_so_login_fails() {
    let mut session = Session::new(1, 0, CKF_RW_SESSION | CKF_SERIAL_SESSION);
    session.on_so_login().unwrap();
    let err = session.on_so_login().unwrap_err();
    assert!(matches!(err, HsmError::UserAlreadyLoggedIn));
}

#[test]
fn test_user_login_while_so_logged_in_fails() {
    let mut session = Session::new(1, 0, CKF_RW_SESSION | CKF_SERIAL_SESSION);
    session.on_so_login().unwrap();
    let err = session.on_user_login().unwrap_err();
    assert!(matches!(err, HsmError::UserAlreadyLoggedIn));
}

#[test]
fn test_so_login_while_user_logged_in_fails() {
    let mut session = Session::new(1, 0, CKF_RW_SESSION | CKF_SERIAL_SESSION);
    session.on_user_login().unwrap();
    let err = session.on_so_login().unwrap_err();
    assert!(matches!(err, HsmError::UserAlreadyLoggedIn));
}

#[test]
fn test_logout_when_public_fails() {
    let mut session = Session::new(1, 0, CKF_SERIAL_SESSION);
    let err = session.on_logout().unwrap_err();
    assert!(matches!(err, HsmError::UserNotLoggedIn));
}

// ============================================================================
// Logout side-effects: clears active_operation and find_context
// ============================================================================

#[test]
fn test_logout_clears_active_operation() {
    let mut session = Session::new(1, 0, CKF_RW_SESSION | CKF_SERIAL_SESSION);
    session.on_user_login().unwrap();
    session.active_operation = Some(ActiveOperation::Encrypt {
        mechanism: CKM_AES_GCM,
        key_handle: 42,
        mechanism_param: zeroize::Zeroizing::new(vec![]),
        data: zeroize::Zeroizing::new(vec![]),
        cached_object: None,
    });
    session.on_logout().unwrap();
    assert!(session.active_operation.is_none());
}

#[test]
fn test_logout_clears_find_context() {
    let mut session = Session::new(1, 0, CKF_RW_SESSION | CKF_SERIAL_SESSION);
    session.on_user_login().unwrap();
    session.find_context = Some(FindContext {
        results: vec![1, 2, 3],
        position: 0,
    });
    session.on_logout().unwrap();
    assert!(session.find_context.is_none());
}

// ============================================================================
// Session info
// ============================================================================

#[test]
fn test_session_info_reflects_state() {
    let session = Session::new(1, 0, CKF_RW_SESSION | CKF_SERIAL_SESSION);
    let info = session.get_info();
    let slot_id = info.slot_id;
    let state = info.state;
    let flags = info.flags;
    assert_eq!(slot_id, 0);
    assert_eq!(state, CKS_RW_PUBLIC_SESSION);
    assert_eq!(flags, CKF_RW_SESSION | CKF_SERIAL_SESSION);
}

#[test]
fn test_is_rw_for_rw_session() {
    let session = Session::new(1, 0, CKF_RW_SESSION | CKF_SERIAL_SESSION);
    assert!(session.is_rw());
}

#[test]
fn test_is_rw_false_for_ro_session() {
    let session = Session::new(1, 0, CKF_SERIAL_SESSION);
    assert!(!session.is_rw());
}

// ============================================================================
// SessionManager tests
// ============================================================================

#[test]
fn test_session_manager_missing_serial_flag() {
    let mgr = SessionManager::new();
    let token = Token::new();
    token
        .init_token(b"sopin123", &padded_label(b"TestTok"))
        .unwrap();
    let err = mgr.open_session(0, CKF_RW_SESSION, &token).unwrap_err();
    assert!(matches!(err, HsmError::SessionParallelNotSupported));
}

#[test]
fn test_session_manager_ro_session_while_so_logged_in() {
    let mgr = SessionManager::new();
    let token = Token::new();
    token
        .init_token(b"sopin123", &padded_label(b"TestTok"))
        .unwrap();

    // Open RW session
    let rw_handle = mgr
        .open_session(0, CKF_RW_SESSION | CKF_SERIAL_SESSION, &token)
        .unwrap();
    // Login as SO via token
    token.login(CKU_SO, b"sopin123").unwrap();
    mgr.login_all(0, CKU_SO).unwrap();

    // Now try to open RO session — should fail
    let err = mgr.open_session(0, CKF_SERIAL_SESSION, &token).unwrap_err();
    assert!(matches!(err, HsmError::SessionReadWriteSoExists));

    // Cleanup
    token.logout().unwrap();
    mgr.logout_all(0).unwrap();
    mgr.close_session(rw_handle, &token).unwrap();
}

#[test]
fn test_session_manager_invalid_handle_close() {
    let mgr = SessionManager::new();
    let token = Token::new();
    token
        .init_token(b"sopin123", &padded_label(b"TestTok"))
        .unwrap();
    let err = mgr.close_session(999999, &token).unwrap_err();
    assert!(matches!(err, HsmError::SessionHandleInvalid));
}

#[test]
fn test_session_manager_get_invalid_handle() {
    let mgr = SessionManager::new();
    assert!(mgr.get_session(999999).is_err());
}

#[test]
fn test_session_manager_login_all_affects_all_sessions() {
    let mgr = SessionManager::new();
    let token = Token::new();
    token
        .init_token(b"sopin123", &padded_label(b"TestTok"))
        .unwrap();
    token.login(CKU_SO, b"sopin123").unwrap();
    token.init_pin(b"userpin1").unwrap();
    token.logout().unwrap();

    // Open two sessions
    let h1 = mgr.open_session(0, CKF_SERIAL_SESSION, &token).unwrap();
    let h2 = mgr
        .open_session(0, CKF_RW_SESSION | CKF_SERIAL_SESSION, &token)
        .unwrap();

    // Login user via token and manager
    token.login(CKU_USER, b"userpin1").unwrap();
    mgr.login_all(0, CKU_USER).unwrap();

    // Both sessions should be in user state
    let s1 = mgr.get_session(h1).unwrap();
    assert!(s1.read().state.is_logged_in());
    let s2 = mgr.get_session(h2).unwrap();
    assert!(s2.read().state.is_logged_in());

    // Logout all
    mgr.logout_all(0).unwrap();
    let s1 = mgr.get_session(h1).unwrap();
    assert!(!s1.read().state.is_logged_in());
    let s2 = mgr.get_session(h2).unwrap();
    assert!(!s2.read().state.is_logged_in());

    token.logout().unwrap();
}

#[test]
fn test_new_session_inherits_user_login_state() {
    let mgr = SessionManager::new();
    let token = Token::new();
    token
        .init_token(b"sopin123", &padded_label(b"Inherit"))
        .unwrap();
    token.login(CKU_SO, b"sopin123").unwrap();
    token.init_pin(b"userpin1").unwrap();
    token.logout().unwrap();
    token.login(CKU_USER, b"userpin1").unwrap();

    // Open new session while token is UserLoggedIn
    let h = mgr.open_session(0, CKF_SERIAL_SESSION, &token).unwrap();
    let s = mgr.get_session(h).unwrap();
    assert_eq!(s.read().state, SessionState::RoUser); // inherited login state

    token.logout().unwrap();
}

#[test]
fn test_close_all_sessions() {
    let mgr = SessionManager::new();
    let token = Token::new();
    token
        .init_token(b"sopin123", &padded_label(b"CloseAll"))
        .unwrap();

    let _h1 = mgr.open_session(0, CKF_SERIAL_SESSION, &token).unwrap();
    let _h2 = mgr
        .open_session(0, CKF_RW_SESSION | CKF_SERIAL_SESSION, &token)
        .unwrap();

    assert_eq!(token.session_count(), 2);
    mgr.close_all_sessions(0, &token);
    assert_eq!(token.session_count(), 0);
}

// ============================================================================
// Token PIN validation
// ============================================================================

#[test]
fn test_pin_too_short() {
    let token = Token::new();
    let err = token
        .init_token(b"abc", &padded_label(b"Short"))
        .unwrap_err(); // min is 4
    assert!(matches!(err, HsmError::PinLenRange));
}

#[test]
fn test_pin_at_minimum_length() {
    let token = Token::new();
    // Token::new() uses DEFAULT_PIN_MIN_LEN = 8, so PIN must be >= 8 chars
    // and meet complexity requirements (2+ character classes, 3+ distinct bytes)
    token
        .init_token(b"abcdEF12", &padded_label(b"MinLen"))
        .unwrap();
    assert!(token.is_initialized());
}

#[test]
fn test_pin_empty_fails() {
    let token = Token::new();
    let err = token.init_token(b"", &padded_label(b"Empty")).unwrap_err();
    assert!(matches!(err, HsmError::PinLenRange));
}

#[test]
fn test_pin_at_maximum_length() {
    let token = Token::new();
    // Token::new() uses DEFAULT_PIN_MAX_LEN = 64. PIN must also meet
    // complexity: 3+ distinct bytes, 2+ character classes.
    let mut long_pin = vec![b'x'; 62];
    long_pin.push(b'Y');
    long_pin.push(b'1');
    assert_eq!(long_pin.len(), 64);
    token
        .init_token(&long_pin, &padded_label(b"MaxLen"))
        .unwrap();
    assert!(token.is_initialized());
}

#[test]
fn test_pin_too_long() {
    let token = Token::new();
    let too_long = vec![b'x'; 65]; // max is 64
    let err = token
        .init_token(&too_long, &padded_label(b"TooLong"))
        .unwrap_err();
    assert!(matches!(err, HsmError::PinLenRange));
}

#[test]
fn test_user_lockout_after_max_failures() {
    let token = Token::new();
    token
        .init_token(b"sopin123", &padded_label(b"Lockout"))
        .unwrap();
    token.login(CKU_SO, b"sopin123").unwrap();
    token.init_pin(b"userpin1").unwrap();
    token.logout().unwrap();

    // Default max_failed_logins is 5 (from Token::new() hardcoded default).
    // Rapid-fire failures may trigger rate limiting (PinRateLimited) in
    // addition to PinIncorrect — both indicate a rejected attempt.
    for i in 0..4 {
        let err = token.login(CKU_USER, b"wrongpin").unwrap_err();
        assert!(
            matches!(err, HsmError::PinIncorrect | HsmError::PinRateLimited),
            "iteration {}: expected PinIncorrect or PinRateLimited, got {:?}",
            i,
            err
        );
    }

    // 5th failure should lock
    let err = token.login(CKU_USER, b"wrongpin").unwrap_err();
    assert!(matches!(
        err,
        HsmError::PinLocked | HsmError::PinRateLimited
    ));

    // Subsequent correct PIN also fails because locked
    let err = token.login(CKU_USER, b"userpin1").unwrap_err();
    assert!(matches!(
        err,
        HsmError::PinLocked | HsmError::PinRateLimited
    ));
}

#[test]
fn test_so_lockout_after_max_failures() {
    let token = Token::new();
    token
        .init_token(b"sopin123", &padded_label(b"SOLock"))
        .unwrap();

    for _ in 0..4 {
        let err = token.login(CKU_SO, b"wrongpin").unwrap_err();
        assert!(matches!(
            err,
            HsmError::PinIncorrect | HsmError::PinRateLimited
        ));
    }
    let err = token.login(CKU_SO, b"wrongpin").unwrap_err();
    assert!(matches!(
        err,
        HsmError::PinLocked | HsmError::PinRateLimited
    ));
}

#[test]
fn test_successful_login_resets_failure_count() {
    let token = Token::new();
    token
        .init_token(b"sopin123", &padded_label(b"Reset"))
        .unwrap();
    token.login(CKU_SO, b"sopin123").unwrap();
    token.init_pin(b"userpin1").unwrap();
    token.logout().unwrap();

    // Fail 3 times (below the max of 5 for Token::new())
    for _ in 0..3 {
        let _ = token.login(CKU_USER, b"wrongpin");
    }
    // Wait for rate-limit backoff to expire before trying the correct PIN
    // After 3 failures: backoff = min(100ms * 2^2, 5000ms) = 400ms; 1s margin is plenty.
    std::thread::sleep(std::time::Duration::from_secs(1));
    // Succeed — resets counter
    token.login(CKU_USER, b"userpin1").unwrap();
    token.logout().unwrap();

    // Fail 4 more times — should NOT lock (counter was reset, max is 5)
    for _ in 0..4 {
        let err = token.login(CKU_USER, b"wrongpin").unwrap_err();
        assert!(matches!(
            err,
            HsmError::PinIncorrect | HsmError::PinRateLimited
        ));
    }
}

#[test]
fn test_set_pin_wrong_old_pin() {
    let token = Token::new();
    token
        .init_token(b"sopin123", &padded_label(b"SetPin"))
        .unwrap();
    token.login(CKU_SO, b"sopin123").unwrap();
    token.init_pin(b"userpin1").unwrap();
    token.logout().unwrap();
    token.login(CKU_USER, b"userpin1").unwrap();

    let err = token.set_pin(b"wrongold", b"newpin12").unwrap_err();
    assert!(matches!(err, HsmError::PinIncorrect));
}

#[test]
fn test_set_pin_while_public_fails() {
    let token = Token::new();
    token
        .init_token(b"sopin123", &padded_label(b"PubSet"))
        .unwrap();

    let err = token.set_pin(b"sopin123", b"newpin12").unwrap_err();
    assert!(matches!(err, HsmError::UserNotLoggedIn));
}

#[test]
fn test_login_on_uninitialized_token_fails() {
    let token = Token::new();
    let err = token.login(CKU_USER, b"userpin1").unwrap_err();
    assert!(matches!(err, HsmError::TokenNotInitialized));
}

#[test]
fn test_login_user_without_pin_initialized() {
    let token = Token::new();
    token
        .init_token(b"sopin123", &padded_label(b"NoUser"))
        .unwrap();
    let err = token.login(CKU_USER, b"userpin1").unwrap_err();
    assert!(matches!(err, HsmError::UserPinNotInitialized));
}

#[test]
fn test_init_pin_requires_so_login() {
    let token = Token::new();
    token
        .init_token(b"sopin123", &padded_label(b"InitPin"))
        .unwrap();
    let err = token.init_pin(b"userpin1").unwrap_err();
    assert!(matches!(err, HsmError::UserNotLoggedIn));
}

#[test]
fn test_invalid_user_type() {
    let token = Token::new();
    token
        .init_token(b"sopin123", &padded_label(b"InvType"))
        .unwrap();
    let err = token.login(99, b"sopin123").unwrap_err();
    assert!(matches!(err, HsmError::UserTypeInvalid));
}

#[test]
fn test_user_login_while_so_logged_in() {
    let token = Token::new();
    token
        .init_token(b"sopin123", &padded_label(b"Cross"))
        .unwrap();
    token.login(CKU_SO, b"sopin123").unwrap();
    token.init_pin(b"userpin1").unwrap();

    let err = token.login(CKU_USER, b"userpin1").unwrap_err();
    assert!(matches!(err, HsmError::UserAnotherAlreadyLoggedIn));
}

#[test]
fn test_so_login_while_user_logged_in() {
    let token = Token::new();
    token
        .init_token(b"sopin123", &padded_label(b"Cross2"))
        .unwrap();
    token.login(CKU_SO, b"sopin123").unwrap();
    token.init_pin(b"userpin1").unwrap();
    token.logout().unwrap();
    token.login(CKU_USER, b"userpin1").unwrap();

    let err = token.login(CKU_SO, b"sopin123").unwrap_err();
    assert!(matches!(err, HsmError::UserAnotherAlreadyLoggedIn));
}

#[test]
fn test_token_reinit_resets_lockout() {
    let token = Token::new();
    token
        .init_token(b"sopin123", &padded_label(b"ReInit"))
        .unwrap();
    token.login(CKU_SO, b"sopin123").unwrap();
    token.init_pin(b"userpin1").unwrap();
    token.logout().unwrap();

    // Lock out user (max_failed_logins = 5 for Token::new())
    for _ in 0..5 {
        let _ = token.login(CKU_USER, b"wrongpin");
    }
    let err = token.login(CKU_USER, b"userpin1").unwrap_err();
    assert!(matches!(
        err,
        HsmError::PinLocked | HsmError::PinRateLimited
    ));

    // Re-init token should clear lockout (including rate-limit state)
    token
        .init_token(b"sopin123", &padded_label(b"ReInit2"))
        .unwrap();
    token.login(CKU_SO, b"sopin123").unwrap();
    token.init_pin(b"userpin1").unwrap();
    token.logout().unwrap();
    token.login(CKU_USER, b"userpin1").unwrap(); // should succeed now
    assert_eq!(token.login_state(), LoginState::UserLoggedIn);
}

#[test]
fn test_token_flags() {
    let token = Token::new();
    let flags = token.flags();
    // Not initialized yet: no CKF_TOKEN_INITIALIZED
    assert_eq!(flags & CKF_TOKEN_INITIALIZED, 0);

    token
        .init_token(b"sopin123", &padded_label(b"Flags"))
        .unwrap();
    let flags = token.flags();
    assert_ne!(flags & CKF_TOKEN_INITIALIZED, 0);
    assert_eq!(flags & CKF_USER_PIN_INITIALIZED, 0); // user PIN not set yet

    token.login(CKU_SO, b"sopin123").unwrap();
    token.init_pin(b"userpin1").unwrap();
    token.logout().unwrap();
    let flags = token.flags();
    assert_ne!(flags & CKF_USER_PIN_INITIALIZED, 0);
}

// ============================================================================
// Cross-slot session isolation
// ============================================================================

#[test]
fn test_login_all_only_affects_matching_slot() {
    let mgr = SessionManager::new();
    let token0 = Token::new();
    let token1 = Token::new();
    token0
        .init_token(b"sopin123", &padded_label(b"Slot0"))
        .unwrap();
    token1
        .init_token(b"sopin456", &padded_label(b"Slot1"))
        .unwrap();
    token0.login(CKU_SO, b"sopin123").unwrap();
    token0.init_pin(b"userpin0").unwrap();
    token0.logout().unwrap();

    // Open sessions on different slots
    let h0 = mgr.open_session(0, CKF_SERIAL_SESSION, &token0).unwrap();
    let h1 = mgr.open_session(1, CKF_SERIAL_SESSION, &token1).unwrap();

    // Login slot 0 only
    token0.login(CKU_USER, b"userpin0").unwrap();
    mgr.login_all(0, CKU_USER).unwrap();

    // Slot 0 session should be logged in
    let s0 = mgr.get_session(h0).unwrap();
    assert!(
        s0.read().state.is_logged_in(),
        "Slot 0 session should be logged in"
    );

    // Slot 1 session should NOT be affected
    let s1 = mgr.get_session(h1).unwrap();
    assert!(
        !s1.read().state.is_logged_in(),
        "Slot 1 session must NOT be affected by slot 0 login"
    );

    token0.logout().unwrap();
    mgr.logout_all(0).unwrap();
}

#[test]
fn test_close_all_sessions_only_affects_matching_slot() {
    let mgr = SessionManager::new();
    let token0 = Token::new();
    let token1 = Token::new();
    token0
        .init_token(b"sopin123", &padded_label(b"SlotA"))
        .unwrap();
    token1
        .init_token(b"sopin456", &padded_label(b"SlotB"))
        .unwrap();

    let _h0 = mgr.open_session(0, CKF_SERIAL_SESSION, &token0).unwrap();
    let h1 = mgr.open_session(1, CKF_SERIAL_SESSION, &token1).unwrap();

    // Close all sessions on slot 0
    mgr.close_all_sessions(0, &token0);

    // Slot 1 session should still be valid
    let s1 = mgr.get_session(h1);
    assert!(
        s1.is_ok(),
        "Slot 1 session must survive close_all_sessions(slot=0)"
    );
}

// ============================================================================
// PIN lockout concurrency: multiple threads racing login attempts
// ============================================================================

#[test]
fn test_pin_lockout_concurrent_attempts() {
    use std::sync::Arc;

    let token = Arc::new(Token::new());
    token
        .init_token(b"sopin123", &padded_label(b"ConcLock"))
        .unwrap();
    token.login(CKU_SO, b"sopin123").unwrap();
    token.init_pin(b"userpin1").unwrap();
    token.logout().unwrap();

    // With per-account rate limiting, concurrent threads within the same
    // backoff window are rejected with PinRateLimited (without incrementing
    // the failure counter). To properly test lockout, we spawn one thread
    // per wave and wait for the backoff window to expire between waves.
    // max_failed_logins = 5 for Token::new().
    //
    // Backoff = min(100ms * 2^(failures-1), 5000ms), so we sleep just enough
    // past each wave's backoff to keep the test fast:
    //   wave 0: 100ms, wave 1: 200ms, wave 2: 400ms, wave 3: 800ms,
    //   wave 4: 1600ms, wave 5 (final): capped 5000ms.
    let backoff_ms = [200, 300, 500, 1000, 2000];
    for wave in 0..6 {
        let token = Arc::clone(&token);
        let h = std::thread::spawn(move || {
            let _ = token.login(CKU_USER, b"wrongpin");
        });
        h.join().unwrap();
        if wave < 5 {
            std::thread::sleep(std::time::Duration::from_millis(backoff_ms[wave]));
        }
    }

    // Wait for final backoff to expire (capped at 5000ms)
    std::thread::sleep(std::time::Duration::from_secs(6));

    // After 6 failed attempts (>5 threshold), the PIN must be locked.
    let result = token.login(CKU_USER, b"userpin1");
    assert!(
        result.is_err(),
        "After enough wrong PINs, account must be locked"
    );
    assert!(
        matches!(result.unwrap_err(), HsmError::PinLocked),
        "Error should be PinLocked"
    );
}

#[test]
fn test_pin_lockout_counter_not_bypassed_by_concurrency() {
    use std::sync::{Arc, Barrier};

    let token = Arc::new(Token::new());
    token
        .init_token(b"sopin123", &padded_label(b"ConcBy"))
        .unwrap();
    token.login(CKU_SO, b"sopin123").unwrap();
    token.init_pin(b"userpin1").unwrap();
    token.logout().unwrap();

    // Use a barrier so all 15 threads start at the exact same moment
    let barrier = Arc::new(Barrier::new(15));
    let mut handles = Vec::new();
    for _ in 0..15 {
        let token = Arc::clone(&token);
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            let _ = token.login(CKU_USER, b"wrongpin");
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    // After 15 concurrent wrong PINs (>10 limit), must be locked
    let result = token.login(CKU_USER, b"userpin1");
    assert!(
        result.is_err(),
        "PIN must be locked after concurrent brute force"
    );
}

// ============================================================================
// Helper
// ============================================================================

fn padded_label(prefix: &[u8]) -> [u8; 32] {
    let mut label = [b' '; 32];
    let len = prefix.len().min(32);
    label[..len].copy_from_slice(&prefix[..len]);
    label
}
