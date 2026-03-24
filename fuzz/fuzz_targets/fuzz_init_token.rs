// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Fuzz target for C_InitToken and related token operations.
//!
//! Token reinitialization is security-critical:
//! - Must handle concurrent sessions correctly
//! - PIN length edge cases (empty, max-length, null bytes)
//! - Label encoding (32 bytes, padded, UTF-8 vs raw)
//! - Reinitialization while objects exist
//! - PIN setting after token init

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::Once;

use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm::pkcs11_abi::functions;
use craton_hsm::pkcs11_abi::types::*;

static INIT: Once = Once::new();

fn ensure_init() {
    INIT.call_once(|| {
        let rv = functions::C_Initialize(std::ptr::null_mut());
        assert!(rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED);
    });
}

fn cleanup_sessions() {
    let _ = functions::C_CloseAllSessions(0);
}

fuzz_target!(|data: &[u8]| {
    ensure_init();

    if data.len() < 4 {
        return;
    }

    let selector = data[0] % 5;
    let payload = &data[1..];

    match selector {
        0 => fuzz_init_token_random_pin(payload),
        1 => fuzz_init_token_random_label(payload),
        2 => fuzz_init_token_null_pointers(payload),
        3 => fuzz_init_pin_after_token(payload),
        4 => fuzz_set_pin_random(payload),
        _ => {}
    }

    cleanup_sessions();
});

/// C_InitToken with fuzz-derived SO PIN (exercises PIN length edge cases).
fn fuzz_init_token_random_pin(data: &[u8]) {
    if data.len() < 2 {
        return;
    }

    // Fuzz-derived PIN
    let pin_len = (data[0] as usize % 128).min(data.len() - 1);
    let pin = &data[1..1 + pin_len];

    // Fixed label (32 bytes, padded with spaces per PKCS#11 spec)
    let mut label = [0x20u8; 32]; // Space-padded
    let label_text = b"fuzz-token";
    label[..label_text.len()].copy_from_slice(label_text);

    // C_InitToken should handle any PIN gracefully
    let _rv = functions::C_InitToken(
        0,
        if pin.is_empty() {
            std::ptr::null_mut()
        } else {
            pin.as_ptr() as *mut _
        },
        pin.len() as CK_ULONG,
        label.as_mut_ptr(),
    );
}

/// C_InitToken with fuzz-derived label.
fn fuzz_init_token_random_label(data: &[u8]) {
    if data.len() < 4 {
        return;
    }

    let so_pin = b"12345678";

    // Fuzz-derived label — could be shorter or longer than 32 bytes,
    // contain null bytes, non-UTF-8 sequences, etc.
    let label_len = (data[0] as usize % 64).min(data.len() - 1);
    let label = &data[1..1 + label_len];

    let _rv = functions::C_InitToken(
        0,
        so_pin.as_ptr() as *mut _,
        so_pin.len() as CK_ULONG,
        if label.is_empty() {
            std::ptr::null_mut()
        } else {
            label.as_ptr() as *mut _
        },
    );
}

/// C_InitToken with null pointers in various positions.
fn fuzz_init_token_null_pointers(data: &[u8]) {
    if data.is_empty() {
        return;
    }

    // FIX #11: Assert that null pointer / invalid cases fail
    match data[0] % 4 {
        0 => {
            // Null PIN, non-zero length — must fail
            let mut label = [0x20u8; 32];
            let rv = functions::C_InitToken(0, std::ptr::null_mut(), 16, label.as_mut_ptr());
            assert!(rv != CKR_OK, "C_InitToken succeeded with null PIN + non-zero length");
        }
        1 => {
            // Null label — must fail
            let pin = b"12345678";
            let rv = functions::C_InitToken(
                0,
                pin.as_ptr() as *mut _,
                pin.len() as CK_ULONG,
                std::ptr::null_mut(),
            );
            assert!(rv != CKR_OK, "C_InitToken succeeded with null label");
        }
        2 => {
            // Both null — must fail
            let rv = functions::C_InitToken(0, std::ptr::null_mut(), 0, std::ptr::null_mut());
            assert!(rv != CKR_OK, "C_InitToken succeeded with all null pointers");
        }
        3 => {
            // Invalid slot ID — must fail
            let pin = b"12345678";
            let mut label = [0x20u8; 32];
            let rv = functions::C_InitToken(
                0xFFFFFFFF,
                pin.as_ptr() as *mut _,
                pin.len() as CK_ULONG,
                label.as_mut_ptr(),
            );
            assert!(rv != CKR_OK, "C_InitToken succeeded with invalid slot ID 0xFFFFFFFF");
        }
        _ => {}
    }
}

/// C_InitPIN after token initialization.
fn fuzz_init_pin_after_token(data: &[u8]) {
    if data.len() < 4 {
        return;
    }

    // First reinitialize the token with known SO PIN
    let so_pin = b"12345678";
    let mut label = [0x20u8; 32];
    let label_text = b"fuzz-token";
    label[..label_text.len()].copy_from_slice(label_text);

    let rv = functions::C_InitToken(
        0,
        so_pin.as_ptr() as *mut _,
        so_pin.len() as CK_ULONG,
        label.as_mut_ptr(),
    );
    if rv != CKR_OK {
        return;
    }

    // Open RW session and login as SO
    let mut session: CK_SESSION_HANDLE = 0;
    let rv = functions::C_OpenSession(
        0,
        CKF_SERIAL_SESSION | CKF_RW_SESSION,
        std::ptr::null_mut(),
        None,
        &mut session,
    );
    if rv != CKR_OK {
        return;
    }

    let rv = functions::C_Login(
        session,
        CKU_SO,
        so_pin.as_ptr() as *mut _,
        so_pin.len() as CK_ULONG,
    );
    if rv != CKR_OK {
        let _ = functions::C_CloseSession(session);
        return;
    }

    // InitPIN with fuzz-derived new user PIN
    let pin_len = (data[0] as usize % 128).min(data.len() - 1);
    let new_pin = &data[1..1 + pin_len];

    let _rv = functions::C_InitPIN(
        session,
        if new_pin.is_empty() {
            std::ptr::null_mut()
        } else {
            new_pin.as_ptr() as *mut _
        },
        new_pin.len() as CK_ULONG,
    );

    let _ = functions::C_Logout(session);
    let _ = functions::C_CloseSession(session);
}

/// C_SetPIN with fuzz-derived old and new PINs.
fn fuzz_set_pin_random(data: &[u8]) {
    if data.len() < 4 {
        return;
    }

    let mut session: CK_SESSION_HANDLE = 0;
    let rv = functions::C_OpenSession(
        0,
        CKF_SERIAL_SESSION | CKF_RW_SESSION,
        std::ptr::null_mut(),
        None,
        &mut session,
    );
    if rv != CKR_OK {
        return;
    }

    // Fuzz-derived old PIN
    let old_pin_len = (data[0] as usize % 64).min(data.len() - 1);
    let old_pin = &data[1..1 + old_pin_len];

    // Fuzz-derived new PIN
    let remaining = &data[1 + old_pin_len..];
    let new_pin_len = if remaining.is_empty() {
        0
    } else {
        (remaining[0] as usize % 64).min(remaining.len().saturating_sub(1))
    };
    let new_pin = if remaining.len() > 1 {
        &remaining[1..1 + new_pin_len]
    } else {
        &[]
    };

    let _rv = functions::C_SetPIN(
        session,
        if old_pin.is_empty() {
            std::ptr::null_mut()
        } else {
            old_pin.as_ptr() as *mut _
        },
        old_pin.len() as CK_ULONG,
        if new_pin.is_empty() {
            std::ptr::null_mut()
        } else {
            new_pin.as_ptr() as *mut _
        },
        new_pin.len() as CK_ULONG,
    );

    let _ = functions::C_CloseSession(session);
}
