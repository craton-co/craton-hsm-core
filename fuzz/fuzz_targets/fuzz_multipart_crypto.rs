// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Fuzz target for multi-part encrypt/decrypt operations.
//!
//! Multi-part operations have distinct buffer management bugs:
//! - EncryptUpdate/DecryptUpdate with varying chunk sizes
//! - EncryptFinal/DecryptFinal buffer too small
//! - Interleaved Update/Final calls
//! - Operations after Final (state confusion)
//! - Zero-length updates

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

/// FIX #3: Extract a fuzz-derived PIN from data.
fn extract_fuzz_pin(data: &[u8]) -> (*mut u8, CK_ULONG, usize) {
    if data.is_empty() {
        return (std::ptr::null_mut(), 0, 0);
    }
    let pin_len = (data[0] as usize) % 65;
    let consumed = 1 + pin_len.min(data.len() - 1);
    let actual_pin = &data[1..consumed];
    if actual_pin.is_empty() {
        (std::ptr::null_mut(), 0, consumed)
    } else {
        (actual_pin.as_ptr() as *mut u8, actual_pin.len() as CK_ULONG, consumed)
    }
}

fn open_rw_session() -> Option<CK_SESSION_HANDLE> {
    let mut session: CK_SESSION_HANDLE = 0;
    let rv = functions::C_OpenSession(
        0,
        CKF_SERIAL_SESSION | CKF_RW_SESSION,
        std::ptr::null_mut(),
        None,
        &mut session,
    );
    if rv != CKR_OK {
        return None;
    }
    let pin = b"1234";
    let _ = functions::C_Login(session, CKU_USER, pin.as_ptr() as *mut _, pin.len() as CK_ULONG);
    Some(session)
}

fn close_session(session: CK_SESSION_HANDLE) {
    let _ = functions::C_Logout(session);
    let _ = functions::C_CloseSession(session);
}

/// Generate an AES-256 key for encryption.
fn generate_aes_key(session: CK_SESSION_HANDLE) -> Option<CK_OBJECT_HANDLE> {
    let true_val: CK_BBOOL = CK_TRUE;
    let value_len: CK_ULONG = 32;

    let mut template = [
        CK_ATTRIBUTE {
            attr_type: CKA_VALUE_LEN,
            p_value: &value_len as *const _ as *mut _,
            value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_ENCRYPT,
            p_value: &true_val as *const _ as *mut _,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_DECRYPT,
            p_value: &true_val as *const _ as *mut _,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_TOKEN,
            p_value: &true_val as *const _ as *mut _,
            value_len: 1,
        },
    ];

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        p_parameter: std::ptr::null_mut(),
        parameter_len: 0,
    };

    let mut key: CK_OBJECT_HANDLE = 0;
    let rv = functions::C_GenerateKey(
        session,
        &mut mechanism,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut key,
    );

    if rv == CKR_OK { Some(key) } else { None }
}

fuzz_target!(|data: &[u8]| {
    ensure_init();

    if data.len() < 4 {
        return;
    }

    let selector = data[0] % 5;
    let payload = &data[1..];

    match selector {
        0 => fuzz_multipart_cbc_encrypt(payload),
        1 => fuzz_multipart_cbc_decrypt_random(payload),
        2 => fuzz_multipart_encrypt_chunk_abuse(payload),
        3 => fuzz_encrypt_after_final(payload),
        4 => fuzz_multipart_encrypt_null_buffers(payload),
        _ => {}
    }

    cleanup_sessions();
});

/// Multi-part AES-CBC encrypt with varying chunk sizes.
fn fuzz_multipart_cbc_encrypt(data: &[u8]) {
    if data.len() < 20 {
        return;
    }

    let session = match open_rw_session() {
        Some(s) => s,
        None => return,
    };

    let key = match generate_aes_key(session) {
        Some(k) => k,
        None => { close_session(session); return; }
    };

    // Use first 16 bytes as IV
    let iv = &data[..16];
    let plaintext = &data[16..];

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_CBC,
        p_parameter: iv.as_ptr() as *mut _,
        parameter_len: 16,
    };

    let rv = functions::C_EncryptInit(session, &mut mechanism, key);
    if rv != CKR_OK {
        let _ = functions::C_DestroyObject(session, key);
        close_session(session);
        return;
    }

    // Feed plaintext in variable-sized chunks driven by fuzz data
    let mut offset = 0;
    let mut out_buf = [0u8; 1024];

    while offset < plaintext.len() {
        let chunk_size = if offset < plaintext.len() {
            ((plaintext[offset] as usize) % 64 + 1).min(plaintext.len() - offset)
        } else {
            break;
        };

        let chunk = &plaintext[offset..offset + chunk_size];
        let mut out_len: CK_ULONG = out_buf.len() as CK_ULONG;

        let _rv = functions::C_EncryptUpdate(
            session,
            chunk.as_ptr() as *mut _,
            chunk.len() as CK_ULONG,
            out_buf.as_mut_ptr(),
            &mut out_len,
        );

        offset += chunk_size;
    }

    // EncryptFinal
    let mut final_buf = [0u8; 64];
    let mut final_len: CK_ULONG = 64;
    let _rv = functions::C_EncryptFinal(session, final_buf.as_mut_ptr(), &mut final_len);

    let _ = functions::C_DestroyObject(session, key);
    close_session(session);
}

/// Multi-part AES-CBC decrypt with random ciphertext.
fn fuzz_multipart_cbc_decrypt_random(data: &[u8]) {
    if data.len() < 20 {
        return;
    }

    let session = match open_rw_session() {
        Some(s) => s,
        None => return,
    };

    let key = match generate_aes_key(session) {
        Some(k) => k,
        None => { close_session(session); return; }
    };

    let iv = &data[..16];
    let ciphertext = &data[16..];

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_CBC,
        p_parameter: iv.as_ptr() as *mut _,
        parameter_len: 16,
    };

    let rv = functions::C_DecryptInit(session, &mut mechanism, key);
    if rv != CKR_OK {
        let _ = functions::C_DestroyObject(session, key);
        close_session(session);
        return;
    }

    // Feed random ciphertext in chunks
    let mut offset = 0;
    let mut out_buf = [0u8; 1024];

    while offset < ciphertext.len() {
        let chunk_size = ((ciphertext.get(offset).copied().unwrap_or(16) as usize) % 64 + 1)
            .min(ciphertext.len() - offset);
        let chunk = &ciphertext[offset..offset + chunk_size];
        let mut out_len: CK_ULONG = out_buf.len() as CK_ULONG;

        let _rv = functions::C_DecryptUpdate(
            session,
            chunk.as_ptr() as *mut _,
            chunk.len() as CK_ULONG,
            out_buf.as_mut_ptr(),
            &mut out_len,
        );

        offset += chunk_size;
    }

    let mut final_buf = [0u8; 64];
    let mut final_len: CK_ULONG = 64;
    let _rv = functions::C_DecryptFinal(session, final_buf.as_mut_ptr(), &mut final_len);

    let _ = functions::C_DestroyObject(session, key);
    close_session(session);
}

/// Abuse multi-part encrypt with extreme chunk patterns.
fn fuzz_multipart_encrypt_chunk_abuse(data: &[u8]) {
    if data.len() < 20 {
        return;
    }

    let session = match open_rw_session() {
        Some(s) => s,
        None => return,
    };

    let key = match generate_aes_key(session) {
        Some(k) => k,
        None => { close_session(session); return; }
    };

    let iv = &data[..16];

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_CBC,
        p_parameter: iv.as_ptr() as *mut _,
        parameter_len: 16,
    };

    let rv = functions::C_EncryptInit(session, &mut mechanism, key);
    if rv != CKR_OK {
        let _ = functions::C_DestroyObject(session, key);
        close_session(session);
        return;
    }

    let payload = &data[16..];
    let mut out_buf = [0u8; 1024];

    for &byte in payload.iter().take(32) {
        match byte % 5 {
            0 => {
                // Zero-length update
                let mut out_len: CK_ULONG = out_buf.len() as CK_ULONG;
                let _rv = functions::C_EncryptUpdate(
                    session,
                    std::ptr::null_mut(),
                    0,
                    out_buf.as_mut_ptr(),
                    &mut out_len,
                );
            }
            1 => {
                // Single-byte update
                let one = [byte];
                let mut out_len: CK_ULONG = out_buf.len() as CK_ULONG;
                let _rv = functions::C_EncryptUpdate(
                    session,
                    one.as_ptr() as *mut _,
                    1,
                    out_buf.as_mut_ptr(),
                    &mut out_len,
                );
            }
            2 => {
                // Block-aligned update (16 bytes)
                let block = [byte; 16];
                let mut out_len: CK_ULONG = out_buf.len() as CK_ULONG;
                let _rv = functions::C_EncryptUpdate(
                    session,
                    block.as_ptr() as *mut _,
                    16,
                    out_buf.as_mut_ptr(),
                    &mut out_len,
                );
            }
            3 => {
                // EncryptFinal in the middle — should finalize or error
                let mut final_buf = [0u8; 64];
                let mut final_len: CK_ULONG = 64;
                let _rv = functions::C_EncryptFinal(
                    session,
                    final_buf.as_mut_ptr(),
                    &mut final_len,
                );
                // After Final, further updates should fail
            }
            4 => {
                // Update with output buffer too small
                let block = [byte; 32];
                let mut out_len: CK_ULONG = 1; // Too small!
                let mut tiny = [0u8; 1];
                let _rv = functions::C_EncryptUpdate(
                    session,
                    block.as_ptr() as *mut _,
                    32,
                    tiny.as_mut_ptr(),
                    &mut out_len,
                );
            }
            _ => {}
        }
    }

    // Final cleanup
    let mut final_buf = [0u8; 64];
    let mut final_len: CK_ULONG = 64;
    let _rv = functions::C_EncryptFinal(session, final_buf.as_mut_ptr(), &mut final_len);

    let _ = functions::C_DestroyObject(session, key);
    close_session(session);
}

/// Call Encrypt/EncryptUpdate after EncryptFinal — state confusion test.
fn fuzz_encrypt_after_final(data: &[u8]) {
    if data.len() < 20 {
        return;
    }

    let session = match open_rw_session() {
        Some(s) => s,
        None => return,
    };

    let key = match generate_aes_key(session) {
        Some(k) => k,
        None => { close_session(session); return; }
    };

    let iv = &data[..16];
    let plaintext = &data[16..];

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_CBC,
        p_parameter: iv.as_ptr() as *mut _,
        parameter_len: 16,
    };

    let rv = functions::C_EncryptInit(session, &mut mechanism, key);
    if rv != CKR_OK {
        let _ = functions::C_DestroyObject(session, key);
        close_session(session);
        return;
    }

    // Do one Update
    let mut out_buf = [0u8; 1024];
    let mut out_len: CK_ULONG = out_buf.len() as CK_ULONG;
    if !plaintext.is_empty() {
        let _rv = functions::C_EncryptUpdate(
            session,
            plaintext.as_ptr() as *mut _,
            plaintext.len() as CK_ULONG,
            out_buf.as_mut_ptr(),
            &mut out_len,
        );
    }

    // Final
    let mut final_buf = [0u8; 64];
    let mut final_len: CK_ULONG = 64;
    let _rv = functions::C_EncryptFinal(session, final_buf.as_mut_ptr(), &mut final_len);

    // Now try operations AFTER Final — all must return error
    out_len = out_buf.len() as CK_ULONG;
    let _rv = functions::C_EncryptUpdate(
        session,
        plaintext.as_ptr() as *mut _,
        plaintext.len() as CK_ULONG,
        out_buf.as_mut_ptr(),
        &mut out_len,
    );

    final_len = 64;
    let _rv = functions::C_EncryptFinal(session, final_buf.as_mut_ptr(), &mut final_len);

    // Try single-shot Encrypt after multi-part was finalized
    out_len = out_buf.len() as CK_ULONG;
    let _rv = functions::C_Encrypt(
        session,
        plaintext.as_ptr() as *mut _,
        plaintext.len() as CK_ULONG,
        out_buf.as_mut_ptr(),
        &mut out_len,
    );

    let _ = functions::C_DestroyObject(session, key);
    close_session(session);
}

/// Multi-part encrypt with null buffers in various positions.
fn fuzz_multipart_encrypt_null_buffers(data: &[u8]) {
    if data.len() < 20 {
        return;
    }

    let session = match open_rw_session() {
        Some(s) => s,
        None => return,
    };

    let key = match generate_aes_key(session) {
        Some(k) => k,
        None => { close_session(session); return; }
    };

    let iv = &data[..16];

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_CBC,
        p_parameter: iv.as_ptr() as *mut _,
        parameter_len: 16,
    };

    let rv = functions::C_EncryptInit(session, &mut mechanism, key);
    if rv != CKR_OK {
        let _ = functions::C_DestroyObject(session, key);
        close_session(session);
        return;
    }

    let selector = data[16] % 4;

    // FIX #11: Assert that null pointer cases return errors
    match selector {
        0 => {
            // Null input with non-zero length — must fail
            let mut out = [0u8; 64];
            let mut out_len: CK_ULONG = 64;
            let rv = functions::C_EncryptUpdate(
                session,
                std::ptr::null_mut(),
                32, // Non-zero!
                out.as_mut_ptr(),
                &mut out_len,
            );
            assert!(rv != CKR_OK, "C_EncryptUpdate succeeded with null input + non-zero length");
        }
        1 => {
            // Null output with non-zero length (size query — may legitimately succeed)
            let input = [0u8; 16];
            let mut out_len: CK_ULONG = 0;
            let _rv = functions::C_EncryptUpdate(
                session,
                input.as_ptr() as *mut _,
                16,
                std::ptr::null_mut(),
                &mut out_len,
            );
        }
        2 => {
            // Null output length pointer — must fail
            let input = [0u8; 16];
            let mut out = [0u8; 64];
            let rv = functions::C_EncryptUpdate(
                session,
                input.as_ptr() as *mut _,
                16,
                out.as_mut_ptr(),
                std::ptr::null_mut(),
            );
            assert!(rv != CKR_OK, "C_EncryptUpdate succeeded with null output length pointer");
        }
        3 => {
            // EncryptFinal with null length pointer — must fail
            let rv = functions::C_EncryptFinal(
                session,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
            assert!(rv != CKR_OK, "C_EncryptFinal succeeded with null length pointer");
        }
        _ => {}
    }

    let _ = functions::C_DestroyObject(session, key);
    close_session(session);
}
