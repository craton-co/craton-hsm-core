// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Fuzz target for RSA operations via C ABI.
//!
//! RSA is historically the most vulnerability-prone crypto path:
//! - Bleichenbacher padding oracle (PKCS#1 v1.5)
//! - Manger's attack (OAEP)
//! - PSS salt length confusion
//! - Key generation with malformed parameters
//!
//! This target exercises RSA key generation, sign/verify, and
//! encrypt/decrypt through the PKCS#11 C ABI.
//!
//! FIX #10: RSA key pair generation is pre-computed once and reused across
//! iterations to avoid the massive per-iteration overhead (~100ms+ per keygen).

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::{Once, OnceLock};

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

/// Open an RW session and login. Returns session handle or None.
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

/// FIX #10: Pre-generated RSA key pair, created once and reused across all iterations.
/// Keys have CKA_TOKEN=true so they persist in the token across sessions.
/// Both sign+verify and encrypt+decrypt permissions are enabled.
struct PregenRsaKeys {
    pub_key: CK_OBJECT_HANDLE,
    priv_key: CK_OBJECT_HANDLE,
}

static RSA_KEYS: OnceLock<Option<PregenRsaKeys>> = OnceLock::new();

fn get_rsa_keys() -> Option<&'static PregenRsaKeys> {
    RSA_KEYS.get_or_init(|| {
        ensure_init();

        let session = open_rw_session()?;

        let modulus_bits: CK_ULONG = 2048;
        let true_val: CK_BBOOL = CK_TRUE;
        let pub_exp = [0x01u8, 0x00, 0x01]; // 65537

        let mut pub_template = [
            CK_ATTRIBUTE {
                attr_type: CKA_MODULUS_BITS,
                p_value: &modulus_bits as *const _ as *mut _,
                value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                attr_type: CKA_PUBLIC_EXPONENT,
                p_value: pub_exp.as_ptr() as *mut _,
                value_len: 3,
            },
            CK_ATTRIBUTE {
                attr_type: CKA_VERIFY,
                p_value: &true_val as *const _ as *mut _,
                value_len: 1,
            },
            CK_ATTRIBUTE {
                attr_type: CKA_ENCRYPT,
                p_value: &true_val as *const _ as *mut _,
                value_len: 1,
            },
            CK_ATTRIBUTE {
                attr_type: CKA_TOKEN,
                p_value: &true_val as *const _ as *mut _,
                value_len: 1,
            },
        ];

        let mut priv_template = [
            CK_ATTRIBUTE {
                attr_type: CKA_SIGN,
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
            mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN,
            p_parameter: std::ptr::null_mut(),
            parameter_len: 0,
        };

        let mut pub_key: CK_OBJECT_HANDLE = 0;
        let mut priv_key: CK_OBJECT_HANDLE = 0;

        let rv = functions::C_GenerateKeyPair(
            session,
            &mut mechanism,
            pub_template.as_mut_ptr(),
            pub_template.len() as CK_ULONG,
            priv_template.as_mut_ptr(),
            priv_template.len() as CK_ULONG,
            &mut pub_key,
            &mut priv_key,
        );

        close_session(session);

        if rv == CKR_OK {
            Some(PregenRsaKeys { pub_key, priv_key })
        } else {
            None
        }
    }).as_ref()
}

fuzz_target!(|data: &[u8]| {
    ensure_init();

    if data.len() < 4 {
        return;
    }

    let selector = data[0] % 6;
    let payload = &data[1..];

    match selector {
        0 => fuzz_rsa_keygen_random_params(payload),
        1 => fuzz_rsa_sign_verify_pkcs1(payload),
        2 => fuzz_rsa_sign_verify_pss(payload),
        3 => fuzz_rsa_encrypt_decrypt_oaep(payload),
        4 => fuzz_rsa_sign_random_key(payload),
        5 => fuzz_rsa_verify_random_sig(payload),
        _ => {}
    }

    cleanup_sessions();
});

/// Generate RSA key pair with fuzz-controlled modulus bits and public exponent.
/// This is the only target that generates keys per-iteration (tests keygen validation).
fn fuzz_rsa_keygen_random_params(data: &[u8]) {
    if data.len() < 8 {
        return;
    }

    let session = match open_rw_session() {
        Some(s) => s,
        None => return,
    };

    // Fuzz-controlled modulus bits (including invalid values like 0, 1, 7, 4097, 65535)
    let modulus_bits: CK_ULONG = u16::from_le_bytes([data[0], data[1]]) as CK_ULONG;
    let true_val: CK_BBOOL = CK_TRUE;

    // Fuzz-controlled public exponent
    let exp_len = (data[2] as usize % 8).min(data.len() - 3);
    let exponent = &data[3..3 + exp_len];

    let mut pub_template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_MODULUS_BITS,
            p_value: &modulus_bits as *const _ as *mut _,
            value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_VERIFY,
            p_value: &true_val as *const _ as *mut _,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_ENCRYPT,
            p_value: &true_val as *const _ as *mut _,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_TOKEN,
            p_value: &true_val as *const _ as *mut _,
            value_len: 1,
        },
    ];

    // Optionally add a public exponent
    if !exponent.is_empty() {
        pub_template.push(CK_ATTRIBUTE {
            attr_type: CKA_PUBLIC_EXPONENT,
            p_value: exponent.as_ptr() as *mut _,
            value_len: exponent.len() as CK_ULONG,
        });
    }

    let mut priv_template = [
        CK_ATTRIBUTE {
            attr_type: CKA_SIGN,
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
        mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN,
        p_parameter: std::ptr::null_mut(),
        parameter_len: 0,
    };

    let mut pub_key: CK_OBJECT_HANDLE = 0;
    let mut priv_key: CK_OBJECT_HANDLE = 0;

    // Should return error for invalid params, not panic
    let rv = functions::C_GenerateKeyPair(
        session,
        &mut mechanism,
        pub_template.as_mut_ptr(),
        pub_template.len() as CK_ULONG,
        priv_template.as_mut_ptr(),
        priv_template.len() as CK_ULONG,
        &mut pub_key,
        &mut priv_key,
    );

    if rv == CKR_OK {
        // Clean up generated keys
        let _ = functions::C_DestroyObject(session, pub_key);
        let _ = functions::C_DestroyObject(session, priv_key);
    }

    close_session(session);
}

/// FIX #10: Sign/verify with PKCS#1 v1.5 using pre-generated RSA keys.
fn fuzz_rsa_sign_verify_pkcs1(data: &[u8]) {
    if data.len() < 4 {
        return;
    }

    let keys = match get_rsa_keys() {
        Some(k) => k,
        None => return,
    };

    let session = match open_rw_session() {
        Some(s) => s,
        None => return,
    };

    // Sign with fuzz data as message
    let mut sign_mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS,
        p_parameter: std::ptr::null_mut(),
        parameter_len: 0,
    };

    let rv = functions::C_SignInit(session, &mut sign_mechanism, keys.priv_key);
    if rv == CKR_OK {
        let mut sig = [0u8; 512];
        let mut sig_len: CK_ULONG = 512;
        let rv = functions::C_Sign(
            session,
            data.as_ptr() as *mut _,
            data.len() as CK_ULONG,
            sig.as_mut_ptr(),
            &mut sig_len,
        );

        if rv == CKR_OK {
            // Verify the signature
            let rv = functions::C_VerifyInit(session, &mut sign_mechanism, keys.pub_key);
            if rv == CKR_OK {
                let rv = functions::C_Verify(
                    session,
                    data.as_ptr() as *mut _,
                    data.len() as CK_ULONG,
                    sig.as_mut_ptr(),
                    sig_len,
                );
                // FIX #11: Valid signature must verify successfully
                assert!(rv == CKR_OK, "C_Verify failed on valid signature (rv=0x{:08X})", rv);
            }

            // Also verify with corrupted signature (must fail)
            let rv = functions::C_VerifyInit(session, &mut sign_mechanism, keys.pub_key);
            if rv == CKR_OK && sig_len > 0 {
                sig[0] ^= 0xFF; // Corrupt first byte
                let rv = functions::C_Verify(
                    session,
                    data.as_ptr() as *mut _,
                    data.len() as CK_ULONG,
                    sig.as_mut_ptr(),
                    sig_len,
                );
                // FIX #11: Corrupted signature must NOT verify
                assert!(rv != CKR_OK, "C_Verify accepted corrupted signature!");
            }
        }
    }

    close_session(session);
}

/// FIX #10: Sign/verify with RSA-PSS using pre-generated keys.
fn fuzz_rsa_sign_verify_pss(data: &[u8]) {
    if data.len() < 4 {
        return;
    }

    let keys = match get_rsa_keys() {
        Some(k) => k,
        None => return,
    };

    let session = match open_rw_session() {
        Some(s) => s,
        None => return,
    };

    // PSS mechanism — fuzz the parameter bytes
    let param_len = (data[0] as usize % 64).min(data.len() - 1);
    let params = &data[1..1 + param_len];

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_PSS,
        p_parameter: if params.is_empty() {
            std::ptr::null_mut()
        } else {
            params.as_ptr() as *mut _
        },
        parameter_len: params.len() as CK_ULONG,
    };

    let rv = functions::C_SignInit(session, &mut mechanism, keys.priv_key);
    if rv == CKR_OK {
        let message = &data[1 + param_len..];
        let mut sig = [0u8; 512];
        let mut sig_len: CK_ULONG = 512;
        let _rv = functions::C_Sign(
            session,
            message.as_ptr() as *mut _,
            message.len() as CK_ULONG,
            sig.as_mut_ptr(),
            &mut sig_len,
        );
    }

    close_session(session);
}

/// FIX #10: RSA-OAEP encrypt/decrypt using pre-generated keys.
fn fuzz_rsa_encrypt_decrypt_oaep(data: &[u8]) {
    if data.len() < 4 {
        return;
    }

    let keys = match get_rsa_keys() {
        Some(k) => k,
        None => return,
    };

    let session = match open_rw_session() {
        Some(s) => s,
        None => return,
    };

    // OAEP mechanism with fuzz-controlled parameters
    let param_len = (data[0] as usize % 64).min(data.len() - 1);
    let params = &data[1..1 + param_len];
    let plaintext = &data[1 + param_len..];

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_OAEP,
        p_parameter: if params.is_empty() {
            std::ptr::null_mut()
        } else {
            params.as_ptr() as *mut _
        },
        parameter_len: params.len() as CK_ULONG,
    };

    // Encrypt
    let rv = functions::C_EncryptInit(session, &mut mechanism, keys.pub_key);
    if rv == CKR_OK {
        let mut ciphertext = [0u8; 512];
        let mut ct_len: CK_ULONG = 512;
        let rv = functions::C_Encrypt(
            session,
            plaintext.as_ptr() as *mut _,
            plaintext.len() as CK_ULONG,
            ciphertext.as_mut_ptr(),
            &mut ct_len,
        );

        if rv == CKR_OK {
            // Decrypt
            let rv = functions::C_DecryptInit(session, &mut mechanism, keys.priv_key);
            if rv == CKR_OK {
                let mut decrypted = [0u8; 512];
                let mut dec_len: CK_ULONG = 512;
                let _rv = functions::C_Decrypt(
                    session,
                    ciphertext.as_mut_ptr(),
                    ct_len,
                    decrypted.as_mut_ptr(),
                    &mut dec_len,
                );
            }
        }
    }

    close_session(session);
}

/// Sign with a random (invalid) key handle — tests handle validation.
fn fuzz_rsa_sign_random_key(data: &[u8]) {
    if data.len() < 8 {
        return;
    }

    let session = match open_rw_session() {
        Some(s) => s,
        None => return,
    };

    let fake_key = u64::from_le_bytes([
        data[0], data[1], data[2], data[3],
        data[4], data[5], data[6], data[7],
    ]) as CK_OBJECT_HANDLE;

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS,
        p_parameter: std::ptr::null_mut(),
        parameter_len: 0,
    };

    // FIX #11: SignInit with invalid key handle — must return error
    let rv = functions::C_SignInit(session, &mut mechanism, fake_key);
    if rv == CKR_OK {
        // Shouldn't happen but test gracefully if it does
        let mut sig = [0u8; 512];
        let mut sig_len: CK_ULONG = 512;
        let message = &data[8..];
        let _rv = functions::C_Sign(
            session,
            message.as_ptr() as *mut _,
            message.len() as CK_ULONG,
            sig.as_mut_ptr(),
            &mut sig_len,
        );
    }

    // Also try PSS and OAEP with invalid key
    mechanism.mechanism = CKM_RSA_PKCS_PSS;
    let _rv = functions::C_SignInit(session, &mut mechanism, fake_key);

    mechanism.mechanism = CKM_RSA_PKCS_OAEP;
    let _rv = functions::C_EncryptInit(session, &mut mechanism, fake_key);

    close_session(session);
}

/// FIX #10: Verify with random signature data using pre-generated keys.
fn fuzz_rsa_verify_random_sig(data: &[u8]) {
    if data.len() < 4 {
        return;
    }

    let keys = match get_rsa_keys() {
        Some(k) => k,
        None => return,
    };

    let session = match open_rw_session() {
        Some(s) => s,
        None => return,
    };

    // Verify with random signature (should fail, not panic)
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS,
        p_parameter: std::ptr::null_mut(),
        parameter_len: 0,
    };

    let rv = functions::C_VerifyInit(session, &mut mechanism, keys.pub_key);
    if rv == CKR_OK {
        let mid = data.len() / 2;
        let message = &data[..mid];
        let random_sig = &data[mid..];
        let rv = functions::C_Verify(
            session,
            message.as_ptr() as *mut _,
            message.len() as CK_ULONG,
            random_sig.as_ptr() as *mut _,
            random_sig.len() as CK_ULONG,
        );
        // FIX #11: Random signature must NOT verify successfully
        assert!(rv != CKR_OK, "C_Verify accepted random signature data!");
    }

    close_session(session);
}
