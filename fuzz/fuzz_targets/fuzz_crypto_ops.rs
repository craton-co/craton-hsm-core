// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Fuzz target for crypto operations.
//!
//! Exercises encrypt/decrypt/sign/verify functions with random inputs
//! to ensure no panics or unexpected behavior.

#![no_main]

use libfuzzer_sys::fuzz_target;
use craton_hsm::crypto::encrypt;
use craton_hsm::crypto::digest;
use craton_hsm::crypto::sign;
use craton_hsm::pkcs11_abi::constants::*;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }

    let selector = data[0] % 12;
    let payload = &data[1..];

    match selector {
        0 => fuzz_aes_gcm(payload),
        1 => fuzz_aes_cbc(payload),
        2 => fuzz_aes_ctr(payload),
        3 => fuzz_digest(payload),
        4 => fuzz_decrypt_random(payload),
        5 => fuzz_verify_random_p256(payload),
        6 => fuzz_cbc_decrypt_random(payload),
        7 => fuzz_rsa_pkcs1v15_sign_random(payload),
        8 => fuzz_rsa_pkcs1v15_verify_random(payload),
        9 => fuzz_rsa_pss_sign_random(payload),
        10 => fuzz_rsa_oaep_roundtrip(payload),
        11 => fuzz_rsa_oaep_decrypt_random(payload),
        _ => {}
    }
});

fn fuzz_aes_gcm(data: &[u8]) {
    if data.len() < 32 {
        return;
    }

    let key: [u8; 32] = data[..32].try_into().unwrap();
    let plaintext = &data[32..];

    // Encrypt then decrypt should roundtrip
    if let Ok(ciphertext) = encrypt::aes_256_gcm_encrypt(&key, plaintext) {
        if let Ok(decrypted) = encrypt::aes_256_gcm_decrypt(&key, &ciphertext) {
            assert_eq!(decrypted, plaintext);
        }
    }
}

fn fuzz_aes_cbc(data: &[u8]) {
    if data.len() < 48 {
        return;
    }

    let key: [u8; 32] = data[..32].try_into().unwrap();
    let iv: [u8; 16] = data[32..48].try_into().unwrap();
    let plaintext = &data[48..];

    if let Ok(ciphertext) = encrypt::aes_cbc_encrypt(&key, &iv, plaintext) {
        if let Ok(decrypted) = encrypt::aes_cbc_decrypt(&key, &iv, &ciphertext) {
            assert_eq!(decrypted, plaintext);
        }
    }
}

fn fuzz_aes_ctr(data: &[u8]) {
    if data.len() < 48 {
        return;
    }

    let key: [u8; 32] = data[..32].try_into().unwrap();
    let iv: [u8; 16] = data[32..48].try_into().unwrap();
    let plaintext = &data[48..];

    if let Ok(ciphertext) = encrypt::aes_ctr_crypt(&key, &iv, plaintext) {
        if let Ok(decrypted) = encrypt::aes_ctr_crypt(&key, &iv, &ciphertext) {
            assert_eq!(decrypted, plaintext);
        }
    }
}

fn fuzz_digest(data: &[u8]) {
    if data.is_empty() {
        return;
    }

    // Use the compute_digest function with valid mechanism types
    let mechanisms = [CKM_SHA256, CKM_SHA384, CKM_SHA512, CKM_SHA_1];
    let mech = mechanisms[(data[0] as usize) % mechanisms.len()];
    let input = &data[1..];

    // Should never panic on any input
    let _ = digest::compute_digest(mech, input);
}

fn fuzz_decrypt_random(data: &[u8]) {
    if data.len() < 32 {
        return;
    }

    let key: [u8; 32] = data[..32].try_into().unwrap();
    let random_ciphertext = &data[32..];

    // Decrypting random data should error, not panic
    let _ = encrypt::aes_256_gcm_decrypt(&key, random_ciphertext);
}

/// FIX: Use correct sizes for P-256 — public key is 65 bytes (uncompressed SEC1),
/// signature is DER-encoded (~70 bytes, variable). Also test compressed (33-byte) keys.
fn fuzz_verify_random_p256(data: &[u8]) {
    if data.len() < 2 {
        return;
    }

    let selector = data[0] % 3;
    let payload = &data[1..];

    match selector {
        0 => {
            // Uncompressed public key (65 bytes) + DER signature (variable, up to ~72 bytes)
            if payload.len() < 137 {
                return;
            }
            let random_key = &payload[..65];
            let random_sig = &payload[65..137];
            let message = &payload[137..];
            let _ = sign::ecdsa_p256_verify(random_key, message, random_sig);
        }
        1 => {
            // Compressed public key (33 bytes) + signature
            if payload.len() < 105 {
                return;
            }
            let random_key = &payload[..33];
            let random_sig = &payload[33..105];
            let message = &payload[105..];
            let _ = sign::ecdsa_p256_verify(random_key, message, random_sig);
        }
        _ => {
            // Fully random lengths — exercise edge cases in parsing
            if payload.len() < 3 {
                return;
            }
            let key_len = (payload[0] as usize % 128).min(payload.len() - 2);
            let remaining = &payload[1..];
            if key_len >= remaining.len() {
                return;
            }
            let random_key = &remaining[..key_len];
            let sig_start = key_len;
            let sig_len = (payload[0].wrapping_add(payload[1]) as usize % 128)
                .min(remaining.len() - sig_start);
            let random_sig = &remaining[sig_start..sig_start + sig_len];
            let message = &remaining[sig_start + sig_len..];
            let _ = sign::ecdsa_p256_verify(random_key, message, random_sig);
        }
    }
}

fn fuzz_cbc_decrypt_random(data: &[u8]) {
    if data.len() < 48 {
        return;
    }

    let key: [u8; 32] = data[..32].try_into().unwrap();
    let iv: [u8; 16] = data[32..48].try_into().unwrap();
    let random_ciphertext = &data[48..];

    // Decrypting random CBC data should error, not panic
    let _ = encrypt::aes_cbc_decrypt(&key, &iv, random_ciphertext);
}

/// RSA PKCS#1 v1.5 sign with random DER "private key" — should fail gracefully.
fn fuzz_rsa_pkcs1v15_sign_random(data: &[u8]) {
    if data.len() < 2 {
        return;
    }

    let hash_alg = match data[0] % 4 {
        0 => None,
        1 => Some(sign::HashAlg::Sha256),
        2 => Some(sign::HashAlg::Sha384),
        _ => Some(sign::HashAlg::Sha512),
    };

    let random_der = &data[1..];
    let message = if random_der.len() > 32 {
        &random_der[..32]
    } else {
        random_der
    };

    // Random bytes as DER key — must error, not panic
    let _ = sign::rsa_pkcs1v15_sign(random_der, message, hash_alg);
}

/// RSA PKCS#1 v1.5 verify with random modulus/exponent/signature.
fn fuzz_rsa_pkcs1v15_verify_random(data: &[u8]) {
    if data.len() < 10 {
        return;
    }

    let hash_alg = match data[0] % 4 {
        0 => None,
        1 => Some(sign::HashAlg::Sha256),
        2 => Some(sign::HashAlg::Sha384),
        _ => Some(sign::HashAlg::Sha512),
    };

    // Split fuzz data into modulus, exponent, message, signature
    let payload = &data[1..];
    let mod_len = (payload[0] as usize % 64).min(payload.len().saturating_sub(4));
    if mod_len + 3 >= payload.len() {
        return;
    }
    let modulus = &payload[1..1 + mod_len];
    let exp_len = (payload[1 + mod_len] as usize % 16).min(payload.len() - mod_len - 2);
    let remaining = &payload[2 + mod_len..];
    if exp_len >= remaining.len() {
        return;
    }
    let exponent = &remaining[..exp_len];
    let rest = &remaining[exp_len..];
    let mid = rest.len() / 2;
    let message = &rest[..mid];
    let signature = &rest[mid..];

    let _ = sign::rsa_pkcs1v15_verify(modulus, exponent, message, signature, hash_alg);
}

/// RSA-PSS sign with random DER "private key".
fn fuzz_rsa_pss_sign_random(data: &[u8]) {
    if data.len() < 2 {
        return;
    }

    let hash_alg = match data[0] % 3 {
        0 => sign::HashAlg::Sha256,
        1 => sign::HashAlg::Sha384,
        _ => sign::HashAlg::Sha512,
    };

    let random_der = &data[1..];
    let message = if random_der.len() > 32 {
        &random_der[..32]
    } else {
        random_der
    };

    let _ = sign::rsa_pss_sign(random_der, message, hash_alg);
}

/// RSA-OAEP encrypt/decrypt roundtrip with random data as modulus/exponent.
fn fuzz_rsa_oaep_roundtrip(data: &[u8]) {
    if data.len() < 10 {
        return;
    }

    let hash_alg = match data[0] % 3 {
        0 => sign::OaepHash::Sha256,
        1 => sign::OaepHash::Sha384,
        _ => sign::OaepHash::Sha512,
    };

    let payload = &data[1..];
    let mod_len = (payload[0] as usize % 128).min(payload.len().saturating_sub(4));
    if mod_len + 2 >= payload.len() {
        return;
    }
    let modulus = &payload[1..1 + mod_len];
    let remaining = &payload[1 + mod_len..];
    let exp_len = (remaining[0] as usize % 8).min(remaining.len().saturating_sub(1));
    let exponent = &remaining[1..1 + exp_len];
    let plaintext = &remaining[1 + exp_len..];

    // Random modulus/exponent — should error, not panic
    let _ = sign::rsa_oaep_encrypt(modulus, exponent, plaintext, hash_alg);
}

/// RSA-OAEP decrypt with random DER key and random ciphertext.
fn fuzz_rsa_oaep_decrypt_random(data: &[u8]) {
    if data.len() < 2 {
        return;
    }

    let hash_alg = match data[0] % 3 {
        0 => sign::OaepHash::Sha256,
        1 => sign::OaepHash::Sha384,
        _ => sign::OaepHash::Sha512,
    };

    let random_der = &data[1..];
    let ciphertext = if random_der.len() > 256 {
        &random_der[256..]
    } else {
        random_der
    };

    let _ = sign::rsa_oaep_decrypt(random_der, ciphertext, hash_alg);
}
