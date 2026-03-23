// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Phase 3 concurrency stress tests
//! Verifies thread safety under load: no data races, no corrupted results.

use std::sync::Arc;
use std::thread;

// Use the PQC crypto primitives directly for concurrency testing
use craton_hsm::crypto::encrypt;
use craton_hsm::crypto::keygen;
use craton_hsm::crypto::pqc::*;
use craton_hsm::crypto::sign;

/// 20 threads each performing ML-DSA sign + verify 50 times
#[test]
fn test_concurrent_ml_dsa_sign_verify() {
    let (sk_seed, vk_bytes) = ml_dsa_keygen(MlDsaVariant::MlDsa44).unwrap();
    let sk_bytes = sk_seed.as_bytes().to_vec();
    let vk_bytes = Arc::new(vk_bytes);

    let mut handles = vec![];
    for i in 0..20 {
        let sk = sk_bytes.clone();
        let vk = vk_bytes.clone();
        handles.push(thread::spawn(move || {
            for j in 0..50 {
                let msg = format!("Thread {} message {}", i, j);
                let sig = ml_dsa_sign(&sk, msg.as_bytes(), MlDsaVariant::MlDsa44).unwrap();
                let valid =
                    ml_dsa_verify(&vk, msg.as_bytes(), &sig, MlDsaVariant::MlDsa44).unwrap();
                assert!(valid, "Thread {} iteration {} failed verification", i, j);
            }
        }));
    }

    for h in handles {
        h.join().expect("Thread panicked");
    }
}

/// 10 threads each performing ML-KEM encapsulate/decapsulate 50 times
#[test]
fn test_concurrent_ml_kem_encap_decap() {
    let (dk_seed, ek_bytes) = ml_kem_keygen(MlKemVariant::MlKem512).unwrap();
    let dk_bytes = dk_seed.as_bytes().to_vec();
    let ek_bytes = Arc::new(ek_bytes);

    let mut handles = vec![];
    for i in 0..10 {
        let dk = dk_bytes.clone();
        let ek = ek_bytes.clone();
        handles.push(thread::spawn(move || {
            for j in 0..50 {
                let (ct, ss_enc) = ml_kem_encapsulate(&ek, MlKemVariant::MlKem512).unwrap();
                let ss_dec = ml_kem_decapsulate(&dk, &ct, MlKemVariant::MlKem512).unwrap();
                assert_eq!(ss_enc, ss_dec, "Thread {} iteration {} KEM mismatch", i, j);
            }
        }));
    }

    for h in handles {
        h.join().expect("Thread panicked");
    }
}

/// 20 threads performing AES-GCM encrypt/decrypt with independent keys
#[test]
fn test_concurrent_aes_encrypt_decrypt() {
    let mut handles = vec![];
    for i in 0..20 {
        handles.push(thread::spawn(move || {
            let key = keygen::generate_aes_key(32, false).unwrap();
            for j in 0..100 {
                let plaintext = format!("Thread {} data block {}", i, j);
                let ciphertext =
                    encrypt::aes_256_gcm_encrypt(key.as_bytes(), plaintext.as_bytes()).unwrap();
                let decrypted = encrypt::aes_256_gcm_decrypt(key.as_bytes(), &ciphertext).unwrap();
                assert_eq!(
                    plaintext.as_bytes(),
                    decrypted.as_slice(),
                    "Thread {} iteration {} AES mismatch",
                    i,
                    j
                );
            }
        }));
    }

    for h in handles {
        h.join().expect("Thread panicked");
    }
}

/// 10 threads each performing ECDSA P-256 sign/verify 100 times
#[test]
fn test_concurrent_ecdsa_sign_verify() {
    let (sk, pk) = keygen::generate_ec_p256_key_pair().unwrap();
    let sk_bytes = sk.as_bytes().to_vec();
    let pk_bytes = Arc::new(pk);

    let mut handles = vec![];
    for i in 0..10 {
        let sk = sk_bytes.clone();
        let pk = pk_bytes.clone();
        handles.push(thread::spawn(move || {
            for j in 0..100 {
                let msg = format!("ECDSA thread {} msg {}", i, j);
                let sig = sign::ecdsa_p256_sign(&sk, msg.as_bytes()).unwrap();
                let valid = sign::ecdsa_p256_verify(&pk, msg.as_bytes(), &sig).unwrap();
                assert!(valid, "Thread {} iteration {} ECDSA failed", i, j);
            }
        }));
    }

    for h in handles {
        h.join().expect("Thread panicked");
    }
}

/// Concurrent keygen: 10 threads each generating 10 key pairs of different types
#[test]
fn test_concurrent_keygen() {
    let mut handles = vec![];

    for _i in 0..10 {
        handles.push(thread::spawn(move || {
            for _ in 0..10 {
                let _aes = keygen::generate_aes_key(32, false).unwrap();
                let _ec = keygen::generate_ec_p256_key_pair().unwrap();
                let _ed = keygen::generate_ed25519_key_pair().unwrap();
                let _ml_dsa = ml_dsa_keygen(MlDsaVariant::MlDsa44).unwrap();
                let _ml_kem = ml_kem_keygen(MlKemVariant::MlKem512).unwrap();
            }
        }));
    }

    for h in handles {
        h.join().expect("Thread panicked");
    }
}
