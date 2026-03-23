// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Phase 3 PQC integration tests — roundtrip KAT tests for ML-KEM, ML-DSA, SLH-DSA, and hybrid

use craton_hsm::crypto::pqc::*;

// ============================================================================
// ML-KEM (FIPS 203) roundtrip tests
// ============================================================================

#[test]
fn test_ml_kem_512_roundtrip() {
    let (dk_seed, ek_bytes) = ml_kem_keygen(MlKemVariant::MlKem512).unwrap();
    assert_eq!(dk_seed.as_bytes().len(), 64);
    assert_eq!(ek_bytes.len(), 800);

    let (ciphertext, shared_secret_enc) =
        ml_kem_encapsulate(&ek_bytes, MlKemVariant::MlKem512).unwrap();
    assert!(!ciphertext.is_empty());
    assert_eq!(shared_secret_enc.len(), 32);

    let shared_secret_dec =
        ml_kem_decapsulate(dk_seed.as_bytes(), &ciphertext, MlKemVariant::MlKem512).unwrap();
    assert_eq!(shared_secret_enc, shared_secret_dec);
}

#[test]
fn test_ml_kem_768_roundtrip() {
    let (dk_seed, ek_bytes) = ml_kem_keygen(MlKemVariant::MlKem768).unwrap();
    assert_eq!(dk_seed.as_bytes().len(), 64);
    assert_eq!(ek_bytes.len(), 1184);

    let (ciphertext, shared_secret_enc) =
        ml_kem_encapsulate(&ek_bytes, MlKemVariant::MlKem768).unwrap();
    assert_eq!(shared_secret_enc.len(), 32);

    let shared_secret_dec =
        ml_kem_decapsulate(dk_seed.as_bytes(), &ciphertext, MlKemVariant::MlKem768).unwrap();
    assert_eq!(shared_secret_enc, shared_secret_dec);
}

#[test]
fn test_ml_kem_1024_roundtrip() {
    let (dk_seed, ek_bytes) = ml_kem_keygen(MlKemVariant::MlKem1024).unwrap();
    assert_eq!(dk_seed.as_bytes().len(), 64);
    assert_eq!(ek_bytes.len(), 1568);

    let (ciphertext, shared_secret_enc) =
        ml_kem_encapsulate(&ek_bytes, MlKemVariant::MlKem1024).unwrap();
    assert_eq!(shared_secret_enc.len(), 32);

    let shared_secret_dec =
        ml_kem_decapsulate(dk_seed.as_bytes(), &ciphertext, MlKemVariant::MlKem1024).unwrap();
    assert_eq!(shared_secret_enc, shared_secret_dec);
}

#[test]
fn test_ml_kem_wrong_ciphertext_fails() {
    let (dk_seed, ek_bytes) = ml_kem_keygen(MlKemVariant::MlKem512).unwrap();
    let (ciphertext, _shared_secret) =
        ml_kem_encapsulate(&ek_bytes, MlKemVariant::MlKem512).unwrap();

    // Tamper with ciphertext — decapsulation still succeeds but gives different shared secret
    let mut bad_ct = ciphertext.clone();
    bad_ct[0] ^= 0xFF;
    let result = ml_kem_decapsulate(dk_seed.as_bytes(), &bad_ct, MlKemVariant::MlKem512);
    // ML-KEM is designed to not fail on invalid ciphertext (implicit rejection)
    // but the shared secret will be different
    assert!(result.is_ok());
    let bad_ss = result.unwrap();
    let good_ss =
        ml_kem_decapsulate(dk_seed.as_bytes(), &ciphertext, MlKemVariant::MlKem512).unwrap();
    assert_ne!(bad_ss, good_ss);
}

#[test]
fn test_ml_kem_invalid_seed_length() {
    let result = ml_kem_decapsulate(&[0u8; 32], &[0u8; 768], MlKemVariant::MlKem512);
    assert!(result.is_err());
}

// ============================================================================
// ML-DSA (FIPS 204) roundtrip tests
// ============================================================================

#[test]
fn test_ml_dsa_44_sign_verify() {
    let (sk_seed, vk_bytes) = ml_dsa_keygen(MlDsaVariant::MlDsa44).unwrap();
    assert_eq!(sk_seed.as_bytes().len(), 32);
    assert_eq!(vk_bytes.len(), 1312);

    let message = b"ML-DSA-44 test message";
    let signature = ml_dsa_sign(sk_seed.as_bytes(), message, MlDsaVariant::MlDsa44).unwrap();
    assert_eq!(signature.len(), 2420);

    let valid = ml_dsa_verify(&vk_bytes, message, &signature, MlDsaVariant::MlDsa44).unwrap();
    assert!(valid);
}

#[test]
fn test_ml_dsa_65_sign_verify() {
    let (sk_seed, vk_bytes) = ml_dsa_keygen(MlDsaVariant::MlDsa65).unwrap();
    assert_eq!(sk_seed.as_bytes().len(), 32);
    assert_eq!(vk_bytes.len(), 1952);

    let message = b"ML-DSA-65 test message";
    let signature = ml_dsa_sign(sk_seed.as_bytes(), message, MlDsaVariant::MlDsa65).unwrap();
    assert_eq!(signature.len(), 3309);

    let valid = ml_dsa_verify(&vk_bytes, message, &signature, MlDsaVariant::MlDsa65).unwrap();
    assert!(valid);
}

#[test]
fn test_ml_dsa_87_sign_verify() {
    let (sk_seed, vk_bytes) = ml_dsa_keygen(MlDsaVariant::MlDsa87).unwrap();
    assert_eq!(sk_seed.as_bytes().len(), 32);
    assert_eq!(vk_bytes.len(), 2592);

    let message = b"ML-DSA-87 test message";
    let signature = ml_dsa_sign(sk_seed.as_bytes(), message, MlDsaVariant::MlDsa87).unwrap();
    assert_eq!(signature.len(), 4627);

    let valid = ml_dsa_verify(&vk_bytes, message, &signature, MlDsaVariant::MlDsa87).unwrap();
    assert!(valid);
}

#[test]
fn test_ml_dsa_wrong_message_fails() {
    let (sk_seed, vk_bytes) = ml_dsa_keygen(MlDsaVariant::MlDsa65).unwrap();
    let message = b"correct message";
    let signature = ml_dsa_sign(sk_seed.as_bytes(), message, MlDsaVariant::MlDsa65).unwrap();

    let valid = ml_dsa_verify(
        &vk_bytes,
        b"wrong message",
        &signature,
        MlDsaVariant::MlDsa65,
    )
    .unwrap();
    assert!(!valid);
}

#[test]
fn test_ml_dsa_wrong_key_fails() {
    let (sk_seed, _vk_bytes) = ml_dsa_keygen(MlDsaVariant::MlDsa44).unwrap();
    let (_sk_seed2, vk_bytes2) = ml_dsa_keygen(MlDsaVariant::MlDsa44).unwrap();

    let message = b"test message";
    let signature = ml_dsa_sign(sk_seed.as_bytes(), message, MlDsaVariant::MlDsa44).unwrap();

    let valid = ml_dsa_verify(&vk_bytes2, message, &signature, MlDsaVariant::MlDsa44).unwrap();
    assert!(!valid);
}

#[test]
fn test_ml_dsa_deterministic() {
    let (sk_seed, _vk_bytes) = ml_dsa_keygen(MlDsaVariant::MlDsa65).unwrap();
    let message = b"deterministic signing test";
    let sig1 = ml_dsa_sign(sk_seed.as_bytes(), message, MlDsaVariant::MlDsa65).unwrap();
    let sig2 = ml_dsa_sign(sk_seed.as_bytes(), message, MlDsaVariant::MlDsa65).unwrap();
    assert_eq!(
        sig1, sig2,
        "Deterministic signing should produce identical signatures"
    );
}

// ============================================================================
// SLH-DSA (FIPS 205) roundtrip tests
// ============================================================================

#[test]
fn test_slh_dsa_sha2_128s_sign_verify() {
    let (sk_bytes, vk_bytes) = slh_dsa_keygen(SlhDsaVariant::Sha2_128s).unwrap();
    assert_eq!(sk_bytes.as_bytes().len(), 64);
    assert_eq!(vk_bytes.len(), 32);

    let message = b"SLH-DSA SHA2-128s test";
    let signature = slh_dsa_sign(sk_bytes.as_bytes(), message, SlhDsaVariant::Sha2_128s).unwrap();
    assert_eq!(signature.len(), 7856);

    let valid = slh_dsa_verify(&vk_bytes, message, &signature, SlhDsaVariant::Sha2_128s).unwrap();
    assert!(valid);
}

#[test]
fn test_slh_dsa_sha2_256s_sign_verify() {
    let (sk_bytes, vk_bytes) = slh_dsa_keygen(SlhDsaVariant::Sha2_256s).unwrap();
    assert_eq!(sk_bytes.as_bytes().len(), 128);
    assert_eq!(vk_bytes.len(), 64);

    let message = b"SLH-DSA SHA2-256s test";
    let signature = slh_dsa_sign(sk_bytes.as_bytes(), message, SlhDsaVariant::Sha2_256s).unwrap();
    assert_eq!(signature.len(), 29792);

    let valid = slh_dsa_verify(&vk_bytes, message, &signature, SlhDsaVariant::Sha2_256s).unwrap();
    assert!(valid);
}

#[test]
fn test_slh_dsa_wrong_message_fails() {
    let (sk_bytes, vk_bytes) = slh_dsa_keygen(SlhDsaVariant::Sha2_128s).unwrap();
    let message = b"correct message";
    let signature = slh_dsa_sign(sk_bytes.as_bytes(), message, SlhDsaVariant::Sha2_128s).unwrap();

    let valid = slh_dsa_verify(
        &vk_bytes,
        b"wrong message",
        &signature,
        SlhDsaVariant::Sha2_128s,
    )
    .unwrap();
    assert!(!valid);
}

// ============================================================================
// Hybrid ML-DSA-65 + ECDSA-P256 tests
// ============================================================================

#[test]
fn test_hybrid_sign_verify() {
    // Generate ML-DSA-65 keypair
    let (ml_dsa_sk, ml_dsa_vk) = ml_dsa_keygen(MlDsaVariant::MlDsa65).unwrap();

    // Generate ECDSA P-256 keypair
    let (ecdsa_sk, ecdsa_pk) = craton_hsm::crypto::keygen::generate_ec_p256_key_pair().unwrap();

    let message = b"Hybrid PQC + classical test message";

    let combined_sig = hybrid_sign(ml_dsa_sk.as_bytes(), ecdsa_sk.as_bytes(), message).unwrap();
    assert!(combined_sig.len() > 4 + 3309); // ML-DSA-65 sig + ECDSA overhead

    let valid = hybrid_verify(&ml_dsa_vk, &ecdsa_pk, message, &combined_sig).unwrap();
    assert!(valid);
}

#[test]
fn test_hybrid_wrong_message_fails() {
    let (ml_dsa_sk, ml_dsa_vk) = ml_dsa_keygen(MlDsaVariant::MlDsa65).unwrap();
    let (ecdsa_sk, ecdsa_pk) = craton_hsm::crypto::keygen::generate_ec_p256_key_pair().unwrap();

    let message = b"correct message";
    let combined_sig = hybrid_sign(ml_dsa_sk.as_bytes(), ecdsa_sk.as_bytes(), message).unwrap();

    let valid = hybrid_verify(&ml_dsa_vk, &ecdsa_pk, b"wrong message", &combined_sig).unwrap();
    assert!(!valid);
}

#[test]
fn test_hybrid_mismatched_keys_fails() {
    let (ml_dsa_sk, _ml_dsa_vk) = ml_dsa_keygen(MlDsaVariant::MlDsa65).unwrap();
    let (_ml_dsa_sk2, ml_dsa_vk2) = ml_dsa_keygen(MlDsaVariant::MlDsa65).unwrap();
    let (ecdsa_sk, ecdsa_pk) = craton_hsm::crypto::keygen::generate_ec_p256_key_pair().unwrap();

    let message = b"test message";
    let combined_sig = hybrid_sign(ml_dsa_sk.as_bytes(), ecdsa_sk.as_bytes(), message).unwrap();

    // Verify with different ML-DSA key — should fail
    let valid = hybrid_verify(&ml_dsa_vk2, &ecdsa_pk, message, &combined_sig).unwrap();
    assert!(!valid);
}

// ============================================================================
// Helper / mechanism mapping tests
// ============================================================================

#[test]
fn test_mechanism_mappings() {
    use craton_hsm::pkcs11_abi::constants::*;

    assert_eq!(
        mechanism_to_ml_kem_variant(CKM_ML_KEM_512),
        Some(MlKemVariant::MlKem512)
    );
    assert_eq!(
        mechanism_to_ml_kem_variant(CKM_ML_KEM_768),
        Some(MlKemVariant::MlKem768)
    );
    assert_eq!(
        mechanism_to_ml_kem_variant(CKM_ML_KEM_1024),
        Some(MlKemVariant::MlKem1024)
    );
    assert_eq!(mechanism_to_ml_kem_variant(0), None);

    assert_eq!(
        mechanism_to_ml_dsa_variant(CKM_ML_DSA_44),
        Some(MlDsaVariant::MlDsa44)
    );
    assert_eq!(
        mechanism_to_ml_dsa_variant(CKM_ML_DSA_65),
        Some(MlDsaVariant::MlDsa65)
    );
    assert_eq!(
        mechanism_to_ml_dsa_variant(CKM_ML_DSA_87),
        Some(MlDsaVariant::MlDsa87)
    );
    assert_eq!(mechanism_to_ml_dsa_variant(0), None);

    assert_eq!(
        mechanism_to_slh_dsa_variant(CKM_SLH_DSA_SHA2_128S),
        Some(SlhDsaVariant::Sha2_128s)
    );
    assert_eq!(
        mechanism_to_slh_dsa_variant(CKM_SLH_DSA_SHA2_256S),
        Some(SlhDsaVariant::Sha2_256s)
    );
    assert_eq!(mechanism_to_slh_dsa_variant(0), None);

    assert!(is_ml_kem_mechanism(CKM_ML_KEM_512));
    assert!(is_ml_dsa_mechanism(CKM_ML_DSA_65));
    assert!(is_slh_dsa_mechanism(CKM_SLH_DSA_SHA2_128S));
    assert!(is_hybrid_mechanism(CKM_HYBRID_ML_DSA_ECDSA));
    assert!(!is_ml_kem_mechanism(CKM_AES_GCM));
}

#[test]
fn test_supported_mechanisms_includes_pqc() {
    let mechs = craton_hsm::crypto::mechanisms::supported_mechanisms();
    use craton_hsm::pkcs11_abi::constants::*;

    assert!(mechs.contains(&CKM_ML_KEM_512));
    assert!(mechs.contains(&CKM_ML_KEM_768));
    assert!(mechs.contains(&CKM_ML_KEM_1024));
    assert!(mechs.contains(&CKM_ML_DSA_44));
    assert!(mechs.contains(&CKM_ML_DSA_65));
    assert!(mechs.contains(&CKM_ML_DSA_87));
    assert!(mechs.contains(&CKM_SLH_DSA_SHA2_128S));
    assert!(mechs.contains(&CKM_SLH_DSA_SHA2_256S));
    assert!(mechs.contains(&CKM_HYBRID_ML_DSA_ECDSA));
}
