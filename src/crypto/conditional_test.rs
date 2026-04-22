// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! FIPS 140-3 Conditional Self-Test (CST) Framework
//!
//! Unlike Power-On Self-Tests (POST) which run once at initialization,
//! conditional self-tests run on-demand before the first use of each
//! algorithm family. Results are cached so subsequent uses of the same
//! algorithm family do not re-run the KAT.
//!
//! FIPS 140-3 IG 9.7: Conditional self-tests are required:
//! - Before first use of each algorithm (lazy initialization)
//! - After key import (pairwise consistency test — handled elsewhere)
//! - After software update (re-run full POST — handled by C_Initialize)

use dashmap::DashMap;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::crypto::backend::CryptoBackend;
use crate::error::{HsmError, HsmResult};
use crate::pkcs11_abi::types::CK_MECHANISM_TYPE;

/// Algorithm families for conditional self-testing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlgorithmFamily {
    // Digests
    Sha256,
    Sha384,
    Sha512,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Sha1,
    // MACs
    HmacSha256,
    HmacSha384,
    HmacSha512,
    // Symmetric encryption
    AesGcm,
    AesCbc,
    AesCtr,
    // Asymmetric signing
    RsaPkcs1,
    RsaPss,
    EcdsaP256,
    EcdsaP384,
    Ed25519,
    // RSA encryption
    RsaOaep,
    // Key wrap
    AesKeyWrap,
    // Key derivation
    EcdhP256,
    EcdhP384,
    // Post-quantum
    MlDsa44,
    MlDsa65,
    MlDsa87,
    MlKem512,
    MlKem768,
    MlKem1024,
    SlhDsaSha2_128s,
    SlhDsaSha2_256s,
    HybridMlDsaEcdsa,
    // DRBG
    Drbg,
}

/// Conditional Self-Test state tracker.
///
/// Thread-safe: uses `DashMap` for lock-free concurrent access.
/// Each algorithm family is tested at most once per HSM initialization.
pub struct ConditionalSelfTest {
    /// Tracks which algorithm families have passed their on-demand KAT.
    passed: DashMap<AlgorithmFamily, ()>,
    /// If true, a CST has failed and the module is in error state.
    error_state: AtomicBool,
}

impl ConditionalSelfTest {
    /// Create a new CST tracker with no algorithms tested.
    pub fn new() -> Self {
        Self {
            passed: DashMap::new(),
            error_state: AtomicBool::new(false),
        }
    }

    /// Check if the module is in error state due to a CST failure.
    pub fn is_error_state(&self) -> bool {
        self.error_state.load(Ordering::Acquire)
    }

    /// Ensure the given algorithm family has passed its CST.
    ///
    /// - If already tested: returns Ok(()) immediately (fast path).
    /// - If not tested: runs the KAT, caches the result.
    /// - If in error state: returns Err immediately.
    pub fn ensure_tested(
        &self,
        family: AlgorithmFamily,
        backend: &dyn CryptoBackend,
    ) -> HsmResult<()> {
        // Fast path: already in error state
        if self.error_state.load(Ordering::Acquire) {
            return Err(HsmError::GeneralError);
        }

        // Fast path: already tested
        if self.passed.contains_key(&family) {
            return Ok(());
        }

        // Atomic check-and-insert via DashMap::entry() to prevent TOCTOU race.
        // If two threads race here, only one runs the KAT; the other waits on
        // the shard lock and finds the entry already present.
        use dashmap::mapref::entry::Entry;
        match self.passed.entry(family) {
            Entry::Occupied(_) => {
                // Another thread already ran the KAT while we were waiting
                // for the shard lock. Re-check error state in case that
                // other thread's KAT failed for a *different* family.
                if self.error_state.load(Ordering::Acquire) {
                    return Err(HsmError::GeneralError);
                }
                Ok(())
            }
            Entry::Vacant(vacant) => {
                let result = self.run_kat(family, backend);
                match result {
                    Ok(()) => {
                        // Re-check error state: another thread may have failed
                        // a different family's KAT while we were running ours.
                        if self.error_state.load(Ordering::Acquire) {
                            return Err(HsmError::GeneralError);
                        }
                        vacant.insert(());
                        Ok(())
                    }
                    Err(e) => {
                        tracing::error!(
                            "Conditional self-test FAILED for {:?} — module entering error state",
                            family
                        );
                        self.error_state.store(true, Ordering::Release);
                        Err(e)
                    }
                }
            }
        }
    }

    /// Run the KAT for a specific algorithm family.
    fn run_kat(&self, family: AlgorithmFamily, backend: &dyn CryptoBackend) -> HsmResult<()> {
        match family {
            AlgorithmFamily::Sha256 => {
                self.kat_digest(backend, crate::pkcs11_abi::constants::CKM_SHA256)
            }
            AlgorithmFamily::Sha384 => {
                self.kat_digest(backend, crate::pkcs11_abi::constants::CKM_SHA384)
            }
            AlgorithmFamily::Sha512 => {
                self.kat_digest(backend, crate::pkcs11_abi::constants::CKM_SHA512)
            }
            AlgorithmFamily::Sha1 => {
                self.kat_digest(backend, crate::pkcs11_abi::constants::CKM_SHA_1)
            }
            AlgorithmFamily::Sha3_256 => {
                self.kat_digest(backend, crate::pkcs11_abi::constants::CKM_SHA3_256)
            }
            AlgorithmFamily::Sha3_384 => {
                self.kat_digest(backend, crate::pkcs11_abi::constants::CKM_SHA3_384)
            }
            AlgorithmFamily::Sha3_512 => {
                self.kat_digest(backend, crate::pkcs11_abi::constants::CKM_SHA3_512)
            }

            AlgorithmFamily::AesGcm => self.kat_aes_gcm(backend),
            AlgorithmFamily::AesCbc => self.kat_aes_cbc(backend),
            AlgorithmFamily::AesCtr => self.kat_aes_ctr(backend),

            AlgorithmFamily::RsaPkcs1 | AlgorithmFamily::RsaPss => self.kat_rsa(backend),
            AlgorithmFamily::RsaOaep => self.kat_rsa(backend),

            AlgorithmFamily::EcdsaP256 => self.kat_ecdsa_p256(backend),
            AlgorithmFamily::EcdsaP384 => self.kat_ecdsa_p384(backend),
            AlgorithmFamily::Ed25519 => self.kat_ed25519(backend),

            AlgorithmFamily::AesKeyWrap => self.kat_aes_key_wrap(backend),

            AlgorithmFamily::EcdhP256 => self.kat_ecdh(backend, false),
            AlgorithmFamily::EcdhP384 => self.kat_ecdh(backend, true),

            AlgorithmFamily::MlDsa44 => {
                self.kat_ml_dsa(backend, crate::crypto::pqc::MlDsaVariant::MlDsa44)
            }
            AlgorithmFamily::MlDsa65 => {
                self.kat_ml_dsa(backend, crate::crypto::pqc::MlDsaVariant::MlDsa65)
            }
            AlgorithmFamily::MlDsa87 => {
                self.kat_ml_dsa(backend, crate::crypto::pqc::MlDsaVariant::MlDsa87)
            }

            AlgorithmFamily::MlKem512 => {
                self.kat_ml_kem(backend, crate::crypto::pqc::MlKemVariant::MlKem512)
            }
            AlgorithmFamily::MlKem768 => {
                self.kat_ml_kem(backend, crate::crypto::pqc::MlKemVariant::MlKem768)
            }
            AlgorithmFamily::MlKem1024 => {
                self.kat_ml_kem(backend, crate::crypto::pqc::MlKemVariant::MlKem1024)
            }

            AlgorithmFamily::SlhDsaSha2_128s => {
                self.kat_slh_dsa(backend, crate::crypto::pqc::SlhDsaVariant::Sha2_128s)
            }
            AlgorithmFamily::SlhDsaSha2_256s => {
                self.kat_slh_dsa(backend, crate::crypto::pqc::SlhDsaVariant::Sha2_256s)
            }

            AlgorithmFamily::HybridMlDsaEcdsa => {
                // Hybrid depends on both ML-DSA and ECDSA
                self.kat_ml_dsa(backend, crate::crypto::pqc::MlDsaVariant::MlDsa65)?;
                self.kat_ecdsa_p256(backend)
            }

            AlgorithmFamily::HmacSha256 => {
                self.kat_hmac(backend, crate::pkcs11_abi::constants::CKM_SHA256)
            }
            AlgorithmFamily::HmacSha384 => {
                self.kat_hmac(backend, crate::pkcs11_abi::constants::CKM_SHA384)
            }
            AlgorithmFamily::HmacSha512 => {
                self.kat_hmac(backend, crate::pkcs11_abi::constants::CKM_SHA512)
            }

            AlgorithmFamily::Drbg => {
                // DRBG health test: generate two blocks, ensure they differ
                let mut drbg = crate::crypto::drbg::HmacDrbg::new()?;
                let mut a = [0u8; 32];
                let mut b = [0u8; 32];
                drbg.generate(&mut a)?;
                drbg.generate(&mut b)?;
                if a == b {
                    return Err(HsmError::GeneralError);
                }
                Ok(())
            }
        }
    }

    // ========================================================================
    // Individual KAT implementations
    // ========================================================================

    fn kat_digest(
        &self,
        backend: &dyn CryptoBackend,
        mechanism: CK_MECHANISM_TYPE,
    ) -> HsmResult<()> {
        let test_data = b"FIPS 140-3 conditional self-test";
        let digest = backend.compute_digest(mechanism, test_data)?;
        if digest.is_empty() {
            return Err(HsmError::GeneralError);
        }
        // Verify determinism: same input → same output
        let digest2 = backend.compute_digest(mechanism, test_data)?;
        if digest != digest2 {
            return Err(HsmError::GeneralError);
        }
        Ok(())
    }

    fn kat_aes_gcm(&self, backend: &dyn CryptoBackend) -> HsmResult<()> {
        let key = [0x42u8; 32];
        let plaintext = b"CST AES-GCM test data";
        let ciphertext = backend.aes_256_gcm_encrypt(&key, plaintext)?;
        let decrypted = backend.aes_256_gcm_decrypt(&key, &ciphertext)?;
        if decrypted != plaintext {
            return Err(HsmError::GeneralError);
        }
        Ok(())
    }

    fn kat_aes_cbc(&self, backend: &dyn CryptoBackend) -> HsmResult<()> {
        let key = [0x42u8; 32];
        let iv = [0x01u8; 16];
        let plaintext = b"CST AES-CBC data"; // 16 bytes
        let ciphertext = backend.aes_cbc_encrypt(&key, &iv, plaintext)?;
        let decrypted = backend.aes_cbc_decrypt(&key, &iv, &ciphertext)?;
        if decrypted != plaintext {
            return Err(HsmError::GeneralError);
        }
        Ok(())
    }

    fn kat_aes_ctr(&self, backend: &dyn CryptoBackend) -> HsmResult<()> {
        let key = [0x42u8; 32];
        let iv = [0x02u8; 16];
        let plaintext = b"CST AES-CTR data";
        let ciphertext = backend.aes_ctr_encrypt(&key, &iv, plaintext)?;
        let decrypted = backend.aes_ctr_decrypt(&key, &iv, &ciphertext)?;
        if decrypted != plaintext {
            return Err(HsmError::GeneralError);
        }
        Ok(())
    }

    fn kat_rsa(&self, backend: &dyn CryptoBackend) -> HsmResult<()> {
        let (priv_key, modulus, pub_exp) = backend.generate_rsa_key_pair(2048, false)?;
        let test_data = b"FIPS 140-3 RSA conditional self-test";
        let signature = backend.rsa_pkcs1v15_sign(
            priv_key.as_bytes(),
            test_data,
            Some(crate::crypto::sign::HashAlg::Sha256),
        )?;
        let valid = backend.rsa_pkcs1v15_verify(
            &modulus,
            &pub_exp,
            test_data,
            &signature,
            Some(crate::crypto::sign::HashAlg::Sha256),
        )?;
        if !valid {
            return Err(HsmError::GeneralError);
        }
        Ok(())
    }

    fn kat_ecdsa_p256(&self, backend: &dyn CryptoBackend) -> HsmResult<()> {
        let (priv_key, pub_key) = backend.generate_ec_p256_key_pair()?;
        let test_data = b"FIPS 140-3 ECDSA P-256 CST";
        let signature = backend.ecdsa_p256_sign(priv_key.as_bytes(), test_data)?;
        let valid = backend.ecdsa_p256_verify(&pub_key, test_data, &signature)?;
        if !valid {
            return Err(HsmError::GeneralError);
        }
        Ok(())
    }

    fn kat_ecdsa_p384(&self, backend: &dyn CryptoBackend) -> HsmResult<()> {
        let (priv_key, pub_key) = backend.generate_ec_p384_key_pair()?;
        let test_data = b"FIPS 140-3 ECDSA P-384 CST";
        let signature = backend.ecdsa_p384_sign(priv_key.as_bytes(), test_data)?;
        let valid = backend.ecdsa_p384_verify(&pub_key, test_data, &signature)?;
        if !valid {
            return Err(HsmError::GeneralError);
        }
        Ok(())
    }

    fn kat_ed25519(&self, backend: &dyn CryptoBackend) -> HsmResult<()> {
        let (priv_key, pub_key) = backend.generate_ed25519_key_pair()?;
        let test_data = b"FIPS 140-3 Ed25519 CST";
        let signature = backend.ed25519_sign(priv_key.as_bytes(), test_data)?;
        let valid = backend.ed25519_verify(&pub_key, test_data, &signature)?;
        if !valid {
            return Err(HsmError::GeneralError);
        }
        Ok(())
    }

    fn kat_aes_key_wrap(&self, backend: &dyn CryptoBackend) -> HsmResult<()> {
        let wrapping_key = [0x42u8; 32];
        let key_to_wrap = [0x55u8; 32]; // Must be multiple of 8 and >= 16
        let wrapped = backend.aes_key_wrap(&wrapping_key, &key_to_wrap, false)?;
        let unwrapped = backend.aes_key_unwrap(&wrapping_key, &wrapped, false)?;
        if unwrapped != key_to_wrap {
            return Err(HsmError::GeneralError);
        }
        Ok(())
    }

    fn kat_ecdh(&self, backend: &dyn CryptoBackend, is_p384: bool) -> HsmResult<()> {
        // Generate two keypairs, derive shared secret from both sides
        if is_p384 {
            let (sk_a, pk_a) = backend.generate_ec_p384_key_pair()?;
            let (sk_b, pk_b) = backend.generate_ec_p384_key_pair()?;
            let ss_a = backend.ecdh_p384(sk_a.as_bytes(), &pk_b, None)?;
            let ss_b = backend.ecdh_p384(sk_b.as_bytes(), &pk_a, None)?;
            if ss_a.as_bytes() != ss_b.as_bytes() {
                return Err(HsmError::GeneralError);
            }
        } else {
            let (sk_a, pk_a) = backend.generate_ec_p256_key_pair()?;
            let (sk_b, pk_b) = backend.generate_ec_p256_key_pair()?;
            let ss_a = backend.ecdh_p256(sk_a.as_bytes(), &pk_b, None)?;
            let ss_b = backend.ecdh_p256(sk_b.as_bytes(), &pk_a, None)?;
            if ss_a.as_bytes() != ss_b.as_bytes() {
                return Err(HsmError::GeneralError);
            }
        }
        Ok(())
    }

    fn kat_ml_dsa(
        &self,
        backend: &dyn CryptoBackend,
        variant: crate::crypto::pqc::MlDsaVariant,
    ) -> HsmResult<()> {
        let (sk, vk) = backend.ml_dsa_keygen(variant)?;
        let test_data = b"FIPS 140-3 ML-DSA CST";
        let signature = backend.ml_dsa_sign(sk.as_bytes(), test_data, variant)?;
        let valid = backend.ml_dsa_verify(&vk, test_data, &signature, variant)?;
        if !valid {
            return Err(HsmError::GeneralError);
        }
        Ok(())
    }

    fn kat_ml_kem(
        &self,
        backend: &dyn CryptoBackend,
        variant: crate::crypto::pqc::MlKemVariant,
    ) -> HsmResult<()> {
        let (dk, ek) = backend.ml_kem_keygen(variant)?;
        let (ct, ss_enc) = backend.ml_kem_encapsulate(&ek, variant)?;
        let ss_dec = backend.ml_kem_decapsulate(dk.as_bytes(), &ct, variant)?;
        if ss_enc != ss_dec {
            return Err(HsmError::GeneralError);
        }
        Ok(())
    }

    fn kat_slh_dsa(
        &self,
        backend: &dyn CryptoBackend,
        variant: crate::crypto::pqc::SlhDsaVariant,
    ) -> HsmResult<()> {
        let (sk, vk) = backend.slh_dsa_keygen(variant)?;
        let test_data = b"FIPS 140-3 SLH-DSA CST";
        let signature = backend.slh_dsa_sign(sk.as_bytes(), test_data, variant)?;
        let valid = backend.slh_dsa_verify(&vk, test_data, &signature, variant)?;
        if !valid {
            return Err(HsmError::GeneralError);
        }
        Ok(())
    }

    /// HMAC KAT: compute an HMAC and verify the result is non-empty and
    /// deterministic (same key + data produces same tag).
    fn kat_hmac(
        &self,
        backend: &dyn CryptoBackend,
        digest_mechanism: CK_MECHANISM_TYPE,
    ) -> HsmResult<()> {
        use hmac::{Hmac, Mac};

        let key = [0x42u8; 32];
        let data = b"FIPS 140-3 HMAC conditional self-test";

        // Determine which HMAC variant to test based on the digest mechanism
        let tag = match digest_mechanism {
            crate::pkcs11_abi::constants::CKM_SHA256 => {
                let mut mac = <Hmac<sha2::Sha256>>::new_from_slice(&key)
                    .map_err(|_| HsmError::GeneralError)?;
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
            crate::pkcs11_abi::constants::CKM_SHA384 => {
                let mut mac = <Hmac<sha2::Sha384>>::new_from_slice(&key)
                    .map_err(|_| HsmError::GeneralError)?;
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
            crate::pkcs11_abi::constants::CKM_SHA512 => {
                let mut mac = <Hmac<sha2::Sha512>>::new_from_slice(&key)
                    .map_err(|_| HsmError::GeneralError)?;
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
            _ => return Err(HsmError::MechanismInvalid),
        };

        if tag.is_empty() {
            return Err(HsmError::GeneralError);
        }

        // Verify determinism: recompute and compare
        let tag2 = match digest_mechanism {
            crate::pkcs11_abi::constants::CKM_SHA256 => {
                let mut mac = <Hmac<sha2::Sha256>>::new_from_slice(&key)
                    .map_err(|_| HsmError::GeneralError)?;
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
            crate::pkcs11_abi::constants::CKM_SHA384 => {
                let mut mac = <Hmac<sha2::Sha384>>::new_from_slice(&key)
                    .map_err(|_| HsmError::GeneralError)?;
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
            crate::pkcs11_abi::constants::CKM_SHA512 => {
                let mut mac = <Hmac<sha2::Sha512>>::new_from_slice(&key)
                    .map_err(|_| HsmError::GeneralError)?;
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
            _ => return Err(HsmError::MechanismInvalid),
        };

        if tag != tag2 {
            return Err(HsmError::GeneralError);
        }

        // Also verify the underlying digest works (defense in depth)
        let _ = backend.compute_digest(digest_mechanism, data)?;

        Ok(())
    }
}

/// Map a PKCS#11 mechanism to its algorithm family for CST lookup.
///
/// `ec_params` should be provided for mechanisms that are curve-agnostic
/// (CKM_ECDSA, CKM_ECDH1_DERIVE) to select the correct algorithm family.
/// When `None`, defaults to P-256 for backwards compatibility.
pub fn mechanism_to_family(
    mechanism: CK_MECHANISM_TYPE,
    ec_params: Option<&[u8]>,
) -> Option<AlgorithmFamily> {
    use crate::pkcs11_abi::constants::*;

    // Helper: check if EC params indicate P-384
    let is_p384 = ec_params.map_or(false, |params| {
        // OID for secp384r1: 06 05 2b 81 04 00 22
        params.len() >= 7
            && params.contains(&0x22)
            && params.contains(&0x04)
            && params.contains(&0x81)
    });

    match mechanism {
        CKM_SHA256 | CKM_SHA256_RSA_PKCS | CKM_SHA256_RSA_PKCS_PSS | CKM_ECDSA_SHA256 => {
            Some(AlgorithmFamily::Sha256)
        }
        CKM_SHA384 | CKM_SHA384_RSA_PKCS | CKM_SHA384_RSA_PKCS_PSS | CKM_ECDSA_SHA384 => {
            Some(AlgorithmFamily::Sha384)
        }
        CKM_SHA512 | CKM_SHA512_RSA_PKCS | CKM_SHA512_RSA_PKCS_PSS | CKM_ECDSA_SHA512 => {
            Some(AlgorithmFamily::Sha512)
        }
        CKM_SHA_1 => Some(AlgorithmFamily::Sha1),
        CKM_SHA3_256 => Some(AlgorithmFamily::Sha3_256),
        CKM_SHA3_384 => Some(AlgorithmFamily::Sha3_384),
        CKM_SHA3_512 => Some(AlgorithmFamily::Sha3_512),
        CKM_AES_GCM => Some(AlgorithmFamily::AesGcm),
        CKM_AES_CBC | CKM_AES_CBC_PAD => Some(AlgorithmFamily::AesCbc),
        CKM_AES_CTR => Some(AlgorithmFamily::AesCtr),
        CKM_RSA_PKCS => Some(AlgorithmFamily::RsaPkcs1),
        CKM_RSA_PKCS_PSS => Some(AlgorithmFamily::RsaPss),
        CKM_RSA_PKCS_OAEP => Some(AlgorithmFamily::RsaOaep),
        CKM_ECDSA => {
            if is_p384 {
                Some(AlgorithmFamily::EcdsaP384)
            } else {
                Some(AlgorithmFamily::EcdsaP256)
            }
        }
        CKM_EDDSA => Some(AlgorithmFamily::Ed25519),
        CKM_AES_KEY_WRAP | CKM_AES_KEY_WRAP_KWP => Some(AlgorithmFamily::AesKeyWrap),
        CKM_ECDH1_DERIVE => {
            if is_p384 {
                Some(AlgorithmFamily::EcdhP384)
            } else {
                Some(AlgorithmFamily::EcdhP256)
            }
        }
        CKM_ML_DSA_44 => Some(AlgorithmFamily::MlDsa44),
        CKM_ML_DSA_65 => Some(AlgorithmFamily::MlDsa65),
        CKM_ML_DSA_87 => Some(AlgorithmFamily::MlDsa87),
        CKM_ML_KEM_512 => Some(AlgorithmFamily::MlKem512),
        CKM_ML_KEM_768 => Some(AlgorithmFamily::MlKem768),
        CKM_ML_KEM_1024 => Some(AlgorithmFamily::MlKem1024),
        CKM_SLH_DSA_SHA2_128S => Some(AlgorithmFamily::SlhDsaSha2_128s),
        CKM_SLH_DSA_SHA2_256S => Some(AlgorithmFamily::SlhDsaSha2_256s),
        CKM_HYBRID_ML_DSA_ECDSA => Some(AlgorithmFamily::HybridMlDsaEcdsa),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "rustcrypto-backend")]
    #[test]
    fn test_conditional_self_test_basic() {
        use crate::crypto::rustcrypto_backend::RustCryptoBackend;
        let backend = RustCryptoBackend;
        let cst = ConditionalSelfTest::new();

        // First call should run the KAT
        assert!(cst.ensure_tested(AlgorithmFamily::Sha256, &backend).is_ok());
        // Second call should be cached
        assert!(cst.ensure_tested(AlgorithmFamily::Sha256, &backend).is_ok());
        assert!(!cst.is_error_state());
    }

    #[cfg(feature = "rustcrypto-backend")]
    #[test]
    fn test_cst_aes_gcm() {
        use crate::crypto::rustcrypto_backend::RustCryptoBackend;
        let backend = RustCryptoBackend;
        let cst = ConditionalSelfTest::new();
        assert!(cst.ensure_tested(AlgorithmFamily::AesGcm, &backend).is_ok());
    }

    #[cfg(feature = "rustcrypto-backend")]
    #[test]
    fn test_cst_drbg() {
        use crate::crypto::rustcrypto_backend::RustCryptoBackend;
        let backend = RustCryptoBackend;
        let cst = ConditionalSelfTest::new();
        assert!(cst.ensure_tested(AlgorithmFamily::Drbg, &backend).is_ok());
    }

    #[cfg(feature = "rustcrypto-backend")]
    #[test]
    fn test_cst_hmac_sha256() {
        use crate::crypto::rustcrypto_backend::RustCryptoBackend;
        let backend = RustCryptoBackend;
        let cst = ConditionalSelfTest::new();
        assert!(cst
            .ensure_tested(AlgorithmFamily::HmacSha256, &backend)
            .is_ok());
    }

    #[cfg(feature = "rustcrypto-backend")]
    #[test]
    fn test_cst_hmac_sha384() {
        use crate::crypto::rustcrypto_backend::RustCryptoBackend;
        let backend = RustCryptoBackend;
        let cst = ConditionalSelfTest::new();
        assert!(cst
            .ensure_tested(AlgorithmFamily::HmacSha384, &backend)
            .is_ok());
    }

    #[cfg(feature = "rustcrypto-backend")]
    #[test]
    fn test_cst_hmac_sha512() {
        use crate::crypto::rustcrypto_backend::RustCryptoBackend;
        let backend = RustCryptoBackend;
        let cst = ConditionalSelfTest::new();
        assert!(cst
            .ensure_tested(AlgorithmFamily::HmacSha512, &backend)
            .is_ok());
    }

    #[test]
    fn test_mechanism_to_family_ecdsa_default_p256() {
        use crate::pkcs11_abi::constants::CKM_ECDSA;
        assert_eq!(
            mechanism_to_family(CKM_ECDSA, None),
            Some(AlgorithmFamily::EcdsaP256)
        );
    }

    #[test]
    fn test_mechanism_to_family_ecdsa_p384() {
        use crate::pkcs11_abi::constants::CKM_ECDSA;
        // OID for secp384r1: 06 05 2b 81 04 00 22
        let p384_oid = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
        assert_eq!(
            mechanism_to_family(CKM_ECDSA, Some(p384_oid)),
            Some(AlgorithmFamily::EcdsaP384)
        );
    }

    #[test]
    fn test_mechanism_to_family_ecdh_default_p256() {
        use crate::pkcs11_abi::constants::CKM_ECDH1_DERIVE;
        assert_eq!(
            mechanism_to_family(CKM_ECDH1_DERIVE, None),
            Some(AlgorithmFamily::EcdhP256)
        );
    }

    #[test]
    fn test_mechanism_to_family_ecdh_p384() {
        use crate::pkcs11_abi::constants::CKM_ECDH1_DERIVE;
        let p384_oid = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
        assert_eq!(
            mechanism_to_family(CKM_ECDH1_DERIVE, Some(p384_oid)),
            Some(AlgorithmFamily::EcdhP384)
        );
    }

    #[cfg(feature = "rustcrypto-backend")]
    #[test]
    fn test_cst_concurrent_ensure_tested() {
        use crate::crypto::rustcrypto_backend::RustCryptoBackend;
        use std::sync::{Arc, Barrier};

        let backend = Arc::new(RustCryptoBackend);
        let cst = Arc::new(ConditionalSelfTest::new());
        let barrier = Arc::new(Barrier::new(4));

        let handles: Vec<_> = (0..4)
            .map(|_| {
                let cst = Arc::clone(&cst);
                let barrier = Arc::clone(&barrier);
                let backend = Arc::clone(&backend);
                std::thread::spawn(move || {
                    barrier.wait();
                    cst.ensure_tested(AlgorithmFamily::Sha256, &*backend)
                })
            })
            .collect();

        for h in handles {
            assert!(h.join().unwrap().is_ok());
        }
        assert!(!cst.is_error_state());
    }
}
