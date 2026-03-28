// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! FIPS 140-3 §9.6 Pairwise Consistency Tests
//!
//! After every asymmetric key pair generation, a sign/verify (or encap/decap)
//! roundtrip must be performed to verify the key pair is consistent.
//! Failure triggers error state (POST_FAILED).

use crate::crypto::backend::CryptoBackend;
use crate::crypto::sign::HashAlg;
use crate::error::{HsmError, HsmResult};
use crate::store::key_material::RawKeyMaterial;

/// Fixed test message for pairwise sign/verify tests.
const PAIRWISE_TEST_DATA: &[u8] = b"FIPS 140-3 pairwise consistency test";

/// RSA pairwise consistency test: sign with private key, verify with public key.
pub fn rsa_pairwise_test(
    backend: &dyn CryptoBackend,
    private_key_der: &RawKeyMaterial,
    modulus: &[u8],
    public_exponent: &[u8],
) -> HsmResult<()> {
    // Sign with SHA-256 RSA PKCS#1v15
    let signature = backend
        .rsa_pkcs1v15_sign(
            private_key_der.as_bytes(),
            PAIRWISE_TEST_DATA,
            Some(HashAlg::Sha256),
        )
        .map_err(|_| {
            tracing::error!("RSA pairwise test: signing failed");
            HsmError::GeneralError
        })?;

    // Verify
    let valid = backend
        .rsa_pkcs1v15_verify(
            modulus,
            public_exponent,
            PAIRWISE_TEST_DATA,
            &signature,
            Some(HashAlg::Sha256),
        )
        .map_err(|_| {
            tracing::error!("RSA pairwise test: verification call failed");
            HsmError::GeneralError
        })?;

    if !valid {
        tracing::error!("RSA pairwise test: signature verification returned false");
        return Err(HsmError::GeneralError);
    }

    tracing::debug!("RSA pairwise consistency test passed");
    Ok(())
}

/// ECDSA P-256 pairwise consistency test.
pub fn ecdsa_p256_pairwise_test(
    backend: &dyn CryptoBackend,
    private_key: &RawKeyMaterial,
    public_key: &[u8],
) -> HsmResult<()> {
    let signature = backend
        .ecdsa_p256_sign(private_key.as_bytes(), PAIRWISE_TEST_DATA)
        .map_err(|_| {
            tracing::error!("ECDSA P-256 pairwise test: signing failed");
            HsmError::GeneralError
        })?;

    let valid = backend
        .ecdsa_p256_verify(public_key, PAIRWISE_TEST_DATA, &signature)
        .map_err(|_| {
            tracing::error!("ECDSA P-256 pairwise test: verification call failed");
            HsmError::GeneralError
        })?;

    if !valid {
        tracing::error!("ECDSA P-256 pairwise test: signature verification returned false");
        return Err(HsmError::GeneralError);
    }

    tracing::debug!("ECDSA P-256 pairwise consistency test passed");
    Ok(())
}

/// ECDSA P-384 pairwise consistency test.
pub fn ecdsa_p384_pairwise_test(
    backend: &dyn CryptoBackend,
    private_key: &RawKeyMaterial,
    public_key: &[u8],
) -> HsmResult<()> {
    let signature = backend
        .ecdsa_p384_sign(private_key.as_bytes(), PAIRWISE_TEST_DATA)
        .map_err(|_| {
            tracing::error!("ECDSA P-384 pairwise test: signing failed");
            HsmError::GeneralError
        })?;

    let valid = backend
        .ecdsa_p384_verify(public_key, PAIRWISE_TEST_DATA, &signature)
        .map_err(|_| {
            tracing::error!("ECDSA P-384 pairwise test: verification call failed");
            HsmError::GeneralError
        })?;

    if !valid {
        tracing::error!("ECDSA P-384 pairwise test: signature verification returned false");
        return Err(HsmError::GeneralError);
    }

    tracing::debug!("ECDSA P-384 pairwise consistency test passed");
    Ok(())
}

/// Ed25519 pairwise consistency test.
pub fn ed25519_pairwise_test(
    backend: &dyn CryptoBackend,
    private_key: &RawKeyMaterial,
    public_key: &[u8],
) -> HsmResult<()> {
    let signature = backend
        .ed25519_sign(private_key.as_bytes(), PAIRWISE_TEST_DATA)
        .map_err(|_| {
            tracing::error!("Ed25519 pairwise test: signing failed");
            HsmError::GeneralError
        })?;

    let valid = backend
        .ed25519_verify(public_key, PAIRWISE_TEST_DATA, &signature)
        .map_err(|_| {
            tracing::error!("Ed25519 pairwise test: verification call failed");
            HsmError::GeneralError
        })?;

    if !valid {
        tracing::error!("Ed25519 pairwise test: signature verification returned false");
        return Err(HsmError::GeneralError);
    }

    tracing::debug!("Ed25519 pairwise consistency test passed");
    Ok(())
}

/// ML-DSA pairwise consistency test (post-quantum signature).
pub fn ml_dsa_pairwise_test(
    backend: &dyn CryptoBackend,
    private_key: &RawKeyMaterial,
    public_key: &[u8],
    variant: &str,
) -> HsmResult<()> {
    use crate::crypto::pqc;

    let ml_dsa_variant = match variant {
        "ML-DSA-44" => pqc::MlDsaVariant::MlDsa44,
        "ML-DSA-65" => pqc::MlDsaVariant::MlDsa65,
        "ML-DSA-87" => pqc::MlDsaVariant::MlDsa87,
        _ => return Err(HsmError::MechanismInvalid),
    };

    let signature = backend
        .ml_dsa_sign(private_key.as_bytes(), PAIRWISE_TEST_DATA, ml_dsa_variant)
        .map_err(|_| {
            tracing::error!("ML-DSA pairwise test: signing failed");
            HsmError::GeneralError
        })?;

    let valid = backend
        .ml_dsa_verify(public_key, PAIRWISE_TEST_DATA, &signature, ml_dsa_variant)
        .map_err(|_| {
            tracing::error!("ML-DSA pairwise test: verification call failed");
            HsmError::GeneralError
        })?;

    if !valid {
        tracing::error!("ML-DSA pairwise test: signature verification returned false");
        return Err(HsmError::GeneralError);
    }

    tracing::debug!("ML-DSA {} pairwise consistency test passed", variant);
    Ok(())
}

/// SLH-DSA pairwise consistency test (post-quantum signature, stateless hash-based).
pub fn slh_dsa_pairwise_test(
    backend: &dyn CryptoBackend,
    private_key: &RawKeyMaterial,
    public_key: &[u8],
    variant: &str,
) -> HsmResult<()> {
    use crate::crypto::pqc;

    let slh_dsa_variant = match variant {
        "SLH-DSA-SHA2-128s" => pqc::SlhDsaVariant::Sha2_128s,
        "SLH-DSA-SHA2-256s" => pqc::SlhDsaVariant::Sha2_256s,
        _ => return Err(HsmError::MechanismInvalid),
    };

    let signature = backend
        .slh_dsa_sign(private_key.as_bytes(), PAIRWISE_TEST_DATA, slh_dsa_variant)
        .map_err(|_| {
            tracing::error!("SLH-DSA pairwise test: signing failed");
            HsmError::GeneralError
        })?;

    let valid = backend
        .slh_dsa_verify(public_key, PAIRWISE_TEST_DATA, &signature, slh_dsa_variant)
        .map_err(|_| {
            tracing::error!("SLH-DSA pairwise test: verification call failed");
            HsmError::GeneralError
        })?;

    if !valid {
        tracing::error!("SLH-DSA pairwise test: signature verification returned false");
        return Err(HsmError::GeneralError);
    }

    tracing::debug!("SLH-DSA {} pairwise consistency test passed", variant);
    Ok(())
}

/// ML-KEM pairwise consistency test (encapsulate/decapsulate roundtrip).
pub fn ml_kem_pairwise_test(
    backend: &dyn CryptoBackend,
    private_key: &RawKeyMaterial,
    public_key: &[u8],
    variant: &str,
) -> HsmResult<()> {
    use crate::crypto::pqc;

    let ml_kem_variant = match variant {
        "ML-KEM-512" => pqc::MlKemVariant::MlKem512,
        "ML-KEM-768" => pqc::MlKemVariant::MlKem768,
        "ML-KEM-1024" => pqc::MlKemVariant::MlKem1024,
        _ => return Err(HsmError::MechanismInvalid),
    };

    // Encapsulate: produce (ciphertext, shared_secret) from public key
    let (ciphertext, shared_secret_enc) = backend
        .ml_kem_encapsulate(public_key, ml_kem_variant)
        .map_err(|_| {
            tracing::error!("ML-KEM pairwise test: encapsulation failed");
            HsmError::GeneralError
        })?;

    // Decapsulate: recover shared secret from private key + ciphertext
    let shared_secret_dec = backend
        .ml_kem_decapsulate(private_key.as_bytes(), &ciphertext, ml_kem_variant)
        .map_err(|_| {
            tracing::error!("ML-KEM pairwise test: decapsulation failed");
            HsmError::GeneralError
        })?;

    use subtle::ConstantTimeEq;
    let secrets_match: bool = shared_secret_enc.ct_eq(&shared_secret_dec).into();
    if !secrets_match {
        tracing::error!("ML-KEM pairwise test: shared secrets don't match");
        return Err(HsmError::GeneralError);
    }

    tracing::debug!("ML-KEM {} pairwise consistency test passed", variant);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "rustcrypto-backend")]
    #[test]
    fn test_rsa_pairwise() {
        use crate::crypto::rustcrypto_backend::RustCryptoBackend;
        let backend = RustCryptoBackend;
        let (priv_key, modulus, pub_exp) = backend.generate_rsa_key_pair(2048, false).unwrap();
        assert!(rsa_pairwise_test(&backend, &priv_key, &modulus, &pub_exp).is_ok());
    }

    #[cfg(feature = "rustcrypto-backend")]
    #[test]
    fn test_ecdsa_p256_pairwise() {
        use crate::crypto::rustcrypto_backend::RustCryptoBackend;
        let backend = RustCryptoBackend;
        let (priv_key, pub_key) = backend.generate_ec_p256_key_pair().unwrap();
        assert!(ecdsa_p256_pairwise_test(&backend, &priv_key, &pub_key).is_ok());
    }

    #[cfg(feature = "rustcrypto-backend")]
    #[test]
    fn test_ecdsa_p384_pairwise() {
        use crate::crypto::rustcrypto_backend::RustCryptoBackend;
        let backend = RustCryptoBackend;
        let (priv_key, pub_key) = backend.generate_ec_p384_key_pair().unwrap();
        assert!(ecdsa_p384_pairwise_test(&backend, &priv_key, &pub_key).is_ok());
    }

    #[cfg(feature = "rustcrypto-backend")]
    #[test]
    fn test_ed25519_pairwise() {
        use crate::crypto::rustcrypto_backend::RustCryptoBackend;
        let backend = RustCryptoBackend;
        let (priv_key, pub_key) = backend.generate_ed25519_key_pair().unwrap();
        assert!(ed25519_pairwise_test(&backend, &priv_key, &pub_key).is_ok());
    }
}
