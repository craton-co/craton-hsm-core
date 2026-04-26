// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! FIPS 140-3 IG 2.4.B Approved Services Table
//!
//! Documents and enforces which PKCS#11 mechanisms are FIPS 140-3 approved
//! versus non-approved. When `fips_approved_only` is set in the algorithm
//! configuration, non-approved mechanisms are rejected.
//!
//! Reference: NIST SP 800-140C, FIPS 140-3 IG 2.4.B

use crate::config::AlgorithmConfig;
use crate::error::{HsmError, HsmResult};
#[allow(unused_imports)]
use crate::pkcs11_abi::types::CK_MECHANISM_TYPE;

/// Whether a mechanism is FIPS 140-3 approved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalStatus {
    /// Algorithm is FIPS 140-3 approved for the given service.
    Approved,
    /// Algorithm is allowed but NOT FIPS approved (e.g., Ed25519, SHA-1 signing).
    NonApproved,
    /// Algorithm is unknown / vendor-defined without FIPS coverage.
    Unknown,
}

impl ApprovalStatus {
    /// Returns true if the mechanism is FIPS approved.
    pub fn is_approved(self) -> bool {
        matches!(self, Self::Approved)
    }
}

/// Check whether a mechanism is FIPS 140-3 approved.
///
/// Based on:
/// - SP 800-131A Rev.2: Transitioning the Use of Cryptographic Algorithms
/// - SP 800-57 Part 1 Rev.5: Key Management
/// - FIPS 186-5: Digital Signature Standard
/// - FIPS 197: AES
/// - FIPS 198-1: HMAC
/// - FIPS 203/204/205: ML-KEM/ML-DSA/SLH-DSA
pub fn approval_status(mechanism: CK_MECHANISM_TYPE) -> ApprovalStatus {
    use crate::pkcs11_abi::constants::*;

    match mechanism {
        // === APPROVED: Digests ===
        CKM_SHA256 | CKM_SHA384 | CKM_SHA512 => ApprovalStatus::Approved,
        CKM_SHA3_256 | CKM_SHA3_384 | CKM_SHA3_512 => ApprovalStatus::Approved,

        // SHA-1: approved for verification only, NOT for signing.
        // We mark it as NonApproved since the mechanism alone doesn't
        // distinguish signing from verification.
        CKM_SHA_1 => ApprovalStatus::NonApproved,

        // === APPROVED: RSA (>= 2048 bits, key size checked elsewhere) ===
        CKM_RSA_PKCS => ApprovalStatus::Approved,
        CKM_SHA256_RSA_PKCS | CKM_SHA384_RSA_PKCS | CKM_SHA512_RSA_PKCS => ApprovalStatus::Approved,
        CKM_RSA_PKCS_PSS
        | CKM_SHA256_RSA_PKCS_PSS
        | CKM_SHA384_RSA_PKCS_PSS
        | CKM_SHA512_RSA_PKCS_PSS => ApprovalStatus::Approved,
        CKM_RSA_PKCS_OAEP => ApprovalStatus::Approved,
        CKM_RSA_PKCS_KEY_PAIR_GEN => ApprovalStatus::Approved,

        // === APPROVED: ECDSA (P-256, P-384 curves) ===
        CKM_ECDSA | CKM_ECDSA_SHA256 | CKM_ECDSA_SHA384 | CKM_ECDSA_SHA512 => {
            ApprovalStatus::Approved
        }
        CKM_EC_KEY_PAIR_GEN => ApprovalStatus::Approved,

        // === NON-APPROVED: Ed25519 (not yet in FIPS 186-5) ===
        CKM_EDDSA => ApprovalStatus::NonApproved,

        // === APPROVED: AES (all modes with 256-bit key) ===
        CKM_AES_GCM => ApprovalStatus::Approved,
        CKM_AES_CBC | CKM_AES_CBC_PAD => ApprovalStatus::Approved,
        CKM_AES_CTR => ApprovalStatus::Approved,
        CKM_AES_KEY_GEN => ApprovalStatus::Approved,
        CKM_AES_KEY_WRAP | CKM_AES_KEY_WRAP_KWP => ApprovalStatus::Approved,

        // === APPROVED: ECDH (P-256, P-384) ===
        CKM_ECDH1_DERIVE => ApprovalStatus::Approved,

        // === APPROVED: Post-Quantum (FIPS 203/204/205) ===
        CKM_ML_KEM_512 | CKM_ML_KEM_768 | CKM_ML_KEM_1024 => ApprovalStatus::Approved,
        CKM_ML_DSA_44 | CKM_ML_DSA_65 | CKM_ML_DSA_87 => ApprovalStatus::Approved,
        CKM_SLH_DSA_SHA2_128S | CKM_SLH_DSA_SHA2_256S => ApprovalStatus::Approved,

        // === NON-APPROVED: Hybrid (not standardized by NIST yet) ===
        CKM_HYBRID_ML_DSA_ECDSA => ApprovalStatus::NonApproved,
        CKM_HYBRID_X25519_ML_KEM_768 | CKM_HYBRID_X25519_ML_KEM_1024 => ApprovalStatus::NonApproved,

        // Everything else is unknown
        _ => ApprovalStatus::Unknown,
    }
}

/// Enforce FIPS approved-only mode.
///
/// If `fips_approved_only` is set in the algorithm config, reject any
/// mechanism that is not FIPS 140-3 approved. This should be called
/// at the top of each cryptographic operation dispatcher.
pub fn enforce(
    mechanism: CK_MECHANISM_TYPE,
    config: &AlgorithmConfig,
    key_size_bits: Option<u32>,
) -> HsmResult<()> {
    if !config.fips_approved_only {
        return Ok(());
    }

    let status = approval_status(mechanism);

    match status {
        ApprovalStatus::Approved => {
            // Log deprecation warning for PKCS#1 v1.5 (Bleichenbacher-vulnerable)
            if mechanism == crate::pkcs11_abi::constants::CKM_RSA_PKCS {
                tracing::warn!(
                    "CKM_RSA_PKCS (PKCS#1 v1.5) is approved but deprecated per SP 800-131A Rev.2; \
                     consider migrating to CKM_RSA_PKCS_OAEP or CKM_RSA_PKCS_PSS"
                );
            }

            // Enforce minimum key sizes for RSA mechanisms in FIPS mode
            if let Some(bits) = key_size_bits {
                let is_rsa = matches!(
                    mechanism,
                    crate::pkcs11_abi::constants::CKM_RSA_PKCS
                        | crate::pkcs11_abi::constants::CKM_RSA_PKCS_PSS
                        | crate::pkcs11_abi::constants::CKM_RSA_PKCS_OAEP
                        | crate::pkcs11_abi::constants::CKM_RSA_PKCS_KEY_PAIR_GEN
                        | crate::pkcs11_abi::constants::CKM_SHA256_RSA_PKCS
                        | crate::pkcs11_abi::constants::CKM_SHA384_RSA_PKCS
                        | crate::pkcs11_abi::constants::CKM_SHA512_RSA_PKCS
                        | crate::pkcs11_abi::constants::CKM_SHA256_RSA_PKCS_PSS
                        | crate::pkcs11_abi::constants::CKM_SHA384_RSA_PKCS_PSS
                        | crate::pkcs11_abi::constants::CKM_SHA512_RSA_PKCS_PSS
                );
                if is_rsa && bits < 2048 {
                    tracing::warn!(
                        "RSA key size {} bits is below FIPS minimum (2048); rejected",
                        bits
                    );
                    return Err(HsmError::KeySizeRange);
                }
            }

            Ok(())
        }
        ApprovalStatus::NonApproved => {
            tracing::warn!(
                "Mechanism 0x{:08X} is non-approved; rejected in FIPS approved-only mode",
                mechanism
            );
            Err(HsmError::MechanismInvalid)
        }
        ApprovalStatus::Unknown => {
            tracing::warn!(
                "Unknown mechanism 0x{:08X}; rejected in FIPS approved-only mode",
                mechanism
            );
            Err(HsmError::MechanismInvalid)
        }
    }
}

/// Returns a human-readable description of the approval status for a mechanism.
/// Useful for audit logging (FIPS 140-3 IG 2.4.C algorithm indicator).
pub fn is_fips_approved(mechanism: CK_MECHANISM_TYPE) -> bool {
    approval_status(mechanism).is_approved()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pkcs11_abi::constants::*;

    #[test]
    fn test_approved_mechanisms() {
        assert!(approval_status(CKM_SHA256).is_approved());
        assert!(approval_status(CKM_RSA_PKCS).is_approved());
        assert!(approval_status(CKM_AES_GCM).is_approved());
        assert!(approval_status(CKM_ECDSA).is_approved());
        assert!(approval_status(CKM_ML_DSA_65).is_approved());
        assert!(approval_status(CKM_ML_KEM_768).is_approved());
    }

    #[test]
    fn test_non_approved_mechanisms() {
        assert!(!approval_status(CKM_EDDSA).is_approved());
        assert!(!approval_status(CKM_SHA_1).is_approved());
        assert!(!approval_status(CKM_HYBRID_ML_DSA_ECDSA).is_approved());
    }

    #[test]
    fn test_enforce_fips_mode() {
        let mut config = AlgorithmConfig::default();
        config.fips_approved_only = true;

        assert!(enforce(CKM_SHA256, &config, None).is_ok());
        assert!(enforce(CKM_EDDSA, &config, None).is_err());
        assert!(enforce(CKM_SHA_1, &config, None).is_err());
    }

    #[test]
    fn test_enforce_non_fips_mode() {
        let mut config = AlgorithmConfig::default();
        config.fips_approved_only = false;

        // In non-FIPS mode, everything is allowed
        assert!(enforce(CKM_SHA256, &config, None).is_ok());
        assert!(enforce(CKM_EDDSA, &config, None).is_ok());
        assert!(enforce(CKM_SHA_1, &config, None).is_ok());
    }

    #[test]
    fn test_enforce_rsa_key_size_fips() {
        let mut config = AlgorithmConfig::default();
        config.fips_approved_only = true;

        // RSA-2048 and above should pass
        assert!(enforce(CKM_RSA_PKCS, &config, Some(2048)).is_ok());
        assert!(enforce(CKM_RSA_PKCS, &config, Some(4096)).is_ok());

        // RSA-1024 should fail in FIPS mode
        assert!(enforce(CKM_RSA_PKCS, &config, Some(1024)).is_err());
        assert!(enforce(CKM_RSA_PKCS_PSS, &config, Some(1024)).is_err());

        // Non-RSA mechanisms ignore key size
        assert!(enforce(CKM_AES_GCM, &config, Some(128)).is_ok());
    }

    #[test]
    fn test_enforce_rsa_key_size_non_fips() {
        let mut config = AlgorithmConfig::default();
        config.fips_approved_only = false;

        // Non-FIPS mode allows any key size
        assert!(enforce(CKM_RSA_PKCS, &config, Some(1024)).is_ok());
    }
}
