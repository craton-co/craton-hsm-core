// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
use crate::config::config::AlgorithmConfig;
use crate::pkcs11_abi::constants::*;
use crate::pkcs11_abi::types::{CK_MECHANISM_TYPE, CK_RV};

/// Check if a mechanism is supported for signing
pub fn is_sign_mechanism(mechanism: CK_MECHANISM_TYPE) -> bool {
    matches!(
        mechanism,
        CKM_RSA_PKCS
            | CKM_SHA256_RSA_PKCS
            | CKM_SHA384_RSA_PKCS
            | CKM_SHA512_RSA_PKCS
            | CKM_RSA_PKCS_PSS
            | CKM_SHA256_RSA_PKCS_PSS
            | CKM_SHA384_RSA_PKCS_PSS
            | CKM_SHA512_RSA_PKCS_PSS
            | CKM_ECDSA
            | CKM_ECDSA_SHA256
            | CKM_ECDSA_SHA384
            | CKM_ECDSA_SHA512
            | CKM_EDDSA
            | CKM_ML_DSA_44
            | CKM_ML_DSA_65
            | CKM_ML_DSA_87
            | CKM_SLH_DSA_SHA2_128S
            | CKM_SLH_DSA_SHA2_256S
            | CKM_HYBRID_ML_DSA_ECDSA
    )
}

/// Check if a mechanism is supported for encryption
pub fn is_encrypt_mechanism(mechanism: CK_MECHANISM_TYPE) -> bool {
    matches!(
        mechanism,
        CKM_AES_GCM | CKM_AES_CBC | CKM_AES_CBC_PAD | CKM_AES_CTR | CKM_RSA_PKCS_OAEP
    )
}

/// Check if a mechanism is supported for key generation
pub fn is_keygen_mechanism(mechanism: CK_MECHANISM_TYPE) -> bool {
    matches!(mechanism, CKM_AES_KEY_GEN)
}

/// Check if a mechanism is supported for key pair generation
pub fn is_keypair_gen_mechanism(mechanism: CK_MECHANISM_TYPE) -> bool {
    matches!(
        mechanism,
        CKM_RSA_PKCS_KEY_PAIR_GEN
            | CKM_EC_KEY_PAIR_GEN
            | CKM_EDDSA
            | CKM_ML_KEM_512
            | CKM_ML_KEM_768
            | CKM_ML_KEM_1024
            | CKM_ML_DSA_44
            | CKM_ML_DSA_65
            | CKM_ML_DSA_87
            | CKM_SLH_DSA_SHA2_128S
            | CKM_SLH_DSA_SHA2_256S
    )
}

/// Check if a mechanism is a KEM (Key Encapsulation) mechanism
pub fn is_kem_mechanism(mechanism: CK_MECHANISM_TYPE) -> bool {
    matches!(mechanism, CKM_ML_KEM_512 | CKM_ML_KEM_768 | CKM_ML_KEM_1024)
}

/// Check if a mechanism is supported for digest
pub fn is_digest_mechanism(mechanism: CK_MECHANISM_TYPE) -> bool {
    matches!(
        mechanism,
        CKM_SHA_1
            | CKM_SHA256
            | CKM_SHA384
            | CKM_SHA512
            | CKM_SHA3_256
            | CKM_SHA3_384
            | CKM_SHA3_512
    )
}

/// Check if a mechanism is supported for key wrapping
pub fn is_wrap_mechanism(mechanism: CK_MECHANISM_TYPE) -> bool {
    matches!(mechanism, CKM_AES_KEY_WRAP | CKM_AES_KEY_WRAP_KWP)
}

/// Check if a mechanism is supported for key derivation
pub fn is_derive_mechanism(mechanism: CK_MECHANISM_TYPE) -> bool {
    matches!(mechanism, CKM_ECDH1_DERIVE | CKM_ECDH1_COFACTOR_DERIVE)
}

/// Get the list of all supported mechanisms
pub fn supported_mechanisms() -> Vec<CK_MECHANISM_TYPE> {
    vec![
        // RSA
        CKM_RSA_PKCS_KEY_PAIR_GEN,
        CKM_RSA_PKCS,
        CKM_SHA256_RSA_PKCS,
        CKM_SHA384_RSA_PKCS,
        CKM_SHA512_RSA_PKCS,
        CKM_RSA_PKCS_PSS,
        CKM_SHA256_RSA_PKCS_PSS,
        CKM_SHA384_RSA_PKCS_PSS,
        CKM_SHA512_RSA_PKCS_PSS,
        CKM_RSA_PKCS_OAEP,
        // EC
        CKM_EC_KEY_PAIR_GEN,
        CKM_ECDSA,
        CKM_ECDSA_SHA256,
        CKM_ECDSA_SHA384,
        CKM_ECDSA_SHA512,
        CKM_ECDH1_DERIVE,
        CKM_ECDH1_COFACTOR_DERIVE,
        // EdDSA
        CKM_EDDSA,
        // AES
        CKM_AES_KEY_GEN,
        CKM_AES_GCM,
        CKM_AES_CBC,
        CKM_AES_CBC_PAD,
        CKM_AES_CTR,
        CKM_AES_KEY_WRAP,
        CKM_AES_KEY_WRAP_KWP,
        // Digest
        CKM_SHA_1,
        CKM_SHA256,
        CKM_SHA384,
        CKM_SHA512,
        CKM_SHA3_256,
        CKM_SHA3_384,
        CKM_SHA3_512,
        // Post-Quantum (vendor-defined)
        CKM_ML_KEM_512,
        CKM_ML_KEM_768,
        CKM_ML_KEM_1024,
        CKM_ML_DSA_44,
        CKM_ML_DSA_65,
        CKM_ML_DSA_87,
        CKM_SLH_DSA_SHA2_128S,
        CKM_SLH_DSA_SHA2_256S,
        CKM_HYBRID_ML_DSA_ECDSA,
    ]
}

// =============================================================================
// FIPS 140-3 Algorithm Policy
// =============================================================================

/// Classify whether a mechanism is FIPS 140-3 approved.
///
/// FIPS-approved mechanisms (per NIST SP 800-131A Rev 2, FIPS 186-5, SP 800-38D, etc.):
/// - RSA (≥2048): key generation, PKCS#1v15, PSS, OAEP
/// - ECDSA (P-256, P-384): key generation, sign, verify
/// - AES (128/192/256): GCM, CBC, CTR, key wrap
/// - SHA-2 family: SHA-256, SHA-384, SHA-512
/// - SHA-3 family: SHA3-256, SHA3-384, SHA3-512
/// - ECDH (P-256, P-384): key derivation (SP 800-56A)
///
/// NOT FIPS-approved:
/// - EdDSA / Ed25519 (not in FIPS 186-5 as of this implementation)
/// - SHA-1 (deprecated for signing per SP 800-131A)
/// - All PQC mechanisms (vendor-defined, not yet FIPS-standardized for CMVP)
pub fn is_fips_approved(mechanism: CK_MECHANISM_TYPE) -> bool {
    matches!(
        mechanism,
        // RSA — FIPS 186-5
        CKM_RSA_PKCS_KEY_PAIR_GEN
            | CKM_RSA_PKCS
            | CKM_SHA256_RSA_PKCS
            | CKM_SHA384_RSA_PKCS
            | CKM_SHA512_RSA_PKCS
            | CKM_RSA_PKCS_PSS
            | CKM_SHA256_RSA_PKCS_PSS
            | CKM_SHA384_RSA_PKCS_PSS
            | CKM_SHA512_RSA_PKCS_PSS
            | CKM_RSA_PKCS_OAEP
            // ECDSA — FIPS 186-5
            | CKM_EC_KEY_PAIR_GEN
            | CKM_ECDSA
            | CKM_ECDSA_SHA256
            | CKM_ECDSA_SHA384
            | CKM_ECDSA_SHA512
            // ECDH — SP 800-56A
            | CKM_ECDH1_DERIVE
            | CKM_ECDH1_COFACTOR_DERIVE
            // AES — FIPS 197, SP 800-38A/D/F
            | CKM_AES_KEY_GEN
            | CKM_AES_GCM
            | CKM_AES_CBC
            | CKM_AES_CBC_PAD
            | CKM_AES_CTR
            | CKM_AES_KEY_WRAP
            | CKM_AES_KEY_WRAP_KWP
            // SHA-2 — FIPS 180-4
            | CKM_SHA256
            | CKM_SHA384
            | CKM_SHA512
            // SHA-3 — FIPS 202
            | CKM_SHA3_256
            | CKM_SHA3_384
            | CKM_SHA3_512
    )
    // NOT approved: CKM_EDDSA, CKM_SHA_1 (for signing), CKM_ML_KEM_*, CKM_ML_DSA_*,
    //               CKM_SLH_DSA_*, CKM_HYBRID_ML_DSA_ECDSA
}

/// Check if a mechanism is a PQC (Post-Quantum Cryptography) mechanism.
fn is_pqc_mechanism(mechanism: CK_MECHANISM_TYPE) -> bool {
    matches!(
        mechanism,
        CKM_ML_KEM_512
            | CKM_ML_KEM_768
            | CKM_ML_KEM_1024
            | CKM_ML_DSA_44
            | CKM_ML_DSA_65
            | CKM_ML_DSA_87
            | CKM_SLH_DSA_SHA2_128S
            | CKM_SLH_DSA_SHA2_256S
            | CKM_HYBRID_ML_DSA_ECDSA
    )
}

/// Validate a mechanism against the algorithm policy configuration.
///
/// Returns `Ok(())` if the mechanism is permitted, or `Err(CKR_MECHANISM_INVALID)`
/// if the policy blocks it.
///
/// Policy checks (in order):
/// 1. `fips_approved_only=true` → block all non-FIPS-approved mechanisms
/// 2. `enable_pqc=false` → block all PQC mechanisms
/// 3. `allow_sha1_signing=false` → block SHA-1 in signing contexts
///
/// The `is_signing_context` parameter indicates whether the mechanism is being
/// used for signing (relevant for SHA-1 policy — SHA-1 digest-only is permitted).
pub fn validate_mechanism_for_policy(
    mechanism: CK_MECHANISM_TYPE,
    config: &AlgorithmConfig,
    is_signing_context: bool,
) -> Result<(), CK_RV> {
    // Check 1: FIPS approved mode blocks all non-approved mechanisms
    if config.fips_approved_only && !is_fips_approved(mechanism) {
        tracing::warn!(
            "FIPS approved mode: blocking non-approved mechanism 0x{:08X}",
            mechanism
        );
        return Err(CKR_MECHANISM_INVALID);
    }

    // Check 2: PQC policy
    if !config.enable_pqc && is_pqc_mechanism(mechanism) {
        tracing::warn!("PQC disabled: blocking PQC mechanism 0x{:08X}", mechanism);
        return Err(CKR_MECHANISM_INVALID);
    }

    // Check 3: SHA-1 policy
    if mechanism == CKM_SHA_1 {
        // In FIPS mode, block SHA-1 entirely — even for digest-only operations.
        // Applications may misuse digest output for signature construction
        // outside the HSM's control, and SHA-1 is deprecated per SP 800-131A.
        if config.fips_approved_only {
            tracing::warn!("FIPS mode: blocking SHA-1 (CKM_SHA_1) — deprecated per SP 800-131A");
            return Err(CKR_MECHANISM_INVALID);
        }
        // Outside FIPS mode, SHA-1 is still blocked for signing if configured
        if !config.allow_sha1_signing && is_signing_context {
            tracing::warn!("SHA-1 signing disabled: blocking CKM_SHA_1 in signing context");
            return Err(CKR_MECHANISM_INVALID);
        }
    }

    Ok(())
}

/// Get the list of mechanisms filtered by policy.
///
/// Used by `C_GetMechanismList` to report only the mechanisms permitted
/// by the current algorithm policy.
pub fn supported_mechanisms_filtered(config: &AlgorithmConfig) -> Vec<CK_MECHANISM_TYPE> {
    supported_mechanisms()
        .into_iter()
        .filter(|&mech| {
            // In FIPS mode, exclude non-approved mechanisms
            if config.fips_approved_only && !is_fips_approved(mech) {
                return false;
            }
            // In FIPS mode, also exclude SHA-1 (deprecated per SP 800-131A)
            if config.fips_approved_only && mech == CKM_SHA_1 {
                return false;
            }
            // If PQC disabled, exclude PQC mechanisms
            if !config.enable_pqc && is_pqc_mechanism(mech) {
                return false;
            }
            true
        })
        .collect()
}
