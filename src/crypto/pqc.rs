// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Post-Quantum Cryptography implementations
//! - ML-KEM (FIPS 203): Key Encapsulation Mechanism
//! - ML-DSA (FIPS 204): Digital Signature Algorithm
//! - SLH-DSA (FIPS 205): Stateless Hash-Based Digital Signature

use crate::error::{HsmError, HsmResult};
use crate::store::key_material::RawKeyMaterial;
use ml_dsa::signature::Keypair;
use ml_kem::KeyExport;

/// DRBG-backed RNG adapter implementing rand_core 0.10 traits for PQC crates.
///
/// Routes all PQC randomness through the SP 800-90A HMAC_DRBG so that
/// key generation benefits from continuous health testing and prediction
/// resistance, matching the classical keygen path in `keygen.rs`.
struct PqcDrbgRng {
    drbg: crate::crypto::drbg::HmacDrbg,
}

impl PqcDrbgRng {
    fn new() -> HsmResult<Self> {
        Ok(Self {
            drbg: crate::crypto::drbg::HmacDrbg::new()?,
        })
    }
}

/// `Error = Infallible` is intentional: the DRBG never returns `Err` — it
/// aborts the process on catastrophic failure instead, because returning weak
/// randomness to a PQC keygen would silently produce insecure keys.
///
/// We use `std::process::abort()` rather than `panic!()` because this code
/// runs inside a `cdylib` (PKCS#11 shared library). A panic would unwind
/// across the FFI boundary into the host application, which is undefined
/// behavior. Aborting is the only safe response to a catastrophic RNG failure
/// in a shared library context.
impl rand_core_new::TryRng for PqcDrbgRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut buf = [0u8; 4];
        if self.drbg.generate(&mut buf).is_err() {
            // DRBG failure indicates a catastrophic system RNG collapse.
            // Aborting is the only safe response for a shared library —
            // continuing with weak randomness would produce insecure keys.
            tracing::error!("FATAL: DRBG generate failed in PQC RNG — aborting process");
            std::process::abort();
        }
        Ok(u32::from_le_bytes(buf))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut buf = [0u8; 8];
        if self.drbg.generate(&mut buf).is_err() {
            tracing::error!("FATAL: DRBG generate failed in PQC RNG — aborting process");
            std::process::abort();
        }
        Ok(u64::from_le_bytes(buf))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        if self.drbg.generate(dest).is_err() {
            tracing::error!("FATAL: DRBG generate failed in PQC RNG — aborting process");
            std::process::abort();
        }
        Ok(())
    }
}

impl rand_core_new::TryCryptoRng for PqcDrbgRng {}

/// Create a rand_core 0.10 CryptoRng backed by the FIPS HMAC_DRBG.
///
/// All PQC randomness is routed through the SP 800-90A DRBG for health
/// testing and prediction resistance, rather than using OsRng directly.
fn new_rng() -> HsmResult<PqcDrbgRng> {
    PqcDrbgRng::new()
}

// ============================================================================
// ML-KEM (FIPS 203) — Key Encapsulation
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlKemVariant {
    MlKem512,
    MlKem768,
    MlKem1024,
}

/// Generate an ML-KEM keypair. Returns (dk_seed_64bytes, ek_bytes).
pub fn ml_kem_keygen(variant: MlKemVariant) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
    // Generate 64 random bytes for the seed via DRBG (SP 800-90A health-tested)
    use zeroize::Zeroizing;
    let mut seed_bytes = Zeroizing::new([0u8; 64]);
    let mut drbg = crate::crypto::drbg::HmacDrbg::new()?;
    drbg.generate(&mut *seed_bytes)?;
    let seed: ml_kem::Seed = (*seed_bytes).into();

    match variant {
        MlKemVariant::MlKem512 => {
            let dk = ml_kem::DecapsulationKey::<ml_kem::MlKem512>::from_seed(seed);
            let ek = dk.encapsulation_key();
            let stored_seed = dk.to_seed().ok_or(HsmError::GeneralError)?;
            Ok((
                RawKeyMaterial::new(stored_seed[..].to_vec()),
                ek.to_bytes()[..].to_vec(),
            ))
        }
        MlKemVariant::MlKem768 => {
            let dk = ml_kem::DecapsulationKey::<ml_kem::MlKem768>::from_seed(seed);
            let ek = dk.encapsulation_key();
            let stored_seed = dk.to_seed().ok_or(HsmError::GeneralError)?;
            Ok((
                RawKeyMaterial::new(stored_seed[..].to_vec()),
                ek.to_bytes()[..].to_vec(),
            ))
        }
        MlKemVariant::MlKem1024 => {
            let dk = ml_kem::DecapsulationKey::<ml_kem::MlKem1024>::from_seed(seed);
            let ek = dk.encapsulation_key();
            let stored_seed = dk.to_seed().ok_or(HsmError::GeneralError)?;
            Ok((
                RawKeyMaterial::new(stored_seed[..].to_vec()),
                ek.to_bytes()[..].to_vec(),
            ))
        }
    }
}

/// ML-KEM encapsulate: given ek bytes, produce (ciphertext, shared_secret).
pub fn ml_kem_encapsulate(ek_bytes: &[u8], variant: MlKemVariant) -> HsmResult<(Vec<u8>, Vec<u8>)> {
    use ml_kem::kem::Encapsulate;

    let mut rng = new_rng()?;

    match variant {
        MlKemVariant::MlKem512 => {
            let key: ml_kem::kem::Key<ml_kem::EncapsulationKey<ml_kem::MlKem512>> = ek_bytes
                .try_into()
                .map_err(|_| HsmError::KeyHandleInvalid)?;
            let ek = ml_kem::EncapsulationKey::<ml_kem::MlKem512>::new(&key)
                .map_err(|_| HsmError::KeyHandleInvalid)?;
            let (ct, ss) = ek.encapsulate_with_rng(&mut rng);
            Ok((ct[..].to_vec(), ss[..].to_vec()))
        }
        MlKemVariant::MlKem768 => {
            let key: ml_kem::kem::Key<ml_kem::EncapsulationKey<ml_kem::MlKem768>> = ek_bytes
                .try_into()
                .map_err(|_| HsmError::KeyHandleInvalid)?;
            let ek = ml_kem::EncapsulationKey::<ml_kem::MlKem768>::new(&key)
                .map_err(|_| HsmError::KeyHandleInvalid)?;
            let (ct, ss) = ek.encapsulate_with_rng(&mut rng);
            Ok((ct[..].to_vec(), ss[..].to_vec()))
        }
        MlKemVariant::MlKem1024 => {
            let key: ml_kem::kem::Key<ml_kem::EncapsulationKey<ml_kem::MlKem1024>> = ek_bytes
                .try_into()
                .map_err(|_| HsmError::KeyHandleInvalid)?;
            let ek = ml_kem::EncapsulationKey::<ml_kem::MlKem1024>::new(&key)
                .map_err(|_| HsmError::KeyHandleInvalid)?;
            let (ct, ss) = ek.encapsulate_with_rng(&mut rng);
            Ok((ct[..].to_vec(), ss[..].to_vec()))
        }
    }
}

/// ML-KEM decapsulate: given dk seed + ciphertext, recover shared_secret.
pub fn ml_kem_decapsulate(
    dk_seed: &[u8],
    ciphertext: &[u8],
    variant: MlKemVariant,
) -> HsmResult<Vec<u8>> {
    use ml_kem::kem::Decapsulate;

    if dk_seed.len() != 64 {
        return Err(HsmError::KeyHandleInvalid);
    }

    let seed: ml_kem::Seed = dk_seed.try_into().map_err(|_| HsmError::KeyHandleInvalid)?;

    match variant {
        MlKemVariant::MlKem512 => {
            let dk = ml_kem::DecapsulationKey::<ml_kem::MlKem512>::from_seed(seed);
            // Let type inference determine the Ciphertext type from decapsulate's signature
            let ct = ciphertext
                .try_into()
                .map_err(|_| HsmError::EncryptedDataInvalid)?;
            let ss = dk.decapsulate(&ct);
            Ok(ss[..].to_vec())
        }
        MlKemVariant::MlKem768 => {
            let dk = ml_kem::DecapsulationKey::<ml_kem::MlKem768>::from_seed(seed);
            let ct = ciphertext
                .try_into()
                .map_err(|_| HsmError::EncryptedDataInvalid)?;
            let ss = dk.decapsulate(&ct);
            Ok(ss[..].to_vec())
        }
        MlKemVariant::MlKem1024 => {
            let dk = ml_kem::DecapsulationKey::<ml_kem::MlKem1024>::from_seed(seed);
            let ct = ciphertext
                .try_into()
                .map_err(|_| HsmError::EncryptedDataInvalid)?;
            let ss = dk.decapsulate(&ct);
            Ok(ss[..].to_vec())
        }
    }
}

// ============================================================================
// ML-DSA (FIPS 204) — Digital Signatures
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlDsaVariant {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

/// Generate an ML-DSA keypair. Returns (signing_key_seed_32bytes, verifying_key_bytes).
pub fn ml_dsa_keygen(variant: MlDsaVariant) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
    use ml_dsa::KeyGen;

    let mut rng = new_rng()?;

    match variant {
        MlDsaVariant::MlDsa44 => {
            let kp = ml_dsa::MlDsa44::key_gen(&mut rng);
            let seed = kp.to_seed();
            let vk_bytes = kp.verifying_key().encode();
            Ok((
                RawKeyMaterial::new(seed[..].to_vec()),
                vk_bytes[..].to_vec(),
            ))
        }
        MlDsaVariant::MlDsa65 => {
            let kp = ml_dsa::MlDsa65::key_gen(&mut rng);
            let seed = kp.to_seed();
            let vk_bytes = kp.verifying_key().encode();
            Ok((
                RawKeyMaterial::new(seed[..].to_vec()),
                vk_bytes[..].to_vec(),
            ))
        }
        MlDsaVariant::MlDsa87 => {
            let kp = ml_dsa::MlDsa87::key_gen(&mut rng);
            let seed = kp.to_seed();
            let vk_bytes = kp.verifying_key().encode();
            Ok((
                RawKeyMaterial::new(seed[..].to_vec()),
                vk_bytes[..].to_vec(),
            ))
        }
    }
}

/// ML-DSA sign a message. signing_key_seed is the 32-byte seed.
pub fn ml_dsa_sign(
    signing_key_seed: &[u8],
    data: &[u8],
    variant: MlDsaVariant,
) -> HsmResult<Vec<u8>> {
    use ml_dsa::signature::Signer;
    use ml_dsa::KeyGen;

    use zeroize::Zeroizing;
    let seed: &[u8; 32] = signing_key_seed
        .try_into()
        .map_err(|_| HsmError::KeyHandleInvalid)?;
    let seed_zeroizing = Zeroizing::new(*seed);
    let seed_arr: ml_dsa::B32 = (*seed_zeroizing).into();

    match variant {
        MlDsaVariant::MlDsa44 => {
            let kp = ml_dsa::MlDsa44::from_seed(&seed_arr);
            let sig = kp.signing_key().sign(data);
            Ok(sig.encode()[..].to_vec())
        }
        MlDsaVariant::MlDsa65 => {
            let kp = ml_dsa::MlDsa65::from_seed(&seed_arr);
            let sig = kp.signing_key().sign(data);
            Ok(sig.encode()[..].to_vec())
        }
        MlDsaVariant::MlDsa87 => {
            let kp = ml_dsa::MlDsa87::from_seed(&seed_arr);
            let sig = kp.signing_key().sign(data);
            Ok(sig.encode()[..].to_vec())
        }
    }
}

/// ML-DSA verify a signature.
pub fn ml_dsa_verify(
    verifying_key_bytes: &[u8],
    data: &[u8],
    signature: &[u8],
    variant: MlDsaVariant,
) -> HsmResult<bool> {
    use ml_dsa::signature::Verifier;

    match variant {
        MlDsaVariant::MlDsa44 => {
            let vk_enc: ml_dsa::EncodedVerifyingKey<ml_dsa::MlDsa44> = verifying_key_bytes
                .try_into()
                .map_err(|_| HsmError::KeyHandleInvalid)?;
            let vk = ml_dsa::VerifyingKey::<ml_dsa::MlDsa44>::decode(&vk_enc);
            let sig = ml_dsa::Signature::<ml_dsa::MlDsa44>::try_from(signature)
                .map_err(|_| HsmError::SignatureInvalid)?;
            Ok(vk.verify(data, &sig).is_ok())
        }
        MlDsaVariant::MlDsa65 => {
            let vk_enc: ml_dsa::EncodedVerifyingKey<ml_dsa::MlDsa65> = verifying_key_bytes
                .try_into()
                .map_err(|_| HsmError::KeyHandleInvalid)?;
            let vk = ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::decode(&vk_enc);
            let sig = ml_dsa::Signature::<ml_dsa::MlDsa65>::try_from(signature)
                .map_err(|_| HsmError::SignatureInvalid)?;
            Ok(vk.verify(data, &sig).is_ok())
        }
        MlDsaVariant::MlDsa87 => {
            let vk_enc: ml_dsa::EncodedVerifyingKey<ml_dsa::MlDsa87> = verifying_key_bytes
                .try_into()
                .map_err(|_| HsmError::KeyHandleInvalid)?;
            let vk = ml_dsa::VerifyingKey::<ml_dsa::MlDsa87>::decode(&vk_enc);
            let sig = ml_dsa::Signature::<ml_dsa::MlDsa87>::try_from(signature)
                .map_err(|_| HsmError::SignatureInvalid)?;
            Ok(vk.verify(data, &sig).is_ok())
        }
    }
}

// ============================================================================
// SLH-DSA (FIPS 205) — Hash-Based Signatures
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlhDsaVariant {
    Sha2_128s,
    Sha2_256s,
}

/// Generate an SLH-DSA keypair. Returns (signing_key_bytes, verifying_key_bytes).
pub fn slh_dsa_keygen(variant: SlhDsaVariant) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
    use slh_dsa::signature::Keypair;
    let mut rng = new_rng()?;

    match variant {
        SlhDsaVariant::Sha2_128s => {
            let sk = slh_dsa::SigningKey::<slh_dsa::Sha2_128s>::new(&mut rng);
            let vk = sk.verifying_key();
            Ok((
                RawKeyMaterial::new(sk.to_bytes()[..].to_vec()),
                vk.to_bytes()[..].to_vec(),
            ))
        }
        SlhDsaVariant::Sha2_256s => {
            let sk = slh_dsa::SigningKey::<slh_dsa::Sha2_256s>::new(&mut rng);
            let vk = sk.verifying_key();
            Ok((
                RawKeyMaterial::new(sk.to_bytes()[..].to_vec()),
                vk.to_bytes()[..].to_vec(),
            ))
        }
    }
}

/// SLH-DSA sign a message (deterministic).
pub fn slh_dsa_sign(
    signing_key_bytes: &[u8],
    data: &[u8],
    variant: SlhDsaVariant,
) -> HsmResult<Vec<u8>> {
    use slh_dsa::signature::Signer;

    match variant {
        SlhDsaVariant::Sha2_128s => {
            let sk = slh_dsa::SigningKey::<slh_dsa::Sha2_128s>::try_from(signing_key_bytes)
                .map_err(|_| HsmError::KeyHandleInvalid)?;
            let sig = sk.try_sign(data).map_err(|_| HsmError::GeneralError)?;
            Ok(sig.to_bytes()[..].to_vec())
        }
        SlhDsaVariant::Sha2_256s => {
            let sk = slh_dsa::SigningKey::<slh_dsa::Sha2_256s>::try_from(signing_key_bytes)
                .map_err(|_| HsmError::KeyHandleInvalid)?;
            let sig = sk.try_sign(data).map_err(|_| HsmError::GeneralError)?;
            Ok(sig.to_bytes()[..].to_vec())
        }
    }
}

/// SLH-DSA verify a signature.
pub fn slh_dsa_verify(
    verifying_key_bytes: &[u8],
    data: &[u8],
    signature: &[u8],
    variant: SlhDsaVariant,
) -> HsmResult<bool> {
    use slh_dsa::signature::Verifier;

    match variant {
        SlhDsaVariant::Sha2_128s => {
            let vk = slh_dsa::VerifyingKey::<slh_dsa::Sha2_128s>::try_from(verifying_key_bytes)
                .map_err(|_| HsmError::KeyHandleInvalid)?;
            let sig = slh_dsa::Signature::<slh_dsa::Sha2_128s>::try_from(signature)
                .map_err(|_| HsmError::SignatureInvalid)?;
            Ok(vk.verify(data, &sig).is_ok())
        }
        SlhDsaVariant::Sha2_256s => {
            let vk = slh_dsa::VerifyingKey::<slh_dsa::Sha2_256s>::try_from(verifying_key_bytes)
                .map_err(|_| HsmError::KeyHandleInvalid)?;
            let sig = slh_dsa::Signature::<slh_dsa::Sha2_256s>::try_from(signature)
                .map_err(|_| HsmError::SignatureInvalid)?;
            Ok(vk.verify(data, &sig).is_ok())
        }
    }
}

// ============================================================================
// Hybrid Classical + PQC
// ============================================================================

/// Hybrid ML-DSA-65 + ECDSA-P256 signing.
/// Format: [4-byte ML-DSA sig length (BE)] [ML-DSA-65 sig] [ECDSA-P256 DER sig]
pub fn hybrid_sign(
    ml_dsa_sk_seed: &[u8],
    ecdsa_sk_bytes: &[u8],
    data: &[u8],
) -> HsmResult<Vec<u8>> {
    let ml_sig = ml_dsa_sign(ml_dsa_sk_seed, data, MlDsaVariant::MlDsa65)?;
    let ec_sig = crate::crypto::sign::ecdsa_p256_sign(ecdsa_sk_bytes, data)?;

    let ml_len = (ml_sig.len() as u32).to_be_bytes();
    let mut combined = Vec::with_capacity(4 + ml_sig.len() + ec_sig.len());
    combined.extend_from_slice(&ml_len);
    combined.extend_from_slice(&ml_sig);
    combined.extend_from_slice(&ec_sig);
    Ok(combined)
}

/// Hybrid ML-DSA-65 + ECDSA-P256 verification. Both must verify.
///
/// Both verification calls always execute regardless of individual results
/// to prevent timing side-channels from revealing which algorithm failed.
pub fn hybrid_verify(
    ml_dsa_vk_bytes: &[u8],
    ecdsa_pk_sec1: &[u8],
    data: &[u8],
    combined_signature: &[u8],
) -> HsmResult<bool> {
    if combined_signature.len() < 4 {
        return Err(HsmError::SignatureInvalid);
    }

    let ml_len_u32 = u32::from_be_bytes([
        combined_signature[0],
        combined_signature[1],
        combined_signature[2],
        combined_signature[3],
    ]);
    let ml_len = ml_len_u32 as usize;

    // Guard against overflow: on 32-bit platforms, `4 + ml_len` could wrap
    // if ml_len_u32 is close to u32::MAX. Use checked arithmetic.
    let total_ml = match 4usize.checked_add(ml_len) {
        Some(v) => v,
        None => return Err(HsmError::SignatureInvalid),
    };
    if combined_signature.len() < total_ml {
        return Err(HsmError::SignatureInvalid);
    }

    let ml_sig = &combined_signature[4..total_ml];
    let ec_sig = &combined_signature[total_ml..];

    // Always execute both verifications to prevent timing side-channels.
    // Convert errors to false so that one algorithm's parse failure
    // doesn't short-circuit the other's execution.
    let ml_valid =
        ml_dsa_verify(ml_dsa_vk_bytes, data, ml_sig, MlDsaVariant::MlDsa65).unwrap_or(false);
    let ec_valid =
        crate::crypto::sign::ecdsa_p256_verify(ecdsa_pk_sec1, data, ec_sig).unwrap_or(false);

    // Use bitwise AND to avoid short-circuit timing leak
    Ok(ml_valid & ec_valid)
}

// ============================================================================
// Helpers
// ============================================================================

pub fn mechanism_to_ml_kem_variant(
    mechanism: crate::pkcs11_abi::types::CK_MECHANISM_TYPE,
) -> Option<MlKemVariant> {
    use crate::pkcs11_abi::constants::*;
    match mechanism {
        CKM_ML_KEM_512 => Some(MlKemVariant::MlKem512),
        CKM_ML_KEM_768 => Some(MlKemVariant::MlKem768),
        CKM_ML_KEM_1024 => Some(MlKemVariant::MlKem1024),
        _ => None,
    }
}

pub fn mechanism_to_ml_dsa_variant(
    mechanism: crate::pkcs11_abi::types::CK_MECHANISM_TYPE,
) -> Option<MlDsaVariant> {
    use crate::pkcs11_abi::constants::*;
    match mechanism {
        CKM_ML_DSA_44 => Some(MlDsaVariant::MlDsa44),
        CKM_ML_DSA_65 => Some(MlDsaVariant::MlDsa65),
        CKM_ML_DSA_87 => Some(MlDsaVariant::MlDsa87),
        _ => None,
    }
}

pub fn mechanism_to_slh_dsa_variant(
    mechanism: crate::pkcs11_abi::types::CK_MECHANISM_TYPE,
) -> Option<SlhDsaVariant> {
    use crate::pkcs11_abi::constants::*;
    match mechanism {
        CKM_SLH_DSA_SHA2_128S => Some(SlhDsaVariant::Sha2_128s),
        CKM_SLH_DSA_SHA2_256S => Some(SlhDsaVariant::Sha2_256s),
        _ => None,
    }
}

pub fn is_ml_kem_mechanism(mechanism: crate::pkcs11_abi::types::CK_MECHANISM_TYPE) -> bool {
    mechanism_to_ml_kem_variant(mechanism).is_some()
}

pub fn is_ml_dsa_mechanism(mechanism: crate::pkcs11_abi::types::CK_MECHANISM_TYPE) -> bool {
    mechanism_to_ml_dsa_variant(mechanism).is_some()
}

pub fn is_slh_dsa_mechanism(mechanism: crate::pkcs11_abi::types::CK_MECHANISM_TYPE) -> bool {
    mechanism_to_slh_dsa_variant(mechanism).is_some()
}

pub fn is_hybrid_mechanism(mechanism: crate::pkcs11_abi::types::CK_MECHANISM_TYPE) -> bool {
    mechanism == crate::pkcs11_abi::constants::CKM_HYBRID_ML_DSA_ECDSA
}
