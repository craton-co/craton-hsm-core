// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
use p256::ecdh::diffie_hellman as p256_dh;
use p256::PublicKey as P256PublicKey;
use p256::SecretKey as P256SecretKey;
use p384::ecdh::diffie_hellman as p384_dh;
use p384::PublicKey as P384PublicKey;
use p384::SecretKey as P384SecretKey;
use zeroize::Zeroizing;

use crate::error::{HsmError, HsmResult};
use crate::store::key_material::RawKeyMaterial;

/// Maximum HKDF-SHA256 output length (255 * 32 = 8160 bytes per RFC 5869).
/// We cap at a practical limit well below this.
const MAX_OKM_LEN: usize = 64;

/// ECDH key derivation for P-256.
///
/// `okm_len` specifies the desired derived key length in bytes. If `None`,
/// defaults to 32 (matching P-256's security level). Common values:
/// - 16 for AES-128
/// - 24 for AES-192
/// - 32 for AES-256
pub fn ecdh_p256(
    private_key_bytes: &[u8],
    peer_public_key_sec1: &[u8],
    okm_len: Option<usize>,
) -> HsmResult<RawKeyMaterial> {
    let derived_len = okm_len.unwrap_or(32);
    validate_okm_len(derived_len)?;

    let secret_key =
        P256SecretKey::from_slice(private_key_bytes).map_err(|_| HsmError::KeyHandleInvalid)?;
    let peer_public =
        P256PublicKey::from_sec1_bytes(peer_public_key_sec1).map_err(|_| HsmError::ArgumentsBad)?;

    let shared_secret = p256_dh(secret_key.to_nonzero_scalar(), peer_public.as_affine());

    // Copy raw bytes into a Zeroizing wrapper so the shared secret is scrubbed
    // from memory promptly after HKDF extraction, regardless of compiler optimizations.
    let raw_bytes = Zeroizing::new(shared_secret.raw_secret_bytes().to_vec());

    // Build context-enriched HKDF info for domain separation (SP 800-56C §4.1).
    //
    // Uses the P-256 OID (1.2.840.10045.3.1.7) as the algorithm identifier per
    // NIST SP 800-56C Rev 2 §4.1, which recommends OID-based identifiers for
    // interoperability. The info string also includes output length and both
    // public keys so that:
    //  - Different curves produce different keys (OID)
    //  - Different requested lengths produce different keys (okm_len)
    //  - Different key pairs between the same parties produce different keys (public keys)
    //
    // NOTE: Changing this info string is a BREAKING CHANGE — existing derived
    // keys will not reproduce. Version the salt (HKDF_SALT) if migration is needed.
    let our_public = secret_key.public_key();
    let our_pk_bytes = elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(&our_public, false);
    // OID 1.2.840.10045.3.1.7 (P-256 / prime256v1) DER-encoded
    const P256_OID: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    let mut info =
        Vec::with_capacity(P256_OID.len() + 4 + our_pk_bytes.len() + peer_public_key_sec1.len());
    info.extend_from_slice(P256_OID);
    info.extend_from_slice(&(derived_len as u32).to_be_bytes());
    info.extend_from_slice(our_pk_bytes.as_bytes());
    info.extend_from_slice(peer_public_key_sec1);

    // Apply HKDF-SHA256 per NIST SP 800-56C — raw shared secret must not be used directly
    let okm = apply_hkdf(&raw_bytes, &info, derived_len)?;
    Ok(RawKeyMaterial::new(okm))
}

/// ECDH key derivation for P-384.
///
/// `okm_len` specifies the desired derived key length in bytes. If `None`,
/// defaults to 48 (matching P-384's security level). Common values:
/// - 16 for AES-128
/// - 24 for AES-192
/// - 32 for AES-256
/// - 48 for full P-384 shared secret length
pub fn ecdh_p384(
    private_key_bytes: &[u8],
    peer_public_key_sec1: &[u8],
    okm_len: Option<usize>,
) -> HsmResult<RawKeyMaterial> {
    let derived_len = okm_len.unwrap_or(48);
    validate_okm_len(derived_len)?;

    let secret_key =
        P384SecretKey::from_slice(private_key_bytes).map_err(|_| HsmError::KeyHandleInvalid)?;
    let peer_public =
        P384PublicKey::from_sec1_bytes(peer_public_key_sec1).map_err(|_| HsmError::ArgumentsBad)?;

    let shared_secret = p384_dh(secret_key.to_nonzero_scalar(), peer_public.as_affine());

    // Copy raw bytes into a Zeroizing wrapper so the shared secret is scrubbed
    // from memory promptly after HKDF extraction.
    let raw_bytes = Zeroizing::new(shared_secret.raw_secret_bytes().to_vec());

    // Build context-enriched HKDF info for domain separation (SP 800-56C §4.1).
    // Uses the P-384 OID (1.3.132.0.34) as the algorithm identifier per NIST
    // SP 800-56C Rev 2 §4.1 for interoperability.
    let our_public = secret_key.public_key();
    let our_pk_bytes = elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(&our_public, false);
    // OID 1.3.132.0.34 (P-384 / secp384r1) DER-encoded
    const P384_OID: &[u8] = &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22];
    let mut info =
        Vec::with_capacity(P384_OID.len() + 4 + our_pk_bytes.len() + peer_public_key_sec1.len());
    info.extend_from_slice(P384_OID);
    info.extend_from_slice(&(derived_len as u32).to_be_bytes());
    info.extend_from_slice(our_pk_bytes.as_bytes());
    info.extend_from_slice(peer_public_key_sec1);

    // Apply HKDF-SHA256 per NIST SP 800-56C — raw shared secret must not be used directly
    let okm = apply_hkdf(&raw_bytes, &info, derived_len)?;
    Ok(RawKeyMaterial::new(okm))
}

/// Validate the requested output key material length.
fn validate_okm_len(len: usize) -> HsmResult<()> {
    if len == 0 || len > MAX_OKM_LEN {
        tracing::error!(
            "ECDH: requested OKM length {} is out of range (1..={})",
            len,
            MAX_OKM_LEN
        );
        return Err(HsmError::KeySizeRange);
    }
    Ok(())
}

/// Fixed salt for HKDF extraction per NIST SP 800-56C Rev 2.
/// Using a non-null salt improves extraction randomness compared to
/// the default all-zero salt. This value is a fixed public constant
/// and does not need to be secret.
const HKDF_SALT: &[u8] = b"CratonHSM-ECDH-HKDF-Salt-v1";

/// Apply HKDF-SHA256 to raw ECDH shared secret (NIST SP 800-56C).
/// Uses a fixed salt for extraction and a context-enriched info string
/// that includes the curve label, output key length, and public keys
/// of both parties for domain separation per NIST SP 800-56C Rev 2 §4.1.
/// `okm_len` specifies the output length.
fn apply_hkdf(ikm: &[u8], info: &[u8], okm_len: usize) -> HsmResult<Vec<u8>> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), ikm);
    let mut okm = vec![0u8; okm_len];
    hk.expand(info, &mut okm).map_err(|e| {
        // Zeroize the output buffer on error before returning
        use zeroize::Zeroize;
        okm.zeroize();
        tracing::error!("HKDF expand failed: {}", e);
        HsmError::GeneralError
    })?;
    Ok(okm)
}
