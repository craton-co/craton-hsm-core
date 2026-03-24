// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
use zeroize::Zeroizing;

use crate::error::{HsmError, HsmResult};
use crate::store::key_material::RawKeyMaterial;

/// Generate cryptographic random bytes using the FIPS-approved HMAC_DRBG.
///
/// All key generation MUST use this function (not OsRng directly) so that
/// randomness passes through the SP 800-90A DRBG with health testing and
/// continuous output comparison.
///
/// A fresh DRBG is instantiated per call, seeded from OsRng. This is
/// intentional: each key gets independently seeded randomness, and modern
/// OS entropy sources (getrandom/BCryptGenRandom) do not exhaust under load.
/// Sharing a single DRBG across keys would create a correlation risk if the
/// DRBG's internal state were ever compromised.
fn generate_random_bytes(out: &mut [u8]) -> HsmResult<()> {
    let mut drbg = crate::crypto::drbg::HmacDrbg::new()?;
    drbg.generate(out)
}

use crate::crypto::drbg::DrbgRng;

/// Generate an AES key of the specified length (16, 24, or 32 bytes).
/// If `fips_mode` is true, AES-128 (16 bytes) is rejected per FIPS 140-3.
pub fn generate_aes_key(key_len_bytes: usize, fips_mode: bool) -> HsmResult<RawKeyMaterial> {
    match key_len_bytes {
        16 | 24 | 32 => {}
        _ => return Err(HsmError::KeySizeRange),
    }
    if fips_mode && key_len_bytes == 16 {
        return Err(HsmError::MechanismParamInvalid);
    }

    // Use Zeroizing<Vec<u8>> to ensure the intermediate buffer is scrubbed
    // even if RawKeyMaterial::new() triggers a reallocation. Without this,
    // the allocator could leave copies of key bytes in freed heap memory.
    let mut key = Zeroizing::new(vec![0u8; key_len_bytes]);
    generate_random_bytes(&mut key)?;
    // Move out of Zeroizing into RawKeyMaterial (which handles mlock + zeroize-on-drop).
    // The Zeroizing wrapper will zeroize its copy on drop.
    Ok(RawKeyMaterial::new(key.to_vec()))
}

/// Generate an RSA key pair. Returns (private_key_der, public_modulus, public_exponent).
/// If `fips_mode` is true, RSA key sizes below 3072 are rejected per FIPS 140-3.
pub fn generate_rsa_key_pair(
    modulus_bits: u32,
    fips_mode: bool,
) -> HsmResult<(RawKeyMaterial, Vec<u8>, Vec<u8>)> {
    use rsa::traits::PublicKeyParts;
    use rsa::{pkcs8::EncodePrivateKey, RsaPrivateKey};

    match modulus_bits {
        2048 | 3072 | 4096 => {}
        _ => return Err(HsmError::KeySizeRange),
    }
    if fips_mode && modulus_bits < 3072 {
        return Err(HsmError::MechanismParamInvalid);
    }

    let mut rng = DrbgRng::new()?;
    let private_key =
        RsaPrivateKey::new(&mut rng, modulus_bits as usize).map_err(|_| HsmError::GeneralError)?;

    let modulus = private_key.n().to_bytes_be();
    let pub_exp = private_key.e().to_bytes_be();

    let der = private_key
        .to_pkcs8_der()
        .map_err(|_| HsmError::GeneralError)?;

    // Move DER bytes directly into RawKeyMaterial — avoid unnecessary clone
    // that would create an extra unzeroized copy in memory (fix #16).
    // RawKeyMaterial handles mlock + zeroize-on-drop for the key material.
    let result = RawKeyMaterial::new(der.as_bytes().to_vec());

    Ok((result, modulus, pub_exp))
}

/// Generate EC key pair for P-256. Returns (private_key_bytes, public_key_sec1_uncompressed).
pub fn generate_ec_p256_key_pair() -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
    use elliptic_curve::sec1::ToEncodedPoint;
    use p256::SecretKey;

    let mut rng = DrbgRng::new()?;
    let secret_key = SecretKey::random(&mut rng);
    let public_key = secret_key.public_key();
    let pub_point = public_key.to_encoded_point(false);

    Ok((
        RawKeyMaterial::new(secret_key.to_bytes().to_vec()),
        pub_point.as_bytes().to_vec(),
    ))
}

/// Generate EC key pair for P-384. Returns (private_key_bytes, public_key_sec1_uncompressed).
pub fn generate_ec_p384_key_pair() -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
    use elliptic_curve::sec1::ToEncodedPoint;
    use p384::SecretKey;

    let mut rng = DrbgRng::new()?;
    let secret_key = SecretKey::random(&mut rng);
    let public_key = secret_key.public_key();
    let pub_point = public_key.to_encoded_point(false);

    Ok((
        RawKeyMaterial::new(secret_key.to_bytes().to_vec()),
        pub_point.as_bytes().to_vec(),
    ))
}

/// Generate Ed25519 key pair. Returns (private_key_bytes, public_key_bytes).
pub fn generate_ed25519_key_pair() -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
    use ed25519_dalek::SigningKey;

    let mut rng = DrbgRng::new()?;
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();

    Ok((
        RawKeyMaterial::new(signing_key.to_bytes().to_vec()),
        verifying_key.to_bytes().to_vec(),
    ))
}
