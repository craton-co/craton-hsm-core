// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
use crate::error::{HsmError, HsmResult};
use aes_kw::Kek;
use zeroize::Zeroize;

/// AES Key Wrap (RFC 3394) — wraps a key using an AES wrapping key.
///
/// If `fips_mode` is true, AES-128 (16-byte) wrapping keys are rejected
/// per FIPS 140-3 requirements (minimum 192-bit for key wrapping).
pub fn aes_key_wrap(
    wrapping_key: &[u8],
    key_to_wrap: &[u8],
    fips_mode: bool,
) -> HsmResult<Vec<u8>> {
    if key_to_wrap.len() % 8 != 0 || key_to_wrap.len() < 16 {
        return Err(HsmError::DataLenRange);
    }

    if fips_mode && wrapping_key.len() == 16 {
        tracing::warn!("FIPS mode: rejecting AES-128 wrapping key — minimum 192-bit required");
        return Err(HsmError::KeySizeRange);
    }

    match wrapping_key.len() {
        16 => {
            let kek =
                Kek::<aes::Aes128>::try_from(wrapping_key).map_err(|_| HsmError::KeySizeRange)?;
            let mut buf = vec![0u8; key_to_wrap.len() + 8];
            kek.wrap(key_to_wrap, &mut buf)
                .map_err(|_| HsmError::GeneralError)?;
            Ok(buf)
        }
        24 => {
            let kek =
                Kek::<aes::Aes192>::try_from(wrapping_key).map_err(|_| HsmError::KeySizeRange)?;
            let mut buf = vec![0u8; key_to_wrap.len() + 8];
            kek.wrap(key_to_wrap, &mut buf)
                .map_err(|_| HsmError::GeneralError)?;
            Ok(buf)
        }
        32 => {
            let kek =
                Kek::<aes::Aes256>::try_from(wrapping_key).map_err(|_| HsmError::KeySizeRange)?;
            let mut buf = vec![0u8; key_to_wrap.len() + 8];
            kek.wrap(key_to_wrap, &mut buf)
                .map_err(|_| HsmError::GeneralError)?;
            Ok(buf)
        }
        _ => Err(HsmError::KeySizeRange),
    }
}

/// AES Key Unwrap (RFC 3394) — unwraps a wrapped key.
///
/// If `fips_mode` is true, AES-128 (16-byte) wrapping keys are rejected
/// per FIPS 140-3 requirements (minimum 192-bit for key wrapping).
pub fn aes_key_unwrap(
    wrapping_key: &[u8],
    wrapped_key: &[u8],
    fips_mode: bool,
) -> HsmResult<Vec<u8>> {
    if wrapped_key.len() % 8 != 0 || wrapped_key.len() < 24 {
        return Err(HsmError::DataLenRange);
    }

    if fips_mode && wrapping_key.len() == 16 {
        tracing::warn!("FIPS mode: rejecting AES-128 unwrapping key — minimum 192-bit required");
        return Err(HsmError::KeySizeRange);
    }

    match wrapping_key.len() {
        16 => {
            let kek =
                Kek::<aes::Aes128>::try_from(wrapping_key).map_err(|_| HsmError::KeySizeRange)?;
            let mut buf = vec![0u8; wrapped_key.len() - 8];
            if kek.unwrap(wrapped_key, &mut buf).is_err() {
                buf.zeroize(); // scrub partial key material on failure
                return Err(HsmError::EncryptedDataInvalid);
            }
            Ok(buf)
        }
        24 => {
            let kek =
                Kek::<aes::Aes192>::try_from(wrapping_key).map_err(|_| HsmError::KeySizeRange)?;
            let mut buf = vec![0u8; wrapped_key.len() - 8];
            if kek.unwrap(wrapped_key, &mut buf).is_err() {
                buf.zeroize();
                return Err(HsmError::EncryptedDataInvalid);
            }
            Ok(buf)
        }
        32 => {
            let kek =
                Kek::<aes::Aes256>::try_from(wrapping_key).map_err(|_| HsmError::KeySizeRange)?;
            let mut buf = vec![0u8; wrapped_key.len() - 8];
            if kek.unwrap(wrapped_key, &mut buf).is_err() {
                buf.zeroize();
                return Err(HsmError::EncryptedDataInvalid);
            }
            Ok(buf)
        }
        _ => Err(HsmError::KeySizeRange),
    }
}
