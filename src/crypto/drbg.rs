// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! HMAC_DRBG implementation per NIST SP 800-90A Rev.1.
//!
//! Uses HMAC-SHA256 as the underlying function.
//! Entropy is sourced from the OS via `OsRng` — this is the ONLY
//! place in the codebase that should use `OsRng` directly (besides
//! self-test and `C_SeedRandom`).
//!
//! Key properties:
//! - Reseed interval: 2^48 (per SP 800-90A Table 2)
//! - Continuous health test: consecutive output comparison (SP 800-90B §4.9)
//! - Prediction resistance: reseeds from OS entropy on each generate call (conservative)
//! - K and V are zeroized on drop

use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{HsmError, HsmResult};

type HmacSha256 = Hmac<Sha256>;

/// Maximum number of generate calls before a reseed is required.
const RESEED_INTERVAL: u64 = 1u64 << 48;

/// HMAC_DRBG per SP 800-90A using HMAC-SHA256.
///
/// This implementation uses prediction resistance mode: it reseeds
/// from `OsRng` on every `generate()` call, ensuring forward secrecy
/// even if internal state is compromised.
#[derive(ZeroizeOnDrop)]
pub struct HmacDrbg {
    /// HMAC key (K), 32 bytes
    #[zeroize(drop)]
    key: [u8; 32],
    /// Value (V), 32 bytes
    #[zeroize(drop)]
    value: [u8; 32],
    /// Reseed counter
    reseed_counter: u64,
    /// Last output block for continuous health test (SP 800-90B §4.9)
    #[zeroize(drop)]
    last_output: [u8; 32],
    /// Whether we've produced any output yet (for first-block health test skip)
    has_output: bool,
}

impl std::fmt::Debug for HmacDrbg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HmacDrbg")
            .field("reseed_counter", &self.reseed_counter)
            .field("has_output", &self.has_output)
            .finish()
    }
}

impl HmacDrbg {
    /// Instantiate a new HMAC_DRBG, seeded from OS entropy.
    ///
    /// Per SP 800-90A §10.1.2.3:
    /// 1. Set K = 0x00...00 (32 bytes)
    /// 2. Set V = 0x01...01 (32 bytes)
    /// 3. Update(seed_material) where seed_material = entropy || nonce
    pub fn new() -> HsmResult<Self> {
        let mut drbg = Self {
            key: [0u8; 32],
            value: [0x01u8; 32],
            reseed_counter: 0,
            last_output: [0u8; 32],
            has_output: false,
        };

        // Gather entropy (32 bytes) + nonce (16 bytes)
        let mut seed = [0u8; 48];
        OsRng.fill_bytes(&mut seed);
        drbg.update(Some(&seed));
        seed.zeroize();

        drbg.reseed_counter = 1;
        Ok(drbg)
    }

    /// Instantiate with a deterministic seed (for KAT testing only).
    #[cfg(test)]
    pub fn new_deterministic(entropy: &[u8], nonce: &[u8]) -> Self {
        let mut drbg = Self {
            key: [0u8; 32],
            value: [0x01u8; 32],
            reseed_counter: 0,
            last_output: [0u8; 32],
            has_output: false,
        };

        let mut seed_material = Vec::new();
        seed_material.extend_from_slice(entropy);
        seed_material.extend_from_slice(nonce);
        drbg.update(Some(&seed_material));
        seed_material.zeroize();

        drbg.reseed_counter = 1;
        drbg
    }

    /// SP 800-90A §10.1.2.2: HMAC_DRBG_Update
    ///
    /// 1. K = HMAC(K, V || 0x00 || provided_data)
    /// 2. V = HMAC(K, V)
    /// 3. If provided_data is not empty:
    ///    K = HMAC(K, V || 0x01 || provided_data)
    ///    V = HMAC(K, V)
    fn update(&mut self, provided_data: Option<&[u8]>) {
        // Step 1: K = HMAC(K, V || 0x00 || provided_data)
        let mut mac =
            HmacSha256::new_from_slice(&self.key).expect("HMAC key length is always valid");
        mac.update(&self.value);
        mac.update(&[0x00]);
        if let Some(data) = provided_data {
            mac.update(data);
        }
        let result = mac.finalize().into_bytes();
        self.key.copy_from_slice(&result);

        // Step 2: V = HMAC(K, V)
        let mut mac =
            HmacSha256::new_from_slice(&self.key).expect("HMAC key length is always valid");
        mac.update(&self.value);
        let result = mac.finalize().into_bytes();
        self.value.copy_from_slice(&result);

        // Step 3: If provided_data is not empty
        if let Some(data) = provided_data {
            if !data.is_empty() {
                let mut mac =
                    HmacSha256::new_from_slice(&self.key).expect("HMAC key length is always valid");
                mac.update(&self.value);
                mac.update(&[0x01]);
                mac.update(data);
                let result = mac.finalize().into_bytes();
                self.key.copy_from_slice(&result);

                let mut mac =
                    HmacSha256::new_from_slice(&self.key).expect("HMAC key length is always valid");
                mac.update(&self.value);
                let result = mac.finalize().into_bytes();
                self.value.copy_from_slice(&result);
            }
        }
    }

    /// Reseed from OS entropy.
    ///
    /// Per SP 800-90A §10.1.2.4:
    /// 1. seed_material = entropy_input
    /// 2. Update(seed_material)
    /// 3. reseed_counter = 1
    pub fn reseed(&mut self) -> HsmResult<()> {
        let mut entropy = [0u8; 32];
        OsRng.fill_bytes(&mut entropy);
        self.update(Some(&entropy));
        entropy.zeroize();
        self.reseed_counter = 1;
        Ok(())
    }

    /// Reseed with deterministic entropy (for testing).
    #[cfg(test)]
    pub fn reseed_deterministic(&mut self, entropy: &[u8]) {
        self.update(Some(entropy));
        self.reseed_counter = 1;
    }

    /// Generate random bytes.
    ///
    /// Per SP 800-90A §10.1.2.5:
    /// 1. If reseed_counter > reseed_interval → reseed
    /// 2. Generate output blocks: V = HMAC(K, V), output V
    /// 3. Update(additional_input)
    /// 4. reseed_counter += 1
    ///
    /// This implementation uses prediction resistance: reseeds from
    /// fresh entropy on every call.
    pub fn generate(&mut self, out: &mut [u8]) -> HsmResult<()> {
        // Check reseed counter
        if self.reseed_counter > RESEED_INTERVAL {
            self.reseed()?;
        }

        // Prediction resistance: reseed with fresh entropy
        self.reseed()?;

        // Generate output blocks
        let mut pos = 0;
        while pos < out.len() {
            // V = HMAC(K, V)
            let mut mac =
                HmacSha256::new_from_slice(&self.key).expect("HMAC key length is always valid");
            mac.update(&self.value);
            let result = mac.finalize().into_bytes();
            self.value.copy_from_slice(&result);

            // Continuous health test: compare with last output.
            // Copy value to a Zeroizing buffer to avoid borrow conflict
            // and ensure the temporary copy is zeroized on drop.
            let current_block = zeroize::Zeroizing::new(self.value);
            if self.has_output {
                self.health_check(current_block.as_slice())?;
            }
            self.last_output.copy_from_slice(current_block.as_slice());
            self.has_output = true;

            // Copy to output
            let remaining = out.len() - pos;
            let copy_len = remaining.min(32);
            out[pos..pos + copy_len].copy_from_slice(&self.value[..copy_len]);
            pos += copy_len;
        }

        // Update with no additional input
        self.update(None);
        self.reseed_counter += 1;

        Ok(())
    }

    /// Continuous health test per SP 800-90B §4.9:
    /// Consecutive outputs must not be identical.
    fn health_check(&self, current: &[u8]) -> HsmResult<()> {
        // Use constant-time comparison is not needed here (not secret data),
        // but we do a simple comparison.
        if current == self.last_output.as_slice() {
            // Stuck output — this indicates a catastrophic DRBG failure
            return Err(HsmError::GeneralError);
        }
        Ok(())
    }
}

/// DRBG-backed RNG adapter that implements `rand::CryptoRng + rand::RngCore`.
///
/// This wrapper routes all randomness through the SP 800-90A HMAC_DRBG so that
/// key generation, RSA-PSS signing, RSA-OAEP encryption, and all other
/// operations that require randomness benefit from the DRBG's continuous
/// health testing and prediction resistance.
///
/// All code paths that need randomness MUST use `DrbgRng` instead of `OsRng`
/// directly (except for DRBG seeding itself and self-tests).
pub struct DrbgRng {
    drbg: HmacDrbg,
}

impl DrbgRng {
    pub fn new() -> HsmResult<Self> {
        Ok(Self {
            drbg: HmacDrbg::new()?,
        })
    }
}

impl rand::RngCore for DrbgRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if let Err(e) = self.drbg.generate(dest) {
            // DRBG health check failure — a catastrophic FIPS error.
            //
            // Zero the output buffer so that no partial DRBG output remains
            // in memory, then abort the process. We use `std::process::abort()`
            // instead of `panic!()` because:
            //   1. `panic!()` unwinds the stack, which in a shared library
            //      (PKCS#11 .so/.dll) can corrupt the host application's state
            //      or be caught by a `catch_unwind`, silently continuing with
            //      zeroed "randomness".
            //   2. `abort()` is immediate and cannot be caught, ensuring the
            //      module halts definitively on RNG failure.
            //
            // This matches FIPS 140-3 §7.3: "If a conditional self-test fails,
            // the module shall enter an error state."
            dest.fill(0);
            tracing::error!(
                "DRBG catastrophic failure in fill_bytes: {:?} — \
                 cannot produce safe randomness, aborting to prevent \
                 weak key generation or signature forgery",
                e
            );
            std::process::abort();
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.drbg
            .generate(dest)
            .map_err(|_| rand::Error::new("DRBG generate failed"))
    }
}

impl rand::CryptoRng for DrbgRng {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_drbg_basic() {
        let mut drbg = HmacDrbg::new().unwrap();
        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];

        drbg.generate(&mut buf1).unwrap();
        drbg.generate(&mut buf2).unwrap();

        // Outputs should be different
        assert_ne!(buf1, buf2, "Consecutive DRBG outputs should differ");
        // Outputs should not be all zeros
        assert_ne!(buf1, [0u8; 32], "DRBG output should not be all zeros");
    }

    #[test]
    fn test_drbg_various_lengths() {
        let mut drbg = HmacDrbg::new().unwrap();

        // Test various output sizes
        for &len in &[1, 16, 32, 48, 64, 100, 256] {
            let mut buf = vec![0u8; len];
            drbg.generate(&mut buf).unwrap();
            assert_ne!(
                buf,
                vec![0u8; len],
                "DRBG output of {} bytes should not be all zeros",
                len
            );
        }
    }

    #[test]
    fn test_drbg_reseed() {
        let mut drbg = HmacDrbg::new().unwrap();
        let mut buf1 = [0u8; 32];
        drbg.generate(&mut buf1).unwrap();

        // Explicit reseed
        drbg.reseed().unwrap();

        let mut buf2 = [0u8; 32];
        drbg.generate(&mut buf2).unwrap();

        assert_ne!(buf1, buf2, "Output after reseed should differ");
    }

    #[test]
    fn test_drbg_deterministic() {
        // Verify deterministic instantiation produces consistent output
        let entropy = [0x42u8; 32];
        let nonce = [0x13u8; 16];

        let drbg1 = HmacDrbg::new_deterministic(&entropy, &nonce);
        let drbg2 = HmacDrbg::new_deterministic(&entropy, &nonce);

        // Without prediction resistance, outputs would be identical.
        // But our generate() always reseeds, so deterministic mode
        // is only useful for testing the Update algorithm.

        // Instead, verify the internal state matches after instantiation
        assert_eq!(drbg1.key, drbg2.key, "Deterministic DRBG keys should match");
        assert_eq!(
            drbg1.value, drbg2.value,
            "Deterministic DRBG values should match"
        );
    }
}
