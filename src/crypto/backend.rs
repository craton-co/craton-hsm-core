// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Crypto backend trait — abstracts all classical crypto operations behind a trait interface.
//! This enables swapping in FIPS-validated backends (e.g., aws-lc-rs) without modifying
//! the PKCS#11 ABI layer.
//!
//! PQC operations are excluded: no alternative PQC backends exist yet.

use super::digest::DigestAccumulator;
use super::sign::HashAlg;
use crate::error::HsmResult;
use crate::pkcs11_abi::types::CK_MECHANISM_TYPE;
use crate::store::key_material::RawKeyMaterial;

/// Combined crypto backend trait. Implementors provide all classical crypto operations.
pub trait CryptoBackend: Send + Sync {
    // ========================================================================
    // Signing
    // ========================================================================

    fn rsa_pkcs1v15_sign(
        &self,
        private_key_der: &[u8],
        data: &[u8],
        hash_alg: Option<HashAlg>,
    ) -> HsmResult<Vec<u8>>;

    fn rsa_pkcs1v15_verify(
        &self,
        modulus: &[u8],
        public_exponent: &[u8],
        data: &[u8],
        signature: &[u8],
        hash_alg: Option<HashAlg>,
    ) -> HsmResult<bool>;

    fn rsa_pss_sign(
        &self,
        private_key_der: &[u8],
        data: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<Vec<u8>>;

    fn rsa_pss_verify(
        &self,
        modulus: &[u8],
        public_exponent: &[u8],
        data: &[u8],
        signature: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<bool>;

    fn ecdsa_p256_sign(&self, private_key_bytes: &[u8], data: &[u8]) -> HsmResult<Vec<u8>>;

    fn ecdsa_p256_verify(
        &self,
        public_key_sec1: &[u8],
        data: &[u8],
        signature_der: &[u8],
    ) -> HsmResult<bool>;

    fn ecdsa_p384_sign(&self, private_key_bytes: &[u8], data: &[u8]) -> HsmResult<Vec<u8>>;

    fn ecdsa_p384_verify(
        &self,
        public_key_sec1: &[u8],
        data: &[u8],
        signature_der: &[u8],
    ) -> HsmResult<bool>;

    fn ed25519_sign(&self, private_key_bytes: &[u8], data: &[u8]) -> HsmResult<Vec<u8>>;

    fn ed25519_verify(
        &self,
        public_key_bytes: &[u8],
        data: &[u8],
        signature_bytes: &[u8],
    ) -> HsmResult<bool>;

    // ========================================================================
    // Prehashed signing (for multi-part C_SignUpdate/C_SignFinal)
    // ========================================================================

    fn rsa_pkcs1v15_sign_prehashed(
        &self,
        private_key_der: &[u8],
        digest: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<Vec<u8>>;

    fn rsa_pkcs1v15_verify_prehashed(
        &self,
        modulus: &[u8],
        public_exponent: &[u8],
        digest: &[u8],
        signature: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<bool>;

    fn rsa_pss_sign_prehashed(
        &self,
        private_key_der: &[u8],
        digest: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<Vec<u8>>;

    fn rsa_pss_verify_prehashed(
        &self,
        modulus: &[u8],
        public_exponent: &[u8],
        digest: &[u8],
        signature: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<bool>;

    fn ecdsa_p256_sign_prehashed(
        &self,
        private_key_bytes: &[u8],
        digest: &[u8],
    ) -> HsmResult<Vec<u8>>;

    fn ecdsa_p256_verify_prehashed(
        &self,
        public_key_sec1: &[u8],
        digest: &[u8],
        signature_der: &[u8],
    ) -> HsmResult<bool>;

    fn ecdsa_p384_sign_prehashed(
        &self,
        private_key_bytes: &[u8],
        digest: &[u8],
    ) -> HsmResult<Vec<u8>>;

    fn ecdsa_p384_verify_prehashed(
        &self,
        public_key_sec1: &[u8],
        digest: &[u8],
        signature_der: &[u8],
    ) -> HsmResult<bool>;

    // ========================================================================
    // Encryption
    // ========================================================================

    fn aes_256_gcm_encrypt(&self, key: &[u8], plaintext: &[u8]) -> HsmResult<Vec<u8>>;
    fn aes_256_gcm_decrypt(&self, key: &[u8], data: &[u8]) -> HsmResult<Vec<u8>>;
    fn aes_cbc_encrypt(&self, key: &[u8], iv: &[u8], plaintext: &[u8]) -> HsmResult<Vec<u8>>;
    fn aes_cbc_decrypt(&self, key: &[u8], iv: &[u8], ciphertext: &[u8]) -> HsmResult<Vec<u8>>;
    fn aes_ctr_encrypt(&self, key: &[u8], iv: &[u8], plaintext: &[u8]) -> HsmResult<Vec<u8>>;
    fn aes_ctr_decrypt(&self, key: &[u8], iv: &[u8], ciphertext: &[u8]) -> HsmResult<Vec<u8>>;

    fn rsa_oaep_encrypt(
        &self,
        modulus: &[u8],
        public_exponent: &[u8],
        plaintext: &[u8],
        hash_alg: super::sign::OaepHash,
    ) -> HsmResult<Vec<u8>>;

    fn rsa_oaep_decrypt(
        &self,
        private_key_der: &[u8],
        ciphertext: &[u8],
        hash_alg: super::sign::OaepHash,
    ) -> HsmResult<Vec<u8>>;

    // ========================================================================
    // Key generation
    // ========================================================================

    fn generate_aes_key(&self, key_len_bytes: usize, fips_mode: bool) -> HsmResult<RawKeyMaterial>;

    /// Returns (private_key_der, public_modulus, public_exponent)
    fn generate_rsa_key_pair(
        &self,
        modulus_bits: u32,
        fips_mode: bool,
    ) -> HsmResult<(RawKeyMaterial, Vec<u8>, Vec<u8>)>;

    /// Returns (private_key_bytes, public_key_sec1_uncompressed)
    fn generate_ec_p256_key_pair(&self) -> HsmResult<(RawKeyMaterial, Vec<u8>)>;

    /// Returns (private_key_bytes, public_key_sec1_uncompressed)
    fn generate_ec_p384_key_pair(&self) -> HsmResult<(RawKeyMaterial, Vec<u8>)>;

    /// Returns (private_key_bytes, public_key_bytes)
    fn generate_ed25519_key_pair(&self) -> HsmResult<(RawKeyMaterial, Vec<u8>)>;

    // ========================================================================
    // Digest
    // ========================================================================

    fn compute_digest(&self, mechanism: CK_MECHANISM_TYPE, data: &[u8]) -> HsmResult<Vec<u8>>;
    fn digest_output_len(&self, mechanism: CK_MECHANISM_TYPE) -> HsmResult<usize>;
    fn create_hasher(&self, mechanism: CK_MECHANISM_TYPE) -> HsmResult<Box<dyn DigestAccumulator>>;

    // ========================================================================
    // Key wrap/unwrap
    // ========================================================================

    fn aes_key_wrap(
        &self,
        wrapping_key: &[u8],
        key_to_wrap: &[u8],
        fips_mode: bool,
    ) -> HsmResult<Vec<u8>>;
    fn aes_key_unwrap(
        &self,
        wrapping_key: &[u8],
        wrapped_key: &[u8],
        fips_mode: bool,
    ) -> HsmResult<Vec<u8>>;

    // ========================================================================
    // Key derivation
    // ========================================================================

    fn ecdh_p256(
        &self,
        private_key_bytes: &[u8],
        peer_public_key_sec1: &[u8],
        okm_len: Option<usize>,
    ) -> HsmResult<RawKeyMaterial>;
    fn ecdh_p384(
        &self,
        private_key_bytes: &[u8],
        peer_public_key_sec1: &[u8],
        okm_len: Option<usize>,
    ) -> HsmResult<RawKeyMaterial>;
}
