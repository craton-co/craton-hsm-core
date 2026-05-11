// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Default CryptoBackend implementation using RustCrypto crates.
//! Zero-cost delegation to existing free functions.

use super::backend::CryptoBackend;
use super::digest::DigestAccumulator;
use super::sign::HashAlg;
use crate::error::HsmResult;
use crate::pkcs11_abi::types::CK_MECHANISM_TYPE;
use crate::store::key_material::RawKeyMaterial;

/// Zero-sized struct — all state lives in the underlying RustCrypto crates.
pub struct RustCryptoBackend;

impl CryptoBackend for RustCryptoBackend {
    // ========================================================================
    // Signing
    // ========================================================================

    fn rsa_pkcs1v15_sign(
        &self,
        private_key_der: &[u8],
        data: &[u8],
        hash_alg: Option<HashAlg>,
    ) -> HsmResult<Vec<u8>> {
        super::sign::rsa_pkcs1v15_sign(private_key_der, data, hash_alg)
    }

    fn rsa_pkcs1v15_sign_with_handle(
        &self,
        slot_id: u64,
        handle: u64,
        private_key_der: &[u8],
        data: &[u8],
        hash_alg: Option<HashAlg>,
    ) -> HsmResult<Vec<u8>> {
        super::sign::rsa_pkcs1v15_sign_cached(slot_id, handle, private_key_der, data, hash_alg)
    }

    fn rsa_pkcs1v15_verify(
        &self,
        modulus: &[u8],
        public_exponent: &[u8],
        data: &[u8],
        signature: &[u8],
        hash_alg: Option<HashAlg>,
    ) -> HsmResult<bool> {
        super::sign::rsa_pkcs1v15_verify(modulus, public_exponent, data, signature, hash_alg)
    }

    fn rsa_pkcs1v15_verify_with_handle(
        &self,
        slot_id: u64,
        handle: u64,
        modulus: &[u8],
        public_exponent: &[u8],
        data: &[u8],
        signature: &[u8],
        hash_alg: Option<HashAlg>,
    ) -> HsmResult<bool> {
        super::sign::rsa_pkcs1v15_verify_cached(
            slot_id,
            handle,
            modulus,
            public_exponent,
            data,
            signature,
            hash_alg,
        )
    }

    fn rsa_pss_sign(
        &self,
        private_key_der: &[u8],
        data: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<Vec<u8>> {
        super::sign::rsa_pss_sign(private_key_der, data, hash_alg)
    }

    fn rsa_pss_sign_with_handle(
        &self,
        slot_id: u64,
        handle: u64,
        private_key_der: &[u8],
        data: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<Vec<u8>> {
        super::sign::rsa_pss_sign_cached(slot_id, handle, private_key_der, data, hash_alg)
    }

    fn rsa_pss_verify(
        &self,
        modulus: &[u8],
        public_exponent: &[u8],
        data: &[u8],
        signature: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<bool> {
        super::sign::rsa_pss_verify(modulus, public_exponent, data, signature, hash_alg)
    }

    fn rsa_pss_verify_with_handle(
        &self,
        slot_id: u64,
        handle: u64,
        modulus: &[u8],
        public_exponent: &[u8],
        data: &[u8],
        signature: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<bool> {
        super::sign::rsa_pss_verify_cached(
            slot_id,
            handle,
            modulus,
            public_exponent,
            data,
            signature,
            hash_alg,
        )
    }

    fn ecdsa_p256_sign(&self, private_key_bytes: &[u8], data: &[u8]) -> HsmResult<Vec<u8>> {
        super::sign::ecdsa_p256_sign(private_key_bytes, data)
    }

    fn ecdsa_p256_verify(
        &self,
        public_key_sec1: &[u8],
        data: &[u8],
        signature_der: &[u8],
    ) -> HsmResult<bool> {
        super::sign::ecdsa_p256_verify(public_key_sec1, data, signature_der)
    }

    fn ecdsa_p384_sign(&self, private_key_bytes: &[u8], data: &[u8]) -> HsmResult<Vec<u8>> {
        super::sign::ecdsa_p384_sign(private_key_bytes, data)
    }

    fn ecdsa_p384_verify(
        &self,
        public_key_sec1: &[u8],
        data: &[u8],
        signature_der: &[u8],
    ) -> HsmResult<bool> {
        super::sign::ecdsa_p384_verify(public_key_sec1, data, signature_der)
    }

    fn ed25519_sign(&self, private_key_bytes: &[u8], data: &[u8]) -> HsmResult<Vec<u8>> {
        super::sign::ed25519_sign(private_key_bytes, data)
    }

    fn ed25519_verify(
        &self,
        public_key_bytes: &[u8],
        data: &[u8],
        signature_bytes: &[u8],
    ) -> HsmResult<bool> {
        super::sign::ed25519_verify(public_key_bytes, data, signature_bytes)
    }

    // ========================================================================
    // Prehashed signing
    // ========================================================================

    fn rsa_pkcs1v15_sign_prehashed(
        &self,
        private_key_der: &[u8],
        digest: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<Vec<u8>> {
        super::sign::rsa_pkcs1v15_sign_prehashed(private_key_der, digest, hash_alg)
    }

    fn rsa_pkcs1v15_sign_prehashed_with_handle(
        &self,
        slot_id: u64,
        handle: u64,
        private_key_der: &[u8],
        digest: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<Vec<u8>> {
        super::sign::rsa_pkcs1v15_sign_prehashed_cached(
            slot_id,
            handle,
            private_key_der,
            digest,
            hash_alg,
        )
    }

    fn rsa_pkcs1v15_verify_prehashed(
        &self,
        modulus: &[u8],
        public_exponent: &[u8],
        digest: &[u8],
        signature: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<bool> {
        super::sign::rsa_pkcs1v15_verify_prehashed(
            modulus,
            public_exponent,
            digest,
            signature,
            hash_alg,
        )
    }

    fn rsa_pkcs1v15_verify_prehashed_with_handle(
        &self,
        slot_id: u64,
        handle: u64,
        modulus: &[u8],
        public_exponent: &[u8],
        digest: &[u8],
        signature: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<bool> {
        super::sign::rsa_pkcs1v15_verify_prehashed_cached(
            slot_id,
            handle,
            modulus,
            public_exponent,
            digest,
            signature,
            hash_alg,
        )
    }

    fn rsa_pss_sign_prehashed(
        &self,
        private_key_der: &[u8],
        digest: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<Vec<u8>> {
        super::sign::rsa_pss_sign_prehashed(private_key_der, digest, hash_alg)
    }

    fn rsa_pss_sign_prehashed_with_handle(
        &self,
        slot_id: u64,
        handle: u64,
        private_key_der: &[u8],
        digest: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<Vec<u8>> {
        super::sign::rsa_pss_sign_prehashed_cached(
            slot_id,
            handle,
            private_key_der,
            digest,
            hash_alg,
        )
    }

    fn rsa_pss_verify_prehashed(
        &self,
        modulus: &[u8],
        public_exponent: &[u8],
        digest: &[u8],
        signature: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<bool> {
        super::sign::rsa_pss_verify_prehashed(modulus, public_exponent, digest, signature, hash_alg)
    }

    fn rsa_pss_verify_prehashed_with_handle(
        &self,
        slot_id: u64,
        handle: u64,
        modulus: &[u8],
        public_exponent: &[u8],
        digest: &[u8],
        signature: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<bool> {
        super::sign::rsa_pss_verify_prehashed_cached(
            slot_id,
            handle,
            modulus,
            public_exponent,
            digest,
            signature,
            hash_alg,
        )
    }

    fn ecdsa_p256_sign_prehashed(
        &self,
        private_key_bytes: &[u8],
        digest: &[u8],
    ) -> HsmResult<Vec<u8>> {
        super::sign::ecdsa_p256_sign_prehashed(private_key_bytes, digest)
    }

    fn ecdsa_p256_verify_prehashed(
        &self,
        public_key_sec1: &[u8],
        digest: &[u8],
        signature_der: &[u8],
    ) -> HsmResult<bool> {
        super::sign::ecdsa_p256_verify_prehashed(public_key_sec1, digest, signature_der)
    }

    fn ecdsa_p384_sign_prehashed(
        &self,
        private_key_bytes: &[u8],
        digest: &[u8],
    ) -> HsmResult<Vec<u8>> {
        super::sign::ecdsa_p384_sign_prehashed(private_key_bytes, digest)
    }

    fn ecdsa_p384_verify_prehashed(
        &self,
        public_key_sec1: &[u8],
        digest: &[u8],
        signature_der: &[u8],
    ) -> HsmResult<bool> {
        super::sign::ecdsa_p384_verify_prehashed(public_key_sec1, digest, signature_der)
    }

    // ========================================================================
    // Encryption
    // ========================================================================

    fn aes_256_gcm_encrypt(&self, key: &[u8], plaintext: &[u8]) -> HsmResult<Vec<u8>> {
        super::encrypt::aes_256_gcm_encrypt(key, plaintext)
    }

    fn aes_256_gcm_decrypt(&self, key: &[u8], data: &[u8]) -> HsmResult<Vec<u8>> {
        super::encrypt::aes_256_gcm_decrypt(key, data)
    }

    fn aes_cbc_encrypt(&self, key: &[u8], iv: &[u8], plaintext: &[u8]) -> HsmResult<Vec<u8>> {
        super::encrypt::aes_cbc_encrypt(key, iv, plaintext)
    }

    fn aes_cbc_decrypt(&self, key: &[u8], iv: &[u8], ciphertext: &[u8]) -> HsmResult<Vec<u8>> {
        super::encrypt::aes_cbc_decrypt(key, iv, ciphertext)
    }

    fn aes_ctr_encrypt(&self, key: &[u8], iv: &[u8], plaintext: &[u8]) -> HsmResult<Vec<u8>> {
        super::encrypt::aes_ctr_encrypt(key, iv, plaintext)
    }

    fn aes_ctr_decrypt(&self, key: &[u8], iv: &[u8], ciphertext: &[u8]) -> HsmResult<Vec<u8>> {
        super::encrypt::aes_ctr_decrypt(key, iv, ciphertext)
    }

    fn rsa_oaep_encrypt(
        &self,
        modulus: &[u8],
        public_exponent: &[u8],
        plaintext: &[u8],
        hash_alg: super::sign::OaepHash,
    ) -> HsmResult<Vec<u8>> {
        super::sign::rsa_oaep_encrypt(modulus, public_exponent, plaintext, hash_alg)
    }

    fn rsa_oaep_encrypt_with_handle(
        &self,
        slot_id: u64,
        handle: u64,
        modulus: &[u8],
        public_exponent: &[u8],
        plaintext: &[u8],
        hash_alg: super::sign::OaepHash,
    ) -> HsmResult<Vec<u8>> {
        super::sign::rsa_oaep_encrypt_cached(
            slot_id,
            handle,
            modulus,
            public_exponent,
            plaintext,
            hash_alg,
        )
    }

    fn rsa_oaep_decrypt(
        &self,
        private_key_der: &[u8],
        ciphertext: &[u8],
        hash_alg: super::sign::OaepHash,
    ) -> HsmResult<Vec<u8>> {
        super::sign::rsa_oaep_decrypt(private_key_der, ciphertext, hash_alg)
    }

    fn rsa_oaep_decrypt_with_handle(
        &self,
        slot_id: u64,
        handle: u64,
        private_key_der: &[u8],
        ciphertext: &[u8],
        hash_alg: super::sign::OaepHash,
    ) -> HsmResult<Vec<u8>> {
        super::sign::rsa_oaep_decrypt_cached(slot_id, handle, private_key_der, ciphertext, hash_alg)
    }

    // ========================================================================
    // Key generation
    // ========================================================================

    fn generate_aes_key(&self, key_len_bytes: usize, fips_mode: bool) -> HsmResult<RawKeyMaterial> {
        super::keygen::generate_aes_key(key_len_bytes, fips_mode)
    }

    fn generate_rsa_key_pair(
        &self,
        modulus_bits: u32,
        fips_mode: bool,
    ) -> HsmResult<(RawKeyMaterial, Vec<u8>, Vec<u8>)> {
        super::keygen::generate_rsa_key_pair(modulus_bits, fips_mode)
    }

    fn generate_ec_p256_key_pair(&self) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
        super::keygen::generate_ec_p256_key_pair()
    }

    fn generate_ec_p384_key_pair(&self) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
        super::keygen::generate_ec_p384_key_pair()
    }

    fn generate_ed25519_key_pair(&self) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
        super::keygen::generate_ed25519_key_pair()
    }

    // ========================================================================
    // Digest
    // ========================================================================

    fn compute_digest(&self, mechanism: CK_MECHANISM_TYPE, data: &[u8]) -> HsmResult<Vec<u8>> {
        super::digest::compute_digest(mechanism, data)
    }

    fn digest_output_len(&self, mechanism: CK_MECHANISM_TYPE) -> HsmResult<usize> {
        super::digest::digest_output_len(mechanism)
    }

    fn create_hasher(&self, mechanism: CK_MECHANISM_TYPE) -> HsmResult<Box<dyn DigestAccumulator>> {
        super::digest::create_hasher(mechanism)
    }

    // ========================================================================
    // Key wrap/unwrap
    // ========================================================================

    fn aes_key_wrap(
        &self,
        wrapping_key: &[u8],
        key_to_wrap: &[u8],
        fips_mode: bool,
    ) -> HsmResult<Vec<u8>> {
        super::wrap::aes_key_wrap(wrapping_key, key_to_wrap, fips_mode)
    }

    fn aes_key_unwrap(
        &self,
        wrapping_key: &[u8],
        wrapped_key: &[u8],
        fips_mode: bool,
    ) -> HsmResult<Vec<u8>> {
        super::wrap::aes_key_unwrap(wrapping_key, wrapped_key, fips_mode)
    }

    // ========================================================================
    // Key derivation
    // ========================================================================

    fn ecdh_p256(
        &self,
        private_key_bytes: &[u8],
        peer_public_key_sec1: &[u8],
        okm_len: Option<usize>,
    ) -> HsmResult<RawKeyMaterial> {
        super::derive::ecdh_p256(private_key_bytes, peer_public_key_sec1, okm_len)
    }

    fn ecdh_p384(
        &self,
        private_key_bytes: &[u8],
        peer_public_key_sec1: &[u8],
        okm_len: Option<usize>,
    ) -> HsmResult<RawKeyMaterial> {
        super::derive::ecdh_p384(private_key_bytes, peer_public_key_sec1, okm_len)
    }
}
