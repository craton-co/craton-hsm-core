// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Crypto backend trait — abstracts all crypto operations behind a trait interface.
//! This enables swapping in FIPS-validated backends (e.g., aws-lc-rs) without modifying
//! the PKCS#11 ABI layer.
//!
//! Both classical and post-quantum operations are included. PQC methods have default
//! implementations that delegate to the reference `pqc.rs` free functions, so backends
//! that don't provide native PQC can inherit them without extra code.

use super::digest::DigestAccumulator;
use super::pqc::{HybridKemVariant, MlDsaVariant, MlKemVariant, SlhDsaVariant};
use super::sign::{HashAlg, SIG_STACK_BUF_SIZE};
use crate::error::{HsmError, HsmResult};
use crate::pkcs11_abi::types::CK_MECHANISM_TYPE;
use crate::store::key_material::RawKeyMaterial;

/// Combined crypto backend trait. Implementors provide all crypto operations.
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
    // Stack-buffer signing (perf — avoids `Vec<u8>` allocation on the hot path)
    // ========================================================================
    //
    // These mirror the `*_sign` methods above but write the signature into a
    // caller-owned fixed-size buffer instead of returning a heap-allocated
    // `Vec<u8>`. The default impls just delegate to the `Vec`-returning
    // variants and copy the bytes in, so backends that do not override get
    // correct behaviour with no perf gain. Backends that wrap a primitive
    // capable of writing into a slice (RustCrypto, aws-lc-rs) override these
    // to skip the intermediate `Vec` allocation.

    /// ECDSA P-256 sign into a caller-supplied stack buffer. Returns the
    /// number of bytes written. See `crypto::sign::ecdsa_p256_sign_into_buf`.
    fn ecdsa_p256_sign_into_buf(
        &self,
        private_key_bytes: &[u8],
        data: &[u8],
        out: &mut [u8; SIG_STACK_BUF_SIZE],
    ) -> HsmResult<usize> {
        let sig = self.ecdsa_p256_sign(private_key_bytes, data)?;
        if sig.len() > out.len() {
            return Err(HsmError::DataLenRange);
        }
        out[..sig.len()].copy_from_slice(&sig);
        Ok(sig.len())
    }

    /// ECDSA P-384 sign into a caller-supplied stack buffer. Returns the
    /// number of bytes written. See `crypto::sign::ecdsa_p384_sign_into_buf`.
    fn ecdsa_p384_sign_into_buf(
        &self,
        private_key_bytes: &[u8],
        data: &[u8],
        out: &mut [u8; SIG_STACK_BUF_SIZE],
    ) -> HsmResult<usize> {
        let sig = self.ecdsa_p384_sign(private_key_bytes, data)?;
        if sig.len() > out.len() {
            return Err(HsmError::DataLenRange);
        }
        out[..sig.len()].copy_from_slice(&sig);
        Ok(sig.len())
    }

    /// Ed25519 sign into a caller-supplied stack buffer. Returns the
    /// number of bytes written. See `crypto::sign::ed25519_sign_into_buf`.
    fn ed25519_sign_into_buf(
        &self,
        private_key_bytes: &[u8],
        data: &[u8],
        out: &mut [u8; SIG_STACK_BUF_SIZE],
    ) -> HsmResult<usize> {
        let sig = self.ed25519_sign(private_key_bytes, data)?;
        if sig.len() > out.len() {
            return Err(HsmError::DataLenRange);
        }
        out[..sig.len()].copy_from_slice(&sig);
        Ok(sig.len())
    }

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

    // ========================================================================
    // Post-Quantum: ML-KEM (FIPS 203) — Key Encapsulation
    // ========================================================================

    /// Generate an ML-KEM keypair. Returns (dk_seed_64bytes, ek_bytes).
    fn ml_kem_keygen(&self, variant: MlKemVariant) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
        super::pqc::ml_kem_keygen(variant)
    }

    /// ML-KEM encapsulate: given ek bytes, produce (ciphertext, shared_secret).
    fn ml_kem_encapsulate(
        &self,
        ek_bytes: &[u8],
        variant: MlKemVariant,
    ) -> HsmResult<(Vec<u8>, Vec<u8>)> {
        super::pqc::ml_kem_encapsulate(ek_bytes, variant)
    }

    /// ML-KEM decapsulate: given dk seed + ciphertext, recover shared_secret.
    fn ml_kem_decapsulate(
        &self,
        dk_seed: &[u8],
        ciphertext: &[u8],
        variant: MlKemVariant,
    ) -> HsmResult<Vec<u8>> {
        super::pqc::ml_kem_decapsulate(dk_seed, ciphertext, variant)
    }

    // ========================================================================
    // Post-Quantum: ML-DSA (FIPS 204) — Digital Signatures
    // ========================================================================

    /// Generate an ML-DSA keypair. Returns (signing_key_seed_32bytes, verifying_key_bytes).
    fn ml_dsa_keygen(&self, variant: MlDsaVariant) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
        super::pqc::ml_dsa_keygen(variant)
    }

    /// ML-DSA sign a message.
    fn ml_dsa_sign(
        &self,
        signing_key_seed: &[u8],
        data: &[u8],
        variant: MlDsaVariant,
    ) -> HsmResult<Vec<u8>> {
        super::pqc::ml_dsa_sign(signing_key_seed, data, variant)
    }

    /// ML-DSA verify a signature.
    fn ml_dsa_verify(
        &self,
        verifying_key_bytes: &[u8],
        data: &[u8],
        signature: &[u8],
        variant: MlDsaVariant,
    ) -> HsmResult<bool> {
        super::pqc::ml_dsa_verify(verifying_key_bytes, data, signature, variant)
    }

    // ========================================================================
    // Post-Quantum: SLH-DSA (FIPS 205) — Hash-Based Signatures
    // ========================================================================

    /// Generate an SLH-DSA keypair. Returns (signing_key_bytes, verifying_key_bytes).
    fn slh_dsa_keygen(&self, variant: SlhDsaVariant) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
        super::pqc::slh_dsa_keygen(variant)
    }

    /// SLH-DSA sign a message.
    fn slh_dsa_sign(
        &self,
        signing_key_bytes: &[u8],
        data: &[u8],
        variant: SlhDsaVariant,
    ) -> HsmResult<Vec<u8>> {
        super::pqc::slh_dsa_sign(signing_key_bytes, data, variant)
    }

    /// SLH-DSA verify a signature.
    fn slh_dsa_verify(
        &self,
        verifying_key_bytes: &[u8],
        data: &[u8],
        signature: &[u8],
        variant: SlhDsaVariant,
    ) -> HsmResult<bool> {
        super::pqc::slh_dsa_verify(verifying_key_bytes, data, signature, variant)
    }

    // ========================================================================
    // Post-Quantum: Hybrid Classical + PQC
    // ========================================================================

    /// Hybrid ML-DSA-65 + ECDSA-P256 signing.
    fn hybrid_sign(
        &self,
        ml_dsa_sk_seed: &[u8],
        ecdsa_sk_bytes: &[u8],
        data: &[u8],
    ) -> HsmResult<Vec<u8>> {
        super::pqc::hybrid_sign(ml_dsa_sk_seed, ecdsa_sk_bytes, data)
    }

    /// Hybrid ML-DSA-65 + ECDSA-P256 verification.
    fn hybrid_verify(
        &self,
        ml_dsa_vk_bytes: &[u8],
        ecdsa_pk_sec1: &[u8],
        data: &[u8],
        combined_signature: &[u8],
    ) -> HsmResult<bool> {
        super::pqc::hybrid_verify(ml_dsa_vk_bytes, ecdsa_pk_sec1, data, combined_signature)
    }

    // ========================================================================
    // Post-Quantum: Hybrid X25519 + ML-KEM Key Exchange
    // ========================================================================

    /// Generate a hybrid X25519 + ML-KEM keypair.
    fn hybrid_kem_keygen(&self, variant: HybridKemVariant) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
        super::pqc::hybrid_kem_keygen(variant)
    }

    /// Hybrid X25519 + ML-KEM encapsulate.
    fn hybrid_kem_encapsulate(
        &self,
        composite_ek: &[u8],
        variant: HybridKemVariant,
    ) -> HsmResult<(Vec<u8>, Vec<u8>)> {
        super::pqc::hybrid_kem_encapsulate(composite_ek, variant)
    }

    /// Hybrid X25519 + ML-KEM decapsulate.
    fn hybrid_kem_decapsulate(
        &self,
        composite_dk: &[u8],
        composite_ct: &[u8],
        variant: HybridKemVariant,
    ) -> HsmResult<Vec<u8>> {
        super::pqc::hybrid_kem_decapsulate(composite_dk, composite_ct, variant)
    }
}

#[cfg(test)]
mod tests {
    //! Trait-level coverage for the stack-buffer signing methods.
    //!
    //! These tests confirm that the `*_into_buf` overrides on
    //! `RustCryptoBackend` produce the same byte count as the corresponding
    //! `Vec<u8>`-returning trait methods. Exact equality of the bytes is not
    //! checked because ECDSA hedged signing is randomized — only the length
    //! is deterministic for Ed25519 (always 64 bytes) and bounded for ECDSA.

    use super::*;
    use crate::crypto::rustcrypto_backend::RustCryptoBackend;

    fn message() -> &'static [u8] {
        b"craton-hsm trait _into_buf round-trip"
    }

    #[test]
    fn ecdsa_p256_sign_into_buf_matches_vec_len() {
        let backend = RustCryptoBackend;
        let (priv_key, _pub_key) = backend
            .generate_ec_p256_key_pair()
            .expect("generate p256 keypair");

        let vec_sig = backend
            .ecdsa_p256_sign(priv_key.as_bytes(), message())
            .expect("ecdsa_p256_sign");

        let mut buf = [0u8; SIG_STACK_BUF_SIZE];
        let n = backend
            .ecdsa_p256_sign_into_buf(priv_key.as_bytes(), message(), &mut buf)
            .expect("ecdsa_p256_sign_into_buf");

        // ECDSA DER signatures vary by 1-2 bytes per call because of
        // leading-zero stripping in the integer encoding. Both lengths
        // must land in the same valid DER-P256 range (~70-72 bytes) and
        // fit inside SIG_STACK_BUF_SIZE.
        assert!(
            (70..=72).contains(&vec_sig.len()),
            "vec sig len {} not in DER-P256 range",
            vec_sig.len()
        );
        assert!(
            (70..=72).contains(&n),
            "stack sig len {} not in DER-P256 range",
            n
        );
        assert!(n <= SIG_STACK_BUF_SIZE);

        // Verify the stack-buffer signature round-trips.
        let pub_sec1 = _pub_key;
        let ok = backend
            .ecdsa_p256_verify(&pub_sec1, message(), &buf[..n])
            .expect("ecdsa_p256_verify");
        assert!(ok, "stack-buffer signature must verify");
    }

    #[test]
    fn ecdsa_p384_sign_into_buf_matches_vec_len() {
        let backend = RustCryptoBackend;
        let (priv_key, pub_sec1) = backend
            .generate_ec_p384_key_pair()
            .expect("generate p384 keypair");

        let vec_sig = backend
            .ecdsa_p384_sign(priv_key.as_bytes(), message())
            .expect("ecdsa_p384_sign");

        let mut buf = [0u8; SIG_STACK_BUF_SIZE];
        let n = backend
            .ecdsa_p384_sign_into_buf(priv_key.as_bytes(), message(), &mut buf)
            .expect("ecdsa_p384_sign_into_buf");

        // P-384 DER signatures fall in the ~100-104 byte range due to the
        // same leading-zero-stripping variability as P-256.
        assert!(
            (100..=104).contains(&vec_sig.len()),
            "vec sig len {} not in DER-P384 range",
            vec_sig.len()
        );
        assert!(
            (100..=104).contains(&n),
            "stack sig len {} not in DER-P384 range",
            n
        );
        assert!(n <= SIG_STACK_BUF_SIZE);

        let ok = backend
            .ecdsa_p384_verify(&pub_sec1, message(), &buf[..n])
            .expect("ecdsa_p384_verify");
        assert!(ok, "stack-buffer signature must verify");
    }

    #[test]
    fn ed25519_sign_into_buf_matches_vec() {
        let backend = RustCryptoBackend;
        let (priv_key, pub_key) = backend
            .generate_ed25519_key_pair()
            .expect("generate ed25519 keypair");

        let vec_sig = backend
            .ed25519_sign(priv_key.as_bytes(), message())
            .expect("ed25519_sign");

        let mut buf = [0u8; SIG_STACK_BUF_SIZE];
        let n = backend
            .ed25519_sign_into_buf(priv_key.as_bytes(), message(), &mut buf)
            .expect("ed25519_sign_into_buf");

        // Ed25519 signing is fully deterministic (RFC 8032), so byte-for-byte
        // equality holds and the length is always 64.
        assert_eq!(n, vec_sig.len());
        assert_eq!(n, 64);
        assert_eq!(&buf[..n], vec_sig.as_slice());

        let ok = backend
            .ed25519_verify(&pub_key, message(), &buf[..n])
            .expect("ed25519_verify");
        assert!(ok, "stack-buffer signature must verify");
    }
}
