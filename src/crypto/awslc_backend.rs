// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! aws-lc-rs CryptoBackend implementation — FIPS-validated AWS-LC library.
//!
//! Compiled only when the `awslc-backend` feature is enabled.
//! This is the inline variant of the `craton_hsm-awslc` enterprise crate,
//! used for benchmarking and single-binary deployments.

use aws_lc_rs::{
    aead::{self, Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM},
    agreement, cipher, digest,
    key_wrap::{self, KeyEncryptionKey, KeyWrap},
    rand as awslc_rand, rsa as awslc_rsa,
    signature::{self, EcdsaKeyPair, Ed25519KeyPair, KeyPair},
};

use crate::crypto::backend::CryptoBackend;
use crate::crypto::digest::DigestAccumulator;
use crate::crypto::sign::{HashAlg, OaepHash};
use crate::error::{HsmError, HsmResult};
use crate::pkcs11_abi::constants::*;
use crate::pkcs11_abi::types::CK_MECHANISM_TYPE;
use crate::store::key_material::RawKeyMaterial;

/// FIPS-validated crypto backend using aws-lc-rs.
pub struct AwsLcBackend;

impl CryptoBackend for AwsLcBackend {
    // ========================================================================
    // Signing
    // ========================================================================

    fn rsa_pkcs1v15_sign(
        &self,
        private_key_der: &[u8],
        data: &[u8],
        hash_alg: Option<HashAlg>,
    ) -> HsmResult<Vec<u8>> {
        let key_pair = awslc_rsa::KeyPair::from_pkcs8(private_key_der)
            .map_err(|_| HsmError::KeyHandleInvalid)?;
        let rng = awslc_rand::SystemRandom::new();

        let alg: &dyn signature::RsaEncoding = match hash_alg {
            Some(HashAlg::Sha256) => &signature::RSA_PKCS1_SHA256,
            Some(HashAlg::Sha384) => &signature::RSA_PKCS1_SHA384,
            Some(HashAlg::Sha512) => &signature::RSA_PKCS1_SHA512,
            None => return Err(HsmError::MechanismInvalid),
        };

        let mut sig = vec![0u8; key_pair.public_modulus_len()];
        key_pair
            .sign(alg, &rng, data, &mut sig)
            .map_err(|_| HsmError::GeneralError)?;
        Ok(sig)
    }

    fn rsa_pkcs1v15_verify(
        &self,
        modulus: &[u8],
        public_exponent: &[u8],
        data: &[u8],
        signature_bytes: &[u8],
        hash_alg: Option<HashAlg>,
    ) -> HsmResult<bool> {
        let params: &signature::RsaParameters = match hash_alg {
            Some(HashAlg::Sha256) => &signature::RSA_PKCS1_2048_8192_SHA256,
            Some(HashAlg::Sha384) => &signature::RSA_PKCS1_2048_8192_SHA384,
            Some(HashAlg::Sha512) => &signature::RSA_PKCS1_2048_8192_SHA512,
            None => return Err(HsmError::MechanismInvalid),
        };

        let components = awslc_rsa::PublicKeyComponents {
            n: modulus,
            e: public_exponent,
        };
        Ok(components.verify(params, data, signature_bytes).is_ok())
    }

    fn rsa_pss_sign(
        &self,
        private_key_der: &[u8],
        data: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<Vec<u8>> {
        let key_pair = awslc_rsa::KeyPair::from_pkcs8(private_key_der)
            .map_err(|_| HsmError::KeyHandleInvalid)?;
        let rng = awslc_rand::SystemRandom::new();

        let alg: &dyn signature::RsaEncoding = match hash_alg {
            HashAlg::Sha256 => &signature::RSA_PSS_SHA256,
            HashAlg::Sha384 => &signature::RSA_PSS_SHA384,
            HashAlg::Sha512 => &signature::RSA_PSS_SHA512,
        };

        let mut sig = vec![0u8; key_pair.public_modulus_len()];
        key_pair
            .sign(alg, &rng, data, &mut sig)
            .map_err(|_| HsmError::GeneralError)?;
        Ok(sig)
    }

    fn rsa_pss_verify(
        &self,
        modulus: &[u8],
        public_exponent: &[u8],
        data: &[u8],
        signature_bytes: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<bool> {
        let params: &signature::RsaParameters = match hash_alg {
            HashAlg::Sha256 => &signature::RSA_PSS_2048_8192_SHA256,
            HashAlg::Sha384 => &signature::RSA_PSS_2048_8192_SHA384,
            HashAlg::Sha512 => &signature::RSA_PSS_2048_8192_SHA512,
        };

        let components = awslc_rsa::PublicKeyComponents {
            n: modulus,
            e: public_exponent,
        };
        Ok(components.verify(params, data, signature_bytes).is_ok())
    }

    fn ecdsa_p256_sign(&self, private_key_bytes: &[u8], data: &[u8]) -> HsmResult<Vec<u8>> {
        let pub_key = derive_ec_public_key(private_key_bytes, &agreement::ECDH_P256)?;
        let key_pair = EcdsaKeyPair::from_private_key_and_public_key(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            private_key_bytes,
            &pub_key,
        )
        .map_err(|_| HsmError::KeyHandleInvalid)?;

        let rng = awslc_rand::SystemRandom::new();
        let sig = key_pair
            .sign(&rng, data)
            .map_err(|_| HsmError::GeneralError)?;
        Ok(sig.as_ref().to_vec())
    }

    fn ecdsa_p256_verify(
        &self,
        public_key_sec1: &[u8],
        data: &[u8],
        signature_der: &[u8],
    ) -> HsmResult<bool> {
        let pub_key =
            signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, public_key_sec1);
        Ok(pub_key.verify(data, signature_der).is_ok())
    }

    fn ecdsa_p384_sign(&self, private_key_bytes: &[u8], data: &[u8]) -> HsmResult<Vec<u8>> {
        let pub_key = derive_ec_public_key(private_key_bytes, &agreement::ECDH_P384)?;
        let key_pair = EcdsaKeyPair::from_private_key_and_public_key(
            &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
            private_key_bytes,
            &pub_key,
        )
        .map_err(|_| HsmError::KeyHandleInvalid)?;

        let rng = awslc_rand::SystemRandom::new();
        let sig = key_pair
            .sign(&rng, data)
            .map_err(|_| HsmError::GeneralError)?;
        Ok(sig.as_ref().to_vec())
    }

    fn ecdsa_p384_verify(
        &self,
        public_key_sec1: &[u8],
        data: &[u8],
        signature_der: &[u8],
    ) -> HsmResult<bool> {
        let pub_key =
            signature::UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_ASN1, public_key_sec1);
        Ok(pub_key.verify(data, signature_der).is_ok())
    }

    fn ed25519_sign(&self, private_key_bytes: &[u8], data: &[u8]) -> HsmResult<Vec<u8>> {
        if private_key_bytes.len() != 32 {
            return Err(HsmError::KeyHandleInvalid);
        }
        let key_pair = Ed25519KeyPair::from_seed_unchecked(private_key_bytes)
            .map_err(|_| HsmError::KeyHandleInvalid)?;
        let sig = key_pair.sign(data);
        Ok(sig.as_ref().to_vec())
    }

    fn ed25519_verify(
        &self,
        public_key_bytes: &[u8],
        data: &[u8],
        signature_bytes: &[u8],
    ) -> HsmResult<bool> {
        if public_key_bytes.len() != 32 {
            return Err(HsmError::KeyHandleInvalid);
        }
        if signature_bytes.len() != 64 {
            return Err(HsmError::SignatureInvalid);
        }
        let pub_key = signature::UnparsedPublicKey::new(&signature::ED25519, public_key_bytes);
        Ok(pub_key.verify(data, signature_bytes).is_ok())
    }

    // ========================================================================
    // Prehashed signing — aws-lc-rs lacks prehashed APIs, use RustCrypto
    // ========================================================================
    //
    // IMPORTANT: The following prehashed sign/verify methods delegate to
    // RustCrypto rather than aws-lc-rs because aws-lc-rs does not expose
    // prehashed signing APIs. This means multi-part (C_SignUpdate/C_SignFinal)
    // operations use RustCrypto even when the awslc backend is selected.
    //
    // Implications for FIPS mode:
    //   - Single-part operations (C_Sign with full data) use aws-lc-rs and
    //     are covered by the FIPS validation.
    //   - Multi-part operations use RustCrypto for the final sign/verify step.
    //     RustCrypto is NOT FIPS-validated — these operations should be
    //     considered non-FIPS even when the awslc backend is active.
    //   - FIPS-strict deployments should prefer single-part operations or
    //     document this limitation in their security policy.

    fn rsa_pkcs1v15_sign_prehashed(
        &self,
        private_key_der: &[u8],
        digest: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<Vec<u8>> {
        use rsa::pkcs8::DecodePrivateKey;
        use rsa::{Pkcs1v15Sign, RsaPrivateKey};

        let private_key = RsaPrivateKey::from_pkcs8_der(private_key_der)
            .map_err(|_| HsmError::KeyHandleInvalid)?;
        let scheme = match hash_alg {
            HashAlg::Sha256 => Pkcs1v15Sign::new::<sha2::Sha256>(),
            HashAlg::Sha384 => Pkcs1v15Sign::new::<sha2::Sha384>(),
            HashAlg::Sha512 => Pkcs1v15Sign::new::<sha2::Sha512>(),
        };
        private_key
            .sign(scheme, digest)
            .map_err(|_| HsmError::GeneralError)
    }

    fn rsa_pkcs1v15_verify_prehashed(
        &self,
        modulus: &[u8],
        public_exponent: &[u8],
        digest: &[u8],
        signature_bytes: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<bool> {
        use rsa::{BigUint, Pkcs1v15Sign, RsaPublicKey};

        let n = BigUint::from_bytes_be(modulus);
        let e = BigUint::from_bytes_be(public_exponent);
        let public_key = RsaPublicKey::new(n, e).map_err(|_| HsmError::KeyHandleInvalid)?;
        let scheme = match hash_alg {
            HashAlg::Sha256 => Pkcs1v15Sign::new::<sha2::Sha256>(),
            HashAlg::Sha384 => Pkcs1v15Sign::new::<sha2::Sha384>(),
            HashAlg::Sha512 => Pkcs1v15Sign::new::<sha2::Sha512>(),
        };
        Ok(public_key.verify(scheme, digest, signature_bytes).is_ok())
    }

    fn rsa_pss_sign_prehashed(
        &self,
        private_key_der: &[u8],
        digest: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<Vec<u8>> {
        use rand::rngs::OsRng;
        use rsa::pkcs8::DecodePrivateKey;
        use rsa::pss::SigningKey;
        use rsa::signature::hazmat::RandomizedPrehashSigner;
        use rsa::signature::SignatureEncoding;
        use rsa::RsaPrivateKey;

        let private_key = RsaPrivateKey::from_pkcs8_der(private_key_der)
            .map_err(|_| HsmError::KeyHandleInvalid)?;
        match hash_alg {
            HashAlg::Sha256 => {
                let signing_key = SigningKey::<sha2::Sha256>::new(private_key);
                let sig = signing_key
                    .sign_prehash_with_rng(&mut OsRng, digest)
                    .map_err(|_| HsmError::GeneralError)?;
                Ok(sig.to_vec())
            }
            HashAlg::Sha384 => {
                let signing_key = SigningKey::<sha2::Sha384>::new(private_key);
                let sig = signing_key
                    .sign_prehash_with_rng(&mut OsRng, digest)
                    .map_err(|_| HsmError::GeneralError)?;
                Ok(sig.to_vec())
            }
            HashAlg::Sha512 => {
                let signing_key = SigningKey::<sha2::Sha512>::new(private_key);
                let sig = signing_key
                    .sign_prehash_with_rng(&mut OsRng, digest)
                    .map_err(|_| HsmError::GeneralError)?;
                Ok(sig.to_vec())
            }
        }
    }

    fn rsa_pss_verify_prehashed(
        &self,
        modulus: &[u8],
        public_exponent: &[u8],
        digest: &[u8],
        signature_bytes: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<bool> {
        use rsa::pss::VerifyingKey;
        use rsa::signature::hazmat::PrehashVerifier;
        use rsa::{BigUint, RsaPublicKey};

        let n = BigUint::from_bytes_be(modulus);
        let e = BigUint::from_bytes_be(public_exponent);
        let public_key = RsaPublicKey::new(n, e).map_err(|_| HsmError::KeyHandleInvalid)?;
        let sig = rsa::pss::Signature::try_from(signature_bytes)
            .map_err(|_| HsmError::SignatureInvalid)?;

        match hash_alg {
            HashAlg::Sha256 => {
                let vk = VerifyingKey::<sha2::Sha256>::new(public_key);
                Ok(vk.verify_prehash(digest, &sig).is_ok())
            }
            HashAlg::Sha384 => {
                let vk = VerifyingKey::<sha2::Sha384>::new(public_key);
                Ok(vk.verify_prehash(digest, &sig).is_ok())
            }
            HashAlg::Sha512 => {
                let vk = VerifyingKey::<sha2::Sha512>::new(public_key);
                Ok(vk.verify_prehash(digest, &sig).is_ok())
            }
        }
    }

    fn ecdsa_p256_sign_prehashed(
        &self,
        private_key_bytes: &[u8],
        digest: &[u8],
    ) -> HsmResult<Vec<u8>> {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        use p256::ecdsa::SigningKey;

        let signing_key =
            SigningKey::from_slice(private_key_bytes).map_err(|_| HsmError::KeyHandleInvalid)?;
        let signature: p256::ecdsa::Signature = signing_key
            .sign_prehash(digest)
            .map_err(|_| HsmError::GeneralError)?;
        Ok(signature.to_der().to_bytes().to_vec())
    }

    fn ecdsa_p256_verify_prehashed(
        &self,
        public_key_sec1: &[u8],
        digest: &[u8],
        signature_der: &[u8],
    ) -> HsmResult<bool> {
        use p256::ecdsa::signature::hazmat::PrehashVerifier;
        use p256::ecdsa::VerifyingKey;

        let verifying_key = VerifyingKey::from_sec1_bytes(public_key_sec1)
            .map_err(|_| HsmError::KeyHandleInvalid)?;
        let signature = p256::ecdsa::Signature::from_der(signature_der)
            .map_err(|_| HsmError::SignatureInvalid)?;
        Ok(verifying_key.verify_prehash(digest, &signature).is_ok())
    }

    fn ecdsa_p384_sign_prehashed(
        &self,
        private_key_bytes: &[u8],
        digest: &[u8],
    ) -> HsmResult<Vec<u8>> {
        use p384::ecdsa::signature::hazmat::PrehashSigner;
        use p384::ecdsa::SigningKey;

        let signing_key =
            SigningKey::from_slice(private_key_bytes).map_err(|_| HsmError::KeyHandleInvalid)?;
        let signature: p384::ecdsa::Signature = signing_key
            .sign_prehash(digest)
            .map_err(|_| HsmError::GeneralError)?;
        Ok(signature.to_der().to_bytes().to_vec())
    }

    fn ecdsa_p384_verify_prehashed(
        &self,
        public_key_sec1: &[u8],
        digest: &[u8],
        signature_der: &[u8],
    ) -> HsmResult<bool> {
        use p384::ecdsa::signature::hazmat::PrehashVerifier;
        use p384::ecdsa::VerifyingKey;

        let verifying_key = VerifyingKey::from_sec1_bytes(public_key_sec1)
            .map_err(|_| HsmError::KeyHandleInvalid)?;
        let signature = p384::ecdsa::Signature::from_der(signature_der)
            .map_err(|_| HsmError::SignatureInvalid)?;
        Ok(verifying_key.verify_prehash(digest, &signature).is_ok())
    }

    // ========================================================================
    // Encryption
    // ========================================================================

    fn aes_256_gcm_encrypt(&self, key: &[u8], plaintext: &[u8]) -> HsmResult<Vec<u8>> {
        if key.len() != 32 {
            return Err(HsmError::KeySizeRange);
        }

        let unbound = UnboundKey::new(&AES_256_GCM, key).map_err(|_| HsmError::KeySizeRange)?;
        let sealing_key = LessSafeKey::new(unbound);

        let mut nonce_bytes = [0u8; 12];
        awslc_rand::fill(&mut nonce_bytes).map_err(|_| HsmError::GeneralError)?;
        let nonce =
            Nonce::try_assume_unique_for_key(&nonce_bytes).map_err(|_| HsmError::GeneralError)?;

        let mut in_out = plaintext.to_vec();
        sealing_key
            .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| HsmError::GeneralError)?;

        let mut result = Vec::with_capacity(12 + in_out.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&in_out);
        Ok(result)
    }

    fn aes_256_gcm_decrypt(&self, key: &[u8], data: &[u8]) -> HsmResult<Vec<u8>> {
        if key.len() != 32 {
            return Err(HsmError::KeySizeRange);
        }
        if data.len() < 12 {
            return Err(HsmError::EncryptedDataInvalid);
        }

        let unbound = UnboundKey::new(&AES_256_GCM, key).map_err(|_| HsmError::KeySizeRange)?;
        let opening_key = LessSafeKey::new(unbound);

        let nonce =
            Nonce::try_assume_unique_for_key(&data[..12]).map_err(|_| HsmError::GeneralError)?;
        let mut in_out = data[12..].to_vec();

        let plaintext = opening_key
            .open_in_place(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| HsmError::EncryptedDataInvalid)?;
        Ok(plaintext.to_vec())
    }

    fn aes_cbc_encrypt(&self, key: &[u8], iv: &[u8], plaintext: &[u8]) -> HsmResult<Vec<u8>> {
        if iv.len() != 16 {
            return Err(HsmError::MechanismParamInvalid);
        }

        let cipher_alg = match key.len() {
            16 => &cipher::AES_128,
            24 => &cipher::AES_192,
            32 => &cipher::AES_256,
            _ => return Err(HsmError::KeySizeRange),
        };

        let unbound =
            cipher::UnboundCipherKey::new(cipher_alg, key).map_err(|_| HsmError::KeySizeRange)?;
        let enc_key = cipher::PaddedBlockEncryptingKey::cbc_pkcs7(unbound)
            .map_err(|_| HsmError::GeneralError)?;

        let iv_array: [u8; 16] = iv.try_into().map_err(|_| HsmError::MechanismParamInvalid)?;
        let context = cipher::EncryptionContext::Iv128(aws_lc_rs::iv::FixedLength::from(&iv_array));

        let mut data = plaintext.to_vec();
        enc_key
            .less_safe_encrypt(&mut data, context)
            .map_err(|_| HsmError::GeneralError)?;
        Ok(data)
    }

    fn aes_cbc_decrypt(&self, key: &[u8], iv: &[u8], ciphertext: &[u8]) -> HsmResult<Vec<u8>> {
        if iv.len() != 16 {
            return Err(HsmError::MechanismParamInvalid);
        }

        let cipher_alg = match key.len() {
            16 => &cipher::AES_128,
            24 => &cipher::AES_192,
            32 => &cipher::AES_256,
            _ => return Err(HsmError::KeySizeRange),
        };

        let unbound =
            cipher::UnboundCipherKey::new(cipher_alg, key).map_err(|_| HsmError::KeySizeRange)?;
        let dec_key = cipher::PaddedBlockDecryptingKey::cbc_pkcs7(unbound)
            .map_err(|_| HsmError::GeneralError)?;

        let iv_array: [u8; 16] = iv.try_into().map_err(|_| HsmError::MechanismParamInvalid)?;
        let context = cipher::DecryptionContext::Iv128(aws_lc_rs::iv::FixedLength::from(&iv_array));

        let mut data = ciphertext.to_vec();
        let plaintext = dec_key
            .decrypt(&mut data, context)
            .map_err(|_| HsmError::EncryptedDataInvalid)?;
        Ok(plaintext.to_vec())
    }

    fn aes_ctr_encrypt(&self, key: &[u8], iv: &[u8], plaintext: &[u8]) -> HsmResult<Vec<u8>> {
        aes_ctr_crypt_inner(key, iv, plaintext)
    }

    fn aes_ctr_decrypt(&self, key: &[u8], iv: &[u8], ciphertext: &[u8]) -> HsmResult<Vec<u8>> {
        aes_ctr_crypt_inner(key, iv, ciphertext)
    }

    fn rsa_oaep_encrypt(
        &self,
        modulus: &[u8],
        public_exponent: &[u8],
        plaintext: &[u8],
        hash_alg: OaepHash,
    ) -> HsmResult<Vec<u8>> {
        let oaep_alg = oaep_hash_to_algorithm(&hash_alg);
        let components = awslc_rsa::PublicKeyComponents {
            n: modulus,
            e: public_exponent,
        };
        let pub_enc_key: awslc_rsa::PublicEncryptingKey = components
            .try_into()
            .map_err(|_| HsmError::KeyHandleInvalid)?;
        let oaep_key = awslc_rsa::OaepPublicEncryptingKey::new(pub_enc_key)
            .map_err(|_| HsmError::GeneralError)?;

        let mut ciphertext = vec![0u8; oaep_key.ciphertext_size()];
        let result = oaep_key
            .encrypt(oaep_alg, plaintext, &mut ciphertext, None)
            .map_err(|_| HsmError::GeneralError)?;
        Ok(result.to_vec())
    }

    fn rsa_oaep_decrypt(
        &self,
        private_key_der: &[u8],
        ciphertext: &[u8],
        hash_alg: OaepHash,
    ) -> HsmResult<Vec<u8>> {
        let oaep_alg = oaep_hash_to_algorithm(&hash_alg);
        let priv_key = awslc_rsa::PrivateDecryptingKey::from_pkcs8(private_key_der)
            .map_err(|_| HsmError::KeyHandleInvalid)?;
        let oaep_key = awslc_rsa::OaepPrivateDecryptingKey::new(priv_key)
            .map_err(|_| HsmError::GeneralError)?;

        let mut plaintext = vec![0u8; ciphertext.len()];
        let result = oaep_key
            .decrypt(oaep_alg, ciphertext, &mut plaintext, None)
            .map_err(|_| HsmError::EncryptedDataInvalid)?;
        Ok(result.to_vec())
    }

    // ========================================================================
    // Key generation
    // ========================================================================

    fn generate_aes_key(
        &self,
        key_len_bytes: usize,
        _fips_mode: bool,
    ) -> HsmResult<RawKeyMaterial> {
        match key_len_bytes {
            16 | 24 | 32 => {}
            _ => return Err(HsmError::KeySizeRange),
        }

        let mut key = vec![0u8; key_len_bytes];
        awslc_rand::fill(&mut key).map_err(|_| HsmError::GeneralError)?;
        Ok(RawKeyMaterial::new(key))
    }

    fn generate_rsa_key_pair(
        &self,
        modulus_bits: u32,
        _fips_mode: bool,
    ) -> HsmResult<(RawKeyMaterial, Vec<u8>, Vec<u8>)> {
        let key_size = match modulus_bits {
            2048 => awslc_rsa::KeySize::Rsa2048,
            3072 => awslc_rsa::KeySize::Rsa3072,
            4096 => awslc_rsa::KeySize::Rsa4096,
            _ => return Err(HsmError::KeySizeRange),
        };

        let key_pair =
            awslc_rsa::KeyPair::generate(key_size).map_err(|_| HsmError::GeneralError)?;

        use aws_lc_rs::encoding::AsDer;
        let pkcs8_der = key_pair.as_der().map_err(|_| HsmError::GeneralError)?;
        let der_bytes = pkcs8_der.as_ref().to_vec();

        let pub_key_der = key_pair.public_key().as_ref();
        let (modulus, exponent) = parse_rsa_spki(pub_key_der)?;

        Ok((RawKeyMaterial::new(der_bytes), modulus, exponent))
    }

    fn generate_ec_p256_key_pair(&self) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
        let private_key = agreement::PrivateKey::generate(&agreement::ECDH_P256)
            .map_err(|_| HsmError::GeneralError)?;
        let public_key = private_key
            .compute_public_key()
            .map_err(|_| HsmError::GeneralError)?;

        use aws_lc_rs::encoding::AsBigEndian;
        use aws_lc_rs::encoding::EcPrivateKeyBin;
        let priv_bytes: EcPrivateKeyBin = private_key
            .as_be_bytes()
            .map_err(|_| HsmError::GeneralError)?;

        Ok((
            RawKeyMaterial::new(priv_bytes.as_ref().to_vec()),
            public_key.as_ref().to_vec(),
        ))
    }

    fn generate_ec_p384_key_pair(&self) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
        let private_key = agreement::PrivateKey::generate(&agreement::ECDH_P384)
            .map_err(|_| HsmError::GeneralError)?;
        let public_key = private_key
            .compute_public_key()
            .map_err(|_| HsmError::GeneralError)?;

        use aws_lc_rs::encoding::AsBigEndian;
        use aws_lc_rs::encoding::EcPrivateKeyBin;
        let priv_bytes: EcPrivateKeyBin = private_key
            .as_be_bytes()
            .map_err(|_| HsmError::GeneralError)?;

        Ok((
            RawKeyMaterial::new(priv_bytes.as_ref().to_vec()),
            public_key.as_ref().to_vec(),
        ))
    }

    fn generate_ed25519_key_pair(&self) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
        let mut seed = [0u8; 32];
        awslc_rand::fill(&mut seed).map_err(|_| HsmError::GeneralError)?;
        let key_pair =
            Ed25519KeyPair::from_seed_unchecked(&seed).map_err(|_| HsmError::GeneralError)?;
        let pub_bytes = key_pair.public_key().as_ref().to_vec();

        Ok((RawKeyMaterial::new(seed.to_vec()), pub_bytes))
    }

    // ========================================================================
    // Digest
    // ========================================================================

    fn compute_digest(&self, mechanism: CK_MECHANISM_TYPE, data: &[u8]) -> HsmResult<Vec<u8>> {
        let alg = mechanism_to_digest_alg(mechanism)?;
        Ok(digest::digest(alg, data).as_ref().to_vec())
    }

    fn digest_output_len(&self, mechanism: CK_MECHANISM_TYPE) -> HsmResult<usize> {
        let alg = mechanism_to_digest_alg(mechanism)?;
        Ok(alg.output_len())
    }

    fn create_hasher(&self, mechanism: CK_MECHANISM_TYPE) -> HsmResult<Box<dyn DigestAccumulator>> {
        let alg = mechanism_to_digest_alg(mechanism)?;
        Ok(Box::new(AwsLcHasher {
            context: digest::Context::new(alg),
            output_len: alg.output_len(),
        }))
    }

    // ========================================================================
    // Key wrap/unwrap
    // ========================================================================

    fn aes_key_wrap(
        &self,
        wrapping_key: &[u8],
        key_to_wrap: &[u8],
        _fips_mode: bool,
    ) -> HsmResult<Vec<u8>> {
        if key_to_wrap.len() % 8 != 0 || key_to_wrap.len() < 16 {
            return Err(HsmError::DataLenRange);
        }

        let kw_alg = match wrapping_key.len() {
            16 => &key_wrap::AES_128,
            32 => &key_wrap::AES_256,
            _ => return Err(HsmError::KeySizeRange),
        };

        let kek =
            KeyEncryptionKey::new(kw_alg, wrapping_key).map_err(|_| HsmError::KeySizeRange)?;

        let mut output = vec![0u8; key_to_wrap.len() + 8];
        let result = kek
            .wrap(key_to_wrap, &mut output)
            .map_err(|_| HsmError::GeneralError)?;
        Ok(result.to_vec())
    }

    fn aes_key_unwrap(
        &self,
        wrapping_key: &[u8],
        wrapped_key: &[u8],
        _fips_mode: bool,
    ) -> HsmResult<Vec<u8>> {
        if wrapped_key.len() % 8 != 0 || wrapped_key.len() < 24 {
            return Err(HsmError::DataLenRange);
        }

        let kw_alg = match wrapping_key.len() {
            16 => &key_wrap::AES_128,
            32 => &key_wrap::AES_256,
            _ => return Err(HsmError::KeySizeRange),
        };

        let kek =
            KeyEncryptionKey::new(kw_alg, wrapping_key).map_err(|_| HsmError::KeySizeRange)?;

        let mut output = vec![0u8; wrapped_key.len() - 8];
        let result = kek
            .unwrap(wrapped_key, &mut output)
            .map_err(|_| HsmError::EncryptedDataInvalid)?;
        Ok(result.to_vec())
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
        let my_private =
            agreement::PrivateKey::from_private_key(&agreement::ECDH_P256, private_key_bytes)
                .map_err(|_| HsmError::KeyHandleInvalid)?;

        let peer_public =
            agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, peer_public_key_sec1);

        agreement::agree(&my_private, peer_public, HsmError::GeneralError, |shared| {
            let mut key_bytes = shared.to_vec();
            if let Some(len) = okm_len {
                if len > key_bytes.len() {
                    return Err(HsmError::KeySizeRange);
                }
                key_bytes.truncate(len);
            }
            Ok(RawKeyMaterial::new(key_bytes))
        })
    }

    fn ecdh_p384(
        &self,
        private_key_bytes: &[u8],
        peer_public_key_sec1: &[u8],
        okm_len: Option<usize>,
    ) -> HsmResult<RawKeyMaterial> {
        let my_private =
            agreement::PrivateKey::from_private_key(&agreement::ECDH_P384, private_key_bytes)
                .map_err(|_| HsmError::KeyHandleInvalid)?;

        let peer_public =
            agreement::UnparsedPublicKey::new(&agreement::ECDH_P384, peer_public_key_sec1);

        agreement::agree(&my_private, peer_public, HsmError::GeneralError, |shared| {
            let mut key_bytes = shared.to_vec();
            if let Some(len) = okm_len {
                if len > key_bytes.len() {
                    return Err(HsmError::KeySizeRange);
                }
                key_bytes.truncate(len);
            }
            Ok(RawKeyMaterial::new(key_bytes))
        })
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn oaep_hash_to_algorithm(hash_alg: &OaepHash) -> &'static awslc_rsa::OaepAlgorithm {
    match hash_alg {
        OaepHash::Sha256 => &awslc_rsa::OAEP_SHA256_MGF1SHA256,
        OaepHash::Sha384 => &awslc_rsa::OAEP_SHA384_MGF1SHA384,
        OaepHash::Sha512 => &awslc_rsa::OAEP_SHA512_MGF1SHA512,
    }
}

fn aes_ctr_crypt_inner(key: &[u8], iv: &[u8], data: &[u8]) -> HsmResult<Vec<u8>> {
    if iv.len() != 16 {
        return Err(HsmError::MechanismParamInvalid);
    }

    let cipher_alg = match key.len() {
        16 => &cipher::AES_128,
        24 => &cipher::AES_192,
        32 => &cipher::AES_256,
        _ => return Err(HsmError::KeySizeRange),
    };

    let unbound =
        cipher::UnboundCipherKey::new(cipher_alg, key).map_err(|_| HsmError::KeySizeRange)?;
    let enc_key = cipher::EncryptingKey::ctr(unbound).map_err(|_| HsmError::GeneralError)?;

    let iv_array: [u8; 16] = iv.try_into().map_err(|_| HsmError::MechanismParamInvalid)?;
    let context = cipher::EncryptionContext::Iv128(aws_lc_rs::iv::FixedLength::from(&iv_array));

    let mut output = data.to_vec();
    enc_key
        .less_safe_encrypt(&mut output, context)
        .map_err(|_| HsmError::GeneralError)?;
    Ok(output)
}

fn derive_ec_public_key(
    private_key_bytes: &[u8],
    alg: &'static agreement::Algorithm,
) -> HsmResult<Vec<u8>> {
    let private_key = agreement::PrivateKey::from_private_key(alg, private_key_bytes)
        .map_err(|_| HsmError::KeyHandleInvalid)?;
    let public_key = private_key
        .compute_public_key()
        .map_err(|_| HsmError::GeneralError)?;
    Ok(public_key.as_ref().to_vec())
}

fn mechanism_to_digest_alg(mechanism: CK_MECHANISM_TYPE) -> HsmResult<&'static digest::Algorithm> {
    match mechanism {
        CKM_SHA_1 => Ok(&digest::SHA1_FOR_LEGACY_USE_ONLY),
        CKM_SHA256 => Ok(&digest::SHA256),
        CKM_SHA384 => Ok(&digest::SHA384),
        CKM_SHA512 => Ok(&digest::SHA512),
        CKM_SHA3_256 => Ok(&digest::SHA3_256),
        CKM_SHA3_384 => Ok(&digest::SHA3_384),
        CKM_SHA3_512 => Ok(&digest::SHA3_512),
        _ => Err(HsmError::MechanismInvalid),
    }
}

fn parse_rsa_spki(der: &[u8]) -> HsmResult<(Vec<u8>, Vec<u8>)> {
    let mut r = DerReader::new(der);
    r.enter_sequence()?;
    let tag = r.read_tag()?;

    if tag == 0x02 {
        let modulus_len = r.read_length()?;
        let modulus = r.read_bytes(modulus_len)?;
        let modulus = if !modulus.is_empty() && modulus[0] == 0x00 {
            &modulus[1..]
        } else {
            modulus
        };
        let exponent = r.read_integer()?;
        Ok((modulus.to_vec(), exponent.to_vec()))
    } else if tag == 0x30 {
        let alg_len = r.read_length()?;
        r.skip(alg_len);
        let bit_tag = r.read_tag()?;
        if bit_tag != 0x03 {
            return Err(HsmError::GeneralError);
        }
        let _bit_len = r.read_length()?;
        r.skip(1);
        r.enter_sequence()?;
        let modulus = r.read_integer()?;
        let exponent = r.read_integer()?;
        Ok((modulus.to_vec(), exponent.to_vec()))
    } else {
        Err(HsmError::GeneralError)
    }
}

struct DerReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> DerReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn read_tag(&mut self) -> HsmResult<u8> {
        if self.pos >= self.data.len() {
            return Err(HsmError::GeneralError);
        }
        let tag = self.data[self.pos];
        self.pos += 1;
        Ok(tag)
    }

    fn read_length(&mut self) -> HsmResult<usize> {
        if self.pos >= self.data.len() {
            return Err(HsmError::GeneralError);
        }
        let first = self.data[self.pos] as usize;
        self.pos += 1;
        if first < 0x80 {
            Ok(first)
        } else {
            let num_bytes = first & 0x7F;
            if num_bytes > 4 || self.pos + num_bytes > self.data.len() {
                return Err(HsmError::GeneralError);
            }
            let mut len = 0usize;
            for _ in 0..num_bytes {
                len = (len << 8) | (self.data[self.pos] as usize);
                self.pos += 1;
            }
            Ok(len)
        }
    }

    fn enter_sequence(&mut self) -> HsmResult<usize> {
        let tag = self.read_tag()?;
        if tag != 0x30 {
            return Err(HsmError::GeneralError);
        }
        self.read_length()
    }

    fn read_integer(&mut self) -> HsmResult<&'a [u8]> {
        let tag = self.read_tag()?;
        if tag != 0x02 {
            return Err(HsmError::GeneralError);
        }
        let len = self.read_length()?;
        if self.pos + len > self.data.len() {
            return Err(HsmError::GeneralError);
        }
        let mut bytes = &self.data[self.pos..self.pos + len];
        self.pos += len;
        if bytes.len() > 1 && bytes[0] == 0x00 {
            bytes = &bytes[1..];
        }
        Ok(bytes)
    }

    fn read_bytes(&mut self, len: usize) -> HsmResult<&'a [u8]> {
        if self.pos + len > self.data.len() {
            return Err(HsmError::GeneralError);
        }
        let bytes = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(bytes)
    }

    fn skip(&mut self, len: usize) {
        self.pos += len;
    }
}

struct AwsLcHasher {
    context: digest::Context,
    output_len: usize,
}

// SAFETY: digest::Context is Send+Sync in aws-lc-rs
unsafe impl Send for AwsLcHasher {}
unsafe impl Sync for AwsLcHasher {}

impl DigestAccumulator for AwsLcHasher {
    fn update(&mut self, data: &[u8]) {
        self.context.update(data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        self.context.finish().as_ref().to_vec()
    }

    fn output_len(&self) -> usize {
        self.output_len
    }
}
