// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//
// # Stack-allocated signature buffers (perf)
//
// ECDSA P-256 / P-384 and Ed25519 produce signatures that fit in a small
// fixed-size buffer (≤144 bytes — see `SIG_STACK_BUF_SIZE`). The
// `*_sign_into_buf` variants below write directly into a caller-owned
// `[u8; SIG_STACK_BUF_SIZE]` and return the byte length, avoiding the
// `Vec<u8>` allocation done by `*_sign`. They are wired end-to-end via
// `CryptoBackend::{ecdsa_p256,ecdsa_p384,ed25519}_sign_into_buf`, so
// dispatcher code can request a stack signature through the trait surface
// rather than reaching into the free functions directly.
//
// RSA signatures (256–512 bytes) come out of the `rsa` crate as
// heap-allocated `Vec<u8>` and intentionally bypass this path. ML-DSA /
// SLH-DSA and hybrid PQC signatures (multi-KB) are far too large for a
// stack buffer and also stay on the heap.

use rsa::pkcs8::DecodePrivateKey;
use rsa::{Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
#[allow(unused_imports)]
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::error::{HsmError, HsmResult};
use crate::pkcs11_abi::constants::*;
use crate::pkcs11_abi::types::CK_MECHANISM_TYPE;

// ============================================================================
// RSA Key Caches
// ============================================================================
//
// Parsing PKCS#8 DER → RsaPrivateKey is expensive (bignum reconstruction).
// Since the same key is reused across many sign operations, we maintain two
// caches:
//
// 1. **DER-hash cache** (`RSA_KEY_CACHE`) — the legacy/slow path keyed by
//    SHA-256(DER).  Used by callers that don't have an object handle.
//
// 2. **Handle-based caches** (`RSA_PRIV_CACHE`, `RSA_PUB_CACHE`) — the fast
//    path keyed by `CK_OBJECT_HANDLE` (u64).  O(1) lookup with no hashing,
//    returns `Arc` (no clone of the inner key), and supports both private and
//    public RSA keys.
//
// When either cache is full (64 entries), a single arbitrary entry is evicted
// instead of clearing the entire map, avoiding thundering-herd repopulation.

use std::sync::{Arc, LazyLock};
use zeroize::Zeroize;

/// Maximum number of entries per cache.
const RSA_KEY_CACHE_MAX: usize = 64;

// ---------------------------------------------------------------------------
// Handle-based Arc caches (fast path)
// ---------------------------------------------------------------------------

/// Handle-based RSA private key cache.
///
/// Keyed by (slot_id, handle) to prevent cross-slot cache collisions.
/// The Arc avoids cloning RSA BigNums on cache hits but note that
/// SigningKey construction still requires a clone due to the rsa crate's
/// ownership API.
static RSA_PRIV_CACHE: LazyLock<dashmap::DashMap<(u64, u64), Arc<RsaPrivateKey>>> =
    LazyLock::new(|| dashmap::DashMap::with_capacity(RSA_KEY_CACHE_MAX));

/// Handle-based RSA public key cache.
///
/// Keyed by (slot_id, handle) to prevent cross-slot cache collisions.
/// The Arc avoids cloning RSA BigNums on cache hits but note that
/// SigningKey construction still requires a clone due to the rsa crate's
/// ownership API.
static RSA_PUB_CACHE: LazyLock<dashmap::DashMap<(u64, u64), Arc<RsaPublicKey>>> =
    LazyLock::new(|| dashmap::DashMap::with_capacity(RSA_KEY_CACHE_MAX));

/// Evict one arbitrary entry from a `DashMap` when it is at capacity.
/// This avoids clearing the entire cache (thundering herd) while keeping
/// the implementation simple (no LRU metadata overhead).
fn evict_one_if_full<K: std::hash::Hash + Eq + Clone, V>(map: &dashmap::DashMap<K, V>) {
    if map.len() >= RSA_KEY_CACHE_MAX {
        if let Some(entry) = map.iter().next() {
            let key = entry.key().clone();
            drop(entry); // release the read guard before removing
            map.remove(&key);
        }
    }
}

/// Cache an already-parsed RSA private key by (slot_id, handle).
pub fn cache_rsa_private_key(slot_id: u64, handle: u64, key: Arc<RsaPrivateKey>) {
    evict_one_if_full(&RSA_PRIV_CACHE);
    RSA_PRIV_CACHE.insert((slot_id, handle), key);
}

/// Get a cached RSA private key by (slot_id, handle). Returns `None` on miss.
pub fn get_cached_rsa_private_key(slot_id: u64, handle: u64) -> Option<Arc<RsaPrivateKey>> {
    RSA_PRIV_CACHE
        .get(&(slot_id, handle))
        .map(|entry| Arc::clone(entry.value()))
}

/// Cache an already-parsed RSA public key by (slot_id, handle).
pub fn cache_rsa_public_key(slot_id: u64, handle: u64, key: Arc<RsaPublicKey>) {
    evict_one_if_full(&RSA_PUB_CACHE);
    RSA_PUB_CACHE.insert((slot_id, handle), key);
}

/// Get a cached RSA public key by (slot_id, handle). Returns `None` on miss.
pub fn get_cached_rsa_public_key(slot_id: u64, handle: u64) -> Option<Arc<RsaPublicKey>> {
    RSA_PUB_CACHE
        .get(&(slot_id, handle))
        .map(|entry| Arc::clone(entry.value()))
}

/// Evict all cached keys for a given (slot_id, handle) pair (call on C_DestroyObject).
pub fn evict_cached_keys(slot_id: u64, handle: u64) {
    RSA_PRIV_CACHE.remove(&(slot_id, handle));
    RSA_PUB_CACHE.remove(&(slot_id, handle));
}

// ---------------------------------------------------------------------------
// DER-hash cache (legacy / slow path)
// ---------------------------------------------------------------------------

/// Wrapper around `RsaPrivateKey` that zeroizes the PKCS#8 DER encoding on drop.
///
/// The `rsa` crate's `RsaPrivateKey` does not implement `Zeroize` (its bignums
/// are heap-allocated via `num-bigint`). We work around this by re-exporting
/// the key to PKCS#8 DER, zeroizing those bytes, and overwriting the struct's
/// in-memory fields with a minimal dummy key. This ensures sensitive key material
/// does not linger in freed heap memory.
struct ZeroizingRsaKey {
    key: RsaPrivateKey,
}

impl ZeroizingRsaKey {
    fn new(key: RsaPrivateKey) -> Self {
        Self { key }
    }
}

impl Drop for ZeroizingRsaKey {
    fn drop(&mut self) {
        // Best-effort zeroization: export to DER and zeroize those bytes.
        // This clears the most accessible copy of the key material.
        use rsa::pkcs8::EncodePrivateKey;
        if let Ok(der) = self.key.to_pkcs8_der() {
            let mut der_bytes = der.as_bytes().to_vec();
            der_bytes.zeroize();
        }
        // Overwrite the in-memory struct fields by assigning a minimal dummy key.
        // This forces the allocator to drop (and eventually reuse) the original
        // bignum heap allocations, limiting the window of exposure.
        use rsa::BigUint;
        if let Ok(dummy) = RsaPrivateKey::from_components(
            BigUint::from(3u32),       // n (minimal)
            BigUint::from(3u32),       // e
            BigUint::from(1u32),       // d
            vec![BigUint::from(3u32)], // primes
        ) {
            self.key = dummy;
        }
    }
}

/// Cache of parsed RSA private keys, keyed by SHA-256(DER).
/// Uses DashMap for lock-free concurrent access. Values are wrapped in
/// `ZeroizingRsaKey` to best-effort zeroize key material on eviction.
///
/// **Slow path** — prefer the handle-based `RSA_PRIV_CACHE` when an object
/// handle is available.
static RSA_KEY_CACHE: LazyLock<dashmap::DashMap<[u8; 32], ZeroizingRsaKey>> =
    LazyLock::new(|| dashmap::DashMap::with_capacity(RSA_KEY_CACHE_MAX));

/// Parse an RSA private key from PKCS#8 DER, using the DER-hash cache.
///
/// **Slow path** — computes SHA-256(DER) on every call and clones the key on
/// cache hit.  Prefer the `*_cached` function variants when a
/// `CK_OBJECT_HANDLE` is available.
fn parse_rsa_private_key(der: &[u8]) -> HsmResult<RsaPrivateKey> {
    let cache_key: [u8; 32] = Sha256::digest(der).into();

    // Fast path: cache hit (still clones — use handle cache to avoid this)
    if let Some(entry) = RSA_KEY_CACHE.get(&cache_key) {
        return Ok(entry.value().key.clone());
    }

    // Slow path: parse and cache
    let private_key = RsaPrivateKey::from_pkcs8_der(der).map_err(|_| HsmError::KeyHandleInvalid)?;

    // Evict one arbitrary entry instead of clearing the whole cache.
    evict_one_if_full_zeroizing(&RSA_KEY_CACHE);

    RSA_KEY_CACHE.insert(cache_key, ZeroizingRsaKey::new(private_key.clone()));
    Ok(private_key)
}

/// Single-entry eviction for the ZeroizingRsaKey DER-hash cache.
fn evict_one_if_full_zeroizing(map: &dashmap::DashMap<[u8; 32], ZeroizingRsaKey>) {
    if map.len() >= RSA_KEY_CACHE_MAX {
        if let Some(entry) = map.iter().next() {
            let key = *entry.key();
            drop(entry);
            map.remove(&key);
        }
    }
}

/// Clear all RSA key caches. Called on C_Finalize / C_InitToken.
/// Each evicted private-key entry in the DER-hash cache is zeroized via
/// `ZeroizingRsaKey::drop()`.
pub fn clear_rsa_key_cache() {
    RSA_KEY_CACHE.clear();
    RSA_PRIV_CACHE.clear();
    RSA_PUB_CACHE.clear();
}

/// Minimum RSA modulus size in bits. Keys below this threshold are rejected
/// for all operations (sign, verify, encrypt, decrypt) regardless of how
/// the key was imported. Per NIST SP 800-131A Rev 2, 2048-bit is the floor.
const RSA_MIN_MODULUS_BITS: usize = 2048;

/// Maximum data size for sign/verify operations (64 MiB).
/// Prevents resource exhaustion from hashing arbitrarily large inputs.
/// This is a practical upper bound; legitimate signing payloads are
/// typically much smaller (documents, certificates, etc.).
const SIGN_MAX_DATA_SIZE: usize = 64 * 1024 * 1024; // 64 MiB

/// Validate that the data to be signed/verified does not exceed the DoS limit.
fn validate_data_size(data: &[u8]) -> HsmResult<()> {
    if data.len() > SIGN_MAX_DATA_SIZE {
        tracing::warn!(
            "Sign/verify data size {} exceeds maximum {} bytes — rejecting to prevent DoS",
            data.len(),
            SIGN_MAX_DATA_SIZE
        );
        return Err(HsmError::DataLenRange);
    }
    Ok(())
}

/// Validate that a pre-computed digest has the correct length for the specified hash algorithm.
/// Accepting a mismatched digest length could cause undefined behavior or silent misoperation
/// in the underlying RSA/ECDSA library (e.g., truncation or padding).
fn validate_digest_length(digest: &[u8], hash_alg: HashAlg) -> HsmResult<()> {
    let expected_len = match hash_alg {
        HashAlg::Sha256 => 32,
        HashAlg::Sha384 => 48,
        HashAlg::Sha512 => 64,
    };
    if digest.len() != expected_len {
        tracing::error!(
            "Prehash digest length mismatch: got {} bytes, expected {} for {:?}",
            digest.len(),
            expected_len,
            hash_alg
        );
        return Err(HsmError::DataLenRange);
    }
    Ok(())
}

/// Validate that an RSA private key meets the minimum key size requirement.
fn validate_rsa_private_key_size(private_key: &RsaPrivateKey) -> HsmResult<()> {
    use rsa::traits::PublicKeyParts;
    let modulus_bits = private_key.n().bits();
    if modulus_bits < RSA_MIN_MODULUS_BITS {
        tracing::warn!(
            "Rejecting RSA operation: key size {} bits is below minimum {} bits",
            modulus_bits,
            RSA_MIN_MODULUS_BITS
        );
        return Err(HsmError::KeySizeRange);
    }
    Ok(())
}

/// Validate that RSA public key components meet the minimum key size requirement.
fn validate_rsa_public_key_size(modulus: &[u8]) -> HsmResult<()> {
    // modulus is big-endian bytes; strip leading zero bytes to count significant bits
    let significant = modulus
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(modulus.len());
    let significant_bytes = &modulus[significant..];
    let modulus_bits = if significant_bytes.is_empty() {
        0
    } else {
        // bits = (byte_count - 1) * 8 + significant_bits_in_first_byte
        (significant_bytes.len() - 1) * 8 + (8 - significant_bytes[0].leading_zeros() as usize)
    };
    if modulus_bits < RSA_MIN_MODULUS_BITS {
        tracing::warn!(
            "Rejecting RSA operation: key size {} bits is below minimum {} bits",
            modulus_bits,
            RSA_MIN_MODULUS_BITS
        );
        return Err(HsmError::KeySizeRange);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
pub enum HashAlg {
    Sha256,
    Sha384,
    Sha512,
}

// ============================================================================
// RSA PKCS#1 v1.5
// ============================================================================

/// RSA PKCS#1 v1.5 sign
pub fn rsa_pkcs1v15_sign(
    private_key_der: &[u8],
    data: &[u8],
    hash_alg: Option<HashAlg>,
) -> HsmResult<Vec<u8>> {
    use rsa::signature::SignatureEncoding;

    validate_data_size(data)?;
    let private_key = parse_rsa_private_key(private_key_der)?;
    validate_rsa_private_key_size(&private_key)?;

    match hash_alg {
        Some(HashAlg::Sha256) => {
            use rsa::pkcs1v15::SigningKey;
            use rsa::signature::Signer;
            let signing_key = SigningKey::<Sha256>::new(private_key);
            let signature = signing_key.sign(data);
            Ok(signature.to_vec())
        }
        Some(HashAlg::Sha384) => {
            use rsa::pkcs1v15::SigningKey;
            use rsa::signature::Signer;
            let signing_key = SigningKey::<Sha384>::new(private_key);
            let signature = signing_key.sign(data);
            Ok(signature.to_vec())
        }
        Some(HashAlg::Sha512) => {
            use rsa::pkcs1v15::SigningKey;
            use rsa::signature::Signer;
            let signing_key = SigningKey::<Sha512>::new(private_key);
            let signature = signing_key.sign(data);
            Ok(signature.to_vec())
        }
        None => {
            // Reject unprefixed PKCS#1 v1.5 signing — vulnerable to Bleichenbacher forgery.
            // Callers must specify a hash algorithm for DigestInfo wrapping.
            Err(HsmError::MechanismParamInvalid)
        }
    }
}

/// RSA PKCS#1 v1.5 verify
pub fn rsa_pkcs1v15_verify(
    modulus: &[u8],
    public_exponent: &[u8],
    data: &[u8],
    signature: &[u8],
    hash_alg: Option<HashAlg>,
) -> HsmResult<bool> {
    validate_data_size(data)?;
    validate_rsa_public_key_size(modulus)?;
    let n = rsa::BigUint::from_bytes_be(modulus);
    let e = rsa::BigUint::from_bytes_be(public_exponent);
    let public_key = RsaPublicKey::new(n, e).map_err(|_| HsmError::KeyHandleInvalid)?;

    match hash_alg {
        Some(HashAlg::Sha256) => {
            use rsa::pkcs1v15::VerifyingKey;
            use rsa::signature::Verifier;
            let verifying_key = VerifyingKey::<Sha256>::new(public_key);
            let sig = rsa::pkcs1v15::Signature::try_from(signature)
                .map_err(|_| HsmError::SignatureInvalid)?;
            Ok(verifying_key.verify(data, &sig).is_ok())
        }
        Some(HashAlg::Sha384) => {
            use rsa::pkcs1v15::VerifyingKey;
            use rsa::signature::Verifier;
            let verifying_key = VerifyingKey::<Sha384>::new(public_key);
            let sig = rsa::pkcs1v15::Signature::try_from(signature)
                .map_err(|_| HsmError::SignatureInvalid)?;
            Ok(verifying_key.verify(data, &sig).is_ok())
        }
        Some(HashAlg::Sha512) => {
            use rsa::pkcs1v15::VerifyingKey;
            use rsa::signature::Verifier;
            let verifying_key = VerifyingKey::<Sha512>::new(public_key);
            let sig = rsa::pkcs1v15::Signature::try_from(signature)
                .map_err(|_| HsmError::SignatureInvalid)?;
            Ok(verifying_key.verify(data, &sig).is_ok())
        }
        None => {
            // Reject unprefixed PKCS#1 v1.5 verification — vulnerable to
            // Bleichenbacher signature forgery with low public exponents (e=3).
            // Callers must specify a hash algorithm for DigestInfo validation.
            Err(HsmError::MechanismParamInvalid)
        }
    }
}

// ============================================================================
// RSA-PSS
// ============================================================================

/// RSA-PSS sign
///
/// Uses the SP 800-90A HMAC_DRBG for salt generation (via `DrbgRng`)
/// instead of `OsRng` directly, ensuring all randomness benefits from
/// the DRBG's continuous health testing and prediction resistance.
pub fn rsa_pss_sign(private_key_der: &[u8], data: &[u8], hash_alg: HashAlg) -> HsmResult<Vec<u8>> {
    use crate::crypto::drbg::DrbgRng;
    use rsa::pss::SigningKey;
    use rsa::signature::{RandomizedSigner, SignatureEncoding};

    validate_data_size(data)?;
    let private_key = parse_rsa_private_key(private_key_der)?;
    validate_rsa_private_key_size(&private_key)?;

    let mut rng = DrbgRng::new()?;

    match hash_alg {
        HashAlg::Sha256 => {
            let signing_key = SigningKey::<Sha256>::new(private_key);
            let signature = signing_key.sign_with_rng(&mut rng, data);
            Ok(signature.to_vec())
        }
        HashAlg::Sha384 => {
            let signing_key = SigningKey::<Sha384>::new(private_key);
            let signature = signing_key.sign_with_rng(&mut rng, data);
            Ok(signature.to_vec())
        }
        HashAlg::Sha512 => {
            let signing_key = SigningKey::<Sha512>::new(private_key);
            let signature = signing_key.sign_with_rng(&mut rng, data);
            Ok(signature.to_vec())
        }
    }
}

/// RSA-PSS verify
pub fn rsa_pss_verify(
    modulus: &[u8],
    public_exponent: &[u8],
    data: &[u8],
    signature: &[u8],
    hash_alg: HashAlg,
) -> HsmResult<bool> {
    use rsa::pss::VerifyingKey;
    use rsa::signature::Verifier;

    validate_data_size(data)?;
    validate_rsa_public_key_size(modulus)?;
    let n = rsa::BigUint::from_bytes_be(modulus);
    let e = rsa::BigUint::from_bytes_be(public_exponent);
    let public_key = RsaPublicKey::new(n, e).map_err(|_| HsmError::KeyHandleInvalid)?;

    match hash_alg {
        HashAlg::Sha256 => {
            let verifying_key = VerifyingKey::<Sha256>::new(public_key);
            let sig =
                rsa::pss::Signature::try_from(signature).map_err(|_| HsmError::SignatureInvalid)?;
            Ok(verifying_key.verify(data, &sig).is_ok())
        }
        HashAlg::Sha384 => {
            let verifying_key = VerifyingKey::<Sha384>::new(public_key);
            let sig =
                rsa::pss::Signature::try_from(signature).map_err(|_| HsmError::SignatureInvalid)?;
            Ok(verifying_key.verify(data, &sig).is_ok())
        }
        HashAlg::Sha512 => {
            let verifying_key = VerifyingKey::<Sha512>::new(public_key);
            let sig =
                rsa::pss::Signature::try_from(signature).map_err(|_| HsmError::SignatureInvalid)?;
            Ok(verifying_key.verify(data, &sig).is_ok())
        }
    }
}

// ============================================================================
// RSA-OAEP
// ============================================================================

/// Hash algorithm selection for RSA-OAEP, derived from CK_RSA_PKCS_OAEP_PARAMS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OaepHash {
    Sha256,
    Sha384,
    Sha512,
}

/// RSA-OAEP encrypt (using public key components)
///
/// Uses the SP 800-90A HMAC_DRBG for OAEP padding randomness (via `DrbgRng`)
/// instead of `OsRng` directly, ensuring all randomness benefits from
/// the DRBG's continuous health testing and prediction resistance.
pub fn rsa_oaep_encrypt(
    modulus: &[u8],
    public_exponent: &[u8],
    plaintext: &[u8],
    hash_alg: OaepHash,
) -> HsmResult<Vec<u8>> {
    use crate::crypto::drbg::DrbgRng;
    use rsa::Oaep;

    validate_rsa_public_key_size(modulus)?;
    let n = rsa::BigUint::from_bytes_be(modulus);
    let e = rsa::BigUint::from_bytes_be(public_exponent);
    let public_key = RsaPublicKey::new(n, e).map_err(|_| HsmError::KeyHandleInvalid)?;

    let mut rng = DrbgRng::new()?;

    match hash_alg {
        OaepHash::Sha256 => {
            let padding = Oaep::new::<Sha256>();
            public_key
                .encrypt(&mut rng, padding, plaintext)
                .map_err(|_| HsmError::GeneralError)
        }
        OaepHash::Sha384 => {
            let padding = Oaep::new::<Sha384>();
            public_key
                .encrypt(&mut rng, padding, plaintext)
                .map_err(|_| HsmError::GeneralError)
        }
        OaepHash::Sha512 => {
            let padding = Oaep::new::<Sha512>();
            public_key
                .encrypt(&mut rng, padding, plaintext)
                .map_err(|_| HsmError::GeneralError)
        }
    }
}

/// RSA-OAEP decrypt (using private key DER)
pub fn rsa_oaep_decrypt(
    private_key_der: &[u8],
    ciphertext: &[u8],
    hash_alg: OaepHash,
) -> HsmResult<Vec<u8>> {
    use rsa::Oaep;

    let private_key = parse_rsa_private_key(private_key_der)?;
    validate_rsa_private_key_size(&private_key)?;

    match hash_alg {
        OaepHash::Sha256 => {
            let padding = Oaep::new::<Sha256>();
            private_key
                .decrypt(padding, ciphertext)
                .map_err(|_| HsmError::EncryptedDataInvalid)
        }
        OaepHash::Sha384 => {
            let padding = Oaep::new::<Sha384>();
            private_key
                .decrypt(padding, ciphertext)
                .map_err(|_| HsmError::EncryptedDataInvalid)
        }
        OaepHash::Sha512 => {
            let padding = Oaep::new::<Sha512>();
            private_key
                .decrypt(padding, ciphertext)
                .map_err(|_| HsmError::EncryptedDataInvalid)
        }
    }
}

// ============================================================================
// Handle-cached RSA PKCS#1 v1.5 (fast path)
// ============================================================================

/// RSA PKCS#1 v1.5 sign using handle-based cache (avoids SHA-256(DER) hashing
/// and BigNum cloning on cache hits).
pub fn rsa_pkcs1v15_sign_cached(
    slot_id: u64,
    handle: u64,
    private_key_der: &[u8],
    data: &[u8],
    hash_alg: Option<HashAlg>,
) -> HsmResult<Vec<u8>> {
    use rsa::signature::SignatureEncoding;

    validate_data_size(data)?;
    let key = get_or_parse_private_key(slot_id, handle, private_key_der)?;
    validate_rsa_private_key_size(&key)?;

    match hash_alg {
        Some(HashAlg::Sha256) => {
            use rsa::pkcs1v15::SigningKey;
            use rsa::signature::Signer;
            let signing_key = SigningKey::<Sha256>::new((*key).clone());
            let signature = signing_key.sign(data);
            Ok(signature.to_vec())
        }
        Some(HashAlg::Sha384) => {
            use rsa::pkcs1v15::SigningKey;
            use rsa::signature::Signer;
            let signing_key = SigningKey::<Sha384>::new((*key).clone());
            let signature = signing_key.sign(data);
            Ok(signature.to_vec())
        }
        Some(HashAlg::Sha512) => {
            use rsa::pkcs1v15::SigningKey;
            use rsa::signature::Signer;
            let signing_key = SigningKey::<Sha512>::new((*key).clone());
            let signature = signing_key.sign(data);
            Ok(signature.to_vec())
        }
        None => Err(HsmError::MechanismParamInvalid),
    }
}

/// RSA PKCS#1 v1.5 verify using handle-based cache (avoids BigUint
/// reconstruction on cache hits).
pub fn rsa_pkcs1v15_verify_cached(
    slot_id: u64,
    handle: u64,
    modulus: &[u8],
    public_exponent: &[u8],
    data: &[u8],
    signature: &[u8],
    hash_alg: Option<HashAlg>,
) -> HsmResult<bool> {
    validate_data_size(data)?;
    validate_rsa_public_key_size(modulus)?;
    let key = get_or_build_public_key(slot_id, handle, modulus, public_exponent)?;

    match hash_alg {
        Some(HashAlg::Sha256) => {
            use rsa::pkcs1v15::VerifyingKey;
            use rsa::signature::Verifier;
            let verifying_key = VerifyingKey::<Sha256>::new((*key).clone());
            let sig = rsa::pkcs1v15::Signature::try_from(signature)
                .map_err(|_| HsmError::SignatureInvalid)?;
            Ok(verifying_key.verify(data, &sig).is_ok())
        }
        Some(HashAlg::Sha384) => {
            use rsa::pkcs1v15::VerifyingKey;
            use rsa::signature::Verifier;
            let verifying_key = VerifyingKey::<Sha384>::new((*key).clone());
            let sig = rsa::pkcs1v15::Signature::try_from(signature)
                .map_err(|_| HsmError::SignatureInvalid)?;
            Ok(verifying_key.verify(data, &sig).is_ok())
        }
        Some(HashAlg::Sha512) => {
            use rsa::pkcs1v15::VerifyingKey;
            use rsa::signature::Verifier;
            let verifying_key = VerifyingKey::<Sha512>::new((*key).clone());
            let sig = rsa::pkcs1v15::Signature::try_from(signature)
                .map_err(|_| HsmError::SignatureInvalid)?;
            Ok(verifying_key.verify(data, &sig).is_ok())
        }
        None => Err(HsmError::MechanismParamInvalid),
    }
}

// ============================================================================
// Handle-cached RSA-PSS (fast path)
// ============================================================================

/// RSA-PSS sign using handle-based cache.
pub fn rsa_pss_sign_cached(
    slot_id: u64,
    handle: u64,
    private_key_der: &[u8],
    data: &[u8],
    hash_alg: HashAlg,
) -> HsmResult<Vec<u8>> {
    use crate::crypto::drbg::DrbgRng;
    use rsa::pss::SigningKey;
    use rsa::signature::{RandomizedSigner, SignatureEncoding};

    validate_data_size(data)?;
    let key = get_or_parse_private_key(slot_id, handle, private_key_der)?;
    validate_rsa_private_key_size(&key)?;

    let mut rng = DrbgRng::new()?;

    match hash_alg {
        HashAlg::Sha256 => {
            let signing_key = SigningKey::<Sha256>::new((*key).clone());
            let signature = signing_key.sign_with_rng(&mut rng, data);
            Ok(signature.to_vec())
        }
        HashAlg::Sha384 => {
            let signing_key = SigningKey::<Sha384>::new((*key).clone());
            let signature = signing_key.sign_with_rng(&mut rng, data);
            Ok(signature.to_vec())
        }
        HashAlg::Sha512 => {
            let signing_key = SigningKey::<Sha512>::new((*key).clone());
            let signature = signing_key.sign_with_rng(&mut rng, data);
            Ok(signature.to_vec())
        }
    }
}

/// RSA-PSS verify using handle-based cache.
pub fn rsa_pss_verify_cached(
    slot_id: u64,
    handle: u64,
    modulus: &[u8],
    public_exponent: &[u8],
    data: &[u8],
    signature: &[u8],
    hash_alg: HashAlg,
) -> HsmResult<bool> {
    use rsa::pss::VerifyingKey;
    use rsa::signature::Verifier;

    validate_data_size(data)?;
    validate_rsa_public_key_size(modulus)?;
    let key = get_or_build_public_key(slot_id, handle, modulus, public_exponent)?;

    match hash_alg {
        HashAlg::Sha256 => {
            let verifying_key = VerifyingKey::<Sha256>::new((*key).clone());
            let sig =
                rsa::pss::Signature::try_from(signature).map_err(|_| HsmError::SignatureInvalid)?;
            Ok(verifying_key.verify(data, &sig).is_ok())
        }
        HashAlg::Sha384 => {
            let verifying_key = VerifyingKey::<Sha384>::new((*key).clone());
            let sig =
                rsa::pss::Signature::try_from(signature).map_err(|_| HsmError::SignatureInvalid)?;
            Ok(verifying_key.verify(data, &sig).is_ok())
        }
        HashAlg::Sha512 => {
            let verifying_key = VerifyingKey::<Sha512>::new((*key).clone());
            let sig =
                rsa::pss::Signature::try_from(signature).map_err(|_| HsmError::SignatureInvalid)?;
            Ok(verifying_key.verify(data, &sig).is_ok())
        }
    }
}

// ============================================================================
// Handle-cached RSA-OAEP (fast path)
// ============================================================================

/// RSA-OAEP encrypt using handle-based public key cache.
pub fn rsa_oaep_encrypt_cached(
    slot_id: u64,
    handle: u64,
    modulus: &[u8],
    public_exponent: &[u8],
    plaintext: &[u8],
    hash_alg: OaepHash,
) -> HsmResult<Vec<u8>> {
    use crate::crypto::drbg::DrbgRng;
    use rsa::Oaep;

    validate_rsa_public_key_size(modulus)?;
    let key = get_or_build_public_key(slot_id, handle, modulus, public_exponent)?;

    let mut rng = DrbgRng::new()?;

    match hash_alg {
        OaepHash::Sha256 => {
            let padding = Oaep::new::<Sha256>();
            key.encrypt(&mut rng, padding, plaintext)
                .map_err(|_| HsmError::GeneralError)
        }
        OaepHash::Sha384 => {
            let padding = Oaep::new::<Sha384>();
            key.encrypt(&mut rng, padding, plaintext)
                .map_err(|_| HsmError::GeneralError)
        }
        OaepHash::Sha512 => {
            let padding = Oaep::new::<Sha512>();
            key.encrypt(&mut rng, padding, plaintext)
                .map_err(|_| HsmError::GeneralError)
        }
    }
}

/// RSA-OAEP decrypt using handle-based private key cache.
pub fn rsa_oaep_decrypt_cached(
    slot_id: u64,
    handle: u64,
    private_key_der: &[u8],
    ciphertext: &[u8],
    hash_alg: OaepHash,
) -> HsmResult<Vec<u8>> {
    use rsa::Oaep;

    let key = get_or_parse_private_key(slot_id, handle, private_key_der)?;
    validate_rsa_private_key_size(&key)?;

    match hash_alg {
        OaepHash::Sha256 => {
            let padding = Oaep::new::<Sha256>();
            key.decrypt(padding, ciphertext)
                .map_err(|_| HsmError::EncryptedDataInvalid)
        }
        OaepHash::Sha384 => {
            let padding = Oaep::new::<Sha384>();
            key.decrypt(padding, ciphertext)
                .map_err(|_| HsmError::EncryptedDataInvalid)
        }
        OaepHash::Sha512 => {
            let padding = Oaep::new::<Sha512>();
            key.decrypt(padding, ciphertext)
                .map_err(|_| HsmError::EncryptedDataInvalid)
        }
    }
}

// ============================================================================
// Handle-cached helpers
// ============================================================================

/// Look up a private key in the handle cache, or parse from DER and cache it.
fn get_or_parse_private_key(
    slot_id: u64,
    handle: u64,
    der: &[u8],
) -> HsmResult<Arc<RsaPrivateKey>> {
    if let Some(k) = get_cached_rsa_private_key(slot_id, handle) {
        return Ok(k);
    }
    let k = Arc::new(RsaPrivateKey::from_pkcs8_der(der).map_err(|_| HsmError::KeyHandleInvalid)?);
    cache_rsa_private_key(slot_id, handle, Arc::clone(&k));
    Ok(k)
}

/// Look up a public key in the handle cache, or build from components and cache it.
fn get_or_build_public_key(
    slot_id: u64,
    handle: u64,
    modulus: &[u8],
    public_exponent: &[u8],
) -> HsmResult<Arc<RsaPublicKey>> {
    if let Some(k) = get_cached_rsa_public_key(slot_id, handle) {
        return Ok(k);
    }
    let n = rsa::BigUint::from_bytes_be(modulus);
    let e = rsa::BigUint::from_bytes_be(public_exponent);
    let k = Arc::new(RsaPublicKey::new(n, e).map_err(|_| HsmError::KeyHandleInvalid)?);
    cache_rsa_public_key(slot_id, handle, Arc::clone(&k));
    Ok(k)
}

// ============================================================================
// ECDSA P-256
// ============================================================================

/// ECDSA P-256 sign (hedged — RFC 6979 + DRBG randomness)
///
/// Uses randomized/hedged signing: the deterministic RFC 6979 nonce is mixed
/// with fresh randomness from the DRBG. This protects against fault injection
/// attacks (Rowhammer, voltage glitching) that can recover the private key
/// from a single faulty deterministic signature, while still preventing
/// catastrophic nonce reuse if the RNG fails.
pub fn ecdsa_p256_sign(private_key_bytes: &[u8], data: &[u8]) -> HsmResult<Vec<u8>> {
    use crate::crypto::drbg::DrbgRng;
    use p256::ecdsa::signature::RandomizedSigner;
    use p256::ecdsa::SigningKey;

    validate_data_size(data)?;
    let signing_key =
        SigningKey::from_slice(private_key_bytes).map_err(|_| HsmError::KeyHandleInvalid)?;
    let mut rng = DrbgRng::new()?;
    let signature: p256::ecdsa::Signature = signing_key.sign_with_rng(&mut rng, data);
    Ok(signature.to_der().to_bytes().to_vec())
}

/// ECDSA P-256 verify
pub fn ecdsa_p256_verify(
    public_key_sec1: &[u8],
    data: &[u8],
    signature_der: &[u8],
) -> HsmResult<bool> {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::VerifyingKey;

    validate_data_size(data)?;
    let verifying_key =
        VerifyingKey::from_sec1_bytes(public_key_sec1).map_err(|_| HsmError::KeyHandleInvalid)?;
    let signature =
        p256::ecdsa::Signature::from_der(signature_der).map_err(|_| HsmError::SignatureInvalid)?;
    Ok(verifying_key.verify(data, &signature).is_ok())
}

/// Maximum signature length (in bytes) covered by the stack-allocated
/// signature buffer used by `*_into_buf` sign variants.
///
/// Sized for the largest ECDSA / EdDSA signature shape we produce:
/// - Ed25519: 64 bytes
/// - ECDSA P-256 raw `r||s`: 64 bytes; DER: up to ~72 bytes
/// - ECDSA P-384 raw `r||s`: 96 bytes; DER: up to ~104 bytes
///
/// 144 leaves comfortable headroom and keeps the buffer cache-line friendly.
/// RSA (256–512 byte signatures) and ML-DSA / SLH-DSA / hybrid signatures
/// (multi-KB) intentionally bypass this path and continue to allocate.
pub const SIG_STACK_BUF_SIZE: usize = 144;

/// ECDSA P-256 sign into a caller-supplied stack buffer.
///
/// Hedged signing — same crypto behavior as [`ecdsa_p256_sign`], just without
/// the heap allocation for the output. Writes the DER-encoded signature into
/// `out` and returns its length on success.
///
/// Returns `HsmError::DataLenRange` if the resulting DER signature would not
/// fit in `SIG_STACK_BUF_SIZE` bytes. For valid P-256 keys this is unreachable
/// — the maximum DER encoding is ~72 bytes — but the check is retained so the
/// buffer size invariant is enforced rather than assumed.
pub fn ecdsa_p256_sign_into_buf(
    private_key_bytes: &[u8],
    data: &[u8],
    out: &mut [u8; SIG_STACK_BUF_SIZE],
) -> HsmResult<usize> {
    use crate::crypto::drbg::DrbgRng;
    use p256::ecdsa::signature::RandomizedSigner;
    use p256::ecdsa::SigningKey;

    validate_data_size(data)?;
    let signing_key =
        SigningKey::from_slice(private_key_bytes).map_err(|_| HsmError::KeyHandleInvalid)?;
    let mut rng = DrbgRng::new()?;
    let signature: p256::ecdsa::Signature = signing_key.sign_with_rng(&mut rng, data);
    let der = signature.to_der();
    let der_bytes = der.as_bytes();
    if der_bytes.len() > out.len() {
        return Err(HsmError::DataLenRange);
    }
    out[..der_bytes.len()].copy_from_slice(der_bytes);
    Ok(der_bytes.len())
}

// ============================================================================
// ECDSA P-384
// ============================================================================

/// ECDSA P-384 sign (hedged — RFC 6979 + DRBG randomness)
///
/// Uses randomized/hedged signing to protect against fault injection attacks.
/// See `ecdsa_p256_sign` for rationale.
pub fn ecdsa_p384_sign(private_key_bytes: &[u8], data: &[u8]) -> HsmResult<Vec<u8>> {
    use crate::crypto::drbg::DrbgRng;
    use p384::ecdsa::signature::RandomizedSigner;
    use p384::ecdsa::SigningKey;

    validate_data_size(data)?;
    let signing_key =
        SigningKey::from_slice(private_key_bytes).map_err(|_| HsmError::KeyHandleInvalid)?;
    let mut rng = DrbgRng::new()?;
    let signature: p384::ecdsa::Signature = signing_key.sign_with_rng(&mut rng, data);
    Ok(signature.to_der().to_bytes().to_vec())
}

/// ECDSA P-384 verify
pub fn ecdsa_p384_verify(
    public_key_sec1: &[u8],
    data: &[u8],
    signature_der: &[u8],
) -> HsmResult<bool> {
    use p384::ecdsa::signature::Verifier;
    use p384::ecdsa::VerifyingKey;

    validate_data_size(data)?;
    let verifying_key =
        VerifyingKey::from_sec1_bytes(public_key_sec1).map_err(|_| HsmError::KeyHandleInvalid)?;
    let signature =
        p384::ecdsa::Signature::from_der(signature_der).map_err(|_| HsmError::SignatureInvalid)?;
    Ok(verifying_key.verify(data, &signature).is_ok())
}

/// ECDSA P-384 sign into a caller-supplied stack buffer.
///
/// See [`ecdsa_p256_sign_into_buf`] for rationale. P-384 DER signatures are
/// at most ~104 bytes, which fits comfortably in `SIG_STACK_BUF_SIZE`.
pub fn ecdsa_p384_sign_into_buf(
    private_key_bytes: &[u8],
    data: &[u8],
    out: &mut [u8; SIG_STACK_BUF_SIZE],
) -> HsmResult<usize> {
    use crate::crypto::drbg::DrbgRng;
    use p384::ecdsa::signature::RandomizedSigner;
    use p384::ecdsa::SigningKey;

    validate_data_size(data)?;
    let signing_key =
        SigningKey::from_slice(private_key_bytes).map_err(|_| HsmError::KeyHandleInvalid)?;
    let mut rng = DrbgRng::new()?;
    let signature: p384::ecdsa::Signature = signing_key.sign_with_rng(&mut rng, data);
    let der = signature.to_der();
    let der_bytes = der.as_bytes();
    if der_bytes.len() > out.len() {
        return Err(HsmError::DataLenRange);
    }
    out[..der_bytes.len()].copy_from_slice(der_bytes);
    Ok(der_bytes.len())
}

// ============================================================================
// Ed25519 EdDSA
// ============================================================================

/// Ed25519 sign (deterministic per RFC 8032)
///
/// Ed25519 is inherently deterministic by specification — the nonce is derived
/// from `SHA-512(expanded_key_prefix || message)`, making it immune to
/// catastrophic nonce reuse from RNG failure.
///
/// **Fault injection caveat:** Unlike ECDSA (which we hedge with additional
/// randomness), Ed25519's nonce derivation cannot be hedged without violating
/// RFC 8032 and breaking interoperability. If fault injection resistance is
/// required, use ECDSA P-256/P-384 (which are hedged) or deploy hardware
/// countermeasures (voltage monitoring, instruction duplication).
pub fn ed25519_sign(private_key_bytes: &[u8], data: &[u8]) -> HsmResult<Vec<u8>> {
    use ed25519_dalek::Signer;
    use ed25519_dalek::SigningKey;

    use zeroize::Zeroizing;

    validate_data_size(data)?;
    if private_key_bytes.len() != 32 {
        return Err(HsmError::KeyHandleInvalid);
    }
    let mut key_array = Zeroizing::new([0u8; 32]);
    key_array.copy_from_slice(private_key_bytes);
    // SigningKey implements ZeroizeOnDrop — key material is scrubbed when
    // `signing_key` goes out of scope at the end of this function.
    let signing_key = SigningKey::from_bytes(&key_array);
    let signature = signing_key.sign(data);
    Ok(signature.to_bytes().to_vec())
}

/// Ed25519 sign into a caller-supplied stack buffer.
///
/// Same deterministic RFC 8032 signing as [`ed25519_sign`] but writes the
/// 64-byte signature directly into `out` instead of returning a
/// heap-allocated `Vec<u8>`. Always writes exactly 64 bytes on success.
pub fn ed25519_sign_into_buf(
    private_key_bytes: &[u8],
    data: &[u8],
    out: &mut [u8; SIG_STACK_BUF_SIZE],
) -> HsmResult<usize> {
    use ed25519_dalek::Signer;
    use ed25519_dalek::SigningKey;
    use zeroize::Zeroizing;

    validate_data_size(data)?;
    if private_key_bytes.len() != 32 {
        return Err(HsmError::KeyHandleInvalid);
    }
    let mut key_array = Zeroizing::new([0u8; 32]);
    key_array.copy_from_slice(private_key_bytes);
    // SigningKey implements ZeroizeOnDrop — key material is scrubbed when
    // `signing_key` goes out of scope at the end of this function.
    let signing_key = SigningKey::from_bytes(&key_array);
    let signature = signing_key.sign(data);
    let sig_bytes = signature.to_bytes();
    // Ed25519 signatures are always exactly 64 bytes, well within
    // SIG_STACK_BUF_SIZE — no length check needed beyond the const-time
    // bound enforced by the array slice.
    out[..sig_bytes.len()].copy_from_slice(&sig_bytes);
    Ok(sig_bytes.len())
}

/// Ed25519 verify
pub fn ed25519_verify(
    public_key_bytes: &[u8],
    data: &[u8],
    signature_bytes: &[u8],
) -> HsmResult<bool> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    validate_data_size(data)?;
    if public_key_bytes.len() != 32 {
        return Err(HsmError::KeyHandleInvalid);
    }
    // Public keys are not secret — no Zeroizing needed
    let key_array: [u8; 32] = public_key_bytes
        .try_into()
        .map_err(|_| HsmError::KeyHandleInvalid)?;
    let verifying_key =
        VerifyingKey::from_bytes(&key_array).map_err(|_| HsmError::KeyHandleInvalid)?;

    if signature_bytes.len() != 64 {
        return Err(HsmError::SignatureInvalid);
    }
    // Signatures are not secret — no Zeroizing needed
    let sig_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| HsmError::SignatureInvalid)?;
    let signature = Signature::from_bytes(&sig_array);
    Ok(verifying_key.verify(data, &signature).is_ok())
}

// ============================================================================
// Helpers
// ============================================================================

/// Map CKM mechanism to optional hash algorithm (for PKCS#1v1.5 RSA)
pub fn mechanism_to_hash(mechanism: CK_MECHANISM_TYPE) -> Option<HashAlg> {
    match mechanism {
        CKM_SHA256_RSA_PKCS => Some(HashAlg::Sha256),
        CKM_SHA384_RSA_PKCS => Some(HashAlg::Sha384),
        CKM_SHA512_RSA_PKCS => Some(HashAlg::Sha512),
        CKM_RSA_PKCS => None,
        _ => None,
    }
}

/// Map CKM PSS mechanism to hash algorithm.
///
/// Returns `Ok(hash)` for typed PSS mechanisms (CKM_SHAx_RSA_PKCS_PSS),
/// `Err(MechanismParamInvalid)` for `CKM_RSA_PKCS_PSS` (caller must provide
/// hash via mechanism params), and `Err(MechanismInvalid)` for unknown mechanisms.
pub fn pss_mechanism_to_hash(mechanism: CK_MECHANISM_TYPE) -> HsmResult<HashAlg> {
    match mechanism {
        CKM_SHA256_RSA_PKCS_PSS => Ok(HashAlg::Sha256),
        CKM_SHA384_RSA_PKCS_PSS => Ok(HashAlg::Sha384),
        CKM_SHA512_RSA_PKCS_PSS => Ok(HashAlg::Sha512),
        CKM_RSA_PKCS_PSS => Err(HsmError::MechanismParamInvalid), // caller must specify hash
        _ => Err(HsmError::MechanismInvalid),
    }
}

/// Check if mechanism is an RSA-PSS mechanism
pub fn is_pss_mechanism(mechanism: CK_MECHANISM_TYPE) -> bool {
    matches!(
        mechanism,
        CKM_RSA_PKCS_PSS
            | CKM_SHA256_RSA_PKCS_PSS
            | CKM_SHA384_RSA_PKCS_PSS
            | CKM_SHA512_RSA_PKCS_PSS
    )
}

/// Check if mechanism is an ECDSA mechanism
pub fn is_ecdsa_mechanism(mechanism: CK_MECHANISM_TYPE) -> bool {
    matches!(
        mechanism,
        CKM_ECDSA | CKM_ECDSA_SHA256 | CKM_ECDSA_SHA384 | CKM_ECDSA_SHA512
    )
}

/// Check if mechanism is EdDSA
pub fn is_eddsa_mechanism(mechanism: CK_MECHANISM_TYPE) -> bool {
    mechanism == CKM_EDDSA
}

/// Check if a sign mechanism supports multi-part (C_SignUpdate/C_SignFinal).
/// Only mechanisms with a built-in hash algorithm support multi-part.
pub fn sign_mechanism_supports_multipart(mechanism: CK_MECHANISM_TYPE) -> bool {
    matches!(
        mechanism,
        CKM_SHA256_RSA_PKCS
            | CKM_SHA384_RSA_PKCS
            | CKM_SHA512_RSA_PKCS
            | CKM_SHA256_RSA_PKCS_PSS
            | CKM_SHA384_RSA_PKCS_PSS
            | CKM_SHA512_RSA_PKCS_PSS
            | CKM_ECDSA_SHA256
            | CKM_ECDSA_SHA384
            | CKM_ECDSA_SHA512
    )
}

/// Map a sign mechanism to the corresponding digest mechanism for creating hashers.
/// Returns None for mechanisms that don't have a built-in hash (e.g., CKM_RSA_PKCS, CKM_ECDSA).
pub fn sign_mechanism_to_digest_mechanism(
    mechanism: CK_MECHANISM_TYPE,
) -> Option<CK_MECHANISM_TYPE> {
    match mechanism {
        CKM_SHA256_RSA_PKCS | CKM_SHA256_RSA_PKCS_PSS | CKM_ECDSA_SHA256 => Some(CKM_SHA256),
        CKM_SHA384_RSA_PKCS | CKM_SHA384_RSA_PKCS_PSS | CKM_ECDSA_SHA384 => Some(CKM_SHA384),
        CKM_SHA512_RSA_PKCS | CKM_SHA512_RSA_PKCS_PSS | CKM_ECDSA_SHA512 => Some(CKM_SHA512),
        _ => None,
    }
}

// ============================================================================
// Prehashed RSA PKCS#1 v1.5
// ============================================================================

/// RSA PKCS#1 v1.5 sign with a pre-computed digest.
/// The `digest` parameter must be the hash output (e.g., 32 bytes for SHA-256).
/// DigestInfo wrapping is handled internally by the scheme.
pub(crate) fn rsa_pkcs1v15_sign_prehashed(
    private_key_der: &[u8],
    digest: &[u8],
    hash_alg: HashAlg,
) -> HsmResult<Vec<u8>> {
    validate_digest_length(digest, hash_alg)?;
    let private_key = parse_rsa_private_key(private_key_der)?;
    validate_rsa_private_key_size(&private_key)?;

    let scheme = match hash_alg {
        HashAlg::Sha256 => Pkcs1v15Sign::new::<Sha256>(),
        HashAlg::Sha384 => Pkcs1v15Sign::new::<Sha384>(),
        HashAlg::Sha512 => Pkcs1v15Sign::new::<Sha512>(),
    };

    private_key
        .sign(scheme, digest)
        .map_err(|_| HsmError::GeneralError)
}

/// RSA PKCS#1 v1.5 verify with a pre-computed digest.
pub(crate) fn rsa_pkcs1v15_verify_prehashed(
    modulus: &[u8],
    public_exponent: &[u8],
    digest: &[u8],
    signature: &[u8],
    hash_alg: HashAlg,
) -> HsmResult<bool> {
    validate_digest_length(digest, hash_alg)?;
    validate_rsa_public_key_size(modulus)?;
    let n = rsa::BigUint::from_bytes_be(modulus);
    let e = rsa::BigUint::from_bytes_be(public_exponent);
    let public_key = RsaPublicKey::new(n, e).map_err(|_| HsmError::KeyHandleInvalid)?;

    let scheme = match hash_alg {
        HashAlg::Sha256 => Pkcs1v15Sign::new::<Sha256>(),
        HashAlg::Sha384 => Pkcs1v15Sign::new::<Sha384>(),
        HashAlg::Sha512 => Pkcs1v15Sign::new::<Sha512>(),
    };

    Ok(public_key.verify(scheme, digest, signature).is_ok())
}

// ============================================================================
// Prehashed RSA-PSS
// ============================================================================

/// RSA-PSS sign with a pre-computed digest.
/// Uses randomized signing (random salt) as required by FIPS.
/// Salt randomness is sourced from the SP 800-90A HMAC_DRBG via `DrbgRng`.
pub(crate) fn rsa_pss_sign_prehashed(
    private_key_der: &[u8],
    digest: &[u8],
    hash_alg: HashAlg,
) -> HsmResult<Vec<u8>> {
    use crate::crypto::drbg::DrbgRng;
    use rsa::pss::SigningKey;
    use rsa::signature::hazmat::RandomizedPrehashSigner;
    use rsa::signature::SignatureEncoding;

    validate_digest_length(digest, hash_alg)?;
    let private_key = parse_rsa_private_key(private_key_der)?;
    validate_rsa_private_key_size(&private_key)?;

    let mut rng = DrbgRng::new()?;

    match hash_alg {
        HashAlg::Sha256 => {
            let signing_key = SigningKey::<Sha256>::new(private_key);
            let signature = signing_key
                .sign_prehash_with_rng(&mut rng, digest)
                .map_err(|_| HsmError::GeneralError)?;
            Ok(signature.to_vec())
        }
        HashAlg::Sha384 => {
            let signing_key = SigningKey::<Sha384>::new(private_key);
            let signature = signing_key
                .sign_prehash_with_rng(&mut rng, digest)
                .map_err(|_| HsmError::GeneralError)?;
            Ok(signature.to_vec())
        }
        HashAlg::Sha512 => {
            let signing_key = SigningKey::<Sha512>::new(private_key);
            let signature = signing_key
                .sign_prehash_with_rng(&mut rng, digest)
                .map_err(|_| HsmError::GeneralError)?;
            Ok(signature.to_vec())
        }
    }
}

/// RSA-PSS verify with a pre-computed digest.
pub(crate) fn rsa_pss_verify_prehashed(
    modulus: &[u8],
    public_exponent: &[u8],
    digest: &[u8],
    signature: &[u8],
    hash_alg: HashAlg,
) -> HsmResult<bool> {
    use rsa::pss::VerifyingKey;
    use rsa::signature::hazmat::PrehashVerifier;

    validate_digest_length(digest, hash_alg)?;
    validate_rsa_public_key_size(modulus)?;
    let n = rsa::BigUint::from_bytes_be(modulus);
    let e = rsa::BigUint::from_bytes_be(public_exponent);
    let public_key = RsaPublicKey::new(n, e).map_err(|_| HsmError::KeyHandleInvalid)?;

    let sig = rsa::pss::Signature::try_from(signature).map_err(|_| HsmError::SignatureInvalid)?;

    match hash_alg {
        HashAlg::Sha256 => {
            let verifying_key = VerifyingKey::<Sha256>::new(public_key);
            Ok(verifying_key.verify_prehash(digest, &sig).is_ok())
        }
        HashAlg::Sha384 => {
            let verifying_key = VerifyingKey::<Sha384>::new(public_key);
            Ok(verifying_key.verify_prehash(digest, &sig).is_ok())
        }
        HashAlg::Sha512 => {
            let verifying_key = VerifyingKey::<Sha512>::new(public_key);
            Ok(verifying_key.verify_prehash(digest, &sig).is_ok())
        }
    }
}

// ============================================================================
// Handle-cached Prehashed RSA PKCS#1 v1.5 (fast path)
// ============================================================================

/// RSA PKCS#1 v1.5 sign with pre-computed digest, using handle-based cache.
pub(crate) fn rsa_pkcs1v15_sign_prehashed_cached(
    slot_id: u64,
    handle: u64,
    private_key_der: &[u8],
    digest: &[u8],
    hash_alg: HashAlg,
) -> HsmResult<Vec<u8>> {
    validate_digest_length(digest, hash_alg)?;
    let key = get_or_parse_private_key(slot_id, handle, private_key_der)?;
    validate_rsa_private_key_size(&key)?;

    let scheme = match hash_alg {
        HashAlg::Sha256 => Pkcs1v15Sign::new::<Sha256>(),
        HashAlg::Sha384 => Pkcs1v15Sign::new::<Sha384>(),
        HashAlg::Sha512 => Pkcs1v15Sign::new::<Sha512>(),
    };

    key.sign(scheme, digest).map_err(|_| HsmError::GeneralError)
}

/// RSA PKCS#1 v1.5 verify with pre-computed digest, using handle-based cache.
pub(crate) fn rsa_pkcs1v15_verify_prehashed_cached(
    slot_id: u64,
    handle: u64,
    modulus: &[u8],
    public_exponent: &[u8],
    digest: &[u8],
    signature: &[u8],
    hash_alg: HashAlg,
) -> HsmResult<bool> {
    validate_digest_length(digest, hash_alg)?;
    validate_rsa_public_key_size(modulus)?;
    let key = get_or_build_public_key(slot_id, handle, modulus, public_exponent)?;

    let scheme = match hash_alg {
        HashAlg::Sha256 => Pkcs1v15Sign::new::<Sha256>(),
        HashAlg::Sha384 => Pkcs1v15Sign::new::<Sha384>(),
        HashAlg::Sha512 => Pkcs1v15Sign::new::<Sha512>(),
    };

    Ok(key.verify(scheme, digest, signature).is_ok())
}

// ============================================================================
// Handle-cached Prehashed RSA-PSS (fast path)
// ============================================================================

/// RSA-PSS sign with pre-computed digest, using handle-based cache.
pub(crate) fn rsa_pss_sign_prehashed_cached(
    slot_id: u64,
    handle: u64,
    private_key_der: &[u8],
    digest: &[u8],
    hash_alg: HashAlg,
) -> HsmResult<Vec<u8>> {
    use crate::crypto::drbg::DrbgRng;
    use rsa::pss::SigningKey;
    use rsa::signature::hazmat::RandomizedPrehashSigner;
    use rsa::signature::SignatureEncoding;

    validate_digest_length(digest, hash_alg)?;
    let key = get_or_parse_private_key(slot_id, handle, private_key_der)?;
    validate_rsa_private_key_size(&key)?;

    let mut rng = DrbgRng::new()?;

    match hash_alg {
        HashAlg::Sha256 => {
            let signing_key = SigningKey::<Sha256>::new((*key).clone());
            let signature = signing_key
                .sign_prehash_with_rng(&mut rng, digest)
                .map_err(|_| HsmError::GeneralError)?;
            Ok(signature.to_vec())
        }
        HashAlg::Sha384 => {
            let signing_key = SigningKey::<Sha384>::new((*key).clone());
            let signature = signing_key
                .sign_prehash_with_rng(&mut rng, digest)
                .map_err(|_| HsmError::GeneralError)?;
            Ok(signature.to_vec())
        }
        HashAlg::Sha512 => {
            let signing_key = SigningKey::<Sha512>::new((*key).clone());
            let signature = signing_key
                .sign_prehash_with_rng(&mut rng, digest)
                .map_err(|_| HsmError::GeneralError)?;
            Ok(signature.to_vec())
        }
    }
}

/// RSA-PSS verify with pre-computed digest, using handle-based cache.
pub(crate) fn rsa_pss_verify_prehashed_cached(
    slot_id: u64,
    handle: u64,
    modulus: &[u8],
    public_exponent: &[u8],
    digest: &[u8],
    signature: &[u8],
    hash_alg: HashAlg,
) -> HsmResult<bool> {
    use rsa::pss::VerifyingKey;
    use rsa::signature::hazmat::PrehashVerifier;

    validate_digest_length(digest, hash_alg)?;
    validate_rsa_public_key_size(modulus)?;
    let key = get_or_build_public_key(slot_id, handle, modulus, public_exponent)?;

    let sig = rsa::pss::Signature::try_from(signature).map_err(|_| HsmError::SignatureInvalid)?;

    match hash_alg {
        HashAlg::Sha256 => {
            let verifying_key = VerifyingKey::<Sha256>::new((*key).clone());
            Ok(verifying_key.verify_prehash(digest, &sig).is_ok())
        }
        HashAlg::Sha384 => {
            let verifying_key = VerifyingKey::<Sha384>::new((*key).clone());
            Ok(verifying_key.verify_prehash(digest, &sig).is_ok())
        }
        HashAlg::Sha512 => {
            let verifying_key = VerifyingKey::<Sha512>::new((*key).clone());
            Ok(verifying_key.verify_prehash(digest, &sig).is_ok())
        }
    }
}

// ============================================================================
// Prehashed ECDSA P-256
// ============================================================================

/// ECDSA P-256 sign with a pre-computed digest (hedged).
///
/// Uses `RandomizedPrehashSigner` to mix DRBG randomness into the nonce
/// derivation, protecting against fault injection attacks.
pub(crate) fn ecdsa_p256_sign_prehashed(
    private_key_bytes: &[u8],
    digest: &[u8],
) -> HsmResult<Vec<u8>> {
    use crate::crypto::drbg::DrbgRng;
    use p256::ecdsa::signature::hazmat::RandomizedPrehashSigner;
    use p256::ecdsa::SigningKey;

    // P-256 operates on SHA-256 digests (32 bytes)
    validate_digest_length(digest, HashAlg::Sha256)?;
    let signing_key =
        SigningKey::from_slice(private_key_bytes).map_err(|_| HsmError::KeyHandleInvalid)?;
    let mut rng = DrbgRng::new()?;
    let signature: p256::ecdsa::Signature = signing_key
        .sign_prehash_with_rng(&mut rng, digest)
        .map_err(|_| HsmError::GeneralError)?;
    Ok(signature.to_der().to_bytes().to_vec())
}

/// ECDSA P-256 verify with a pre-computed digest.
pub(crate) fn ecdsa_p256_verify_prehashed(
    public_key_sec1: &[u8],
    digest: &[u8],
    signature_der: &[u8],
) -> HsmResult<bool> {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    use p256::ecdsa::VerifyingKey;

    // P-256 operates on SHA-256 digests (32 bytes)
    validate_digest_length(digest, HashAlg::Sha256)?;
    let verifying_key =
        VerifyingKey::from_sec1_bytes(public_key_sec1).map_err(|_| HsmError::KeyHandleInvalid)?;
    let signature =
        p256::ecdsa::Signature::from_der(signature_der).map_err(|_| HsmError::SignatureInvalid)?;
    Ok(verifying_key.verify_prehash(digest, &signature).is_ok())
}

// ============================================================================
// Prehashed ECDSA P-384
// ============================================================================

/// ECDSA P-384 sign with a pre-computed digest (hedged).
///
/// Uses `RandomizedPrehashSigner` to mix DRBG randomness into the nonce
/// derivation, protecting against fault injection attacks.
pub(crate) fn ecdsa_p384_sign_prehashed(
    private_key_bytes: &[u8],
    digest: &[u8],
) -> HsmResult<Vec<u8>> {
    use crate::crypto::drbg::DrbgRng;
    use p384::ecdsa::signature::hazmat::RandomizedPrehashSigner;
    use p384::ecdsa::SigningKey;

    // P-384 operates on SHA-384 digests (48 bytes)
    validate_digest_length(digest, HashAlg::Sha384)?;
    let signing_key =
        SigningKey::from_slice(private_key_bytes).map_err(|_| HsmError::KeyHandleInvalid)?;
    let mut rng = DrbgRng::new()?;
    let signature: p384::ecdsa::Signature = signing_key
        .sign_prehash_with_rng(&mut rng, digest)
        .map_err(|_| HsmError::GeneralError)?;
    Ok(signature.to_der().to_bytes().to_vec())
}

/// ECDSA P-384 verify with a pre-computed digest.
pub(crate) fn ecdsa_p384_verify_prehashed(
    public_key_sec1: &[u8],
    digest: &[u8],
    signature_der: &[u8],
) -> HsmResult<bool> {
    use p384::ecdsa::signature::hazmat::PrehashVerifier;
    use p384::ecdsa::VerifyingKey;

    // P-384 operates on SHA-384 digests (48 bytes)
    validate_digest_length(digest, HashAlg::Sha384)?;
    let verifying_key =
        VerifyingKey::from_sec1_bytes(public_key_sec1).map_err(|_| HsmError::KeyHandleInvalid)?;
    let signature =
        p384::ecdsa::Signature::from_der(signature_der).map_err(|_| HsmError::SignatureInvalid)?;
    Ok(verifying_key.verify_prehash(digest, &signature).is_ok())
}
