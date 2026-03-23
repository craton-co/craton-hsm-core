// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use sha2::{self};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use crate::error::{HsmError, HsmResult};

/// Maximum plaintext size for AES-GCM per NIST SP 800-38D: 2^36 - 32 bytes.
/// Enforced to prevent silent overflow in the GCM counter.
const AES_GCM_MAX_PLAINTEXT: usize = (1usize << 36) - 32;

/// Maximum plaintext size for AES-CBC and AES-CTR operations.
/// Set to 256 MiB as a practical upper bound. For CTR mode specifically,
/// encrypting large amounts under a single IV risks counter wraparound
/// (though the 128-bit CTR theoretically allows ~2^132 bytes, memory limits
/// make this moot). The limit primarily guards against resource exhaustion.
const AES_CBC_CTR_MAX_PLAINTEXT: usize = 256 * 1024 * 1024; // 256 MiB

/// Per-key counters for AES-GCM encryptions.
/// Per NIST SP 800-38D, nonce uniqueness must be guaranteed per key.
/// Using a global counter was overly restrictive for multi-key workloads and
/// could not be reset on C_Initialize, causing permanent DoS.
///
/// This map tracks encryptions per key (keyed by SHA-256 hash of the key
/// material). Using the full 32-byte hash eliminates birthday collisions that
/// could cause two distinct keys to share a counter — which could either
/// prematurely lock out a key or, worse, fail to detect nonce-reuse limits
/// on a heavily-used key. The hash also avoids storing raw key material in
/// the map.
static GCM_ENCRYPT_COUNTERS: std::sync::LazyLock<dashmap::DashMap<[u8; 32], AtomicU64>> =
    std::sync::LazyLock::new(|| dashmap::DashMap::new());

/// Per-key random nonce prefixes for AES-GCM.
/// Each key gets a 4-byte random prefix generated once via DRBG. This prefix
/// occupies the upper 4 bytes of the 12-byte nonce; the lower 8 bytes are
/// the monotonic counter. This guarantees nonce uniqueness within a single
/// HSM lifetime (counter) and across restarts (random prefix).
static GCM_NONCE_PREFIXES: std::sync::LazyLock<dashmap::DashMap<[u8; 32], [u8; 4]>> =
    std::sync::LazyLock::new(|| dashmap::DashMap::new());

/// Maximum number of AES-GCM encryptions permitted per key.
/// With deterministic counter-based nonces, the limit is the counter space
/// (2^64), but we cap conservatively to encourage key rotation.
const GCM_MAX_RANDOM_NONCE_ENCRYPTIONS: u64 = 1u64 << 31; // ~2 billion, safety margin

/// Reset CBC/CTR IV trackers on re-initialization.
///
/// GCM per-key encryption counters are intentionally NOT reset here. They are
/// tied to the key material's lifetime, not the library lifecycle. Resetting
/// counters while retaining the same AES keys would undermine nonce-reuse
/// protection by allowing the birthday bound to be exceeded across
/// C_Initialize/C_Finalize cycles.
///
/// GCM counters are removed when the key is destroyed (via
/// [`remove_gcm_counter`]) or when the key naturally reaches its limit.
pub fn reset_gcm_counters() {
    // Only reset IV trackers — GCM counters survive re-initialization
    // to prevent nonce-reuse across C_Initialize/C_Finalize cycles.
    reset_iv_trackers();
    tracing::info!(
        "CBC/CTR IV trackers reset. GCM per-key counters preserved \
         (tied to key lifetime, not library lifecycle)."
    );
}

/// Remove the GCM encryption counter and nonce prefix for a specific key.
/// Called when an AES key is destroyed via C_DestroyObject, ensuring the
/// counter is tied to the key's lifetime rather than the library lifecycle.
pub fn remove_gcm_counter(key: &[u8]) {
    let kid = gcm_key_id(key);
    GCM_ENCRYPT_COUNTERS.remove(&kid);
    GCM_NONCE_PREFIXES.remove(&kid);
    // Also remove IV tracking for this key
    CBC_CTR_IV_TRACKER.remove(&kid);
}

/// Force-reset all GCM counters and nonce prefixes. Only called during
/// C_InitToken which destroys all objects on the token, so no keys survive
/// to be reused.
pub fn force_reset_all_counters() {
    GCM_ENCRYPT_COUNTERS.clear();
    GCM_NONCE_PREFIXES.clear();
    reset_iv_trackers();
    tracing::info!(
        "All GCM counters, nonce prefixes, and IV trackers cleared (token re-initialized)."
    );
}

/// Compute a stable 32-byte key identifier for counter tracking.
///
/// Always uses SHA-256 to derive the key identifier, avoiding storage of raw
/// key material in the counter DashMap. While the counter maps are
/// process-private and never serialized, using a hash eliminates any residual
/// key material in the map after key destruction (the hash is not reversible).
#[inline(always)]
fn gcm_key_id(key: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(key).into()
}

/// Get or generate the 4-byte random nonce prefix for a given key.
/// Generated once per key via DRBG and cached for the key's lifetime.
/// The prefix provides uniqueness across HSM restarts while the counter
/// provides uniqueness within a single run.
///
/// Uses `entry().or_try_insert_with()` to atomically generate-and-insert,
/// preventing a TOCTOU race where concurrent first-use of the same key
/// could generate different prefixes and cause nonce reuse.
fn gcm_nonce_prefix(key: &[u8]) -> HsmResult<[u8; 4]> {
    let kid = gcm_key_id(key);
    let entry = GCM_NONCE_PREFIXES
        .entry(kid)
        .or_try_insert_with(|| -> HsmResult<[u8; 4]> {
            let mut prefix = [0u8; 4];
            let mut drbg = crate::crypto::drbg::HmacDrbg::new()?;
            drbg.generate(&mut prefix)?;
            Ok(prefix)
        })?;
    Ok(*entry.value())
}

// ============================================================================
// CBC/CTR IV-reuse detection
// ============================================================================

/// Per-key set of recently used IVs for CBC and CTR modes.
/// Keyed by SHA-256(key) to avoid storing raw key material.
/// Each entry stores a set of IVs (as 16-byte arrays) seen for that key.
///
/// This provides best-effort IV-reuse detection. For CBC, IV reuse leaks
/// common plaintext prefixes. For CTR, IV reuse is catastrophic (two-time pad).
static CBC_CTR_IV_TRACKER: std::sync::LazyLock<
    dashmap::DashMap<[u8; 32], Mutex<HashSet<[u8; 16]>>>,
> = std::sync::LazyLock::new(|| dashmap::DashMap::new());

/// Maximum number of tracked IVs per key before eviction.
/// Prevents unbounded memory growth for long-running sessions.
const MAX_TRACKED_IVS_PER_KEY: usize = 100_000;

/// Maximum number of distinct keys tracked in the CBC/CTR IV tracker.
/// Prevents unbounded memory growth from an attacker creating many keys
/// and encrypting once with each to exhaust memory. When this limit is
/// reached, new keys are rejected until existing keys are destroyed.
const MAX_TRACKED_KEYS: usize = 10_000;

/// Check if an IV has been used before with this key. Returns error on reuse.
/// Tracks the IV for future reuse detection.
fn check_iv_reuse(key: &[u8], iv: &[u8; 16], mode: &str) -> HsmResult<()> {
    use sha2::{Digest, Sha256};
    let key_hash: [u8; 32] = Sha256::digest(key).into();

    // Guard against unbounded key growth in the IV tracker. An attacker who
    // can create many keys and encrypt once with each would grow this map
    // indefinitely without this cap.
    if !CBC_CTR_IV_TRACKER.contains_key(&key_hash) && CBC_CTR_IV_TRACKER.len() >= MAX_TRACKED_KEYS {
        tracing::error!(
            "{}: IV tracker key limit reached ({} keys) — destroy unused keys \
             before creating new ones, or use AES-GCM instead.",
            mode,
            MAX_TRACKED_KEYS
        );
        return Err(HsmError::GeneralError);
    }

    let entry = CBC_CTR_IV_TRACKER
        .entry(key_hash)
        .or_insert_with(|| Mutex::new(HashSet::new()));
    let mut iv_set = entry.value().lock().map_err(|_| {
        tracing::error!(
            "{}: IV tracker mutex poisoned — a prior panic left the tracker \
             in an inconsistent state. Refusing operation to prevent \
             undetected IV reuse.",
            mode
        );
        HsmError::GeneralError
    })?;

    if iv_set.contains(iv) {
        tracing::error!(
            "{} IV reuse detected — same IV used with the same key. \
             This is a critical security violation.",
            mode
        );
        return Err(HsmError::MechanismParamInvalid);
    }

    // Refuse new encryptions if we've tracked too many IVs for this key.
    // Clearing the set would silently lose reuse detection, allowing a
    // previously-used IV to be accepted again. Instead, force re-keying.
    if iv_set.len() >= MAX_TRACKED_IVS_PER_KEY {
        tracing::error!(
            "{}: IV tracker for key is full ({} entries) — re-key required. \
             Generate a new AES key via C_GenerateKey and destroy the exhausted key.",
            mode,
            MAX_TRACKED_IVS_PER_KEY
        );
        return Err(HsmError::GeneralError);
    }

    iv_set.insert(*iv);
    Ok(())
}

/// Reset CBC/CTR IV trackers. Called alongside GCM counter reset on C_Initialize.
pub fn reset_iv_trackers() {
    CBC_CTR_IV_TRACKER.clear();
}

// ============================================================================
// AES-256-GCM
// ============================================================================

/// AES-256-GCM encrypt. Returns nonce || ciphertext.
///
/// Uses deterministic counter-based 96-bit nonces to guarantee uniqueness:
///   - Upper 4 bytes: random prefix (generated once per key via DRBG)
///   - Lower 8 bytes: monotonic counter (unique per encryption)
///
/// This eliminates the birthday-bound collision risk of purely random nonces
/// and prevents nonce reuse even under high concurrency. After 2^31
/// encryptions per key, further operations are refused (re-key required).
pub fn aes_256_gcm_encrypt(key: &[u8], plaintext: &[u8]) -> HsmResult<Vec<u8>> {
    if key.len() != 32 {
        return Err(HsmError::KeySizeRange);
    }

    // Enforce NIST SP 800-38D maximum plaintext length for AES-GCM
    if plaintext.len() > AES_GCM_MAX_PLAINTEXT {
        return Err(HsmError::DataLenRange);
    }

    // Enforce per-key nonce-reuse safety limit (per NIST SP 800-38D).
    //
    // Uses a CAS loop instead of fetch_add to prevent the counter from advancing
    // past the limit. With fetch_add, concurrent threads could all increment past
    // the limit before any of them checks the result, and the counter would never
    // roll back. The CAS loop ensures the counter only advances if the new value
    // is within bounds.
    let kid = gcm_key_id(key);
    let counter = GCM_ENCRYPT_COUNTERS
        .entry(kid)
        .or_insert_with(|| AtomicU64::new(0));

    let count = loop {
        let current = counter.value().load(Ordering::Acquire);
        if current >= GCM_MAX_RANDOM_NONCE_ENCRYPTIONS {
            tracing::error!(
                "AES-GCM per-key encryption limit reached ({} operations) — \
                 re-key required to prevent nonce reuse. Generate a new AES key \
                 via C_GenerateKey and destroy the exhausted key via C_DestroyObject.",
                current
            );
            return Err(HsmError::GeneralError);
        }
        match counter.value().compare_exchange(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(prev) => break prev,
            Err(_) => continue, // another thread raced us — retry
        }
    };

    // Warn at 75% of the limit so operators have time to rotate keys
    // before hitting the hard cap (~500M operations of runway).
    const GCM_WARN_THRESHOLD: u64 = GCM_MAX_RANDOM_NONCE_ENCRYPTIONS * 3 / 4;
    if count == GCM_WARN_THRESHOLD {
        tracing::warn!(
            "AES-GCM per-key encryption count at 75% of limit ({}/{}) — \
             schedule key rotation to avoid hitting the hard cap. \
             Generate a new AES key via C_GenerateKey and re-wrap data.",
            count,
            GCM_MAX_RANDOM_NONCE_ENCRYPTIONS,
        );
    }

    let aes_key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(aes_key);

    // Build deterministic nonce: random_prefix (4 bytes) || counter (8 bytes).
    // The random prefix is generated once per key via DRBG and cached.
    // The counter is monotonically increasing and unique per encryption,
    // so nonce collisions are impossible within a single HSM lifetime.
    // The random prefix provides uniqueness across restarts.
    let prefix = gcm_nonce_prefix(key)?;
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[..4].copy_from_slice(&prefix);
    nonce_bytes[4..].copy_from_slice(&count.to_be_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| HsmError::GeneralError)?;

    // Prepend nonce to ciphertext
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// AES-256-GCM encrypt with Additional Authenticated Data (AAD).
///
/// AAD provides context binding — an attacker who can swap ciphertexts between
/// different contexts (e.g., different object handles or key IDs) will be
/// detected at decryption time because the AAD won't match.
///
/// Returns nonce (12 bytes) || ciphertext (with authentication tag).
pub fn aes_256_gcm_encrypt_with_aad(
    key: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> HsmResult<Vec<u8>> {
    use aes_gcm::aead::Payload;

    if key.len() != 32 {
        return Err(HsmError::KeySizeRange);
    }
    if plaintext.len() > AES_GCM_MAX_PLAINTEXT {
        return Err(HsmError::DataLenRange);
    }

    let kid = gcm_key_id(key);
    let counter = GCM_ENCRYPT_COUNTERS
        .entry(kid)
        .or_insert_with(|| AtomicU64::new(0));

    let count = loop {
        let current = counter.value().load(Ordering::Acquire);
        if current >= GCM_MAX_RANDOM_NONCE_ENCRYPTIONS {
            return Err(HsmError::GeneralError);
        }
        match counter.value().compare_exchange(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(prev) => break prev,
            Err(_) => continue,
        }
    };

    const GCM_WARN_THRESHOLD: u64 = GCM_MAX_RANDOM_NONCE_ENCRYPTIONS * 3 / 4;
    if count == GCM_WARN_THRESHOLD {
        tracing::warn!("AES-GCM per-key count at 75% — schedule key rotation");
    }

    let aes_key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(aes_key);

    // Deterministic nonce: random_prefix (4 bytes) || counter (8 bytes)
    let prefix = gcm_nonce_prefix(key)?;
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[..4].copy_from_slice(&prefix);
    nonce_bytes[4..].copy_from_slice(&count.to_be_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);

    let payload = Payload {
        msg: plaintext,
        aad,
    };
    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|_| HsmError::GeneralError)?;

    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// AES-256-GCM decrypt. Input is nonce (12 bytes) || ciphertext.
pub fn aes_256_gcm_decrypt(key: &[u8], data: &[u8]) -> HsmResult<Vec<u8>> {
    if key.len() != 32 {
        return Err(HsmError::KeySizeRange);
    }
    // Minimum: 12 bytes nonce + 16 bytes GCM auth tag
    if data.len() < 28 {
        return Err(HsmError::EncryptedDataInvalid);
    }

    let aes_key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(aes_key);

    let nonce = Nonce::from_slice(&data[..12]);
    let ciphertext = &data[12..];

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| HsmError::EncryptedDataInvalid)
}

/// AES-256-GCM decrypt with Additional Authenticated Data (AAD).
///
/// The AAD must match what was provided during encryption, or decryption
/// will fail with `EncryptedDataInvalid`. This prevents ciphertext swapping
/// between different contexts.
///
/// Input is nonce (12 bytes) || ciphertext (with authentication tag).
pub fn aes_256_gcm_decrypt_with_aad(key: &[u8], data: &[u8], aad: &[u8]) -> HsmResult<Vec<u8>> {
    use aes_gcm::aead::Payload;

    if key.len() != 32 {
        return Err(HsmError::KeySizeRange);
    }
    if data.len() < 28 {
        return Err(HsmError::EncryptedDataInvalid);
    }

    let aes_key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(aes_key);

    let nonce = Nonce::from_slice(&data[..12]);
    let ciphertext = &data[12..];

    let payload = Payload {
        msg: ciphertext,
        aad,
    };
    cipher
        .decrypt(nonce, payload)
        .map_err(|_| HsmError::EncryptedDataInvalid)
}

// ============================================================================
// AES-CBC (with PKCS#7 padding)
// ============================================================================
//
// **WARNING — NON-AUTHENTICATED ENCRYPTION**
//
// AES-CBC provides confidentiality only — no integrity or authenticity.
// It is vulnerable to:
//   - **Padding oracle attacks**: timing differences in PKCS#7 unpadding can
//     leak plaintext byte-by-byte if the attacker can submit modified ciphertexts.
//   - **Bit-flipping**: modifying a ciphertext block garbles that block but
//     predictably flips bits in the next block.
//
// Callers SHOULD prefer AES-GCM (authenticated encryption) whenever possible.
// If AES-CBC is required (e.g., for PKCS#11 interoperability), the caller MUST
// apply an independent MAC (encrypt-then-MAC) over the IV + ciphertext to
// prevent these attacks.
//
// **KNOWN LIMITATION — TIMING MITIGATION IS IMPERFECT**
//
// The `aes_cbc_decrypt` function below applies a 10 ms minimum-duration floor
// to equalize timing between padding-valid and padding-invalid code paths.
// While this dominates over the sub-microsecond padding check variance in
// most scenarios, it is NOT a constant-time guarantee:
//
//   - OS scheduler jitter, CPU frequency scaling (DVFS), and cache/TLB effects
//     can introduce observable variance below the 10 ms floor.
//   - A sufficiently motivated attacker with high-resolution timing (e.g.,
//     co-located VM, local process) may still extract signal.
//   - The `sleep()` call itself is subject to OS scheduling granularity
//     (~1–4 ms on Linux, ~15 ms on Windows), adding further variance.
//
// This timing equalization is a **defense-in-depth measure only**. The
// primary defense against padding oracle attacks is encrypt-then-MAC:
// verify a MAC over IV + ciphertext BEFORE calling `aes_cbc_decrypt`.
// AES-GCM is strongly preferred for new applications.
// ============================================================================

/// AES-CBC encrypt. IV is provided (16 bytes). Returns ciphertext with PKCS#7 padding.
///
/// **Security warning:** AES-CBC is non-authenticated encryption. Without an
/// independent MAC, it is vulnerable to padding oracle and bit-flipping attacks.
/// Prefer AES-GCM where possible. See module-level documentation for details.
///
/// The caller is responsible for IV uniqueness. Reusing an IV with the same key
/// leaks information about common plaintext prefixes.
pub fn aes_cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> HsmResult<Vec<u8>> {
    use cbc::cipher::{BlockEncryptMut, KeyIvInit};

    tracing::warn!("AES-CBC encrypt: unauthenticated mode — prefer AES-GCM for new applications");

    if plaintext.len() > AES_CBC_CTR_MAX_PLAINTEXT {
        return Err(HsmError::DataLenRange);
    }

    if iv.len() != 16 {
        return Err(HsmError::MechanismParamInvalid);
    }

    // Security hardening: reject all-zero IV.
    //
    // While PKCS#11 does not explicitly forbid a zero IV, an all-zero IV
    // almost always indicates an uninitialized buffer or a caller that
    // forgot to generate a random IV. Accepting it silently would mask
    // critical IV-reuse bugs that destroy CBC confidentiality.
    //
    // This is an intentional deviation from strict PKCS#11 compatibility
    // in favor of defense-in-depth. No legitimate use case for zero IV
    // in CBC mode is known.
    if iv.iter().all(|&b| b == 0) {
        tracing::error!(
            "AES-CBC encrypt rejected: all-zero IV is not permitted (likely uninitialized)"
        );
        return Err(HsmError::MechanismParamInvalid);
    }

    tracing::warn!(
        "AES-CBC encrypt invoked — this is non-authenticated encryption. \
         Prefer AES-GCM or apply encrypt-then-MAC to prevent padding oracle attacks."
    );

    // IV-reuse detection: reject if same IV has been used with this key before
    let iv_array: [u8; 16] = iv.try_into().unwrap(); // length already validated
    check_iv_reuse(key, &iv_array, "AES-CBC")?;

    match key.len() {
        16 => {
            type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
            let encryptor =
                Aes128CbcEnc::new_from_slices(key, iv).map_err(|_| HsmError::KeySizeRange)?;
            Ok(encryptor.encrypt_padded_vec_mut::<cbc::cipher::block_padding::Pkcs7>(plaintext))
        }
        24 => {
            type Aes192CbcEnc = cbc::Encryptor<aes::Aes192>;
            let encryptor =
                Aes192CbcEnc::new_from_slices(key, iv).map_err(|_| HsmError::KeySizeRange)?;
            Ok(encryptor.encrypt_padded_vec_mut::<cbc::cipher::block_padding::Pkcs7>(plaintext))
        }
        32 => {
            type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
            let encryptor =
                Aes256CbcEnc::new_from_slices(key, iv).map_err(|_| HsmError::KeySizeRange)?;
            Ok(encryptor.encrypt_padded_vec_mut::<cbc::cipher::block_padding::Pkcs7>(plaintext))
        }
        _ => Err(HsmError::KeySizeRange),
    }
}

/// AES-CBC decrypt. IV is provided (16 bytes). Expects PKCS#7 padded ciphertext.
///
/// **Security warning:** AES-CBC decryption with PKCS#7 padding is inherently
/// vulnerable to padding oracle attacks if the attacker can observe whether
/// decryption succeeded or failed. The caller MUST verify a MAC (encrypt-then-MAC)
/// over the IV + ciphertext BEFORE calling this function.
pub fn aes_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> HsmResult<Vec<u8>> {
    use cbc::cipher::{BlockDecryptMut, KeyIvInit};

    if iv.len() != 16 {
        return Err(HsmError::MechanismParamInvalid);
    }

    tracing::warn!(
        "AES-CBC decrypt invoked — vulnerable to padding oracle without external MAC. \
         Ensure encrypt-then-MAC is applied before decryption."
    );

    // SECURITY: All decryption errors (padding, key size, etc.) return the same
    // generic error code to prevent padding oracle attacks. An attacker must not
    // be able to distinguish a padding failure from a decryption failure.
    //
    // Timing equalization: we enforce a minimum duration so that padding-valid
    // and padding-invalid paths take the same wall-clock time. The floor is set
    // high enough (10ms) to dominate over the sub-microsecond padding check
    // variance, even accounting for scheduler jitter and context switches.
    //
    // IMPORTANT: This is a defense-in-depth measure only. Timing equalization
    // via sleep is inherently imperfect — OS scheduling, CPU frequency scaling,
    // and cache effects can introduce observable variance. Callers MUST apply
    // encrypt-then-MAC (verify MAC before decryption) for robust padding oracle
    // prevention. AES-GCM is strongly preferred over AES-CBC for new applications.
    let start = std::time::Instant::now();

    let result = match key.len() {
        16 => {
            type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
            Aes128CbcDec::new_from_slices(key, iv)
                .map_err(|_| HsmError::EncryptedDataInvalid)
                .and_then(|decryptor| {
                    decryptor
                        .decrypt_padded_vec_mut::<cbc::cipher::block_padding::Pkcs7>(ciphertext)
                        .map_err(|_| HsmError::EncryptedDataInvalid)
                })
        }
        24 => {
            type Aes192CbcDec = cbc::Decryptor<aes::Aes192>;
            Aes192CbcDec::new_from_slices(key, iv)
                .map_err(|_| HsmError::EncryptedDataInvalid)
                .and_then(|decryptor| {
                    decryptor
                        .decrypt_padded_vec_mut::<cbc::cipher::block_padding::Pkcs7>(ciphertext)
                        .map_err(|_| HsmError::EncryptedDataInvalid)
                })
        }
        32 => {
            type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
            Aes256CbcDec::new_from_slices(key, iv)
                .map_err(|_| HsmError::EncryptedDataInvalid)
                .and_then(|decryptor| {
                    decryptor
                        .decrypt_padded_vec_mut::<cbc::cipher::block_padding::Pkcs7>(ciphertext)
                        .map_err(|_| HsmError::EncryptedDataInvalid)
                })
        }
        _ => Err(HsmError::EncryptedDataInvalid),
    };

    // Enforce a minimum duration of 10ms for CBC decryption to equalize timing
    // between padding-valid and padding-invalid paths. 10ms is chosen to be
    // well above typical OS scheduling granularity (~1-4ms) so that the sleep
    // dominates the observable response time regardless of padding check outcome.
    const CBC_DECRYPT_MIN_DURATION: std::time::Duration = std::time::Duration::from_millis(10);
    let elapsed = start.elapsed();
    if elapsed < CBC_DECRYPT_MIN_DURATION {
        std::thread::sleep(CBC_DECRYPT_MIN_DURATION - elapsed);
    }

    result
}

// ============================================================================
// AES-CTR
// ============================================================================
//
// **WARNING — NON-AUTHENTICATED, MALLEABLE ENCRYPTION**
//
// AES-CTR provides confidentiality only — no integrity or authenticity.
// It is a stream cipher mode, meaning:
//   - **Bit-flipping**: flipping a ciphertext bit flips the corresponding
//     plaintext bit with certainty (fully malleable).
//   - **Nonce reuse is catastrophic**: reusing the same IV/nonce with the
//     same key reveals the XOR of both plaintexts, enabling full recovery.
//
// Callers MUST either:
//   1. Use AES-GCM instead (strongly recommended), or
//   2. Apply an independent MAC (encrypt-then-MAC) over the IV + ciphertext,
//      AND guarantee IV uniqueness per key (e.g., via a monotonic counter).
// ============================================================================

/// AES-CTR encrypt. Tracks the IV to prevent catastrophic nonce reuse.
///
/// **Security warning:** AES-CTR is fully malleable (bit-flipping) and provides
/// no authentication. Nonce reuse is catastrophic. See module-level docs.
/// Prefer AES-GCM where possible.
pub fn aes_ctr_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> HsmResult<Vec<u8>> {
    tracing::warn!(
        "AES-CTR encrypt: unauthenticated, malleable mode — prefer AES-GCM for new applications"
    );

    aes_ctr_validate(key, iv, plaintext)?;

    // IV-reuse detection on encrypt: CTR nonce reuse is catastrophic (two-time pad).
    let iv_array: [u8; 16] = iv.try_into().unwrap(); // length validated above
    check_iv_reuse(key, &iv_array, "AES-CTR")?;

    aes_ctr_apply(key, iv, plaintext)
}

/// AES-CTR decrypt. Does NOT track the IV (the same key+IV pair used for
/// encryption must be reused for decryption).
///
/// **Security warning:** AES-CTR is fully malleable (bit-flipping) and provides
/// no authentication. See module-level docs. Prefer AES-GCM where possible.
pub fn aes_ctr_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> HsmResult<Vec<u8>> {
    tracing::warn!(
        "AES-CTR decrypt: unauthenticated, malleable mode — prefer AES-GCM for new applications"
    );

    aes_ctr_validate(key, iv, ciphertext)?;

    // No IV-reuse check on decrypt: the same (key, IV) pair from encryption
    // must be reused to recover the plaintext.
    aes_ctr_apply(key, iv, ciphertext)
}

/// Legacy combined encrypt/decrypt entry point. Callers should migrate to
/// [`aes_ctr_encrypt`] / [`aes_ctr_decrypt`] for proper IV-reuse protection.
///
/// This function does NOT perform IV-reuse detection and is retained only
/// for backward compatibility.
///
/// # Security Warning
///
/// This function provides **zero nonce-reuse protection**. Nonce reuse in CTR
/// mode is catastrophic (two-time pad → full plaintext recovery). Migrate to
/// [`aes_ctr_encrypt`] / [`aes_ctr_decrypt`] immediately.
#[deprecated(
    since = "0.2.0",
    note = "Use aes_ctr_encrypt/aes_ctr_decrypt for nonce-reuse protection. \
            This function bypasses IV-reuse detection entirely."
)]
pub fn aes_ctr_crypt(key: &[u8], iv: &[u8], data: &[u8]) -> HsmResult<Vec<u8>> {
    tracing::warn!(
        "AES-CTR: using legacy combined crypt — migrate to aes_ctr_encrypt/aes_ctr_decrypt \
         for nonce-reuse protection"
    );

    aes_ctr_validate(key, iv, data)?;
    aes_ctr_apply(key, iv, data)
}

/// Shared validation for AES-CTR operations.
fn aes_ctr_validate(key: &[u8], iv: &[u8], data: &[u8]) -> HsmResult<()> {
    if data.len() > AES_CBC_CTR_MAX_PLAINTEXT {
        return Err(HsmError::DataLenRange);
    }

    if iv.len() != 16 {
        return Err(HsmError::MechanismParamInvalid);
    }

    // Reject all-zero IV — CTR with all-zero nonce is catastrophic for security
    if iv.iter().all(|&b| b == 0) {
        tracing::error!("AES-CTR rejected: all-zero IV/nonce is not permitted");
        return Err(HsmError::MechanismParamInvalid);
    }

    if !matches!(key.len(), 16 | 24 | 32) {
        return Err(HsmError::KeySizeRange);
    }

    Ok(())
}

/// Shared AES-CTR keystream application (encrypt and decrypt are identical in CTR mode).
fn aes_ctr_apply(key: &[u8], iv: &[u8], data: &[u8]) -> HsmResult<Vec<u8>> {
    use ctr::cipher::{KeyIvInit, StreamCipher};

    let mut output = data.to_vec();

    match key.len() {
        16 => {
            type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;
            let mut cipher =
                Aes128Ctr::new_from_slices(key, iv).map_err(|_| HsmError::KeySizeRange)?;
            cipher.apply_keystream(&mut output);
        }
        24 => {
            type Aes192Ctr = ctr::Ctr128BE<aes::Aes192>;
            let mut cipher =
                Aes192Ctr::new_from_slices(key, iv).map_err(|_| HsmError::KeySizeRange)?;
            cipher.apply_keystream(&mut output);
        }
        32 => {
            type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;
            let mut cipher =
                Aes256Ctr::new_from_slices(key, iv).map_err(|_| HsmError::KeySizeRange)?;
            cipher.apply_keystream(&mut output);
        }
        _ => return Err(HsmError::KeySizeRange),
    }

    Ok(output)
}
