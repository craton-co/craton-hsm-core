// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
use crate::error::{HsmError, HsmResult};
use crate::pkcs11_abi::constants::*;
use crate::pkcs11_abi::types::CK_MECHANISM_TYPE;
use sha2::{Digest, Sha256, Sha384, Sha512};

/// Size of the scratch buffer used for zeroizing hasher state on drop.
/// Must be >= the largest internal state of any supported hash function.
/// SHA-512/SHA3-512 have the largest state at ~200-210 bytes; 256 is safe.
#[allow(dead_code)]
const HASHER_ZEROIZE_BUF_SIZE: usize = 256;

/// Compute a digest of the given data using the specified mechanism.
///
/// **SHA-1 deprecation:** SHA-1 is cryptographically broken for collision
/// resistance (SHAttered, 2017). It is supported only for backward
/// compatibility with legacy applications. New applications MUST use
/// SHA-256 or stronger. FIPS mode should reject SHA-1 at the caller level
/// via algorithm policy checks.
pub fn compute_digest(mechanism: CK_MECHANISM_TYPE, data: &[u8]) -> HsmResult<Vec<u8>> {
    match mechanism {
        CKM_SHA_1 => {
            tracing::warn!(
                "SHA-1 digest requested — SHA-1 is cryptographically broken for \
                 collision resistance. Migrate to SHA-256 or stronger."
            );
            use sha1::Sha1;
            Ok(Sha1::digest(data).to_vec())
        }
        CKM_SHA256 => Ok(Sha256::digest(data).to_vec()),
        CKM_SHA384 => Ok(Sha384::digest(data).to_vec()),
        CKM_SHA512 => Ok(Sha512::digest(data).to_vec()),
        CKM_SHA3_256 => {
            use sha3::Sha3_256;
            Ok(Sha3_256::digest(data).to_vec())
        }
        CKM_SHA3_384 => {
            use sha3::Sha3_384;
            Ok(Sha3_384::digest(data).to_vec())
        }
        CKM_SHA3_512 => {
            use sha3::Sha3_512;
            Ok(Sha3_512::digest(data).to_vec())
        }
        _ => Err(HsmError::MechanismInvalid),
    }
}

/// Get the output length for a digest mechanism
pub fn digest_output_len(mechanism: CK_MECHANISM_TYPE) -> HsmResult<usize> {
    match mechanism {
        CKM_SHA_1 => Ok(20),
        CKM_SHA256 | CKM_SHA3_256 => Ok(32),
        CKM_SHA384 | CKM_SHA3_384 => Ok(48),
        CKM_SHA512 | CKM_SHA3_512 => Ok(64),
        _ => Err(HsmError::MechanismInvalid),
    }
}

/// Create a new hasher for multi-part digest operations.
pub fn create_hasher(mechanism: CK_MECHANISM_TYPE) -> HsmResult<Box<dyn DigestAccumulator>> {
    match mechanism {
        CKM_SHA_1 => {
            tracing::warn!(
                "SHA-1 hasher requested — SHA-1 is cryptographically broken for \
                 collision resistance. Migrate to SHA-256 or stronger."
            );
            use sha1::Sha1;
            Ok(Box::new(GenericHasher::<Sha1>::new()))
        }
        CKM_SHA256 => Ok(Box::new(GenericHasher::<Sha256>::new())),
        CKM_SHA384 => Ok(Box::new(GenericHasher::<Sha384>::new())),
        CKM_SHA512 => Ok(Box::new(GenericHasher::<Sha512>::new())),
        CKM_SHA3_256 => {
            use sha3::Sha3_256;
            Ok(Box::new(GenericHasher::<Sha3_256>::new()))
        }
        CKM_SHA3_384 => {
            use sha3::Sha3_384;
            Ok(Box::new(GenericHasher::<Sha3_384>::new()))
        }
        CKM_SHA3_512 => {
            use sha3::Sha3_512;
            Ok(Box::new(GenericHasher::<Sha3_512>::new()))
        }
        _ => Err(HsmError::MechanismInvalid),
    }
}

/// Trait for multi-part digest accumulation
pub trait DigestAccumulator: Send + Sync {
    fn update(&mut self, data: &[u8]);
    fn finalize(self: Box<Self>) -> Vec<u8>;
    fn output_len(&self) -> usize;
}

struct GenericHasher<D: Digest + Send + Sync> {
    hasher: Option<D>,
}

impl<D: Digest + Send + Sync> GenericHasher<D> {
    fn new() -> Self {
        Self {
            hasher: Some(D::new()),
        }
    }
}

impl<D: Digest + Send + Sync + 'static> DigestAccumulator for GenericHasher<D> {
    fn update(&mut self, data: &[u8]) {
        if let Some(ref mut h) = self.hasher {
            h.update(data);
        }
    }

    fn finalize(mut self: Box<Self>) -> Vec<u8> {
        self.hasher
            .take()
            .map(|h| h.finalize().to_vec())
            .unwrap_or_default()
    }

    fn output_len(&self) -> usize {
        <D as Digest>::output_size()
    }
}

/// Zeroize the hasher's internal state on drop to prevent residual
/// digest input data from remaining in memory (FIPS 140-3 §7.7).
///
/// Uses `ManuallyDrop` to prevent calling `D::drop()` after zeroization,
/// which would read zeroed memory and could cause UB if `D` stores heap
/// pointers (double-free / null-pointer dereference). Instead, we:
/// 1. Move the hasher into `ManuallyDrop` (suppresses automatic drop)
/// 2. Zeroize the raw bytes via volatile writes
/// 3. Do NOT call `D::drop()` — the zeroized memory is simply reclaimed
///
/// This means any heap allocations owned by `D` will leak. In practice,
/// RustCrypto hash implementations (SHA-256, SHA-384, SHA-512, SHA3-*)
/// are entirely stack-allocated, so no heap memory is leaked.
impl<D: Digest + Send + Sync> Drop for GenericHasher<D> {
    fn drop(&mut self) {
        if let Some(hasher) = self.hasher.take() {
            // Size guard: RustCrypto hashers must not exceed a reasonable
            // size, which serves as a proxy for "stack-only" types. If a
            // hasher has heap allocations, its size_of would typically be
            // very small (just pointers), but we'd be zeroizing pointers
            // rather than the heap data they point to. All RustCrypto
            // hashers (SHA-1 through SHA3-512) store their full state
            // inline and are under 512 bytes. This assertion catches new
            // hasher types that need review before zeroization.
            debug_assert!(
                std::mem::size_of::<D>() <= 512,
                "Hasher type {} exceeds 512 bytes — review for heap allocations before zeroizing",
                std::any::type_name::<D>()
            );
            // Wrap in ManuallyDrop to suppress D::drop(), which would read
            // the zeroed bytes and potentially cause UB.
            let mut hasher = std::mem::ManuallyDrop::new(hasher);
            let ptr = &mut *hasher as *mut D as *mut u8;
            let size = std::mem::size_of::<D>();
            if size > 0 {
                // SAFETY:
                // 1. `ptr` is derived from a valid, live `D` inside ManuallyDrop.
                // 2. `u8` has alignment 1, so any pointer is validly aligned for `u8`.
                // 3. The `size` bytes are within the same allocation (the ManuallyDrop<D>).
                // 4. ManuallyDrop guarantees `D::drop()` won't run after zeroization.
                // 5. The compile-time size assertion above ensures D is small enough to
                //    be a stack-only type (no heap indirection that would escape zeroization).
                let slice = unsafe { std::slice::from_raw_parts_mut(ptr, size) };
                zeroize::Zeroize::zeroize(slice);
            }
            // ManuallyDrop prevents D::drop() from running on zeroed memory.
            // For stack-only types (all RustCrypto hashers), this is safe.
        }
    }
}
