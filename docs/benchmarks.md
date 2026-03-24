# Craton HSM Benchmarks

Craton HSM includes two benchmark suites that measure cryptographic performance at different abstraction levels. This document covers methodology, baseline results, the nine optimizations applied, before/after comparisons, and a three-way head-to-head against SoftHSMv2.

All measurements on Windows 11, x86_64, single-threaded, `--release` with LTO and `target-cpu=native`. Median values reported via Criterion.rs (100 samples; 10 for RSA keygen).

## Benchmark Suites

### 1. Direct Rust API (`benches/crypto_bench.rs`)

Measures raw cryptographic throughput by calling Rust functions directly — no FFI overhead, no session management, no PKCS#11 ABI marshalling.

```bash
RUSTFLAGS="-C target-cpu=native" cargo bench --bench crypto_bench
```

Backend comparison benchmarks (RustCrypto vs aws-lc-rs) run automatically when `craton_hsm-awslc` is available as a dev-dependency.

### 2. PKCS#11 C ABI (`benches/pkcs11_abi_bench.rs`)

Measures end-to-end performance through the PKCS#11 C ABI — the same code path that real consumers (OpenSSL, Java SunPKCS11, NSS) use. Loads `libcraton_hsm.so`/`craton_hsm.dll` via `libloading` and calls through `C_GetFunctionList`.

```bash
RUSTFLAGS="-C target-cpu=native" cargo bench --bench pkcs11_abi_bench
```

Each benchmark iteration includes the full `C_*Init` + `C_*` pair (e.g., `C_SignInit` + `C_Sign`), which reflects real-world usage patterns. For the SoftHSMv2 comparison, both libraries are loaded in the same process and run identical operations within the same Criterion report, eliminating environmental variance.

| Benchmark Group | Operation | Data Size |
|----------------|-----------|-----------|
| `pkcs11_rsa_sign_2048` | RSA PKCS#1 v1.5 + SHA-256 sign | 32 B |
| `pkcs11_rsa_verify_2048` | RSA PKCS#1 v1.5 + SHA-256 verify | 32 B |
| `pkcs11_ecdsa_p256_sign` | ECDSA P-256 sign (raw hash) | 32 B |
| `pkcs11_ecdsa_p256_verify` | ECDSA P-256 verify (raw hash) | 32 B |
| `pkcs11_aes_gcm_encrypt_4kb` | AES-256-GCM encrypt | 4 KB |
| `pkcs11_aes_gcm_decrypt_4kb` | AES-256-GCM decrypt | 4 KB |
| `pkcs11_sha256_digest_4kb` | SHA-256 digest | 4 KB |
| `pkcs11_keygen_rsa_2048` | RSA-2048 key pair generation | -- |
| `pkcs11_keygen_ec_p256` | EC P-256 key pair generation | -- |
| `pkcs11_keygen_aes_256` | AES-256 symmetric key generation | -- |

---

## Phase 1: Baseline (Direct Rust API, RustCrypto)

Initial measurements before any optimization work, using the RustCrypto backend:

| Operation | Baseline |
|-----------|----------|
| RSA-2048 Sign | 1.806 ms |
| RSA-2048 Verify | 206.2 us |
| RSA-4096 Sign | 11.94 ms |
| ECDSA P-256 Sign | 339.7 us |
| ECDSA P-256 Verify | 289.6 us |
| Ed25519 Sign | 45.99 us |
| Ed25519 Verify | 47.44 us |
| AES-GCM Encrypt 256B | 1.396 us |
| AES-GCM Encrypt 4KB | 5.970 us |
| AES-GCM Encrypt 64KB | 62.35 us |
| AES-GCM Decrypt 256B | 0.589 us |
| AES-GCM Decrypt 4KB | 3.822 us |
| AES-GCM Decrypt 64KB | 58.05 us |
| SHA-256 4KB | 18.63 us |
| SHA-512 4KB | 10.45 us |
| ML-KEM-512 Encap | 56.11 us |
| ML-KEM-768 Encap | 82.43 us |
| ML-KEM-512 Decap | 97.04 us |
| ML-KEM-768 Decap | 179.9 us |

---

## Phase 2: Optimizations

Nine targeted optimizations were applied across two layers: the cryptographic backend and the PKCS#11 ABI layer.

### Crypto-Layer Optimizations

1. **RSA Private Key Cache** (`src/crypto/sign.rs`): Parsed `RsaPrivateKey` structs are cached in a lock-free DashMap keyed by SHA-256(DER). Avoids expensive PKCS#8 DER parsing + bignum reconstruction on every sign operation. Cache holds up to 64 keys with full eviction on overflow.

2. **GCM Key ID Fast Path** (`src/crypto/encrypt.rs`): For 32-byte AES-256 keys, the GCM nonce counter lookup uses the raw key bytes directly as the DashMap key instead of computing SHA-256(key). Eliminates a hash computation on every AES-GCM encrypt. AES-GCM encrypt 256B dropped from 1.396 us to 0.600 us (**57% faster**).

3. **Compile-time Tracing Elimination**: Added `tracing/max_level_info` and `tracing/release_max_level_info` features to eliminate `debug!` and `trace!` instrumentation at compile time in release builds.

4. **`target-cpu=native`**: Enables hardware-specific instruction selection (AES-NI, AVX2, ADX, MULX). ML-KEM-768 decapsulation improved 25% (179.9 us to 135.3 us) from AVX2 codegen.

5. **aws-lc-rs Backend** (`awslc-backend` feature / `craton_hsm-awslc` crate): FIPS 140-3 validated backend using AWS-LC's assembly-optimized primitives. RSA-2048 verify: 8.3x faster. ECDSA P-256 verify: 4.5x faster. RSA-2048 keygen: 2.3x faster.

### Crypto-Layer Results (Direct Rust API)

| Operation | Baseline | Optimized | Improvement |
|-----------|----------|-----------|-------------|
| AES-GCM Encrypt 256B | 1.396 us | 0.600 us | **57% faster** |
| AES-GCM Encrypt 4KB | 5.970 us | 3.633 us | **39% faster** |
| AES-GCM Encrypt 64KB | 62.35 us | 56.32 us | **10% faster** |
| AES-GCM Decrypt 256B | 0.589 us | 0.510 us | **13% faster** |
| AES-GCM Decrypt 4KB | 3.822 us | 3.552 us | 7% faster |
| SHA-256 4KB | 18.63 us | 17.24 us | 7% faster |
| ML-KEM-768 Decap | 179.9 us | 135.3 us | **25% faster** |
| ML-KEM-512 Decap | 97.04 us | 84.95 us | **12% faster** |
| ML-KEM-768 Encap | 82.43 us | 74.46 us | **10% faster** |
| Ed25519 Sign | 45.99 us | 43.79 us | 4.8% faster |

### Backend Comparison: RustCrypto vs aws-lc-rs (Direct Rust API)

Both backends benchmarked with `target-cpu=native`. The aws-lc-rs backend uses assembly-optimized routines (AES-NI, AVX2, Montgomery multiplication).

| Operation | RustCrypto | aws-lc-rs | Speedup |
|-----------|-----------|-----------|---------|
| RSA-2048 Sign | 2.001 ms | 1.628 ms | **1.2x** |
| RSA-2048 Verify | 222.0 us | 26.79 us | **8.3x** |
| ECDSA P-256 Sign | 331.6 us | 291.8 us | **1.1x** |
| ECDSA P-256 Verify | 298.3 us | 66.44 us | **4.5x** |
| AES-GCM Decrypt 4KB | 3.590 us | 2.015 us | **1.8x** |
| SHA-256 4KB | 16.63 us | 11.52 us | **1.4x** |
| SHA-512 4KB | 10.14 us | 8.362 us | **1.2x** |
| RSA-2048 Keygen | 214.7 ms | 91.42 ms | **2.3x** |
| EC P-256 Keygen | 184.4 us | 157.3 us | **1.2x** |

**Note on AES-GCM Encrypt**: The aws-lc-rs encrypt path includes random nonce generation via SystemRandom (OS entropy call per encrypt), while RustCrypto uses a cached deterministic counter nonce. The decrypt path (no nonce generation) shows the true algorithmic difference: aws-lc-rs is 1.8x faster.

### ABI-Layer Optimizations

After optimizing the crypto layer, the PKCS#11 ABI layer became the dominant bottleneck. RSA-2048 verify took 26.79 us in direct Rust API calls but 291.3 us through the C ABI — a 10.8x overhead. We traced the hot path and applied four targeted fixes.

6. **Async Audit Logging** (`src/audit/log.rs`): Every `C_Sign`, `C_Verify`, `C_Encrypt` call was synchronously computing a SHA-256 hash chain, serializing JSON, and calling `fsync()` for the audit trail. Moved all expensive work to a background thread via an `mpsc` channel. The `record()` method now completes in sub-microsecond. Delivered 48-55% improvement for fast operations like AES-GCM and SHA-256 where audit overhead previously dominated.

7. **Cached Object in ActiveOperation** (`src/session/session.rs`): Both `C_*Init` and the corresponding `C_*` completion function were re-fetching the key object from a DashMap on every call. `C_*Init` now caches the `Arc<RwLock<StoredObject>>` in the `ActiveOperation` state, so completion functions skip the second DashMap lookup entirely.

8. **Thread-Local HSM Reference** (`src/pkcs11_abi/functions.rs`): Every C_* function called `get_hsm()`, which locked a global mutex and cloned an `Arc<HsmCore>`. For a typical Init+Operation pair, that was two mutex acquisitions. Added a thread-local cache with a generation counter bumped on `C_Initialize`/`C_Finalize`. The fast path now avoids the mutex entirely.

9. **parking_lot Mutex for HSM Global** (`src/pkcs11_abi/functions.rs`): Replaced `std::sync::Mutex` with `parking_lot::Mutex` for the global HSM singleton. Lower uncontended overhead (spin-then-park vs immediate syscall).

### ABI-Layer Results (Before/After, PKCS#11 C ABI)

All three implementations shown. Optimizations affect only Craton HSM; SoftHSMv2 numbers from the same benchmark runs for reference.

| Operation | RustCrypto Before | RustCrypto After | Improvement | aws-lc-rs Before | aws-lc-rs After | Improvement | SoftHSMv2 |
|-----------|------------------|-----------------|-------------|-----------------|----------------|-------------|-----------|
| RSA-2048 Sign | 3.566 ms | 2.558 ms | **28%** | 2.515 ms | 1.837 ms | **27%** | 1.522 ms |
| RSA-2048 Verify | 350.3 us | 303.5 us | **13%** | 291.3 us | 251.0 us | **14%** | 37.82 us |
| ECDSA P-256 Sign | 707.6 us | 511.5 us | **28%** | 430.6 us | 363.2 us | **16%** | 89.10 us |
| ECDSA P-256 Verify | 830.3 us | 506.5 us | **39%** | 481.8 us | 338.0 us | **30%** | 109.1 us |
| SHA-256 Digest 4KB | 42.48 us | 26.0 us | **39%** | 32.29 us | 15.58 us | **52%** | 9.90 us |
| AES-GCM Encrypt 4KB | 8.797 us | 6.173 us | **30%** | 8.424 us | 4.419 us | **48%** | — |
| AES-GCM Decrypt 4KB | 12.57 us | 5.605 us | **55%** | 9.063 us | 4.094 us | **55%** | — |
| RSA-2048 Keygen | 334.8 ms | 313.6 ms | **6%** | 200.3 ms | 208.6 ms | ~ | 80.99 ms |
| EC P-256 Keygen | 1.467 ms | 824.4 us | **44%** | 978.5 us | 824.9 us | **16%** | 224.5 us |
| AES-256 Keygen | 27.10 us | 18.83 us | **31%** | 20.15 us | 17.79 us | **12%** | 90.63 us |

Key wins: SHA-256 digest improved 52%, AES-GCM decrypt improved 55% — dominated by eliminating synchronous audit logging overhead (SHA-256 hash chain + file I/O per call). ECDSA P-256 verify improved 39% (RustCrypto) from combined async audit + cached object lookup.

---

## Phase 3: SoftHSMv2 Head-to-Head

Three-way PKCS#11 C ABI comparison: Craton HSM (RustCrypto backend), Craton HSM (aws-lc-rs FIPS backend), and SoftHSMv2 2.6.1. All measurements through `C_GetFunctionList` with dynamically loaded shared libraries, same machine, same Criterion harness. All Craton HSM optimizations applied.

| Operation | Craton HSM (RustCrypto) | Craton HSM (aws-lc-rs) | SoftHSMv2 | Best vs SoftHSM |
|-----------|---------------------|--------------------:|----------:|:----------------|
| RSA-2048 Sign | 2.558 ms | **1.837 ms** | 1.522 ms | SoftHSM 1.2x |
| RSA-2048 Verify | 303.5 us | 251.0 us | **37.82 us** | SoftHSM 6.6x |
| ECDSA P-256 Sign | 511.5 us | 363.2 us | **89.10 us** | SoftHSM 4.1x |
| ECDSA P-256 Verify | 506.5 us | 338.0 us | **109.1 us** | SoftHSM 3.1x |
| SHA-256 Digest 4KB | 26.0 us | 15.58 us | **9.90 us** | SoftHSM 1.6x |
| AES-GCM Encrypt 4KB | 6.173 us | **4.419 us** | — | Craton HSM only |
| AES-GCM Decrypt 4KB | 5.605 us | **4.094 us** | — | Craton HSM only |
| RSA-2048 Keygen | 313.6 ms | 208.6 ms | **80.99 ms** | SoftHSM 2.6x |
| EC P-256 Keygen | 824.4 us | 824.9 us | **224.5 us** | SoftHSM 3.7x |
| AES-256 Keygen | **18.83 us** | **17.79 us** | 90.63 us | **Craton HSM 5.1x** |

**Bold** = best result per row. Median values reported.

### Analysis

**Where Craton HSM wins:**
- **AES-256 key generation: 5.1x faster** — Craton HSM uses direct OS entropy (`SystemRandom`), while SoftHSMv2 goes through Botan's DRBG layer with additional overhead
- **AES-GCM encryption/decryption** — SoftHSMv2 does not support null-parameter GCM (requires explicit `CK_GCM_PARAMS`), so no direct comparison is possible

**Where SoftHSMv2 wins:**
- **RSA-2048 Verify: 6.6x faster** — Botan's assembly-optimized Montgomery multiplication with ADX/MULX instructions
- **ECDSA P-256 Sign: 4.1x faster** — Botan uses precomputed point tables and wNAF scalar multiplication
- **EC P-256 keygen: 3.7x faster** — Botan's EC scalar generation is heavily optimized
- **SHA-256 digest: 1.6x faster** — Botan uses platform-specific SHA-256 acceleration

**aws-lc-rs vs RustCrypto (same Craton HSM, through PKCS#11 ABI):**
- RSA-2048 Sign: **1.4x faster** with aws-lc-rs
- ECDSA P-256 Sign: **1.4x faster** with aws-lc-rs
- ECDSA P-256 Verify: **1.5x faster** with aws-lc-rs
- SHA-256 Digest: **1.7x faster** with aws-lc-rs
- AES-GCM Decrypt: **1.4x faster** with aws-lc-rs

### What This Means

Craton HSM is not the fastest software HSM on every operation. SoftHSMv2's Botan backend has years of assembly optimization behind it. But Craton HSM offers what SoftHSMv2 cannot: memory safety across 19,000 lines of Rust, post-quantum cryptography with nine PQC mechanisms, and a pluggable backend architecture. RSA-2048 sign is within 1.2x of SoftHSMv2. AES-GCM decrypt completes in 4.1 us. AES key generation is over 5x faster. And for post-quantum operations (ML-KEM encapsulation at 51.84 us, ML-DSA signing at 563.3 us), Craton HSM is the only PKCS#11 implementation with numbers to report.

---

## Post-Quantum Cryptography

PQC algorithms use pure-Rust implementations (ml-kem, ml-dsa crates) — no backend variation.

| Operation | Time |
|-----------|------|
| ML-DSA-44 Sign | 711.9 us |
| ML-DSA-65 Sign | 563.3 us |
| ML-DSA-44 Verify | 158.1 us |
| ML-DSA-65 Verify | 270.1 us |
| ML-KEM-512 Encap | 51.84 us |
| ML-KEM-768 Encap | 74.46 us |
| ML-KEM-512 Decap | 84.95 us |
| ML-KEM-768 Decap | 135.3 us |

---

## Running Benchmarks

### Craton HSM Only

```bash
# Direct Rust API
RUSTFLAGS="-C target-cpu=native" cargo bench --bench crypto_bench

# PKCS#11 C ABI (RustCrypto backend)
RUSTFLAGS="-C target-cpu=native" cargo bench --bench pkcs11_abi_bench

# PKCS#11 C ABI (aws-lc-rs backend)
RUSTFLAGS="-C target-cpu=native" cargo bench --bench pkcs11_abi_bench \
    --features awslc-backend --no-default-features
```

### With SoftHSMv2 Comparison

```bash
# Linux
SOFTHSM2_LIB=/usr/lib/softhsm/libsofthsm2.so \
    RUSTFLAGS="-C target-cpu=native" cargo bench --bench pkcs11_abi_bench

# macOS
SOFTHSM2_LIB=$(brew --prefix softhsm)/lib/softhsm/libsofthsm2.so \
    RUSTFLAGS="-C target-cpu=native" cargo bench --bench pkcs11_abi_bench

# Windows
SOFTHSM2_LIB=C:/SoftHSM2/SoftHSM2/lib/softhsm2-x64.dll \
    RUSTFLAGS="-C target-cpu=native" cargo bench --bench pkcs11_abi_bench
```

### Installing SoftHSMv2

```bash
# Linux (Debian/Ubuntu)
sudo apt-get install softhsm2

# macOS
brew install softhsm

# Windows (portable ZIP)
# Download from https://github.com/nickluck8/SoftHSMv2-x64-MinGW/releases
# Extract to C:\SoftHSM2\
```

The benchmark harness automatically:
1. Creates a token directory at `target/bench-tokens/`
2. Generates a `softhsm2.conf` with absolute paths
3. Initializes a SoftHSMv2 token with the same PINs as Craton HSM
4. Runs identical operations through both libraries

### Viewing Reports

```bash
open target/criterion/report/index.html    # macOS
xdg-open target/criterion/report/index.html  # Linux
start target/criterion/report/index.html     # Windows
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CRATON_HSM_LIB` | Path to Craton HSM shared library | Auto-detected in `target/release/` |
| `SOFTHSM2_LIB` | Path to SoftHSMv2 shared library | Not set (comparison disabled) |
| `SOFTHSM2_CONF` | SoftHSMv2 config file | Set automatically by harness |

## Known Limitations

- **Single-threaded**: All benchmarks run single-threaded due to PKCS#11's global singleton state
- **Warm cache**: Keys are pre-generated in setup; measured operations benefit from warm CPU caches
- **No AES-GCM comparison**: AES-GCM is not compared with SoftHSMv2 due to differing parameter conventions
- **RSA keygen variance**: RSA key generation time depends on prime number luck; results show high variance
- **Release mode only**: `cargo bench` uses `--release` automatically; debug-mode numbers are not meaningful
