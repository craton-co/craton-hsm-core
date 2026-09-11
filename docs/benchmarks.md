# Craton HSM Benchmarks

Craton HSM includes two benchmark suites that measure cryptographic performance at different abstraction levels. This document covers methodology, baseline results, the nine optimizations applied, before/after comparisons, and a three-way head-to-head against SoftHSMv2.

Two reference hosts are used, and the difference between them matters for
anything I/O- or SHA-256-bound:

| Ref | Host | Notes |
|-----|------|-------|
| **L** | Windows 11, Intel i7-8550U (4c/8t, mobile) | **No SHA-NI**; SATA-class storage; thermally throttling |
| **S** | Ubuntu 24.04, AMD EPYC 9V45 (8 vCPU) | SHA-NI, AVX2; NVMe; shared host |

Unless stated otherwise, figures are from **L** and are single-threaded,
`--release` with LTO and `target-cpu=native`, medians via Criterion.rs (100
samples; 10 for RSA keygen). SHA-256 through the ABI costs 28-56 us on L and
2.4 us on S for the same 4 KB input -- roughly 15x, almost entirely SHA-NI. Do
not compare absolute numbers across hosts.

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
| `pkcs11_find_objects_selective` | `C_FindObjects`, CKA_LABEL matching 1 of 257 | -- |
| `pkcs11_find_objects_by_class` | `C_FindObjects`, CKA_CLASS matching all secret keys | -- |
| `pkcs11_aes_gcm_encrypt_sizes` | AES-256-GCM encrypt | 256 B, 4 KB, 64 KB, 1 MB |
| `pkcs11_sha256_digest_sizes` | SHA-256 digest | 256 B, 4 KB, 64 KB, 1 MB |
| `pkcs11_concurrent_encrypt` | AES-256-GCM encrypt across 1/2/4/8 sessions | 4 KB |
| `pkcs11_concurrent_sign` | ECDSA P-256 sign across 1/2/4/8 sessions | 32 B |

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
| SHA-256 4KB | 16.63 us | 11.52 us | **1.4x** (host L only — inverts on a SHA-NI CPU, see below) |
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

---

## Phase 4: Audit Trail Throughput

The audit trail sits on the critical path of most PKCS#11 operations —
`C_Sign`, `C_Verify`, `C_Encrypt`, `C_Decrypt`, key generation, and the object
and session calls each emit an event (`C_Digest` notably does not) — so its
throughput bounds the rate of audited operations. Optimisation #6 above moved
the work off the caller's thread, which fixed *latency* — but the worker itself
still opened the log file, serialised one event, wrote it, and `fsync`-ed once
per event. That capped the whole module at roughly **760 operations per second**
no matter how fast the cryptography was, and nothing measured it.

Three changes addressed it:

10. **Persistent log file handle** (`src/audit/log.rs`): the worker opens the
    audit file once and keeps it open, rather than calling `open()` +
    `metadata()` per event. On Windows this also removes one ACL-hardening
    syscall per event.

11. **Group commit** (`src/audit/log.rs`): the worker blocks for one command,
    then drains everything already queued behind it, serialises the whole batch
    into one buffer, and issues a single `write` + a single `fsync`. This is not
    a durability trade — a `record_sync` caller is still released only after its
    own event is on stable storage; the `fsync` is simply shared with every
    event that was already waiting.

12. **Canonical binary chain encoding** (`src/audit/log.rs`): the chain hash
    input changed from `serde_json` to a fixed-width, length-prefixed, injective
    binary encoding (`AUDIT_LOG_FORMAT_VERSION = 1`). This shrinks the hashed
    payload from ~148 bytes to ~40 and removes a per-event allocation. The
    **on-disk NDJSON line is unchanged** — it is an interop contract with SIEM
    consumers — and the verifier dispatches on each record's own
    `format_version`, so logs written by earlier builds still verify and a file
    containing both versions verifies end to end.

### Audit Results

Medians of six runs, alternating which binary is measured first and cooling
between them. See "Measurement hygiene" below for why that matters.

| Measurement | Before | After | Improvement |
|-------------|--------|-------|-------------|
| Sustained async throughput | 1319 us/event | 6.58 us/event | **200x** (758 → 152,000 events/s) |
| `record_sync` durable write | 1482 us | 633 us | **57% faster** |
| Per-event CPU (chain hash + locks) | 3.76 us | 1.22 us | **68% faster** |

The first row is the one that matters: it removes a ceiling that sat below every
cryptographic operation in the module.

These figures come from a dedicated A/B harness that ran a "before" and an
"after" binary alternately against the same workload, which is the only way to
compare two builds credibly on this machine.

### The same effect through the PKCS#11 ABI

The figures above measure the audit API directly. Reproducing the effect through
the C ABI needs care, because **Criterion's reported per-iteration time does not
show it at all**.

`record()` only enqueues; the worker owes the write. A benchmark that issues N
audited operations and stops has not paid for them yet — the queue drains when
the module is finalised, outside the measured region. So Criterion reports the
same ~4 us per `C_Encrypt` for both builds while one of them still owes several
seconds of `fsync`.

Measure the **whole process** instead. It ends when the audit worker has drained,
so it accounts for the work actually generated:

AES-256-GCM 4 KB, `--measurement-time 5`, total wall clock, median of 5, one
harness with only the library swapped:

| Arm | Wall clock | |
|-----|-----------:|--|
| before (A) | 16.11 s | |
| before (B) | 16.57 s | control, +2.9% |
| after | 11.08 s | **1.45x faster** (−31%) |

The control — the same build measured as though it were two — is +2.9%, so a 31%
difference is comfortably real.

#### This is strongly host-dependent

The size of the effect tracks `fsync` latency, so it varies enormously with
storage:

| Host | Audit events/s sustained (before) |
|------|---------------------------------:|
| Laptop, SATA-class storage, no SHA-NI | ~760 |
| Server, NVMe, SHA-NI | ~13,700 |

On the laptop the worker fell so far behind that even a 30-second Criterion
window showed it (per-iteration time degraded 3.55x, versus 1.68x after). On the
NVMe server the worker keeps up well enough that the same window shows nothing —
1.04x versus 1.00x, inside the ±3% control. The cost has not disappeared; it has
moved into teardown, where the wall-clock method above finds it.

Use the wall-clock method. The window comparison only works on slow storage and
will read as a null result on a fast host.

#### Two ways to measure this wrongly

Both were hit while producing the numbers above, and both look like clean
refutations:

* **Benchmark an operation that is not audited.** `C_Digest` emits no audit
  event, so digest benchmarks are flat at every window length and every host.
* **Trust Criterion's per-iteration time.** It excludes the queued audit work,
  which on this workload is most of the cost.

---

## Backend Comparison on Host S (RustCrypto vs AWS-LC FIPS)

Measured through the PKCS#11 ABI on host **S** (AMD EPYC, SHA-NI, NVMe), one
harness with only the library swapped. RustCrypto is built with
`insecure-rustcrypto-rsa-private-ops` so that its RSA paths can run at all;
AWS-LC is `--no-default-features --features awslc-backend`.

| Operation | RustCrypto | AWS-LC | |
|-----------|-----------:|-------:|--|
| RSA-2048 sign | 1.453 ms | 610 us | **2.4x** |
| RSA-2048 verify | 160.1 us | 19.5 us | **8.2x** |
| RSA-2048 keygen | 121.8 ms | 78.6 ms | **1.5x** |
| ECDSA P-256 sign | 294.7 us | 178.8 us | **1.6x** |
| ECDSA P-256 verify | 231.3 us | 73.4 us | **3.2x** |
| EC P-256 keygen | 680.9 us | 418.6 us | **1.6x** |
| AES-GCM decrypt 4 KB | 3.643 us | 1.454 us | **2.5x** |
| SHA-256 4 KB | **2.331 us** | 2.717 us | RustCrypto 1.17x |

AWS-LC wins everything asymmetric, and RSA verify by 8.2x — closely matching the
8.3x recorded on host L.

**SHA-256 is the exception, and it inverts on this host.** The Phase 2 table
(measured on host L) shows AWS-LC 1.4x faster at SHA-256. On host S, RustCrypto
is 1.17x *faster*. The reason is SHA-NI: the `sha2` crate dispatches to the
hardware instruction at runtime, and on a CPU that has it there is nothing left
for hand-written assembly to win. Host L has no SHA-NI, so the comparison there
measured two software implementations.

Choose the backend for the asymmetric and AES numbers, not the digest one, and
be aware that any SHA-256 comparison you read is really a statement about the
CPU it was measured on.

### AWS-LC and RSA availability

The AWS-LC backend is also the answer to the RSA restriction described in
[troubleshooting.md](troubleshooting.md#rsa-operations-return-ckr_mechanism_invalid):
`CryptoBackend::supports_rsa_private_ops()` reports `true` for it, so
`C_GenerateKeyPair`, `C_Sign`, and `C_Decrypt` all work with RSA, as the table
above shows.

Note that before the power-on self-test was made capability-aware, an AWS-LC
release build failed `C_Initialize` for the same reason the RustCrypto one did —
the POST's RSA known-answer test called the RustCrypto signing path regardless of
the configured backend. The POST now runs its algorithm KATs against the
configured backend, so an AWS-LC deployment self-tests AWS-LC; it previously
tested RustCrypto regardless of what the module was about to use.

Multi-part RSA on this backend has its own scope caveat — signing works and runs
on AWS-LC, but through an API outside its FIPS-approved set, and verification
still uses RustCrypto. See
[fips-mode-guide.md](fips-mode-guide.md) before relying on it for a validated
deployment.

---

## Coverage Added

The suites originally measured single-threaded, fixed-size operations only.
Three gaps were closed, each because a whole class of regression was invisible
without it.

| Group | Operation | Why it exists |
|-------|-----------|---------------|
| `pkcs11_find_objects_selective` | `C_FindObjects` on a `CKA_LABEL` matching 1 of 257 objects | Object lookup was entirely unmeasured. This is the shape a consumer uses to resolve a named key before signing. |
| `pkcs11_find_objects_by_class` | `C_FindObjects` on `CKA_CLASS` matching every secret key | Complements the selective case: the result set is large, so handle marshalling is included, not just the scan. |
| `pkcs11_aes_gcm_encrypt_sizes` | AES-256-GCM, 256 B → 1 MB | Fixed-size benchmarks cannot separate a per-call regression from a per-byte one. |
| `pkcs11_sha256_digest_sizes` | SHA-256, 256 B → 1 MB | As above. |
| `pkcs11_concurrent_encrypt` | AES-256-GCM across 1, 2, 4, 8 sessions | Every other benchmark is single-threaded, so a new lock on a shared path is invisible to them. A flat curve here means contention. |
| `pkcs11_concurrent_sign` | ECDSA P-256 across 1, 2, 4, 8 sessions | As above, exercising the key-object read locks and signing-key cache instead. |
| `audit_record_*` | Audit trail, in-memory / to disk / synchronous | The module's throughput ceiling (see Phase 4). |

### Object Lookup

Measured against a token holding 257 labelled secret keys:

| Search | Matches | Time |
|--------|--------:|-----:|
| `CKA_LABEL` matching exactly one object | 1 | 32.1 us |
| `CKA_CLASS` matching every secret key | 257 | 31.9 us |

The two are the **same cost**, which is the point. `ObjectStore::find_objects`
deliberately scans every object and evaluates the full template against each,
including objects that will be filtered out, so the work does not vary with what
matches or with whether the caller is logged in — timing cannot reveal how many
private objects a token holds. The cost is therefore driven by store population
(~125 ns per object here), not by selectivity.

These benchmarks are **not** a prompt to add an attribute index. A selective
search served from an index would be far faster precisely because it stops
visiting non-matching objects, which is the property being protected. See
[performance-tuning.md](performance-tuning.md#4-optimisations-considered-and-rejected)
for why that would leak object existence to an unauthenticated caller.

### Payload Scaling

The fixed-size groups cannot distinguish a per-call regression from a per-byte
one. These curves can:

| Size | AES-256-GCM encrypt | | SHA-256 digest | |
|------|--------------------:|--:|---------------:|--:|
|      | time | throughput | time | throughput |
| 256 B | 6.38 us | 38 MiB/s | 3.49 us | 70 MiB/s |
| 4 KB | 11.9 us | 329 MiB/s | 37.1 us | 105 MiB/s |
| 64 KB | 189 us | 331 MiB/s | 564 us | 111 MiB/s |
| 1 MB | 4.33 ms | 231 MiB/s | 8.77 ms | 114 MiB/s |

At 256 B both are dominated by fixed per-call cost — session lookup, object
fetch, audit enqueue, FFI marshalling — which is why throughput is an order of
magnitude below the steady state. From 4 KB upward the per-byte cost dominates.
A change that moves the small-payload column but not the large one is a per-call
regression; the reverse is a primitive regression.

The SHA-256 ceiling of ~110 MiB/s is this host, not the implementation: it has no
SHA-NI. Expect several times that on a current server.

### Concurrency

`pkcs11_concurrent_encrypt` and `pkcs11_concurrent_sign` open one session per
thread and run 1, 2, 4, and 8 of them. They exist to catch a *scalability*
regression: every other group is single-threaded, so a new lock on a shared path
is invisible to them. A flat or inverted curve from 1 to 4 threads means
contention.

Absolute numbers are not published from this reference machine — a thermally
throttling 4-core laptop where the control measurement (see below) reaches ±170%
on these groups. Run them on a quiesced multi-core host.

#### A caution these benchmarks taught us

An early comparison of the audit group-commit change measured these groups as
part of a full-suite run and reported improvements of 58x and 23x. Re-measuring
each group in its **own process**, against a control, collapsed the difference to
1.0x within a very wide noise band. The first result was an artifact of position
in the suite, not a property of concurrent operation.

The cause is worth understanding, because it is a real effect measured wrongly.
Before group commit the audit worker sustained roughly 760 events/second. A full
benchmark run generates events far faster than that, so by the time the
concurrency groups ran — near the end of the suite, after key generation and
hundreds of thousands of crypto iterations — the worker was still draining a
backlog accumulated by every group before it, and its disk I/O contended with
whatever was being measured. Start a fresh process and there is no backlog to
contend with, and a single group's short measurement window does not build one.

So the throughput ceiling is real (see Phase 4), and a long-running deployment
does hit it. But attributing it to whichever benchmark happened to run last is
wrong, and a whole-suite A/B will do exactly that. Measure the audit path
directly, or isolate the group.

---

## Measurement Hygiene

The numbers above were produced on a laptop-class CPU, and the first attempt at
an A/B comparison produced a result that was entirely an artifact of the
machine. It is worth recording how, because the same trap applies to anyone
reproducing these figures.

Running "before" and "after" binaries in that order, repeatedly, made the
"after" binary look **10% slower** on EC key generation and 40% slower on RSA
key generation — because it was always measured second, on a hotter package. The
same comparison with the order alternated and an 8-second cooldown between runs
showed both were within noise of each other. A separate measurement taken
immediately after a long compile read 3x *faster* than the identical
measurement on a warm machine.

For a comparison to mean anything:

- alternate which binary runs first, and take medians across several pairs;
- insert a cooldown between runs;
- fix the CPU governor to `performance` and disable turbo where possible;
- never compare a number from one session against a number from another;
- **measure a control**: run the *unchanged* build twice, as though it were two
  different builds, and compare those. That is your noise floor. On this host it
  is around ±20% for micro-benchmarks, which means a 15% "improvement" is not a
  result. Every claim in this document either clears its control by a wide
  margin or is labelled inconclusive.

This machine also lacks the SHA-NI instruction set (Intel added it to
mainstream Core parts only with Ice Lake), which makes every SHA-256-bound
figure several times worse than it would be on a current server. Absolute
values here are not portable; ratios within a single session are.

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

### Prerequisites

The PKCS#11 ABI suite loads the built shared library and calls `C_Initialize`,
which runs the power-on self-test. An unsigned local build has no integrity
signature, so the POST refuses to start unless the development bypass is set:

```bash
export CRATON_HSM_INTEGRITY_BYPASS=unsafe-dev-only
```

This is a development-only escape hatch — never set it in production. CI sets it
globally for the same reason.

**RSA groups are skipped on a default release build.** Release builds provide no
RustCrypto RSA private-key capability (RUSTSEC-2023-0071 / Marvin), so RSA
signing *and* key-pair generation are refused; key-pair generation runs a
pairwise consistency test that signs. Both suites detect this, print a note, and
run every other group. To measure RSA, use the hardened backend:

```bash
cargo bench --bench pkcs11_abi_bench --no-default-features --features awslc-backend
```

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

- **Mostly single-threaded**: all groups except `pkcs11_concurrent_*` run single-threaded. The concurrent groups open one session per thread against the same token; PKCS#11's global singleton state means they cannot be run against two libraries simultaneously
- **Warm cache**: Keys are pre-generated in setup; measured operations benefit from warm CPU caches
- **No AES-GCM comparison**: AES-GCM is not compared with SoftHSMv2 due to differing parameter conventions
- **RSA keygen variance**: RSA key generation time depends on prime number luck; results show high variance
- **Release mode only**: `cargo bench` uses `--release` automatically; debug-mode numbers are not meaningful
- **Host-dependent**: the reference machine has no SHA-NI, so SHA-256-bound figures are several times worse than on a current server. See "Measurement Hygiene" above before comparing across machines or sessions
