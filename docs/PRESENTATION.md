# Craton HSM — A Post-Quantum Software HSM in Rust

---

## What is Craton HSM?

A **PKCS#11 v3.0-compliant Software HSM** written entirely in Rust.

- Drop-in replacement for SoftHSMv2
- Dynamically loadable shared library (`.so` / `.dll` / `.dylib`)
- 41 cryptographic mechanisms including 9 post-quantum
- 617+ passing tests across 33 suites (including 46 PKCS#11 conformance tests), zero `unsafe` in crypto paths
- Dual crypto backend: RustCrypto (default) or aws-lc-rs (FIPS 140-3 validated)
- Persistent storage with per-object encryption (redb + AES-256-GCM)
- gRPC daemon, admin CLI, Kubernetes-ready

---

## Why Build a Software HSM in Rust?

### The problem with C/C++ HSM implementations

SoftHSMv2 (the de facto open-source software HSM) is written in C++. C++ HSM code is vulnerable to:

- Buffer overflows in attribute parsing
- Use-after-free in session/object lifecycle
- Double-free in error paths
- Data races in concurrent access
- Memory leaks of key material

These are not theoretical — they are the root cause of real CVEs in cryptographic software.

### Rust eliminates these by construction

| Vulnerability class | C++ status | Rust status |
|---------------------|-----------|-------------|
| Buffer overflow | Runtime crash or exploit | Compile-time prevented |
| Use-after-free | Runtime crash or exploit | Compile-time prevented |
| Double-free | Runtime crash or exploit | Compile-time prevented |
| Null pointer deref | Runtime crash | Compile-time prevented (`Option<T>`) |
| Data races | Silent corruption | Compile-time prevented (borrow checker) |
| Memory leak of keys | Manual discipline | `ZeroizeOnDrop` automatic |

---

## Architecture at a Glance

```
  Applications (OpenSSL, Java, SSH, custom)
       |              |              |
    dlopen         gRPC/TLS       CLI
    C ABI          (tonic)       (clap)
       |              |              |
       v              v              v
  ┌────────────────────────────────────┐
  |            HsmCore                 |
  |                                    |
  |  SessionManager   SlotManager      |
  |  ObjectStore      AuditLog         |
  |         CryptoEngine               |
  └────────────────────────────────────┘
```

Three consumption modes, one core engine.

---

## Algorithm Coverage

### Classical (32 mechanisms)

| Category | Algorithms |
|----------|-----------|
| Symmetric | AES-256 GCM, CBC, CTR, Key Wrap |
| RSA | 2048/3072/4096: PKCS#1 v1.5, PSS, OAEP |
| Elliptic curve | ECDSA P-256/P-384, Ed25519, ECDH |
| Hash | SHA-1, SHA-256/384/512, SHA3-256/384/512 |
| MAC | HMAC-SHA256/384/512 |
| KDF | PBKDF2-HMAC-SHA256 (600K iterations) |

### Post-Quantum (9 mechanisms)

| Algorithm | Standard | Use case |
|-----------|----------|----------|
| ML-DSA-44/65/87 | FIPS 204 | Digital signatures |
| ML-KEM-512/768/1024 | FIPS 203 | Key encapsulation |
| SLH-DSA-SHA2-128s/256s | FIPS 205 | Stateless hash-based signatures |
| Hybrid X25519 + ML-KEM-768 | Composite | Transitional hybrid KEM |

SoftHSMv2 has **zero** post-quantum support.

---

## Security Design

### 10 Invariants (enforced at every phase)

1. No panic crosses FFI boundary (`catch_unwind` on all exports)
2. No key bytes in logs (custom `Debug` prints `[REDACTED]`)
3. No key export when `SENSITIVE=true, EXTRACTABLE=false`
4. Constant-time PIN/HMAC comparison (`subtle::ConstantTimeEq`)
5. All key material zeroized on drop (`ZeroizeOnDrop`)
6. Session state machine is authoritative (5-state FSM)
7. Audit log written synchronously before function returns
8. SP 800-90A DRBG for all key material (`DrbgRng` adapter routes RSA/EC/Ed25519 through HMAC_DRBG)
9. No `unsafe` in crypto paths (all unsafe confined to ABI layer + mlock)
10. Generic errors to callers (never leak internal state)

### PIN Protection

| Property | Value |
|----------|-------|
| Algorithm | PBKDF2-HMAC-SHA256 |
| Iterations | 600,000 |
| Salt | 32 bytes (per-PIN, from OsRng) |
| Comparison | Constant-time |
| Lockout | Configurable (default: 10 attempts) |

### Audit Trail

Append-only log with chained SHA-256 hashes. Every modification, deletion, or reordering breaks the chain — making tampering detectable.

---

## FIPS 140-3 Readiness

### FIPS Approved Mode ✅

When `fips_approved_only = true` in `craton_hsm.toml`, the module restricts all operations to FIPS-approved algorithms only:
- `C_GetMechanismList` filters out non-approved mechanisms
- `C_SignInit`, `C_VerifyInit`, `C_EncryptInit`, `C_DecryptInit`, and all keygen functions validate mechanism policy
- Non-approved operations return `CKR_MECHANISM_INVALID`

### Power-On Self-Tests (17 tests: integrity + 16 KATs)

Run during `C_Initialize` — failure blocks all operations:

| # | Test | Type |
|---|------|------|
| 0 | Software integrity (HMAC-SHA256) | Module binary verification (§9.4) |
| 1-4 | SHA-256, SHA-384, SHA-512, SHA3-256 | NIST known-answer |
| 5-7 | HMAC-SHA256, HMAC-SHA384, HMAC-SHA512 | RFC 4231 known-answer |
| 8 | AES-256-GCM | Roundtrip + known-answer decrypt |
| 9-10 | AES-256-CBC, AES-256-CTR | Known-answer (hardcoded expected ciphertext) |
| 11 | RSA 2048 PKCS#1 v1.5 | Sign/verify roundtrip |
| 12 | ECDSA P-256 | Sign/verify roundtrip |
| 13 | ML-DSA-44 | Sign/verify roundtrip |
| 14 | ML-KEM-768 | Encapsulate/decapsulate roundtrip |
| 15 | RNG | Entropy + continuous test (SP 800-90B §4.3) |
| 16 | HMAC_DRBG | NIST CAVP known-answer |

**KAT design note (v0.9.1):** AES-CBC and AES-CTR KATs use genuine known-answer tests with hardcoded expected ciphertexts — not circular encrypt/decrypt roundtrips. This catches symmetric implementation bugs that roundtrip tests would miss.

### Pairwise Consistency Tests (§9.6) ✅

Every key pair generation triggers a sign/verify (or encap/decap) roundtrip before returning the keys:
- RSA (PKCS#1 v1.5), ECDSA P-256/P-384, Ed25519
- ML-DSA-44/65/87, SLH-DSA-SHA2-128s/256s
- ML-KEM-768 (encapsulate/decapsulate)

Failure sets `POST_FAILED` and blocks all subsequent operations.

### Algorithm Indicator (IG 2.4.C) ✅

Every crypto operation records `fips_approved: bool` in the audit log. The `last_operation_fips_approved` field on `Session` and `CKA_VENDOR_FIPS_APPROVED` attribute enable runtime indicator querying.

### Intermediate Zeroization (§7.7) ✅

All `ActiveOperation` data buffers and mechanism parameters use `Zeroizing<Vec<u8>>` from the `zeroize` crate — intermediate plaintext is automatically zeroed on drop, even in error paths.

### Software Integrity Test (§9.4) ✅

HMAC-SHA256 of the module binary verified at POST time against a `.hmac` sidecar file. Tools provided for computing the integrity HMAC: `compute-integrity-hmac.sh` (Linux/macOS) and `compute-integrity-hmac.ps1` (Windows).

### SP 800-90A DRBG ✅

HMAC_DRBG (HMAC-SHA256) with prediction resistance replaces direct OsRng usage. All key generation — including RSA, EC P-256/P-384, and Ed25519 — routed through the DRBG via a `DrbgRng` wrapper implementing `rand::CryptoRng`. NIST CAVP known-answer test (KAT #16) validates correctness.

### Per-Key AES-GCM Nonce Counters ✅ (v0.9.1)

AES-GCM encryption uses per-key nonce counters (via `DashMap<u64, AtomicU64>`, keyed by SHA-256 hash of key material) to enforce the NIST SP 800-38D birthday bound of 2^31 encryptions per key with random 96-bit nonces. Counters reset on `C_Initialize`.

### SP 800-57 Key Lifecycle ✅

Date-based key lifecycle states enforce operational policies:
- **Pre-activation**: before `CKA_START_DATE` — no operations
- **Active**: normal use — all permitted operations
- **Deactivated**: after `CKA_END_DATE` — verify/decrypt only
- **Compromised**: manually marked — all operations blocked

### FIPS Crypto Backend

Two backends available via feature flags:

| Backend | Feature | Status |
|---------|---------|--------|
| RustCrypto (default) | `rustcrypto-backend` | Pure Rust, not FIPS-certified |
| AWS-LC (aws-lc-rs) | `awslc-backend` | FIPS 140-3 validated module |

Select via `algorithms.crypto_backend = "awslc"` in `craton_hsm.toml`.

### Remaining gaps for Level 1 certification

All technical FIPS 140-3 requirements are now implemented. Remaining steps:
- Third-party security audit
- Formal FIPS 140-3 submission and CMVP certification process

Full analysis: `docs/fips-gap-analysis.md`

---

## Performance (Criterion Benchmarks)

All measurements on Windows 11, x86_64, single-threaded, `--release` with LTO and `target-cpu=native`.

### Native Rust API (Optimized, RustCrypto Backend)

| Operation | Latency |
|-----------|---------|
| RSA-2048 sign | 1.927 ms |
| RSA-2048 verify | 229.8 us |
| RSA-4096 sign | 12.44 ms |
| ECDSA P-256 sign | 342.6 us |
| ECDSA P-256 verify | 292.5 us |
| Ed25519 sign | 43.79 us |
| Ed25519 verify | 46.21 us |
| AES-256-GCM encrypt 256B | 0.600 us |
| AES-256-GCM encrypt 4KB | 3.633 us |
| AES-256-GCM encrypt 64KB | 56.32 us |
| SHA-256 (4KB) | 17.24 us |
| SHA-512 (4KB) | 10.16 us |
| ML-DSA-44 sign | 711.9 us |
| ML-DSA-44 verify | 158.1 us |
| ML-DSA-65 sign | 563.3 us |
| ML-KEM-512 encapsulate | 51.84 us |
| ML-KEM-768 encapsulate | 74.46 us |
| ML-KEM-768 decapsulate | 135.3 us |

### Backend Comparison: RustCrypto vs aws-lc-rs (FIPS)

| Operation | RustCrypto | aws-lc-rs | Speedup |
|-----------|-----------|-----------|---------|
| RSA-2048 Sign | 2.001 ms | 1.628 ms | **1.2x** |
| RSA-2048 Verify | 222.0 us | 26.79 us | **8.3x** |
| ECDSA P-256 Sign | 331.6 us | 291.8 us | **1.1x** |
| ECDSA P-256 Verify | 298.3 us | 66.44 us | **4.5x** |
| AES-GCM Decrypt 4KB | 3.590 us | 2.015 us | **1.8x** |
| SHA-256 4KB | 16.63 us | 11.52 us | **1.4x** |
| RSA-2048 Keygen | 214.7 ms | 91.42 ms | **2.3x** |

### PKCS#11 C ABI — Three-Way Comparison vs SoftHSMv2

Measured through the PKCS#11 C ABI via `C_GetFunctionList`. Each iteration includes the full `C_*Init` + `C_*` pair. SoftHSMv2 2.6.1 (Botan backend).

| Operation | Craton HSM (RustCrypto) | Craton HSM (aws-lc-rs) | SoftHSMv2 |
|-----------|---------------------|--------------------:|----------:|
| RSA-2048 Sign | 2.558 ms | **1.837 ms** | 1.522 ms |
| RSA-2048 Verify | 303.5 us | 251.0 us | **37.82 us** |
| ECDSA P-256 Sign | 511.5 us | 363.2 us | **89.10 us** |
| ECDSA P-256 Verify | 506.5 us | 338.0 us | **109.1 us** |
| SHA-256 Digest 4KB | 26.0 us | 15.58 us | **9.90 us** |
| AES-GCM Encrypt 4KB | 6.173 us | **4.419 us** | — |
| AES-GCM Decrypt 4KB | 5.605 us | **4.094 us** | — |
| RSA-2048 Keygen | 313.6 ms | 208.6 ms | **80.99 ms** |
| EC P-256 Keygen | 824.4 us | 824.9 us | **224.5 us** |
| AES-256 Keygen | **18.83 us** | **17.79 us** | 90.63 us |

**Craton HSM wins:** AES-256 key generation (5.1x faster than SoftHSMv2). **SoftHSMv2 wins:** RSA/ECDSA verify (3.1-6.6x faster via Botan assembly). The aws-lc-rs backend closes the gap by 1.4-1.7x across all operations vs RustCrypto.

See `docs/benchmarks.md` for full methodology, setup instructions, and analysis.

---

## Craton HSM vs SoftHSMv2

| Feature | SoftHSMv2 | Craton HSM |
|---------|-----------|---------|
| Language | C++ | Rust |
| Memory safety | Manual | Compiler-enforced |
| PKCS#11 version | 2.40 | 3.0 |
| Post-quantum | None | 9 mechanisms (ML-DSA, ML-KEM, SLH-DSA) |
| Hybrid signatures | No | ML-DSA-65 + ECDSA-P256 |
| FIPS Approved Mode | No | `fips_approved_only` flag restricts to approved algorithms |
| FIPS POST | No | 17 tests (integrity + 16 KATs including RSA) |
| AES-GCM nonce safety | Unknown | Per-key counters with 2^31 limit (SP 800-38D) |
| Zero IV rejection | Unknown | All-zero IVs rejected at C_EncryptInit for CBC/CTR |
| Pairwise Consistency | No | Sign/verify roundtrip on every keygen (§9.6) |
| Software Integrity | No | HMAC-SHA256 of module binary at POST (§9.4) |
| Algorithm Indicator | No | `fips_approved: bool` in all audit log entries (IG 2.4.C) |
| Intermediate Zeroization | Unknown | `Zeroizing<Vec<u8>>` on all intermediate buffers (§7.7) |
| FIPS crypto backend | No | Optional aws-lc-rs (FIPS 140-3 validated) |
| Fork safety | Unknown | PID-based detection, child must re-initialize |
| Memory locking | Unknown | mlock/VirtualLock on all key material |
| Audit log | No | Chained SHA-256, tamper-evident |
| gRPC API | No | Yes (tonic + TLS) |
| Admin CLI | Limited (softhsm2-util) | Full (token, key, PIN, audit) |
| Kubernetes ready | No | Helm chart + distroless container |
| PIN hashing | PBKDF2 | PBKDF2-SHA256 (600K iterations) |
| PIN lockout | No | Configurable threshold |
| Constant-time PIN check | Not guaranteed | `subtle::ConstantTimeEq` |
| Key zeroization | Manual | `ZeroizeOnDrop` automatic |
| Spy/debug tool | Yes (pkcs11-spy) | Yes (JSON-lines spy wrapper) |
| FIPS certified | No | No (gap analysis available) |
| Production maturity | Years of deployment | New project |

---

## Deployment Options

### 1. In-process shared library

```
Application --> dlopen(libcraton_hsm.so) --> PKCS#11 C API
```

Drop-in replacement for any PKCS#11 consumer (OpenSSL, Java, SSH, etc.)

### 2. Network daemon

```
Application --> gRPC/TLS --> craton-hsm-daemon (port 5696)
```

Standalone server with mutual TLS. Decouples crypto from application lifecycle.

### 3. Kubernetes sidecar

```
Pod:
  [App Container] --localhost:5696--> [Craton HSM Container]
```

Helm chart with:
- Distroless base image (no shell, non-root)
- ConfigMap for craton_hsm.toml
- Secret for TLS cert/key
- Optional PVC for persistent key storage
- Security context: read-only root, no privilege escalation, drop all capabilities

---

## Storage & Concurrency

### Storage
- **Default**: In-memory (`DashMap`) — objects lost on process exit
- **Persistent**: Optional redb backend with AES-256-GCM per-object encryption
- **Key derivation**: PIN -> PBKDF2-HMAC-SHA256 (600K iterations) -> encryption key
- **ACID transactions**: redb provides explicit `begin_write()`/`commit()` for crash safety
- **File locking**: Exclusive advisory lock prevents two processes from opening the same database

### Concurrency
- **Single-process, multi-threaded**: `DashMap` + `parking_lot::RwLock` + `AtomicU64`
- **Multi-process safety**: Exclusive file lock on database; fork detection on Unix
- **Multi-process access**: Through gRPC daemon (serializes operations) or separate database paths
- See `docs/fork-safety.md` for deployment patterns

---

## Project Metrics

| Metric | Value |
|--------|-------|
| Total tasks | 61 + 25 + 22 + 7 + 7 + 25 (Phases 1-10) |
| Completed | 143/147 (97%) |
| Deferred | 2 (interop tests) |
| Test suites | 33 |
| Total tests | 617+ |
| PKCS#11 exports | 70+ |
| Mechanisms | 41 |
| PQC mechanisms | 9 |
| POST self-tests | 17 (integrity + 16 KATs) |
| Conformance tests | 46 (PKCS#11 ABI-level security) |
| Lines of Rust (core) | ~10,000 |
| `unsafe` in crypto | 0 |

---

## Test Coverage

| Suite | Tests | What it covers |
|-------|-------|---------------|
| Unit (self_test + drbg) | 22 | FIPS POST verification (17 tests), DRBG unit tests, mlock, integrity, pairwise |
| crypto_vectors | 12 | AES-GCM, RSA sign/verify, key sizes |
| crypto_vectors_phase2 | 56 | ECDH, AES-CBC/CTR, RSA-OAEP/PSS, key wrap, all digests, PBKDF2 |
| pkcs11_compliance | 1 | Full PKCS#11 lifecycle (init, login, keygen, sign, verify, close) |
| pkcs11_compliance_extended | 1 | PQC ABI, PIN enforcement, FindObjects, DestroyObject |
| pqc_phase3 | 19 | ML-KEM, ML-DSA, SLH-DSA, hybrid roundtrips |
| concurrent_stress | 5 | Thread safety under concurrent keygen/sign/encrypt |
| pkcs11_error_paths | 50 | CKR_ARGUMENTS_BAD, BUFFER_TOO_SMALL, OPERATION_ACTIVE, etc. |
| session_state_machine | 42 | FSM transitions, PIN validation, lockout, SessionManager |
| attribute_validation | 24 | Sensitivity, CKA_PRIVATE, template matching, destroyability |
| concurrent_session_stress | 6 | Multi-threaded session/object management, handle uniqueness |
| zeroization | 7 | Key material zeroization verification (debug mode, ignored) |
| persistence | 9 | Persistent storage integrity and roundtrip |
| multipart_sign_verify | 1 | C_SignUpdate/Final, C_VerifyUpdate/Final (RSA, ECDSA) |
| multipart_encrypt_decrypt | 1 | C_EncryptUpdate/Final, C_DecryptUpdate/Final (AES-CBC/CTR) |
| supplementary_functions | 15 | C_CopyObject, C_DigestKey tests |
| fips_approved_mode | 11 | FIPS approved mode policy enforcement |
| pairwise_consistency | 6 | Pairwise consistency tests on all keygen paths |
| **pkcs11_info_functions** | **25** | **C_GetInfo, C_GetSlotInfo, C_GetTokenInfo, C_GetMechanismInfo** |
| **key_lifecycle_abi** | **25** | **SP 800-57 states, date-based activation/deactivation** |
| **key_wrapping_abi** | **22** | **C_WrapKey/C_UnwrapKey roundtrips and error paths** |
| **key_derivation_abi** | **19** | **ECDH P-256/P-384 key derivation, cross-party validation** |
| **rsa_abi_comprehensive** | **28** | **RSA 2048/3072 sign/verify/encrypt/decrypt, OAEP, PSS** |
| **digest_abi** | **25** | **All 7 hash algorithms, single-part and multi-part** |
| **attribute_management** | **25** | **C_GetAttributeValue, C_SetAttributeValue, C_FindObjects** |
| **random_and_session** | **22** | **C_GenerateRandom, session management, PIN operations** |
| **pqc_abi_comprehensive** | **28** | **ML-DSA/ML-KEM/SLH-DSA/hybrid through C ABI** |
| **audit_and_integrity** | **24** | **AuditLog chain integrity, StoredObject lifecycle, FIPS fields** |
| **negative_edge_cases** | **30** | **Cross-algo failures, boundary conditions, empty data** |
| **pkcs11_conformance** | **46** | **Security audit conformance tests (see below)** |
| **Total** | **617+** | |

### PKCS#11 Conformance Test Suite (v0.9.1) — 46 Tests

Added following a comprehensive security audit. All tests run through the PKCS#11 C ABI (`C_Initialize` → `C_Finalize`) with `--test-threads=1` due to shared global state.

```
$ cargo test --release --test pkcs11_conformance -- --test-threads=1

running 46 tests
test test_aes_cbc_zero_iv_rejected ... ok           # All-zero IV blocked at C_EncryptInit
test test_aes_ctr_zero_iv_rejected ... ok           # All-zero IV blocked at C_EncryptInit
test test_aes_gcm_roundtrip_via_abi ... ok          # AES-GCM encrypt/decrypt through ABI
test test_aes_key_gen_invalid_length ... ok         # Invalid AES key sizes rejected
test test_audit_log_chain_integrity ... ok          # SHA-256 hash chain verified
test test_audit_log_injection_prevention ... ok     # Newline/control chars in audit entries
test test_close_all_sessions ... ok                 # C_CloseAllSessions for a slot
test test_config_absolute_path_rejection ... ok     # Absolute storage_path rejected
test test_config_path_traversal_rejection ... ok    # ".." in storage_path rejected
test test_config_pbkdf2_iterations_floor ... ok     # PBKDF2 < 100K rejected
test test_config_unc_path_rejection ... ok          # UNC paths (\\server\share) rejected
test test_destroy_object ... ok                     # C_DestroyObject + invalid handle
test test_double_initialize ... ok                  # CKR_CRYPTOKI_ALREADY_INITIALIZED
test test_double_session_close ... ok               # Second close returns CKR_SESSION_HANDLE_INVALID
test test_ec_p256_keygen_sign_verify_via_abi ... ok # EC P-256 full lifecycle via ABI
test test_encrypt_without_init ... ok               # CKR_OPERATION_NOT_INITIALIZED
test test_finalize_non_null_reserved ... ok         # CKR_ARGUMENTS_BAD
test test_find_objects_lifecycle ... ok             # FindObjectsInit/FindObjects/FindObjectsFinal
test test_generate_random ... ok                    # C_GenerateRandom produces non-zero bytes
test test_get_function_list ... ok                  # C_GetFunctionList returns valid table
test test_get_function_list_null_arg ... ok         # Null arg rejected
test test_get_info_version ... ok                   # PKCS#11 version check
test test_get_slot_list_buffer_too_small ... ok     # CKR_BUFFER_TOO_SMALL
test test_init_finalize_reinit_cycle ... ok         # Init → Finalize → Re-Init lifecycle
test test_invalid_slot_id ... ok                    # CKR_SLOT_ID_INVALID
test test_login_invalid_user_type ... ok            # CKR_USER_TYPE_INVALID
test test_login_lockout ... ok                      # PIN lockout after max failures
test test_logout_without_login ... ok               # CKR_USER_NOT_LOGGED_IN
test test_mechanism_list_and_info ... ok            # Mechanism enumeration + flag check
test test_multipart_digest_sha256 ... ok            # DigestUpdate/DigestFinal
test test_null_pointer_get_info ... ok              # Null ptr → CKR_ARGUMENTS_BAD
test test_null_pointer_get_slot_info ... ok         # Null ptr → CKR_ARGUMENTS_BAD
test test_null_pointer_get_slot_list_count ... ok   # Null ptr → CKR_ARGUMENTS_BAD
test test_null_pointer_get_token_info ... ok        # Null ptr → CKR_ARGUMENTS_BAD
test test_operation_on_invalid_session ... ok       # CKR_SESSION_HANDLE_INVALID
test test_operation_state_save_restore_digest ... ok # GetOperationState/SetOperationState
test test_pin_complexity_all_same_char ... ok       # "aaaaaaaa" rejected
test test_pin_complexity_single_class ... ok        # "abcdefgh" rejected (no digits)
test test_pin_complexity_valid ... ok               # "Secure1!" accepted
test test_pin_too_short ... ok                      # Short PIN rejected
test test_rsa_keygen_sign_verify_via_abi ... ok     # RSA-2048 PKCS#1 v1.5 full lifecycle
test test_session_info_state ... ok                 # Session state machine via C_GetSessionInfo
test test_session_without_serial_flag ... ok        # CKR_SESSION_PARALLEL_NOT_SUPPORTED
test test_sha256_digest_via_abi ... ok              # SHA-256 digest roundtrip via ABI
test test_sign_without_init ... ok                  # CKR_OPERATION_NOT_INITIALIZED
test test_token_info_flags ... ok                   # Token info flag verification

test result: ok. 46 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

Tests organized by category:

| Category | Tests | Coverage |
|----------|-------|----------|
| IV/Nonce Security | 2 | All-zero IV rejection for AES-CBC and AES-CTR at `C_EncryptInit` |
| Session Management | 4 | Double close, close all, session flags, session info state |
| PIN Security | 4 | Too short, all same chars, single char class, valid complexity |
| Lifecycle | 3 | Init/finalize/reinit, double init, finalize with non-null reserved |
| Null Pointer Safety | 4 | Null output pointers for GetInfo, GetSlotInfo, GetSlotList, GetTokenInfo |
| Invalid Parameters | 3 | Invalid slot ID, invalid session, buffer too small |
| Crypto Operations | 6 | AES-GCM roundtrip, RSA keygen+sign+verify, EC P-256 keygen+sign+verify, SHA-256 digest, random gen, invalid key length |
| Object Management | 2 | FindObjects lifecycle, DestroyObject |
| Token & Mechanism Info | 4 | Token flags, version, mechanism list, function list |
| Auth & Access Control | 3 | Logout without login, invalid user type, login lockout |
| Operation State | 2 | Save/restore digest, encrypt/sign without init |
| Multi-part Operations | 1 | Multi-part SHA-256 digest (Update + Final) |
| Config Validation | 4 | Path traversal, absolute path, UNC path, PBKDF2 iterations floor |
| Audit Logging | 2 | Chain integrity, injection prevention |

---

## Security Audit Findings Fixed (v0.9.1)

A comprehensive security audit identified and fixed the following vulnerabilities:

| Severity | Finding | Fix |
|----------|---------|-----|
| **CRITICAL** | RSA/EC/Ed25519 keygen used `OsRng` directly, bypassing DRBG | `DrbgRng` wrapper routes all keygen through HMAC_DRBG |
| **HIGH** | Global AES-GCM nonce counter (shared across keys) | Per-key counters via `DashMap` keyed by SHA-256 of key |
| **HIGH** | AES-CBC/CTR KATs were circular (roundtrip only) | Genuine known-answer tests with hardcoded ciphertexts |
| **HIGH** | No RSA KAT in POST | Added RSA-2048 PKCS#1 v1.5 sign/verify KAT |
| **MEDIUM** | RSA key size validation with leading zeros | Strip leading zero bytes before counting bits |
| **MEDIUM** | All-zero IV accepted at `C_EncryptInit` | Early rejection for CBC and CTR modes |
| **MEDIUM** | `POST_FAILED` never reset on re-init | Reset before re-running POST |
| **MEDIUM** | Session count race in `close_all_sessions` | Track actual removed counts per slot |
| **LOW** | Config path traversal (UNC, `..`) | Added UNC path and literal `..` segment checks |
| **LOW** | Unzeroized copy of RSA DER bytes | Eliminated unnecessary `.clone()` |
| **LOW** | Missing AES-GCM max plaintext check | Added SP 800-38D limit enforcement |

---

## Roadmap Completed

| Phase | Tasks | Status |
|-------|-------|--------|
| 1. Core PKCS#11 | 26 | ✅ Complete |
| 2. Full Algorithm Suite | 16 | ✅ Complete (1 deferred) |
| 3. PQC and Hardening | 11 | ✅ Complete (1 deferred) |
| 4. Production Tooling | 8 | ✅ Complete |
| 5. Hardening | — | ✅ Complete |
| 6. Enterprise & Audit Readiness | 25 | ✅ Complete |
| 7. PKCS#11 Completeness | 22 | ✅ Complete |
| 8. Interop & Benchmarking | 7 | ✅ Complete |
| 9. Security Polish | 7 | ✅ Complete |
| 10. FIPS 140-3 Level 1 Ready | 25 | ✅ Complete |

Phase 7 deliverables:
- Multi-part sign/verify (`C_SignUpdate`/`C_SignFinal`, `C_VerifyUpdate`/`C_VerifyFinal`)
- Multi-part encrypt/decrypt (`C_EncryptUpdate`/`C_EncryptFinal`, `C_DecryptUpdate`/`C_DecryptFinal`)
- SP 800-90A HMAC_DRBG with prediction resistance and continuous health test
- SP 800-57 key lifecycle states with date-based transitions
- `C_CopyObject` and `C_DigestKey` implementations
- DRBG POST KAT (#15)
- GitHub Actions CI pipeline (build, test, lint, docs)
- 50+ new integration tests

---

## What's Next

### Phase 6 — Enterprise & Audit Readiness ✅

All 25 tasks complete: aws-lc-rs FIPS backend, 14→15 POST KATs, memory hardening, fork detection, redb storage, fuzzing, security policy, audit documentation.

### Phase 7 — PKCS#11 Completeness ✅

All 22 tasks complete: multi-part sign/verify/encrypt/decrypt, SP 800-90A HMAC_DRBG, SP 800-57 key lifecycle, C_CopyObject, C_DigestKey, GitHub Actions CI.

### Phase 8 — Interoperability & Benchmarking ✅

All 7 tasks complete: PKCS#11 ABI benchmarks, SoftHSMv2 head-to-head comparison, Java SunPKCS11 interop tests, OpenSSL/pkcs11-tool interop tests, comprehensive integration documentation.

### Phase 9 — Security Polish ✅

All 7 tasks complete: cargo audit + deny in CI, expanded fuzzing (5 targets), Miri CI, security review checklist, release signing docs, side-channel resistance docs, visual examples.

### Phase 10 — FIPS 140-3 Level 1 Ready ✅

All 25 tasks complete: FIPS approved mode enforcement, pairwise consistency tests (§9.6), software integrity test (§9.4), algorithm indicator (IG 2.4.C), intermediate zeroization (§7.7), updated security policy v3.0, FIPS operator guide. 17 new tests.

### v0.9.1 — Security Audit Hardening ✅

11 security fixes from comprehensive ethical hacker audit:
- DRBG bypass in key generation (CRITICAL)
- Per-key AES-GCM nonce counters (HIGH)
- Genuine AES-CBC/CTR KATs (HIGH), RSA KAT added (HIGH)
- All-zero IV early rejection, POST_FAILED reset, RSA key size validation (MEDIUM)
- Config path traversal hardening, RSA DER zeroization (LOW)
- 46 new PKCS#11 conformance tests, updated security policy v4.0

### Next Steps

1. Third-party security audit (preparation complete — see `docs/security-review-checklist.md`)

### Long-term

5. FIPS 140-3 Level 1 certification (all technical requirements now implemented)
6. Hardware backend support (TPM integration)
7. Multi-token / multi-slot support
8. Clustering and replication

---

## What It Looks Like in Practice

### Admin CLI — Token Management

```
$ craton-hsm-admin status --json
{
  "token_label": "Production HSM",
  "token_initialized": true,
  "user_pin_set": true,
  "sessions_open": 3,
  "objects_count": 12,
  "mechanisms_count": 41,
  "post_status": "PASSED",
  "crypto_backend": "rustcrypto"
}

$ craton-hsm-admin key list
Handle  Type     Label            Bits  Sensitive  Extractable  Lifecycle
------  -------  ---------------  ----  ---------  -----------  ---------
    1   RSA      tls-signing-key  2048  true       false        Active
    2   EC       ecdsa-p256       256   true       false        Active
    3   AES      data-encryption  256   true       false        Active
    4   ML-DSA   pqc-signing-65   -     true       false        Active
    5   ML-KEM   pqc-kem-768      -     true       false        Active
```

### Audit Log — Tamper-Evident Chain

```
$ craton-hsm-admin audit dump --last 5
[2026-03-06T14:22:01Z] C_Login        session=3  user=CKU_USER  result=CKR_OK
  hash: a1b2c3d4e5f6...  prev: 9f8e7d6c5b4a...
[2026-03-06T14:22:02Z] C_SignInit      session=3  mechanism=CKM_SHA256_RSA_PKCS  key=1  result=CKR_OK
  hash: 2b3c4d5e6f7a...  prev: a1b2c3d4e5f6...
[2026-03-06T14:22:02Z] C_Sign         session=3  data_len=32  sig_len=256  result=CKR_OK
  hash: 3c4d5e6f7a8b...  prev: 2b3c4d5e6f7a...
[2026-03-06T14:22:03Z] C_GenerateRandom  session=3  len=32  result=CKR_OK
  hash: 4d5e6f7a8b9c...  prev: 3c4d5e6f7a8b...
[2026-03-06T14:22:03Z] C_Logout       session=3  result=CKR_OK
  hash: 5e6f7a8b9c0d...  prev: 4d5e6f7a8b9c...
```

Every entry links to its predecessor via SHA-256. Modifying, deleting, or reordering any entry breaks the chain.

### Key Material Protection — [REDACTED] in Debug Output

```rust
// What you see in logs:
StoredObject {
    handle: 1,
    class: CKO_SECRET_KEY,
    key_type: CKK_AES,
    label: "data-encryption",
    key_material: RawKeyMaterial([REDACTED: 32 bytes]),
    sensitive: true,
    extractable: false,
}
```

Key bytes never appear in logs, debug output, or error messages. This is enforced by a custom `Debug` impl on `RawKeyMaterial`.

### FIPS POST Output (Power-On Self-Test)

```
[C_Initialize] Running FIPS 140-3 Power-On Self-Tests...
  [ OK ] POST 0: Software integrity (HMAC-SHA256 of module binary)
  [ OK ] KAT  1: SHA-256 digest
  [ OK ] KAT  2: SHA-384 digest
  [ OK ] KAT  3: SHA-512 digest
  [ OK ] KAT  4: SHA3-256 digest
  [ OK ] KAT  5: HMAC-SHA256
  [ OK ] KAT  6: HMAC-SHA384
  [ OK ] KAT  7: HMAC-SHA512
  [ OK ] KAT  8: AES-256-GCM (roundtrip + known-answer decrypt)
  [ OK ] KAT  9: AES-256-CBC (known-answer, hardcoded ciphertext)
  [ OK ] KAT 10: AES-256-CTR (known-answer, hardcoded ciphertext)
  [ OK ] KAT 11: RSA-2048 PKCS#1 v1.5 sign/verify
  [ OK ] KAT 12: ECDSA P-256 sign/verify
  [ OK ] KAT 13: ML-DSA-44 sign/verify
  [ OK ] KAT 14: ML-KEM-768 encapsulate/decapsulate
  [ OK ] KAT 15: RNG entropy + continuous health test
  [ OK ] KAT 16: HMAC-DRBG (NIST CAVP vector)
  All 17 POST self-tests passed. Module operational.
```

If any test fails, `POST_FAILED` is set and ALL subsequent operations return `CKR_GENERAL_ERROR`. On re-initialization (after `C_Finalize`), `POST_FAILED` is reset and POST re-runs.

### pkcs11-tool Interop (OpenSC)

```
$ pkcs11-tool --module ./target/release/libcraton_hsm.so --list-mechanisms
Supported mechanisms:
  CKM_RSA_PKCS_KEY_PAIR_GEN       keySize={2048,4096}
  CKM_RSA_PKCS                    keySize={2048,4096}  sign verify encrypt decrypt
  CKM_SHA256_RSA_PKCS             keySize={2048,4096}  sign verify
  CKM_RSA_PKCS_PSS                keySize={2048,4096}  sign verify
  CKM_RSA_PKCS_OAEP               keySize={2048,4096}  encrypt decrypt
  CKM_EC_KEY_PAIR_GEN             keySize={256,384}
  CKM_ECDSA                       keySize={256,384}    sign verify
  CKM_ECDSA_SHA256                keySize={256,384}    sign verify
  CKM_AES_KEY_GEN                 keySize={32,32}
  CKM_AES_GCM                     keySize={32,32}      encrypt decrypt
  CKM_AES_CBC                     keySize={32,32}      encrypt decrypt
  CKM_SHA256                                           digest
  CKM_SHA384                                           digest
  CKM_SHA512                                           digest
  ... (41 mechanisms total)
```

---

## Side-Channel Resistance

| Operation | Defense | Implementation |
|-----------|---------|---------------|
| PIN comparison | Constant-time | `subtle::ConstantTimeEq` on PBKDF2 hashes |
| RSA signing | Blinding | Randomized blinding factor (RustCrypto + aws-lc-rs) |
| ECDSA signing | Constant-time scalar mult | No branching on secret scalars |
| AES encryption | Hardware intrinsics | AES-NI (no timing-leaky table lookups) |
| HMAC verification | Constant-time comparison | `subtle::ConstantTimeEq` on all tags |

See `docs/security-model.md` for the full side-channel analysis including backend-specific notes.

---

## Supply-Chain & Binary Security

| Layer | Defense |
|-------|---------|
| Dependencies | `cargo audit` (CVE), `cargo deny` (license + advisory) in CI |
| Build | Reproducible `--locked` builds, GitHub Actions artifacts |
| Binary | Release signing (GPG/cosign/Authenticode) + SHA256 checksums |
| Runtime | 17 FIPS POST tests (integrity + 16 KATs) at every `C_Initialize` |
| Fuzzing | 5 cargo-fuzz targets covering ABI, crypto, attributes, sessions, buffers |
| UB Detection | Miri in CI, AddressSanitizer/MemorySanitizer for manual review |

See `docs/release-signing.md` for binary verification instructions.

---

## Summary

Craton HSM is a modern, memory-safe, post-quantum-ready PKCS#11 implementation.

**What it delivers today:**
- Full PKCS#11 v3.0 C ABI (70+ exports) with multi-part operations
- 41 mechanisms including ML-DSA, ML-KEM, SLH-DSA
- Memory safety by construction (Rust)
- SP 800-90A HMAC_DRBG with prediction resistance
- SP 800-57 key lifecycle states with date-based transitions
- FIPS Approved Mode (`fips_approved_only` restricts to approved algorithms)
- FIPS 140-3 POST self-tests (17 tests: integrity + 16 KATs with genuine known-answer values)
- Pairwise consistency tests on every key pair generation (§9.6)
- Software integrity verification (HMAC-SHA256 of module binary, §9.4)
- Algorithm indicator in all audit log entries (IG 2.4.C)
- Intermediate zeroization of all plaintext buffers (§7.7)
- Dual crypto backend (RustCrypto or aws-lc-rs FIPS) with comparative benchmarks
- Fork safety, memory hardening (mlock + zeroization verification)
- Persistent encrypted storage (redb + AES-256-GCM) with file-level locking
- Fuzzing infrastructure (5 cargo-fuzz targets: ABI, crypto, attributes, sessions, buffer overflow)
- FIPS Security Policy and CSP documentation
- Production deployment via gRPC daemon or Kubernetes sidecar
- GitHub Actions CI/CD pipeline (build, test, lint, security audit, Miri, benchmarks)
- Supply-chain security: `cargo audit`, `cargo deny`, Miri, AddressSanitizer support
- Release binary signing documentation (GPG, cosign, Authenticode)
- Side-channel resistance: constant-time comparisons, RSA blinding, AES-NI
- PKCS#11 C ABI benchmarks with SoftHSMv2 head-to-head comparison
- Java SunPKCS11 and OpenSSL/pkcs11-tool interoperability test suites
- Security review checklist for pre-audit preparation
- FIPS operator guide (`docs/fips-mode-guide.md`)
- 617+ passing tests across 33 suites (including 46 PKCS#11 conformance tests)

**What it honestly does not have yet:**
- FIPS 140-3 certification (all technical requirements implemented, see `docs/fips-gap-analysis.md`)
- Third-party security audit (checklist prepared, see `docs/security-review-checklist.md`)
- Years of production deployment history

The codebase is open, the gaps are documented, and the architecture is designed for certification.

---

*Craton HSM v0.9.1
