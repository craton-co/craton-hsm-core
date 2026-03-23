# FIPS 140-3 Gap Analysis

> **DISCLAIMER: Craton HSM is NOT FIPS 140-3 certified.** This gap analysis documents technical readiness, not certification status.

## Current Status: Level 1 Ready (with aws-lc-rs backend)

Craton HSM implements the core cryptographic requirements for FIPS 140-3 Level 1. With the `awslc-backend` feature, all classical crypto operations use aws-lc-rs (FIPS 140-3 certified). This document identifies remaining gaps before formal certification submission.

> **v0.9.1 Security Audit Update**: All key generation (RSA, EC, Ed25519) now routes through DRBG via `DrbgRng` adapter (was using `OsRng` directly). AES-CBC/CTR KATs upgraded from circular roundtrips to genuine known-answer tests. RSA PKCS#1 v1.5 KAT added. Per-key AES-GCM nonce counters replace global counter. POST_FAILED now resets on re-initialization. All-zero IV rejection at `C_EncryptInit`. 46 new PKCS#11 conformance tests. POST count: 17 (integrity + 16 KATs).
>
> **Phase 10 Update**: FIPS Approved Mode enforcement, pairwise consistency tests on all key pair generation (§9.6), software/firmware integrity test (§9.4) via HMAC-SHA256, algorithm indicator (IG 2.4.C) in audit log, intermediate zeroization via `Zeroizing<Vec<u8>>` for all `ActiveOperation` data buffers.
>
> **Phase 7 Update**: 15 POST KATs implemented (HMAC_DRBG KAT added), SP 800-90A HMAC_DRBG replaces direct OsRng, SP 800-57 key lifecycle states implemented, multi-part sign/verify/encrypt/decrypt operations, C_CopyObject and C_DigestKey, GitHub Actions CI pipeline.
>
> **Phase 6 Update**: 14 POST KATs implemented, continuous RNG health test active, aws-lc-rs backend available, memory hardening complete (mlock + zeroization), persistent storage via redb with file-level locking, fork detection on Unix, comprehensive fuzzing infrastructure.

## Approved Algorithm Coverage

### Fully Covered

| Algorithm | Standard | Crate |
|-----------|----------|-------|
| AES-256 (GCM, CBC, CTR, KW) | SP 800-38A/D/F | `aes-gcm`, `aes`, `cbc`, `ctr`, `aes-kw` |
| RSA 2048/3072/4096 (PKCS#1 v1.5, PSS, OAEP) | FIPS 186-5 | `rsa` |
| ECDSA P-256, P-384 | FIPS 186-5 | `p256`, `p384` |
| ECDH P-256, P-384 | SP 800-56A | `p256`, `p384` |
| SHA-256, SHA-384, SHA-512 | FIPS 180-4 | `sha2` |
| SHA3-256, SHA3-384, SHA3-512 | FIPS 202 | `sha3` |
| HMAC-SHA256/384/512 | FIPS 198-1 | `hmac` |
| PBKDF2-HMAC-SHA256 | SP 800-132 | `pbkdf2` |
| ML-DSA-44/65/87 | FIPS 204 | `ml-dsa` |
| ML-KEM-512/768/1024 | FIPS 203 | `ml-kem` |
| SLH-DSA (multiple parameter sets) | FIPS 205 | `slh-dsa` |

### Partially Covered

- **Ed25519** — implemented but Ed25519 is not yet FIPS-approved (may be approved under FIPS 186-6)

### Resolved in Phase 7

- **DRBG** — ✅ SP 800-90A HMAC_DRBG (HMAC-SHA256) implemented with prediction resistance and continuous health test. All cryptographic random generation routed through DRBG; OsRng used only as entropy source.

## Power-On Self-Test (POST) Coverage

### Covered (17 tests: integrity + 16 KATs) ✅

| Test | Type | Vector | Status |
|------|------|--------|--------|
| Software integrity | HMAC-SHA256 of binary | §9.4 sidecar | ✅ Phase 10 |
| SHA-256 | Known Answer Test | NIST "abc" | ✅ Original |
| SHA-384 | Known Answer Test | NIST "abc" | ✅ Phase 6 |
| SHA-512 | Known Answer Test | NIST "abc" | ✅ Original |
| SHA3-256 | Known Answer Test | NIST "abc" | ✅ Phase 6 |
| HMAC-SHA256 | Known Answer Test | RFC 4231 TC2 | ✅ Original |
| HMAC-SHA384 | Known Answer Test | RFC 4231 TC2 | ✅ Phase 6 |
| HMAC-SHA512 | Known Answer Test | RFC 4231 TC2 | ✅ Phase 6 |
| AES-GCM | Roundtrip + known-answer decrypt | Fixed key | ✅ Original |
| AES-CBC | Known Answer (hardcoded ciphertext) | Fixed key/IV | ✅ v0.9.1 upgraded |
| AES-CTR | Known Answer (hardcoded ciphertext) | Fixed key/IV | ✅ v0.9.1 upgraded |
| RSA 2048 PKCS#1 v1.5 | Sign/Verify roundtrip | Generated key | ✅ v0.9.1 added |
| ECDSA P-256 | Sign/Verify roundtrip | Generated key | ✅ Original |
| ML-DSA-44 | Sign/Verify roundtrip | Generated key | ✅ Original |
| ML-KEM-768 | Encap/Decap roundtrip | Generated key | ✅ Phase 6 |
| RNG | Health + continuous test | OsRng output | ✅ Original + Phase 6 |
| HMAC_DRBG | Known Answer Test | NIST CAVP vector | ✅ Phase 7 |

### Continuous RNG Health Test ✅

Implemented in Phase 6 per SP 800-90B. Stores last 32 bytes of RNG output in `Mutex<[u8; 32]>`. Each `C_GenerateRandom` call compares new output against previous — identical output fails with `CKR_FUNCTION_FAILED`.

### DRBG Health Test ✅

Implemented in Phase 7. The HMAC_DRBG continuous health test compares consecutive outputs. Additionally, a NIST CAVP known-answer test validates DRBG correctness during POST.

### Remaining POST Gaps

None — all required POST KATs are implemented.

### Software Integrity Test (§9.4) ✅

Added in Phase 10, refined in v0.9.1. HMAC-SHA256 of the module binary computed at POST time using an embedded key (per FIPS IG 9.7). Compared against a `.hmac` sidecar file next to the library. The `.hmac` file is opt-in: without it, the check passes (development/test/non-FIPS deployments). With the `fips` feature enabled, the `.hmac` file is mandatory. Mismatched HMAC always fails POST.

### Pairwise Consistency Tests (§9.6) ✅

Added in Phase 10. After every key pair generation (RSA, ECDSA P-256/P-384, Ed25519, ML-DSA, ML-KEM, SLH-DSA), a sign/verify or encap/decap roundtrip verifies key pair consistency. Failure sets `POST_FAILED` and enters error state.

### Algorithm Indicator (IG 2.4.C) ✅

Added in Phase 10. Every audit log entry for crypto operations (Sign, Verify, Encrypt, Decrypt, Digest, GenerateKey, GenerateKeyPair, WrapKey, UnwrapKey, DeriveKey) includes `fips_approved: bool`. Session tracks `last_operation_fips_approved`. Vendor-defined attribute `CKA_VENDOR_FIPS_APPROVED` (0x80000001) defined.

### FIPS Approved Mode ✅

Added in Phase 10. When `fips_approved_only = true` in config:
- Ed25519 (CKM_EDDSA) blocked — not yet FIPS-approved
- All PQC mechanisms blocked — not yet FIPS-approved (pending FIPS 203/204/205 adoption)
- SHA-1 signing blocked
- C_GetMechanismList returns only approved mechanisms
- All Init/keygen functions validate mechanism against policy

## Key Management Gaps

### Current state

| Property | Implementation | Status |
|----------|---------------|--------|
| Key storage | Process memory with `ZeroizeOnDrop` + `mlock`/`VirtualLock` | ✅ Hardened in Phase 6 |
| Key export control | `CKA_EXTRACTABLE` defaults to `false` | ✅ |
| PIN hashing | PBKDF2-HMAC-SHA256 (600K iterations) | ✅ |
| Persistent storage | redb with per-object AES-256-GCM encryption + file-level locking | ✅ Upgraded in Phase 6 (sled → redb) |
| Memory locking | `mlock()` (Unix) / `VirtualLock()` (Windows) on key pages | ✅ Implemented in Phase 6 |
| Zeroization verification | 7 tests verify `ZeroizeOnDrop` clears memory | ✅ Phase 6 |
| Multi-process safety | Exclusive file lock prevents database corruption; fork detection on Unix | ✅ Phase 6 |

### Resolved Gaps (Phase 6)

| Gap | Resolution | Status |
|-----|-----------|--------|
| Key zeroization verification | 7 `#[ignore]` tests in `tests/zeroization.rs` demonstrate memory clearing for 32/48/256/2560 byte keys | ✅ Resolved |
| Memory locking (Windows) | Windows `VirtualLock`/`VirtualUnlock` via `windows-sys` crate; graceful fallback on quota exceeded | ✅ Resolved |
| mlock lifecycle | `RawKeyMaterial::new()` calls `mlock_buffer()`; `Drop` impl calls `zeroize()` then `munlock_buffer()` | ✅ Resolved |
| Storage engine | Replaced unmaintained sled with redb v2 (ACID transactions, no known corruption bugs) | ✅ Resolved |
| FIPS crypto backend | aws-lc-rs backend available via `--features awslc-backend`; all 26 `CryptoBackend` methods | ✅ Resolved |

### Resolved Gaps (Phase 7)

| Gap | Resolution | Status |
|-----|-----------|--------|
| Key lifecycle states | SP 800-57 states (PreActivation, Active, Deactivated, Compromised, Destroyed) with date-based transitions via CKA_START_DATE/CKA_END_DATE | ✅ Resolved |
| SP 800-90A DRBG | HMAC_DRBG (HMAC-SHA256) with prediction resistance, continuous health test, NIST CAVP KAT | ✅ Resolved |

### Remaining Gaps

| Gap | Description | Priority | Status |
|-----|-------------|----------|--------|
| Key transport | If keys are imported/exported, must use approved methods only | P1 | Open |
| CSP management | Formal documentation of all Critical Security Parameters and their protection | P0 | ✅ Done — CSP table in `security-policy.md` §11 |

### Resolved Gaps (Phase 10)

| Gap | Resolution | Status |
|-----|-----------|--------|
| Approved mode enforcement | `fips_approved_only` config flag, `validate_mechanism_for_policy()` in all Init/keygen functions | ✅ Resolved |
| Pairwise consistency tests | Sign/verify or encap/decap roundtrip after every key pair generation | ✅ Resolved |
| Software integrity test | HMAC-SHA256 of module binary at POST time | ✅ Resolved |
| Algorithm indicator | `fips_approved: bool` in audit log entries + session tracking | ✅ Resolved |
| Intermediate zeroization | `Zeroizing<Vec<u8>>` for all ActiveOperation data/mechanism_param fields | ✅ Resolved |

### Resolved Gaps (v0.9.1 Security Audit)

| Gap | Resolution | Status |
|-----|-----------|--------|
| DRBG bypass in key generation | All key types (RSA, EC P-256/P-384, Ed25519) now use `DrbgRng` wrapper routing through HMAC_DRBG instead of `OsRng` directly | ✅ Resolved |
| Circular AES-CBC/CTR KATs | Replaced with genuine known-answer tests using hardcoded expected ciphertexts | ✅ Resolved |
| Missing RSA KAT | Added RSA-2048 PKCS#1 v1.5 sign/verify roundtrip to POST | ✅ Resolved |
| Global AES-GCM nonce counter | Changed to per-key counters via `DashMap<u64, AtomicU64>` keyed by SHA-256 hash of key material | ✅ Resolved |
| POST_FAILED not resettable | `POST_FAILED` now reset before re-running POST on `C_Initialize` | ✅ Resolved |
| All-zero IV accepted at init time | Added early IV validation in `C_EncryptInit` for CBC and CTR modes | ✅ Resolved |
| RSA key size validation with leading zeros | `validate_rsa_public_key_size` now strips leading zero bytes before counting bits | ✅ Resolved |
| Config path traversal | Added UNC path rejection and literal `..` segment check | ✅ Resolved |
| Unzeroized RSA DER copy | Eliminated unnecessary `.clone()` of RSA private key DER bytes | ✅ Resolved |

## Operational Environment

### Current state
- Runs on any OS with Rust support (Linux, macOS, Windows)
- No OS-level integrity verification

### Gap
- FIPS Level 1 for software modules on modifiable operating environments requires that the OS is validated (typically listed in vendor's security policy)
- Need to document and test on specific platform versions

## Documentation Gaps

| Document | Status | Required for |
|----------|--------|-------------|
| Security Policy | ✅ Written (`docs/security-policy.md`) | Submission (mandatory) |
| Finite State Model | ✅ Documented in `architecture.md` and `security-policy.md` §4 | Submission |
| User Guide (operator) | ✅ Written (`operator-runbook.md`) | Submission |
| Algorithm specification | ✅ Covered in `audit-scope.md` | Submission |
| Physical security | N/A (Level 1) | - |
| Design assurance | ✅ Source code available, CI/CD pipeline with automated tests | Submission |

## Dependency Audit

### Critical dependencies (inside module boundary)

| Crate | Version | Purpose | FIPS status |
|-------|---------|---------|-------------|
| `rsa` | 0.9 | RSA operations | Not FIPS-certified; uses `num-bigint` |
| `p256` | 0.13 | ECDSA/ECDH P-256 | RustCrypto; not FIPS-certified |
| `p384` | 0.13 | ECDSA/ECDH P-384 | RustCrypto; not FIPS-certified |
| `aes-gcm` | 0.10 | AES-GCM encryption | RustCrypto; not FIPS-certified |
| `aes` | 0.8 | AES block cipher | RustCrypto; not FIPS-certified |
| `sha2` | 0.10 | SHA-2 digests | RustCrypto; not FIPS-certified |
| `sha3` | 0.10 | SHA-3 digests | RustCrypto; not FIPS-certified |
| `hmac` | 0.12 | HMAC | RustCrypto; not FIPS-certified |
| `ed25519-dalek` | 2 | Ed25519 | Not FIPS-certified |
| `ml-dsa` | 0.1.0-rc.7 | ML-DSA signing | Pre-release; needs NIST compliance review |
| `ml-kem` | 0.3.0-rc.0 | ML-KEM | Pre-release; needs NIST compliance review |
| `slh-dsa` | 0.2.0-rc.4 | SLH-DSA signing | Pre-release; needs NIST compliance review |
| `pbkdf2` | 0.12 | PIN hashing | RustCrypto; not FIPS-certified |
| `subtle` | 2 | Constant-time ops | RustCrypto; not FIPS-certified |
| `zeroize` | 1 | Memory zeroization | RustCrypto; not FIPS-certified |

### Resolution: Dual Backend Architecture (Phase 6)

Craton HSM now supports two crypto backends selectable at compile time:

| Backend | Feature Flag | FIPS Status | Use Case |
|---------|-------------|-------------|----------|
| **RustCrypto** (default) | `rustcrypto-backend` | Not certified | Development, testing, pure-Rust environments |
| **aws-lc-rs** | `awslc-backend` | FIPS 140-3 certified (AWS-LC) | Production FIPS environments |

**Recommended deployment**: `cargo build --features awslc-backend` for FIPS environments. The `CryptoBackend` trait (26 methods) provides identical API; backend is selected at build time via feature flags and at runtime via `crypto_backend` config.

PQC algorithms (ML-DSA, ML-KEM, SLH-DSA) use dedicated crates regardless of backend, as aws-lc-rs does not yet cover post-quantum algorithms.

## Remediation Priority

### P0 — Required for submission

| # | Item | Effort estimate | Status |
|---|------|----------------|--------|
| 1 | Write Security Policy document | 2-3 weeks | ✅ **Done** — `docs/security-policy.md` with CSP table |
| 2 | Implement DRBG (SP 800-90A HMAC_DRBG) | 1-2 weeks | ✅ **Done** — HMAC_DRBG with prediction resistance |
| 3 | Add missing POST KATs | 1 week | ✅ **Done** — 15 KATs total (including DRBG KAT) |
| 4 | Add continuous RNG test | 2-3 days | ✅ **Done** — SP 800-90B compliant |
| 5 | Document Critical Security Parameters formally | 1 week | ✅ **Done** — CSP table in security-policy.md §11 |

### P1 — Strongly recommended

| # | Item | Effort estimate | Status |
|---|------|----------------|--------|
| 6 | Implement key lifecycle state tracking | 1-2 weeks | ✅ **Done** — SP 800-57 states with CKA_START/END_DATE |
| 7 | Add key zeroization verification tests | 3-5 days | ✅ **Done** — 7 tests in `tests/zeroization.rs` |
| 8 | Evaluate crypto library FIPS status (RustCrypto vs aws-lc-rs) | 2-4 weeks | ✅ **Done** — aws-lc-rs backend implemented |
| 9 | Document tested platforms and OS requirements | 3-5 days | ✅ **Done** — `docs/tested-platforms.md` |

### P2 — For higher security levels (Level 2+)

| # | Item |
|---|------|
| 10 | Hardware-backed key storage (TPM, HSM backend) |
| 11 | Role-based authentication strengthening |
| 12 | Physical security measures |
| 13 | Entropy source qualification |

## Security Testing Infrastructure (Phase 6)

### Fuzzing

Five `cargo-fuzz` targets provide continuous security testing:

| Target | Coverage |
|--------|----------|
| `fuzz_c_abi` | C_CreateObject, C_FindObjects, C_GenerateRandom, C_OpenSession/CloseSession, C_DigestInit/Digest |
| `fuzz_crypto_ops` | AES-GCM/CBC/CTR encrypt/decrypt roundtrips, digest, random ciphertext/signature handling |
| `fuzz_attributes` | ObjectStore::create_object, read_attribute, matches_template with random templates |
| `fuzz_session_lifecycle` | Session state machine edge cases, login/logout interleaving, multi-session stress |
| `fuzz_buffer_overflow` | Integer overflow, two-call pattern, null pointers, extreme attribute lengths |

Run: `cargo fuzz run <target> -- -max_total_time=60`

### Memory Safety

| Feature | Implementation |
|---------|---------------|
| mlock (Unix) | `libc::mlock()` on key allocation |
| VirtualLock (Windows) | `windows_sys::Win32::System::Memory::VirtualLock()` |
| Zeroization | `ZeroizeOnDrop` + manual `Drop` calling `zeroize()` then `munlock_buffer()` |
| Fork detection (Unix) | PID comparison in `get_hsm()` — child processes forced to re-initialize |
| File locking | `fs2::FileExt::try_lock_exclusive()` prevents dual-process database access |
