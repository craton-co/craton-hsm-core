# FIPS 140-3 Audit Scope

## Cryptographic Module Boundary

The cryptographic module boundary encompasses all code that handles key material, performs cryptographic operations, or enforces security policy.

### Inside the boundary

| Component | Path | Role |
|-----------|------|------|
| Core library | `src/` | All cryptographic logic |
| Crypto engine | `src/crypto/` | Algorithm implementations and self-tests |
| Key material management | `src/store/` | RawKeyMaterial, ObjectStore, EncryptedStore |
| Session and authentication | `src/session/`, `src/token/` | Session state machine, PIN hashing, login |
| PKCS#11 C ABI | `src/pkcs11_abi/` | Input validation, output marshalling |
| Self-tests | `src/crypto/self_test.rs` | FIPS POST known-answer tests |
| Audit log | `src/audit/` | Tamper-evident event recording |

### Outside the boundary (excluded)

| Component | Path | Reason |
|-----------|------|--------|
| gRPC daemon | `craton-hsm-daemon/` | Network transport layer; calls into module |
| Admin CLI | `tools/craton-hsm-admin/` | Management interface; calls into module |
| Spy wrapper | `tools/pkcs11-spy/` | Debug/logging tool; no crypto |
| Deployment artifacts | `deploy/` | Infrastructure only |
| Benchmarks | `benches/` | Testing only |
| Third-party dependencies | `Cargo.lock` | Evaluated separately (see Dependency Audit) |

## Algorithm Inventory

### Approved Algorithms (FIPS 140-3)

| Algorithm | Standard | Key Sizes | Crate | Status |
|-----------|----------|-----------|-------|--------|
| AES-GCM | SP 800-38D | 256-bit | `aes-gcm` 0.10 | Implemented |
| AES-CBC | SP 800-38A | 128/192/256-bit | `aes` 0.8 + `cbc` 0.1 | Implemented |
| AES-CTR | SP 800-38A | 128/256-bit | `aes` 0.8 + `ctr` 0.9 | Implemented |
| AES-KW | SP 800-38F | 128/256-bit | `aes-kw` 0.2 | Implemented |
| RSA PKCS#1 v1.5 | FIPS 186-5 | 2048, 3072, 4096 | `rsa` 0.9 | Implemented |
| RSA-PSS | FIPS 186-5 | 2048, 3072, 4096 | `rsa` 0.9 | Implemented |
| RSA-OAEP | PKCS#1 v2.2 | 2048, 3072, 4096 | `rsa` 0.9 | Implemented |
| ECDSA P-256 | FIPS 186-5 | 256-bit | `p256` 0.13 | Implemented |
| ECDSA P-384 | FIPS 186-5 | 384-bit | `p384` 0.13 | Implemented |
| Ed25519 | RFC 8032 | 256-bit | `ed25519-dalek` 2 | Implemented |
| ECDH P-256 | SP 800-56A | 256-bit | `p256` 0.13 | Implemented |
| ECDH P-384 | SP 800-56A | 384-bit | `p384` 0.13 | Implemented |
| SHA-256 | FIPS 180-4 | - | `sha2` 0.10 | Implemented |
| SHA-384 | FIPS 180-4 | - | `sha2` 0.10 | Implemented |
| SHA-512 | FIPS 180-4 | - | `sha2` 0.10 | Implemented |
| SHA3-256 | FIPS 202 | - | `sha3` 0.10 | Implemented |
| SHA3-384 | FIPS 202 | - | `sha3` 0.10 | Implemented |
| SHA3-512 | FIPS 202 | - | `sha3` 0.10 | Implemented |
| HMAC-SHA256 | FIPS 198-1 | - | `hmac` 0.12 | Implemented |
| HMAC-SHA384 | FIPS 198-1 | - | `hmac` 0.12 | Implemented |
| HMAC-SHA512 | FIPS 198-1 | - | `hmac` 0.12 | Implemented |
| PBKDF2-HMAC-SHA256 | SP 800-132 | - | `pbkdf2` 0.12 | Implemented (PIN hashing) |
| ML-DSA-44/65/87 | FIPS 204 | - | `ml-dsa` 0.1.0-rc.7 | Implemented |
| ML-KEM-512/768/1024 | FIPS 203 | - | `ml-kem` 0.3.0-rc.0 | Implemented |
| SLH-DSA | FIPS 205 | Multiple | `slh-dsa` 0.2.0-rc.4 | Implemented |

### Non-approved (restricted by configuration)

| Algorithm | Status | Config control |
|-----------|--------|----------------|
| SHA-1 | Available but blocked for signing | `allow_sha1_signing = false` |
| RSA < 2048 | Blocked | `allow_weak_rsa = false` |

### Mechanism count

41 PKCS#11 mechanisms registered via `C_GetMechanismList`:
- 10 RSA (keygen, PKCS#1, PSS with SHA-256/384/512, OAEP)
- 7 EC (keygen, ECDSA, ECDSA-SHA*, ECDH)
- 1 EdDSA
- 7 AES (keygen, GCM, CBC, CBC-PAD, CTR, KW, KWP)
- 7 Digest (SHA-1, SHA-256/384/512, SHA3-256/384/512)
- 9 PQC (ML-KEM-512/768/1024, ML-DSA-44/65/87, SLH-DSA-128s/256s, Hybrid)

## Self-Test Coverage (POST) — 17 tests (integrity + 16 KATs) ✅

All P0 POST KATs have been implemented. Security audit (v0.9.1) upgraded AES-CBC/CTR from circular roundtrip tests to genuine known-answer tests with hardcoded expected ciphertexts, and added RSA PKCS#1 v1.5 KAT.

| Test | Algorithm | Vector Source | Type | Status |
|------|-----------|---------------|------|--------|
| Software integrity | HMAC-SHA256 | Module binary | Integrity check (§9.4) | ✅ Phase 10 |
| SHA-256 KAT | SHA-256 | NIST "abc" | Known Answer | ✅ |
| SHA-384 KAT | SHA-384 | NIST "abc" | Known Answer | ✅ Phase 6 |
| SHA-512 KAT | SHA-512 | NIST "abc" | Known Answer | ✅ |
| SHA3-256 KAT | SHA3-256 | NIST "abc" | Known Answer | ✅ Phase 6 |
| HMAC-SHA256 KAT | HMAC-SHA256 | RFC 4231 TC2 | Known Answer | ✅ |
| HMAC-SHA384 KAT | HMAC-SHA384 | RFC 4231 TC2 | Known Answer | ✅ Phase 6 |
| HMAC-SHA512 KAT | HMAC-SHA512 | RFC 4231 TC2 | Known Answer | ✅ Phase 6 |
| AES-GCM KAT | AES-256-GCM | Fixed key | Roundtrip + known-answer decrypt | ✅ |
| AES-CBC KAT | AES-256-CBC | Fixed key/IV | Known Answer (hardcoded ciphertext) | ✅ v0.9.1 upgraded |
| AES-CTR KAT | AES-256-CTR | Fixed key/IV | Known Answer (hardcoded ciphertext) | ✅ v0.9.1 upgraded |
| RSA 2048 KAT | RSA 2048 PKCS#1 v1.5 | Generated key | Sign/Verify roundtrip | ✅ v0.9.1 added |
| ECDSA roundtrip | ECDSA P-256 | Generated key | Sign/Verify | ✅ |
| ML-DSA roundtrip | ML-DSA-44 | Generated key | Sign/Verify | ✅ |
| ML-KEM roundtrip | ML-KEM-768 | Generated key | Encap/Decap | ✅ Phase 6 |
| RNG health | OS RNG | Entropy + continuous | Health | ✅ Phase 6 enhanced |
| HMAC_DRBG KAT | HMAC_DRBG | NIST CAVP vector | Known Answer | ✅ Phase 7 |

### Continuous RNG Health Test

Per SP 800-90B, a continuous RNG test runs on every `C_GenerateRandom` call. Previous 32-byte output is stored; identical consecutive outputs cause `CKR_FUNCTION_FAILED`.

### DRBG Health Test ✅

The HMAC_DRBG includes a continuous health test that compares consecutive outputs (Phase 7). A NIST CAVP known-answer test validates DRBG correctness during POST.

## Test Suite Summary

| Suite | Tests | Description |
|-------|-------|-------------|
| `crypto::self_test` | 1 | POST verification (17 tests: integrity + 16 KATs) |
| `crypto::drbg` | 6 | HMAC_DRBG unit tests |
| `crypto_vectors` | 12 | Phase 1 KAT tests (AES, RSA, ECDSA, EdDSA) |
| `crypto_vectors_phase2` | 56 | Phase 2 KATs (ECDH, AES modes, RSA-OAEP/PSS, key wrap, digests, PBKDF2) |
| `pkcs11_compliance` | 1 | Core session state machine lifecycle |
| `pkcs11_compliance_extended` | 1 | PQC ABI, PIN enforcement, FindObjects, DestroyObject |
| `pqc_phase3` | 19 | ML-KEM, ML-DSA, SLH-DSA, hybrid roundtrips |
| `concurrent_stress` | 5 | Thread-safety: ML-DSA, ML-KEM, AES, ECDSA, mixed keygen |
| `pkcs11_error_paths` | 50 | Error handling coverage for all ABI functions |
| `session_state_machine` | 42 | Session lifecycle and state transition tests |
| `attribute_validation` | 24 | Template validation and attribute handling |
| `concurrent_session_stress` | 6 | Multi-threaded session stress tests |
| `zeroization` | 7 | Key material zeroization verification (ignored by default) |
| `persistence` | 9 | Persistent storage roundtrip and integrity |
| `multipart_sign_verify` | 12 | Multi-part C_SignUpdate/Final, C_VerifyUpdate/Final |
| `multipart_encrypt_decrypt` | 10 | Multi-part C_EncryptUpdate/Final, C_DecryptUpdate/Final |
| `supplementary_functions` | 15 | C_CopyObject, C_DigestKey tests |
| `drbg` | 5 | DRBG integration tests (keygen + sign + encrypt roundtrip) |
| `multi_slot` | 8 | Multi-slot support (configurable slot count) |
| `operation_state` | 8 | C_GetOperationState/C_SetOperationState save/restore |
| `backup_restore` | 8 | Encrypted HSM backup/restore roundtrip |
| `pkcs11_conformance` | 46 | PKCS#11 ABI conformance, security hardening, config validation |
| **Total** | **617+** | |

## Fuzzing Infrastructure

| Target | Coverage | Run Command |
|--------|----------|-------------|
| `fuzz_c_abi` | C_CreateObject, C_FindObjects, C_GenerateRandom, sessions, digest | `cargo fuzz run fuzz_c_abi` |
| `fuzz_crypto_ops` | AES-GCM/CBC/CTR roundtrips, digest, random ciphertext/signature | `cargo fuzz run fuzz_crypto_ops` |
| `fuzz_attributes` | ObjectStore create, read_attribute, template matching | `cargo fuzz run fuzz_attributes` |
| `fuzz_session_lifecycle` | Session open/close, login/logout, state transitions | `cargo fuzz run fuzz_session_lifecycle` |
| `fuzz_buffer_overflow` | Buffer boundary testing for C ABI output parameters | `cargo fuzz run fuzz_buffer_overflow` |

## Recommended Audit Firm Requirements

A FIPS 140-3 audit requires a CMVP-accredited laboratory. The audit covers:

1. **Security Policy** document (see [security-policy.md](security-policy.md))
2. **Finite State Model** of the module (documented in architecture.md)
3. **Physical Security** — N/A for software module (Level 1)
4. **Operational Environment** — general-purpose OS, no modification required
5. **Cryptographic Key Management** — key lifecycle, zeroization
6. **Self-Tests** — POST and conditional tests
7. **Design Assurance** — source code review, configuration management
8. **Mitigation of Other Attacks** — N/A for Level 1

## Estimated Scope for Level 1 Certification

| Property | Value |
|----------|-------|
| Module type | Software |
| Security level | 1 (no physical security requirements) |
| Operational environment | Modifiable (general-purpose OS) |
| Key management | Plaintext keys in process memory (zeroized on free) |
| Ports and interfaces | PKCS#11 C API, gRPC API |
| Lines of Rust code | ~10,000 (core library, excluding tests and tools) |
| Third-party crypto crates | 15 (see Dependency Audit in fips-gap-analysis.md) |
