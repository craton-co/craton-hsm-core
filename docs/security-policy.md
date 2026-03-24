# Craton HSM Security Policy

> **DISCLAIMER: Craton HSM is NOT FIPS 140-3 certified.** This document describes the security design targeting FIPS 140-3 Level 1 requirements. The module has not been validated by a CMVP-accredited laboratory.

## Document Information

| Property | Value |
|----------|-------|
| Module Name | Craton HSM |
| Module Version | 0.9.1 |
| Module Type | Software |
| FIPS 140-3 Target Level | 1 (not certified) |
| Document Version | 4.0 |
| Date | 2026-03-17 |

---

## 1. Module Description

Craton HSM is a PKCS#11 v3.0-compliant software Hardware Security Module (HSM) implemented in Rust. It provides cryptographic key management, generation, storage, and operations through the standard PKCS#11 C API interface.

The module runs as a shared library (`libcraton_hsm.so` / `craton_hsm.dll`) loaded into an application's address space, or as a standalone gRPC daemon for remote access.

### 1.1 Module Architecture

```
+---------------------------------------------------------------+
|                    Cryptographic Module Boundary                |
|                                                                 |
|  +-------------------+  +------------------+  +--------------+ |
|  | PKCS#11 C ABI     |  | gRPC Interface   |  | Admin CLI    | |
|  | (libcraton_hsm.so)   |  | (craton-hsm-daemon) |  | (craton_hsm-   | |
|  |                    |  |                  |  |  admin)      | |
|  +--------+-----------+  +--------+---------+  +------+-------+ |
|           |                       |                    |         |
|  +--------v-----------------------v--------------------v-------+ |
|  |                      HsmCore                                | |
|  |  +------------------+  +------------------+                 | |
|  |  | SessionManager   |  | SlotManager      |                 | |
|  |  | (DashMap)        |  | (Token, PIN)     |                 | |
|  |  +------------------+  +------------------+                 | |
|  |  +------------------+  +------------------+                 | |
|  |  | ObjectStore      |  | CryptoBackend    |                 | |
|  |  | (in-memory +     |  | (RustCrypto or   |                 | |
|  |  |  EncryptedStore) |  |  aws-lc-rs)      |                 | |
|  |  +------------------+  +------------------+                 | |
|  |  +------------------+  +------------------+                 | |
|  |  | AuditLog         |  | Self-Test (POST) |                 | |
|  |  +------------------+  +------------------+                 | |
|  +-------------------------------------------------------------+ |
+---------------------------------------------------------------+
```

### 1.2 Physical Boundary

As a software-only module (FIPS 140-3 Level 1), the physical boundary is defined by the process address space of the host application loading the module. There are no physical security mechanisms.

---

## 2. Ports and Interfaces

### 2.1 Logical Interfaces

| Interface | Type | Description |
|-----------|------|-------------|
| Data Input | PKCS#11 API parameters | Plaintext data, mechanism parameters, templates |
| Data Output | PKCS#11 API return values | Ciphertext, signatures, digests, object handles |
| Control Input | PKCS#11 management functions | C_Initialize, C_Login, C_InitToken, C_InitPIN |
| Control Output | CK_RV return codes | Status/error codes per PKCS#11 specification |
| Status Output | C_GetInfo, C_GetSlotInfo, C_GetTokenInfo | Module status, slot configuration |

### 2.2 API Entry Points

The module exports 70+ PKCS#11 v3.0 C functions via `#[no_mangle] pub extern "C"` declarations. All entry points use `catch_unwind` at the FFI boundary to prevent Rust panics from unwinding through C callers.

---

## 3. Roles, Services, and Authentication

### 3.1 Roles

| Role | PKCS#11 Identity | Authentication |
|------|-----------------|----------------|
| Security Officer (SO) | `CKU_SO` | PIN (PBKDF2-HMAC-SHA256, 600K iterations) |
| Crypto User | `CKU_USER` | PIN (PBKDF2-HMAC-SHA256, 600K iterations) |
| Unauthenticated | (no login) | None — limited to read-only public objects |

### 3.2 Services

| Service | SO Access | User Access | Unauthenticated |
|---------|-----------|-------------|-----------------|
| Key generation | No | Yes | No |
| Signing/Verification | No | Yes | No |
| Encryption/Decryption | No | Yes | No |
| Digest computation | No | Yes | Yes (no key needed) |
| Object creation (private) | No | Yes | No |
| Object creation (public) | No | Yes | Yes |
| Token initialization | Yes | No | No |
| PIN management | Yes (set User PIN) | Yes (change own PIN) | No |
| Object destruction | Yes (any) | Yes (own objects) | No |
| Random number generation | No | Yes | Yes |

### 3.3 Authentication Mechanism

PINs are verified using PBKDF2-HMAC-SHA256 with 600,000 iterations and a random 32-byte salt. The PIN hash is stored; the plaintext PIN is never persisted. PIN comparison uses constant-time comparison (`subtle::ConstantTimeEq`) to prevent timing attacks.

Default PINs:
- SO PIN: `"12345678"` (must be changed on first use via `C_InitToken`)
- User PIN: Set by SO via `C_InitPIN`

---

## 4. Finite State Model

### 4.1 Module States

```
                    +---------------+
                    |   Power Off   |
                    +-------+-------+
                            |
                            v
                    +-------+-------+
             +----->|  POST Running |
             |      +-------+-------+
             |              |
             |        Pass  |  Fail
             |     +--------+--------+
             |     v                 v
      +------+-----+        +-------+-------+
      | Initialized |        |  POST Failed  |
      | (Ready)     |        | (Error State)  |
      +------+------+        +---------------+
             |                  All operations
             |                  return CKR_
             |                  GENERAL_ERROR
     C_Login |
             v
      +------+------+
      | Authenticated|
      | (Operational)|
      +------+------+
             |
     C_Logout|
             v
      (back to Initialized)
```

### 4.2 Session States

Per PKCS#11 specification, each session has an independent state:

| State | Description |
|-------|-------------|
| R/O Public | Read-only, no authentication |
| R/W Public | Read-write, no authentication |
| R/O User | Read-only, user authenticated |
| R/W User | Read-write, user authenticated |
| R/W SO | Read-write, SO authenticated |

### 4.3 Error States

- **POST_FAILED**: If any Power-On Self-Test fails, `POST_FAILED` AtomicBool is set. All subsequent cryptographic operations return `CKR_GENERAL_ERROR`.
- **Fork Detected** (Unix): If a child process calls any PKCS#11 function after `fork()`, it receives `CKR_CRYPTOKI_NOT_INITIALIZED` and must re-initialize.

---

## 5. Cryptographic Algorithms

### 5.1 Approved Algorithms

| Algorithm | Standard | Key Sizes | Use |
|-----------|----------|-----------|-----|
| AES-GCM | SP 800-38D | 256-bit | Authenticated encryption |
| AES-CBC | SP 800-38A | 128/192/256-bit | Block encryption |
| AES-CTR | SP 800-38A | 128/256-bit | Stream encryption |
| AES-KW | SP 800-38F | 128/256-bit | Key wrapping |
| RSA PKCS#1 v1.5 | FIPS 186-5 | 2048/3072/4096 | Signing, verification |
| RSA-PSS | FIPS 186-5 | 2048/3072/4096 | Signing, verification |
| RSA-OAEP | PKCS#1 v2.2 | 2048/3072/4096 | Key transport |
| ECDSA P-256 | FIPS 186-5 | 256-bit | Signing, verification |
| ECDSA P-384 | FIPS 186-5 | 384-bit | Signing, verification |
| ECDH P-256 | SP 800-56A | 256-bit | Key agreement |
| ECDH P-384 | SP 800-56A | 384-bit | Key agreement |
| SHA-256/384/512 | FIPS 180-4 | - | Message digest |
| SHA3-256/384/512 | FIPS 202 | - | Message digest |
| HMAC-SHA256/384/512 | FIPS 198-1 | - | Message authentication |
| PBKDF2-HMAC-SHA256 | SP 800-132 | - | PIN hashing |
| ML-DSA-44/65/87 | FIPS 204 | - | Post-quantum signing |
| ML-KEM-512/768/1024 | FIPS 203 | - | Post-quantum key encapsulation |
| SLH-DSA | FIPS 205 | Multiple | Post-quantum signing (stateless hash-based) |

### 5.2 Non-Approved Algorithms

| Algorithm | Status | Control |
|-----------|--------|---------|
| Ed25519 | Available (not yet FIPS-approved) | Allowed by default |
| SHA-1 | Digest only — blocked for signing | `allow_sha1_signing = false` |
| RSA < 2048 | Blocked | `allow_weak_rsa = false` |

### 5.3 Crypto Backend Selection

Two backends are available at compile time:

| Backend | Feature Flag | FIPS Status |
|---------|-------------|-------------|
| RustCrypto (default) | `rustcrypto-backend` | Not FIPS-certified |
| aws-lc-rs | `awslc-backend` | Backed by AWS-LC (FIPS 140-3 certified) |

For FIPS deployments, build with `--features awslc-backend`. The backend is selected by the `crypto_backend` configuration parameter. Both backends implement the identical `CryptoBackend` trait (26 methods).

### 5.4 Random Number Generation

The module uses an SP 800-90A-compliant HMAC_DRBG (HMAC-SHA256) for all cryptographic random number generation. The DRBG is seeded from the operating system's CSPRNG (`OsRng`):
- **Linux**: `getrandom(2)` system call
- **Windows**: `BCryptGenRandom`
- **macOS**: `SecRandomCopyBytes`

The DRBG provides:
- **Prediction resistance**: fresh entropy from OsRng on every generate call
- **Continuous health test**: compares consecutive DRBG outputs per SP 800-90B
- **Reseed interval**: 2^48 requests before mandatory reseed
- **POST KAT**: NIST CAVP known-answer test validates DRBG correctness at initialization

A continuous RNG health test on the entropy source (per SP 800-90B) compares each 32-byte output block against the previous output. Identical consecutive outputs cause the operation to fail.

---

## 6. Key Management

### 6.1 Key Generation

Keys are generated using approved algorithms and the SP 800-90A HMAC_DRBG (seeded from OS CSPRNG). Key material is allocated in process memory and immediately locked via `mlock()` (Unix) or `VirtualLock()` (Windows) to prevent paging to disk.

### 6.1.1 Key Lifecycle States (SP 800-57)

Keys support lifecycle state tracking per SP 800-57 Part 1:

| State | Trigger | Permitted Operations |
|-------|---------|---------------------|
| Pre-activation | Before `CKA_START_DATE` | None |
| Active | Between start and end dates | All permitted operations |
| Deactivated | After `CKA_END_DATE` | Verify, decrypt, unwrap only |
| Compromised | Manual marking | None |
| Destroyed | `C_DestroyObject` | Handle invalid |

State transitions based on `CKA_START_DATE` and `CKA_END_DATE` are evaluated automatically at each cryptographic operation.

### 6.2 Key Storage

| Storage Mode | Description |
|-------------|-------------|
| In-memory (default) | Keys exist only in process memory; lost on process exit |
| Persistent | Keys stored in redb database, encrypted per-object with AES-256-GCM |

Persistent storage uses a master encryption key derived from the SO PIN via PBKDF2 (600K iterations). Each object is serialized, encrypted with a unique random nonce, and stored as an opaque blob.

### 6.3 Key Protection

| Protection | Mechanism |
|-----------|-----------|
| Memory locking | `mlock()` / `VirtualLock()` prevents swap |
| Zeroization | `ZeroizeOnDrop` trait + manual `Drop` impl |
| Access control | `CKA_EXTRACTABLE`, `CKA_SENSITIVE`, session authentication |
| Constant-time comparison | `subtle::ConstantTimeEq` for PIN verification |
| Debug redaction | Custom `Debug` impls show `[REDACTED]` for key bytes |

### 6.4 Key Destruction

When a key object is destroyed (via `C_DestroyObject` or session close for session objects):

1. `RawKeyMaterial::drop()` is called
2. Memory is overwritten with zeros via `zeroize()`
3. `munlock_buffer()` / `VirtualUnlock()` releases the memory lock
4. If persistent, the encrypted blob is deleted from the database

### 6.5 Key Import/Export

- **Import**: Via `C_CreateObject` with `CKA_VALUE`. Subject to `CKA_TOKEN` and `CKA_PRIVATE` attribute enforcement.
- **Export**: Only if `CKA_EXTRACTABLE = true` (defaults to `false`). Exported via `C_GetAttributeValue` for `CKA_VALUE`.
- **Wrapping**: AES Key Wrap (SP 800-38F) via `C_WrapKey` / `C_UnwrapKey`.

---

## 7. Self-Tests

### 7.1 Power-On Self-Tests (POST)

17 self-tests run at module initialization (`C_Initialize`):

| # | Test | Type |
|---|------|------|
| 0 | Software integrity | HMAC-SHA256 of module binary (§9.4) |
| 1 | SHA-256 | Known Answer (NIST "abc") |
| 2 | SHA-384 | Known Answer (NIST "abc") |
| 3 | SHA-512 | Known Answer (NIST "abc") |
| 4 | SHA3-256 | Known Answer (NIST "abc") |
| 5 | HMAC-SHA256 | Known Answer (RFC 4231 TC2) |
| 6 | HMAC-SHA384 | Known Answer (RFC 4231 TC2) |
| 7 | HMAC-SHA512 | Known Answer (RFC 4231 TC2) |
| 8 | AES-256-GCM | Encrypt/Decrypt roundtrip + known-answer decrypt |
| 9 | AES-256-CBC | Known Answer (hardcoded expected ciphertext) |
| 10 | AES-256-CTR | Known Answer (hardcoded expected ciphertext) |
| 11 | RSA 2048 PKCS#1 v1.5 | Sign/Verify roundtrip |
| 12 | ECDSA P-256 | Sign/Verify roundtrip |
| 13 | ML-DSA-44 | Sign/Verify roundtrip |
| 14 | ML-KEM-768 | Encap/Decap roundtrip |
| 15 | RNG health | Entropy + continuous test (SP 800-90B) |
| 16 | HMAC_DRBG | Known Answer (NIST CAVP) |

The RNG health test verifies the OS random number generator produces non-zero, non-repeating output, and the DRBG continuous health test validates non-repeating DRBG output.

**Note on KAT design (v0.9.1):** AES-CBC and AES-CTR KATs use genuine known-answer tests with hardcoded expected ciphertexts (not circular encrypt/decrypt roundtrips). This catches symmetric implementation bugs that a roundtrip-only test would miss.

### 7.2 POST Failure Behavior

If any POST fails:
- `POST_FAILED` atomic flag is set to `true`
- All subsequent cryptographic operations return `CKR_GENERAL_ERROR`
- On re-initialization (after `C_Finalize`), `POST_FAILED` is reset and POST re-runs
- If POST fails again, the module remains in error state

### 7.3 Conditional Self-Tests (§9.6)

| Test | Trigger | Behavior |
|------|---------|----------|
| Continuous RNG | Every `C_GenerateRandom` call | Compare 32-byte output against previous; fail if identical |
| DRBG continuous | Every DRBG `generate()` call | Compare consecutive outputs; fail if identical |
| RSA pairwise | `C_GenerateKeyPair(CKM_RSA_PKCS_KEY_PAIR_GEN)` | Sign/verify roundtrip with SHA-256 RSA PKCS#1v15 |
| ECDSA P-256 pairwise | `C_GenerateKeyPair(CKM_EC_KEY_PAIR_GEN)` with P-256 | Sign/verify roundtrip |
| ECDSA P-384 pairwise | `C_GenerateKeyPair(CKM_EC_KEY_PAIR_GEN)` with P-384 | Sign/verify roundtrip |
| Ed25519 pairwise | `C_GenerateKeyPair(CKM_EDDSA)` | Sign/verify roundtrip |
| ML-DSA pairwise | `C_GenerateKeyPair(CKM_ML_DSA_*)` | Sign/verify roundtrip |
| ML-KEM pairwise | `C_GenerateKeyPair(CKM_ML_KEM_*)` | Encap/decap roundtrip |
| SLH-DSA pairwise | `C_GenerateKeyPair(CKM_SLH_DSA_*)` | Sign/verify roundtrip |

Pairwise test failure sets `POST_FAILED` and the module enters error state.

---

## 8. Operational Environment

### 8.1 Requirements

- **Operating System**: Any OS supporting Rust compilation (Linux, Windows, macOS)
- **Rust Compiler**: Edition 2021 or later
- **Memory**: Process must have sufficient mlock quota for key material

### 8.2 Multi-Process Considerations

- The module is NOT fork-safe on Unix. Child processes must call `C_Initialize` after fork.
- If persistent storage is enabled, only one process may access a given database path (enforced by exclusive file lock via `fs2`).
- Multi-process access is supported via the gRPC daemon (`craton-hsm-daemon`).

---

## 9. Design Assurance

### 9.1 Source Code Management

- All source code managed in Git
- Rust's ownership model provides compile-time memory safety guarantees
- No `unsafe` code outside the PKCS#11 C ABI boundary (where `catch_unwind` protects callers)

### 9.2 Testing

| Category | Count | Description |
|----------|-------|-------------|
| Unit + integration tests | 617+ | Covers all algorithms, error paths, state machine, multi-part ops, FIPS mode |
| PKCS#11 conformance tests | 46 | ABI-level tests: zero IV rejection, session mgmt, PIN security, crypto roundtrips, config validation |
| Pairwise consistency tests | 6 | RSA, ECDSA P-256/P-384, Ed25519, ML-DSA, ML-KEM sign/verify roundtrips |
| FIPS approved mode tests | 11 | Mechanism blocking, policy enforcement, approved classification |
| Zeroization tests | 7 | Verify key material cleared after drop |
| Persistence tests | 9 | Verify storage integrity across restarts |
| Fuzz targets | 5 | C ABI, crypto ops, attributes, session lifecycle, buffer overflow |
| POST verification | 1 | Validates all 17 self-tests pass (integrity + 16 KATs) |

### 9.3 Build Configuration

For FIPS deployments:
```bash
# Build with FIPS-certified crypto backend
cargo build --release --features awslc-backend

# Verify all tests pass
cargo test --features awslc-backend -- --test-threads=1
```

---

## 10. Mitigation of Other Attacks

FIPS 140-3 Level 1 does not require mitigation of attacks beyond the module boundary. However, the module implements:

| Mitigation | Attack | Mechanism |
|-----------|--------|-----------|
| Constant-time PIN comparison | Timing attacks | `subtle::ConstantTimeEq` |
| Memory locking | Cold boot / swap recovery | `mlock()` / `VirtualLock()` |
| Zeroization | Memory remanence | `ZeroizeOnDrop` on all key material |
| Audit logging | Unauthorized use detection | Tamper-evident append-only log with chained SHA-256 |
| Fork detection | State corruption after fork | PID comparison on every API call (Unix) |
| File locking | Database corruption | Exclusive advisory lock on database file |

---

## 11. Critical Security Parameters (CSPs)

The following table documents all Critical Security Parameters managed by the module, their storage location, protection mechanism, and zeroization method.

| CSP | Type | Storage | Protection | Zeroization |
|-----|------|---------|-----------|-------------|
| AES-256 keys | Symmetric key (32 bytes) | `RawKeyMaterial` (process memory) | mlock, ZeroizeOnDrop | Overwrite with zeros on drop, then munlock |
| AES-128 keys | Symmetric key (16 bytes) | `RawKeyMaterial` (process memory) | mlock, ZeroizeOnDrop | Overwrite with zeros on drop, then munlock |
| RSA private keys | Asymmetric key (PKCS#8 DER) | `RawKeyMaterial` (process memory) | mlock, ZeroizeOnDrop | Overwrite with zeros on drop, then munlock |
| ECDSA P-256 private keys | Asymmetric key (32 bytes scalar) | `RawKeyMaterial` (process memory) | mlock, ZeroizeOnDrop | Overwrite with zeros on drop, then munlock |
| ECDSA P-384 private keys | Asymmetric key (48 bytes scalar) | `RawKeyMaterial` (process memory) | mlock, ZeroizeOnDrop | Overwrite with zeros on drop, then munlock |
| Ed25519 private keys | Asymmetric key (32 bytes) | `RawKeyMaterial` (process memory) | mlock, ZeroizeOnDrop | Overwrite with zeros on drop, then munlock |
| ML-DSA signing keys | PQC key (variable size) | `RawKeyMaterial` (process memory) | mlock, ZeroizeOnDrop | Overwrite with zeros on drop, then munlock |
| ML-KEM decapsulation keys | PQC key (variable size) | `RawKeyMaterial` (process memory) | mlock, ZeroizeOnDrop | Overwrite with zeros on drop, then munlock |
| SLH-DSA signing keys | PQC key (variable size) | `RawKeyMaterial` (process memory) | mlock, ZeroizeOnDrop | Overwrite with zeros on drop, then munlock |
| HMAC keys | Symmetric key (variable) | `RawKeyMaterial` (process memory) | mlock, ZeroizeOnDrop | Overwrite with zeros on drop, then munlock |
| SO PIN hash | PBKDF2 output (32 bytes + 32 bytes salt) | `Token` struct (process memory) | Not extractable via API | Zeroized on process exit |
| User PIN hash | PBKDF2 output (32 bytes + 32 bytes salt) | `Token` struct (process memory) | Not extractable via API | Zeroized on process exit |
| Storage encryption key | AES-256 key (32 bytes) | `ObjectStore::persist_key` (Mutex) | mlock, in-memory only | Cleared via `clear_persist_key()` on C_Logout/C_InitToken |
| HMAC_DRBG state (K, V) | DRBG internal state (64 bytes) | `HmacDrbg` struct (Mutex) | Process memory, Mutex-protected | ZeroizeOnDrop on K and V |
| AES-GCM nonces | 12-byte random values | Ephemeral (stack) | Generated fresh per DRBG call | Dropped from stack |
| PBKDF2 salt | 32 random bytes | Stored alongside PIN hash | Not sensitive (public parameter) | N/A |
| Integrity HMAC key | 32-byte constant | Embedded in binary (compile-time) | Per FIPS IG 9.7 (software module) | N/A (constant) |
| Intermediate plaintext | Variable-length buffers | `ActiveOperation` fields (session memory) | `Zeroizing<Vec<u8>>` — zeroized on drop | Automatic via ZeroizeOnDrop |

### 11.1 CSP Lifecycle

```
Generation/Import --> mlock() --> Active Use --> zeroize() --> munlock() --> Destroyed
                      |                           |
                      |  (if persistent)           |
                      +-> AES-256-GCM encrypt ->   |
                          store in redb             |
                                                   |
                      (if persistent)              |
                      delete from redb <-----------+
```

### 11.2 CSP Access Control

| CSP Category | Who Can Access | API Function |
|-------------|---------------|--------------|
| Private keys | Authenticated User | C_Sign, C_Decrypt, C_UnwrapKey |
| Secret keys | Authenticated User | C_Encrypt, C_Decrypt, C_WrapKey |
| Key material (raw) | Authenticated User + CKA_EXTRACTABLE=true | C_GetAttributeValue(CKA_VALUE) |
| PIN hashes | Module internals only | Not exposed via any API |
| Storage encryption key | Module internals only | Derived from SO PIN during C_Login(CKU_SO) |
