# Security Model

## Threat Model

Craton HSM is a software HSM. Unlike hardware HSMs, it does not protect against physical attacks or OS-level compromise. Its security boundary is the process.

### In scope (threats Craton HSM defends against)

| Threat | Defense |
|--------|---------|
| Memory corruption (buffer overflow, use-after-free) | Rust's ownership system prevents these at compile time |
| PIN brute-force | PBKDF2 (600K iterations) + configurable lockout after N failures |
| Timing side-channels on PIN comparison | `subtle::ConstantTimeEq` for all sensitive comparisons |
| Key material leakage via logging | Custom `Debug` impls print `[REDACTED]` for all key types |
| Key material leakage in memory after use | `ZeroizeOnDrop` on `RawKeyMaterial`; `mlock`/`VirtualLock` on key pages |
| Fork-induced state corruption | PID recorded at init; child gets `CKR_CRYPTOKI_NOT_INITIALIZED` |
| Database corruption from concurrent processes | Exclusive file lock on persistent store |
| Unauthorized key extraction | `CKA_SENSITIVE=true` and `CKA_EXTRACTABLE=false` enforced |
| Unauthorized operations | Session state machine enforces login before private object access |
| Audit log tampering | Chained SHA-256 hashes; any modification breaks the chain |
| Panic-induced undefined behavior at FFI boundary | `catch_unwind` wraps every `extern "C"` export |
| Use of weak algorithms | `allow_weak_rsa=false`, `allow_sha1_signing=false` by default |
| Corrupted binary / supply-chain | FIPS POST: 17 self-tests (integrity + 16 KATs) + continuous RNG health check run before any crypto operation |
| AES-GCM nonce reuse (per key) | Per-key encryption counters with 2^31 limit; all-zero IV rejection at C_EncryptInit |
| Config path traversal | UNC path, `..` traversal, and absolute path rejection in config validation |
| Key misuse after expiry | SP 800-57 key lifecycle: date-based deactivation blocks signing/encryption |

### Out of scope (threats requiring hardware HSM or OS hardening)

| Threat | Why out of scope |
|--------|-----------------|
| Cold boot attacks | Keys live in process memory; physical access can dump RAM |
| DMA attacks | No IOMMU enforcement at software level |
| OS kernel compromise | If the kernel is compromised, all process memory is accessible |
| Power analysis / EM side-channels | Software cannot prevent hardware-level leakage |
| Speculative execution attacks (Spectre) | Mitigations depend on CPU microcode and OS patches |

### Side-Channel Resistance

Craton HSM implements software-level side-channel countermeasures for timing attacks. Physical side-channels (power, electromagnetic) are out of scope for a software HSM.

**Constant-time operations:**

| Operation | Implementation | Side-Channel Defense |
|-----------|---------------|---------------------|
| PIN comparison | PBKDF2-HMAC-SHA256 + `subtle::ConstantTimeEq` | Timing-safe: compare time independent of correct/incorrect PIN bytes |
| HMAC verification | `subtle::ConstantTimeEq` on HMAC tags | Prevents byte-by-byte timing leakage of MAC values |
| RSA signing (RustCrypto) | `rsa` crate with blinding by default | Montgomery multiplication with randomized blinding factor |
| RSA signing (aws-lc-rs) | AWS-LC (BoringSSL fork) | Constant-time bignum arithmetic, same as Google/AWS production |
| ECDSA signing (RustCrypto) | `p256`/`p384` crates | Field arithmetic in constant time (no branching on secret scalars) |
| ECDSA signing (aws-lc-rs) | AWS-LC P-256/P-384 | Assembly-optimized constant-time point multiplication |
| AES operations | RustCrypto `aes` crate with AES-NI | Hardware AES-NI intrinsics are inherently constant-time (no table lookups) |
| SHA-256/384/512 | RustCrypto `sha2` crate | No secret-dependent branching; hardware SHA extensions when available |

**Backend-specific notes:**

- **RustCrypto backend** (default): Pure Rust implementations. RSA uses randomized blinding. ECC uses projective coordinates with complete addition formulas. AES uses AES-NI when available, falling back to a bitsliced implementation that avoids timing-leaky S-box table lookups.

- **aws-lc-rs backend** (FIPS): Assembly-optimized constant-time implementations from AWS-LC/BoringSSL. Battle-tested in AWS production. RSA uses constant-time modular exponentiation. ECC uses optimized P-256 and P-384 assembly with constant-time scalar multiplication. This is the same cryptographic core used by AWS KMS.

**What we do NOT claim:**
- Protection against cache-timing attacks on systems without AES-NI (extremely rare on modern hardware)
- Protection against speculative execution attacks (Spectre/Meltdown variants)
- Protection against physical side-channels (power analysis, EM emanations)
- Formally verified constant-time guarantees (would require tools like ct-verif or Jasmin)

## Key Protection

### Memory safety (Rust guarantees)

Rust eliminates at compile time the vulnerability classes responsible for the majority of memory-safety CVEs in C/C++ HSM implementations:

- **No buffer overflows**: array bounds are checked at runtime
- **No use-after-free**: the ownership system prevents accessing freed memory
- **No double-free**: memory is freed exactly once when the owner is dropped
- **No null pointer dereference**: `Option<T>` forces explicit handling
- **No data races**: the borrow checker prevents concurrent mutable access

The only `unsafe` code is in the PKCS#11 C ABI layer (`src/pkcs11_abi/functions.rs`) and the memory locking module (`src/crypto/mlock.rs`). All blocks are annotated with `// SAFETY:` comments explaining their correctness.

**Fork safety**: On Unix, Craton HSM detects `fork(2)` by comparing the current PID against the PID stored at `C_Initialize` time. A forked child process receives `CKR_CRYPTOKI_NOT_INITIALIZED` on any PKCS#11 call and must call `C_Initialize` to create fresh state. See `docs/fork-safety.md` for full details.

**Multi-process access**: Concurrent multi-process access to the same persistent database is prevented by an exclusive file lock acquired at initialization. For multi-process access to the same token, use the gRPC daemon (`craton-hsm-daemon`), which serializes all operations.

### Key material lifecycle

```
Generate / Import
       |
       v
  RawKeyMaterial::new(bytes)
  |  └── mlock(ptr, len)    <-- locks pages into physical RAM
  |  └── Debug: [REDACTED]  <-- never logs key bytes
  |
  |  Used via &[u8] borrow (never cloned unnecessarily)
  |
  v
  Crypto operation (sign, encrypt, etc.)
  |
  v
  Drop (manual impl):
  |  1. self.0.zeroize()     <-- clears all bytes to 0x00
  |  2. munlock(ptr, len)    <-- unlocks (now-zeroed) pages
```

**Platform support**:
- Unix: `libc::mlock` / `libc::munlock`
- Windows: `VirtualLock` / `VirtualUnlock` via `windows-sys`
- Failure is non-fatal (logged, continues) — may lack privileges for large buffers

### Access control model

PKCS#11 objects have three levels of protection:

1. **CKA_PRIVATE**: If `true`, object is invisible to `C_FindObjects` unless the session is logged in
2. **CKA_SENSITIVE**: If `true`, `CKA_VALUE` (key bytes) cannot be read via `C_GetAttributeValue`
3. **CKA_EXTRACTABLE**: If `false`, key material cannot be exported

Default for generated keys: `PRIVATE=true, SENSITIVE=true, EXTRACTABLE=false` (maximum protection).

### PIN security

| Property | Implementation |
|----------|---------------|
| Hash algorithm | PBKDF2-HMAC-SHA256 |
| Iterations | 600,000 (configurable) |
| Salt | 32 bytes from `OsRng` (per-PIN, stored with hash) |
| Comparison | `subtle::ConstantTimeEq` |
| Lockout | Configurable threshold (default: 10 failures) |
| PIN storage | Hash stored in `Zeroizing<Vec<u8>>` (zeroed on drop) |
| PIN in transit | Never logged; CLI uses `rpassword` (no terminal echo) |

## Audit Integrity

The audit log is append-only with chained SHA-256 hashes:

```
Entry[0].previous_hash = [0; 32]  (genesis)
Entry[1].previous_hash = SHA-256(serialize(Entry[0]))
Entry[2].previous_hash = SHA-256(serialize(Entry[1]))
...
```

Properties:
- **Tamper-evident**: modifying, deleting, or reordering any entry breaks the hash chain
- **Synchronous**: event is recorded before the PKCS#11 function returns (not fire-and-forget)
- **Non-repudiable**: each entry includes session handle, operation type, timestamp, and result

Audited operations: Initialize, Finalize, Login, Logout, GenerateKey, GenerateKeyPair, Sign, Verify, Encrypt, Decrypt, CreateObject, DestroyObject, GenerateRandom.

## Algorithm Selection

### Approved algorithms

| Category | Algorithms | Standard |
|----------|-----------|----------|
| Symmetric encryption | AES-256-GCM, AES-256-CBC, AES-256-CTR | SP 800-38A/D |
| Key wrapping | AES Key Wrap | SP 800-38F (RFC 3394) |
| RSA signing | PKCS#1 v1.5, PSS (SHA-256/384/512) | FIPS 186-5 |
| RSA encryption | OAEP (SHA-256) | PKCS#1 v2.2 |
| Elliptic curve | ECDSA P-256, P-384 | FIPS 186-5 |
| Edwards curve | Ed25519 | RFC 8032 |
| Key agreement | ECDH P-256, P-384 | SP 800-56A |
| Hash | SHA-256, SHA-384, SHA-512 | FIPS 180-4 |
| Hash (SHA-3) | SHA3-256, SHA3-384, SHA3-512 | FIPS 202 |
| MAC | HMAC-SHA256/384/512 | FIPS 198-1 |
| KDF | PBKDF2-HMAC-SHA256 | SP 800-132 |
| PQC signing | ML-DSA-44/65/87 | FIPS 204 |
| PQC KEM | ML-KEM-512/768/1024 | FIPS 203 |
| PQC signing | SLH-DSA (SHA2-128s, SHA2-256s) | FIPS 205 |
| Hybrid | ML-DSA-65 + ECDSA-P256 | Composite |

### Restricted by default

| Setting | Default | Effect |
|---------|---------|--------|
| `allow_weak_rsa` | `false` | Blocks RSA key generation < 2048 bits |
| `allow_sha1_signing` | `false` | Blocks SHA-1 as a hash in signatures |

## FIPS 140-3 Readiness

### Power-On Self-Tests (POST)

Run during `C_Initialize`. If any test fails, the module sets `POST_FAILED=true` and all subsequent calls return `CKR_GENERAL_ERROR`. On re-initialization (after `C_Finalize`), `POST_FAILED` is reset and POST re-runs. See `docs/audit-scope.md` for the full POST table (17 tests: integrity check + 16 KATs).

### SP 800-90A DRBG

All cryptographic random number generation — including key generation for RSA, EC, and Ed25519 — is routed through an HMAC_DRBG (HMAC-SHA256) per SP 800-90A via a `DrbgRng` wrapper implementing `rand::CryptoRng`. The DRBG is seeded from the OS CSPRNG with prediction resistance (fresh entropy on every call). A continuous health test (SP 800-90B) detects stuck output.

### SP 800-57 Key Lifecycle

Keys support date-based lifecycle states per SP 800-57: pre-activation (before `CKA_START_DATE`), active, deactivated (after `CKA_END_DATE`), compromised, and destroyed. Deactivated keys can still verify/decrypt but cannot sign/encrypt.

### FIPS crypto backend

Craton HSM supports two crypto backends, selectable via `algorithms.crypto_backend` in config:

| Backend | Feature Flag | FIPS Status |
|---------|-------------|-------------|
| RustCrypto (default) | `rustcrypto-backend` | Not FIPS-certified |
| AWS-LC (aws-lc-rs) | `awslc-backend` | FIPS 140-3 validated module |

With `--features awslc-backend` and `crypto_backend = "awslc"`, all classical crypto operations use the FIPS-validated AWS-LC library.

### Remaining gaps for formal FIPS certification

See `docs/fips-gap-analysis.md` for the full analysis. The major gaps (DRBG, key lifecycle, POST KATs) have been resolved. Remaining items are documentation and formal certification process.

## Security Invariants

These 10 properties are verified at every development phase and must never be violated:

1. **No panic crosses FFI boundary** — `catch_unwind` on all `extern "C"` functions
2. **No key bytes in logs** — custom `Debug` impls with `[REDACTED]`
3. **No key bytes returned** for `CKA_SENSITIVE=true, CKA_EXTRACTABLE=false` objects
4. **Constant-time PIN/HMAC comparison** — `subtle::ConstantTimeEq` everywhere
5. **All key material zeroized on drop** — `ZeroizeOnDrop` derive on all key types
6. **Session state machine is authoritative** — check state, not just login flag
7. **Audit log written before operation returns** — not fire-and-forget async
8. **DRBG for all key material** — SP 800-90A HMAC_DRBG (via `DrbgRng` adapter) for RSA, EC, Ed25519, AES key generation; never `OsRng` directly or `rand::random()` for keys
9. **No unsafe in crypto paths** — all unsafe blocks confined to ABI layer and mlock.rs, none in crypto engine
10. **Generic errors to callers** — never leak internal state via error messages
