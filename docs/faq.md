# Frequently Asked Questions

## General

### Is Craton HSM FIPS 140-3 certified?

**No.** Craton HSM implements FIPS 140-3 Level 1 technical requirements (POST self-tests, approved-only mode, HMAC_DRBG, pairwise consistency tests, module integrity checks), but it has **not** undergone CMVP validation by an accredited laboratory. Do not rely on it for FIPS compliance without independent certification. See [FIPS Gap Analysis](fips-gap-analysis.md) for details.

### Can I use Craton HSM in production?

Craton HSM is designed for production use as a software PKCS#11 provider. It includes memory hardening, tamper-evident audit logging, encrypted persistence, and comprehensive self-tests. However:

- It is a **software** HSM (FIPS Level 1) — it does not provide physical tamper resistance
- The PQC dependencies are at release candidate versions
- It has not undergone formal third-party security audit (yet)

Evaluate your threat model and compliance requirements before deploying.

### How does Craton HSM compare to SoftHSMv2?

| Feature | Craton HSM | SoftHSMv2 |
|---------|---------|-----------|
| Language | Rust (memory-safe) | C++ |
| Post-quantum crypto | ML-KEM, ML-DSA, SLH-DSA | No |
| FIPS self-tests | 17 POST KATs | No |
| Audit logging | Chained SHA-256 tamper-evident | No |
| Key lifecycle (SP 800-57) | Yes | No |
| HMAC_DRBG (SP 800-90A) | Yes (prediction resistance) | No |
| Memory hardening | mlock + ZeroizeOnDrop | Partial |
| Multi-slot | Yes (up to 256) | Yes |
| Encrypted persistence | AES-256-GCM + PBKDF2 | SQLite + AES |

See [Benchmarks](benchmarks.md) for performance comparisons.

### What PKCS#11 version does Craton HSM implement?

PKCS#11 v3.0 (OASIS Standard). The library exports 70+ functions covering initialization, session management, object management, key generation, signing, verification, encryption, decryption, digesting, key wrapping, key derivation, and random number generation.

## Cryptography

### What algorithms are supported?

**Classical**:
- RSA: 2048/3072/4096-bit (PKCS#1 v1.5, PSS, OAEP)
- ECDSA: P-256, P-384
- EdDSA: Ed25519
- AES: 128/192/256-bit (GCM, CBC, CTR, Key Wrap)
- Digest: SHA-1, SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512
- HMAC: SHA-256, SHA-384, SHA-512
- KDF: ECDH (P-256/P-384) with internal HKDF-SHA256 per SP 800-56C

**Post-Quantum** (NIST standards, RC crate versions):
- ML-KEM: 512, 768, 1024 (FIPS 203)
- ML-DSA: 44, 65, 87 (FIPS 204)
- SLH-DSA: SHA2-128s, SHA2-256s (FIPS 205)

### Are the PQC implementations stable?

The PQC crates (`ml-kem 0.3.0-rc.0`, `ml-dsa 0.1.0-rc.7`, `slh-dsa 0.2.0-rc.4`) are release candidates. Their APIs and key serialization formats may change before reaching 1.0. Keys generated with RC versions should be considered non-portable across major version bumps. See [Future Work Guide](future-work-guide.md) for the upgrade timeline.

### Why is SHA-1 available but restricted?

SHA-1 is available for digest operations (`C_Digest`) and signature verification (`C_Verify`) for backward compatibility, but is blocked for new signatures by default. This is controlled by `allow_sha1_signing` in the `[algorithms]` config section. In FIPS approved mode, SHA-1 is fully blocked.

### How is randomness generated?

All randomness goes through an SP 800-90A HMAC_DRBG (HMAC-SHA256) with:
- **Prediction resistance**: Reseeds from OS entropy on every `generate()` call
- **Continuous health test**: Rejects identical consecutive outputs (SP 800-90B)
- **Monotonic reseed counter**: Limits calls to 2^48 before mandatory reseed
- No key generation or crypto operation uses `OsRng` directly

## Security

### How is key material protected?

1. **In memory**: Wrapped in `RawKeyMaterial` (`Vec<u8>` with mlock), locked to physical RAM via `mlock`/`VirtualLock`, zeroed on drop via `ZeroizeOnDrop`
2. **At rest**: Encrypted with AES-256-GCM using a PBKDF2-derived key (600,000 iterations, configurable)
3. **In logs**: Never appears — `Debug` impl returns `[REDACTED]`
4. **In backups**: Encrypted with PIN-derived key (PBKDF2 + AES-256-GCM)

### What happens after too many failed PINs?

Failed login attempts trigger exponential backoff:
- Base delay: 100 ms, doubles per failure, capped at 5 seconds
- After `max_failed_logins` failures (default: 10), the account is locked
- Locked accounts require token re-initialization (`C_InitToken`) by the SO

### Does Craton HSM protect against side-channel attacks?

At the software level:
- **Constant-time PIN comparison** via `subtle::ConstantTimeEq`
- **Constant-time template matching** using bitwise accumulators (no early returns)
- **No secret-dependent branching** in the HSM logic layer

The underlying crypto libraries (RustCrypto, aws-lc-rs) have their own side-channel resistance properties. See [Security Model](security-model.md) for details.

## Operations

### Can multiple processes use Craton HSM simultaneously?

Not directly — the persistent store uses exclusive file locking. For multi-process access, use the **gRPC daemon** (`craton-hsm-daemon`) which serializes all access through a single HSM instance with mutual TLS authentication. See [Fork Safety](fork-safety.md) for deployment patterns.

### How do I back up token data?

```bash
# Export encrypted backup
craton-hsm-admin backup --pin <SO_PIN> --output backup.enc

# Restore from backup
craton-hsm-admin restore --pin <SO_PIN> --input backup.enc
```

Backups are encrypted with the SO PIN via PBKDF2 + AES-256-GCM. See [Operator Runbook](operator-runbook.md).

### How do I run in a container?

A production Dockerfile is provided at `deploy/Dockerfile` using a distroless runtime image (no shell, non-root). A Helm chart is available at `deploy/helm/craton_hsm/`. See [Installation Guide](install.md) for details.

## Development

### Why must tests run single-threaded?

PKCS#11 defines a single global state per process (`C_Initialize` / `C_Finalize`). Running tests in parallel causes race conditions on this global state. Always use `cargo test -- --test-threads=1`.

### How do I add a new crypto mechanism?

1. Add the mechanism constant to `src/pkcs11_abi/constants.rs`
2. Register it in `src/crypto/mechanisms.rs` (validation + FIPS policy)
3. Implement the operation in the appropriate `src/crypto/` module
4. Add the `CryptoBackend` trait method in `src/crypto/backend.rs`
5. Implement for both backends (`rustcrypto_backend.rs`, `awslc_backend.rs`)
6. Wire it into the C ABI in `src/pkcs11_abi/functions.rs`
7. Add integration tests and update `C_GetMechanismList`/`C_GetMechanismInfo`

### How do I run the fuzz targets?

```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Run a specific target
cargo +nightly fuzz run fuzz_buffer_overflow

# Run with a time limit
cargo +nightly fuzz run fuzz_c_abi -- -max_total_time=300
```

See [Security Review Checklist](security-review-checklist.md) for fuzz target priorities.
