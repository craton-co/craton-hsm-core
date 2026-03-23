# FIPS 140-3 Mode Operator Guide

## Overview

Craton HSM supports a FIPS-approved mode of operation when configured correctly. This guide covers the required build, configuration, and deployment steps for FIPS compliance.

---

## 1. Build for FIPS

### Required: aws-lc-rs Backend

For FIPS deployments, build with the FIPS-certified crypto backend:

```bash
cargo build --release --features awslc-backend
```

This uses [AWS-LC](https://github.com/aws/aws-lc), which holds FIPS 140-3 certification. The default `rustcrypto-backend` uses RustCrypto crates which are not FIPS-certified.

### Build Dependencies (aws-lc-rs)

- CMake 3.x
- Clang / LLVM
- Go (for AWS-LC build system)

On Windows, set:
```
LIBCLANG_PATH=C:\path\to\llvm\bin
AWS_LC_SYS_NO_ASM=1
```

---

## 2. Configuration

Create or modify `craton_hsm.toml` (or set `CRATON_HSM_CONFIG` env var):

```toml
[algorithms]
# Required: use FIPS-certified backend
crypto_backend = "awslc"

# Required: restrict to FIPS-approved algorithms only
fips_approved_only = true

# Recommended: disable PQC (not yet FIPS-approved)
enable_pqc = false

# Defaults (already correct for FIPS):
# allow_weak_rsa = false    # RSA < 2048 blocked
# allow_sha1_signing = false # SHA-1 signing blocked
```

### Configuration Effects

When `fips_approved_only = true`:

| Category | Allowed | Blocked |
|----------|---------|---------|
| Symmetric | AES-128/192/256 (GCM, CBC, CTR, KW) | — |
| RSA | RSA-2048/3072/4096 (PKCS#1v15, PSS, OAEP) | RSA < 2048 |
| ECDSA | P-256, P-384 | — |
| ECDH | P-256, P-384 | — |
| Digest | SHA-256/384/512, SHA3-256/384/512 | SHA-1 |
| MAC | HMAC-SHA256/384/512 | — |
| EdDSA | — | Ed25519 (not FIPS-approved) |
| PQC | — | ML-DSA, ML-KEM, SLH-DSA, Hybrids |

---

## 3. Software Integrity Verification

### Compute the Integrity HMAC

After building, compute the HMAC-SHA256 sidecar file:

**Linux/macOS:**
```bash
./tools/compute-integrity-hmac.sh target/release/libcraton_hsm.so
```

**Windows (PowerShell):**
```powershell
.\tools\compute-integrity-hmac.ps1 -LibPath target\release\craton_hsm.dll
```

This creates a `.hmac` file (e.g., `libcraton_hsm.hmac`) next to the library. The module verifies this HMAC at every `C_Initialize` call as part of the Power-On Self-Test.

### Integrity Check Behavior

| Scenario | Behavior |
|----------|----------|
| No `.hmac` file | Warning logged, check skipped (development mode) |
| `.hmac` file matches | Check passes silently |
| `.hmac` file mismatch | POST fails, module enters error state (`CKR_GENERAL_ERROR`) |
| Binary modified after `.hmac` computed | POST fails |

**Important**: Recompute the `.hmac` file after every rebuild.

---

## 4. Algorithm Indicator (IG 2.4.C)

Every cryptographic operation records whether it used a FIPS-approved algorithm. This information is available in two places:

### 4.1 Audit Log

Each audit log entry for crypto operations includes `"fips_approved": true/false`:

```json
{
  "timestamp": 1709740800000000000,
  "session_handle": 1,
  "operation": {
    "Sign": {
      "mechanism": 7,
      "fips_approved": true
    }
  },
  "result": "Success",
  "previous_hash": "..."
}
```

### 4.2 Session State

After each crypto operation, the session records `last_operation_fips_approved`. This can be queried programmatically.

### 4.3 Vendor-Defined Attribute

`CKA_VENDOR_FIPS_APPROVED` (0x80000001) is defined for future use with `C_GetSessionInfo` extensions.

---

## 5. Approved vs Non-Approved Services

### Approved Services (FIPS mode)

| Service | Mechanisms |
|---------|-----------|
| Key Generation | RSA (≥2048), EC (P-256, P-384), AES |
| Digital Signature | SHA256/384/512-RSA-PKCS, SHA256/384/512-RSA-PSS, ECDSA |
| Verification | Same as signing |
| Encryption | AES-GCM, AES-CBC, AES-CTR |
| Decryption | AES-GCM, AES-CBC, AES-CTR |
| Key Wrapping | AES Key Wrap (RFC 3394) |
| Digest | SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512 |
| MAC | HMAC-SHA256, HMAC-SHA384, HMAC-SHA512 |
| Key Agreement | ECDH P-256, ECDH P-384 |
| Random Generation | SP 800-90A HMAC_DRBG (seeded from OS CSPRNG) |

### Non-Approved Services

| Service | Mechanism | Availability |
|---------|-----------|-------------|
| EdDSA signing | CKM_EDDSA (Ed25519) | Blocked in FIPS mode |
| SHA-1 digest | CKM_SHA_1 | Available for digest only, blocked for signing |
| PQC operations | ML-DSA, ML-KEM, SLH-DSA | Blocked in FIPS mode |

---

## 6. Self-Tests

### Power-On Self-Tests (POST)

Run automatically at `C_Initialize`:

1. **Software integrity test** (HMAC-SHA256 of module binary)
2. 16 Known Answer Tests (SHA-2/3, HMAC, AES-GCM/CBC/CTR, RSA, ECDSA, ML-DSA, ML-KEM, RNG, DRBG)

Total: 17 self-tests (integrity + 16 KATs).

### Conditional Self-Tests

| Test | Trigger |
|------|---------|
| Pairwise consistency | After every `C_GenerateKeyPair` (sign/verify or encap/decap roundtrip) |
| Continuous RNG health | Every `C_GenerateRandom` call |
| DRBG continuous health | Every DRBG generate call |

### Error State

If any self-test fails:
- `POST_FAILED` flag is set
- All subsequent operations return `CKR_GENERAL_ERROR`
- Process must be restarted to recover

---

## 7. Deployment Checklist

- [ ] Build with `--features awslc-backend`
- [ ] Set `crypto_backend = "awslc"` in config
- [ ] Set `fips_approved_only = true` in config
- [ ] Compute `.hmac` integrity sidecar: `./tools/compute-integrity-hmac.sh`
- [ ] Verify POST passes: check for `CKR_OK` from `C_Initialize`
- [ ] Verify only approved mechanisms listed: `pkcs11-tool --module ./libcraton_hsm.so --list-mechanisms`
- [ ] Initialize token with strong SO PIN: `pkcs11-tool --module ./libcraton_hsm.so --init-token --label "Production" --so-pin <strong-pin>`
- [ ] Set user PIN: `pkcs11-tool --module ./libcraton_hsm.so --init-pin --pin <user-pin> --so-pin <so-pin>`
- [ ] Review audit log periodically for algorithm indicator compliance
- [ ] Run `cargo test --features awslc-backend -- --test-threads=1` to verify all tests pass
