# Craton HSM

[![CI](https://github.com/craton-co/craton-hsm-core/actions/workflows/ci.yml/badge.svg)](https://github.com/craton-co/craton-hsm-core/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
<!-- Badges below will activate after crates.io publish and Codecov setup -->
[![Crates.io](https://img.shields.io/crates/v/craton_hsm.svg)](https://crates.io/crates/craton_hsm)
[![docs.rs](https://docs.rs/craton_hsm/badge.svg)](https://docs.rs/craton_hsm)
[![codecov](https://codecov.io/gh/craton-co/craton-hsm-core/branch/main/graph/badge.svg)](https://codecov.io/gh/craton-co/craton-hsm-core)

> **Not FIPS 140-3 certified.** This software has not undergone CMVP validation.
> See [FIPS Gap Analysis](docs/fips-gap-analysis.md) for details.

A PKCS#11 v3.0-compliant Software Hardware Security Module (HSM) written in pure Rust.

## Overview

Craton HSM provides a software-based implementation of the PKCS#11 Cryptographic Token Interface standard (v3.0). It exposes the standard C ABI so that any PKCS#11-aware application (OpenSSL engines, Java PKCS11 providers, Firefox NSS, etc.) can use it as a drop-in cryptographic backend.

### Key Features

- **Full PKCS#11 C ABI** with 70+ exported functions
- **Classical cryptography**: RSA (2048/3072/4096), ECDSA (P-256/P-384), EdDSA (Ed25519), AES-256 (GCM/CBC/CTR)
- **Post-quantum cryptography**: ML-KEM-768, ML-DSA-44/65/87, SLH-DSA-SHA2-128s, hybrid X25519+ML-KEM-768 *(PQC crates are at RC versions — API may change before 1.0; see [Known Issues](CHANGELOG.md))*
- **Multi-part operations**: streaming sign/verify (SHA-256/384/512), streaming encrypt/decrypt (AES-CBC/CTR)
- **SP 800-90A HMAC_DRBG** with prediction resistance and continuous health tests — all key generation routes through DRBG
- **FIPS 140-3 Power-On Self-Tests (POST)**: 17 self-tests (integrity check + 16 KATs) covering all approved algorithms
- **SP 800-57 key lifecycle management**: date-based activation/deactivation
- **Memory hardening**: mlock/VirtualLock for key material, ZeroizeOnDrop, constant-time PIN comparison
- **Tamper-evident audit log** with chained SHA-256 hashes
- **Pluggable crypto backends**: RustCrypto (default); FIPS-validated aws-lc-rs available via [craton-hsm-enterprise](https://github.com/craton-co/craton-hsm-core-enterprise)
- **Encrypted persistent storage**: AES-256-GCM with PBKDF2-derived keys
- **gRPC daemon** with mutual TLS for remote HSM access
- **Admin CLI** for token management, PIN operations, and diagnostics

## Quick Start

### Build

```bash
# Default build (RustCrypto backend)
cargo build --release
```

### Test

```bash
# Run all tests (must use single thread due to global PKCS#11 state)
cargo test -- --test-threads=1

```

### Use as a PKCS#11 Library

Build the cdylib and point your application to it:

```bash
cargo build --release
# Output: target/release/craton_hsm.dll (Windows) / libcraton_hsm.so (Linux) / libcraton_hsm.dylib (macOS)
```

Configure your PKCS#11 consumer to load the library:

```bash
# OpenSSL example
export PKCS11_MODULE_PATH=/path/to/libcraton_hsm.so

# pkcs11-tool
pkcs11-tool --module /path/to/libcraton_hsm.so --list-slots
```

## Architecture

```
craton_hsm/
  src/
    core.rs           - HsmCore: central state shared by all interfaces
    pkcs11_abi/        - C ABI layer (types, constants, 70+ function exports)
    session/           - Session management (DashMap-based concurrent sessions)
    token/             - Token/slot management, PIN lifecycle
    store/             - Object storage, encrypted persistence, key material
    crypto/            - Cryptographic operations, backends, DRBG, self-tests
    audit/             - Tamper-evident append-only audit log
    error.rs           - HsmError -> CK_RV mapping
  craton-hsm-daemon/      - gRPC server with mutual TLS
  tools/
    craton-hsm-admin/     - Admin CLI (clap)
    pkcs11-spy/        - PKCS#11 spy/logging wrapper
  deploy/              - Dockerfile + Helm chart
  docs/                - Architecture, security model, operator runbook
  tests/               - Integration test suites
  benches/             - Criterion benchmarks
```

## Crypto Backend Selection

Craton HSM supports pluggable crypto backends via the `CryptoBackend` trait:

| Backend | Location | FIPS Status | Notes |
|---------|----------|-------------|-------|
| **RustCrypto** (default) | This repo | Not FIPS-validated | Pure Rust, no C dependencies |
| **aws-lc-rs** | [craton-hsm-enterprise](https://github.com/craton-co/craton-hsm-core-enterprise) | FIPS 140-3 Level 1 | BSL 1.1 license, requires CMake |

Use `HsmCore::new_with_backend()` to inject an external backend.

## Security Model

- **Memory protection**: Key material is mlock'd to prevent swapping; zeroed on drop
- **PIN security**: PBKDF2-SHA256 (600k iterations) with constant-time comparison
- **Self-tests**: 17 POST self-tests (integrity + 16 KATs including RSA) run before any cryptographic service is available
- **Audit trail**: Every operation is logged with chained SHA-256 integrity hashes
- **Session isolation**: Per-session state with DashMap for safe concurrent access
- **Key lifecycle**: SP 800-57 states (pre-activation, active, deactivated, compromised)

## FIPS 140-3 Status

The FIPS-validated aws-lc-rs backend is available in [craton-hsm-enterprise](https://github.com/craton-co/craton-hsm-core-enterprise) (`craton-hsm-awslc` crate). See `docs/fips-gap-analysis.md` for a detailed assessment of remaining gaps for a full FIPS 140-3 Level 1 certification.

## Documentation

- [Documentation Index](docs/README.md) — full documentation table of contents
- [Installation Guide](docs/install.md) — build, test, deploy, configure
- [API Reference](docs/api-reference.md) — PKCS#11 C ABI functions and Rust library API
- [Examples](docs/examples.md) — usage with pkcs11-tool, OpenSSL, Python, Java
- [Configuration Reference](docs/configuration-reference.md) — all `craton_hsm.toml` fields, defaults, and examples
- [Architecture Overview](docs/architecture.md) — module diagram, source layout, data flow
- [Security Model](docs/security-model.md) — threat model, key protection, access control
- [Troubleshooting](docs/troubleshooting.md) — common errors, build issues, runtime problems
- [FAQ](docs/faq.md) — frequently asked questions
- [Migration Guide](docs/migration-guide.md) — version upgrade instructions
- [FIPS Gap Analysis](docs/fips-gap-analysis.md) — certification readiness assessment
- [Operator Runbook](docs/operator-runbook.md) — day-to-day operations
- [Tested Platforms](docs/tested-platforms.md) — platform support matrix, CI pipeline
- [Changelog](CHANGELOG.md) — version history
- [Roadmap](ROADMAP.md) — completed phases and future directions
- [Governance](GOVERNANCE.md) — decision-making, roles, contribution process

## Disclaimer

**Craton HSM is NOT FIPS 140-3 certified.** While the codebase implements FIPS 140-3 Level 1 technical requirements (POST KATs, pairwise consistency tests, approved mode, etc.), it has not undergone CMVP validation. Use at your own risk. See `docs/fips-gap-analysis.md` for details.

## License

Copyright 2026 Craton Software Company Licensed under the [Apache License, Version 2.0](LICENSE).

### Related Repositories

| Repository | License | Contents |
|-----------|---------|----------|
| [craton_hsm](https://github.com/craton-co/craton-hsm-core) | Apache-2.0 | Core PKCS#11 library, daemon, CLI, tooling |
| [craton-hsm-enterprise](https://github.com/craton-co/craton-hsm-core-enterprise) | BSL 1.1 | FIPS backend (aws-lc-rs), vendor backends (NXP, Infineon), certified builds |
