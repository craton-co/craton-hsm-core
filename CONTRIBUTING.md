# Contributing to Craton HSM

Thank you for your interest in contributing to Craton HSM! This document covers the process for contributing to the project.

## Getting Started

### Prerequisites

- Rust 1.75+ (install via [rustup](https://rustup.rs/))
- Git

Optional (for full workspace build):
- protoc 3.x+ (for gRPC daemon)
- CMake 3.x+ (for aws-lc-rs backend)

### Building

```bash
git clone https://github.com/craton-co/craton-hsm-core.git
cd craton-hsm-core

# Build the core library
cargo build

# Build the full workspace (requires protoc)
cargo build --workspace
```

### Running Tests

**Important**: Tests must run single-threaded due to global PKCS#11 state.

```bash
# Full test suite
cargo test -- --test-threads=1

```

### Linting

```bash
cargo fmt --check
cargo clippy -- -D warnings
```

## How to Contribute

### Bug Reports

Open a [GitHub issue](https://github.com/craton-co/craton-hsm-core/issues) with:
- Steps to reproduce
- Expected vs actual behavior
- Rust version (`rustc --version`)
- OS and architecture

**Security bugs**: Please see [SECURITY.md](SECURITY.md) instead.

### Feature Requests

Open an issue describing the use case and proposed solution. For PKCS#11 compliance features, reference the relevant section of the PKCS#11 v3.0 specification.

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b my-feature`)
3. Make your changes
4. Ensure all tests pass: `cargo test -- --test-threads=1`
5. Ensure lints pass: `cargo clippy -- -D warnings && cargo fmt --check`
6. Commit with a clear message
7. Push and open a PR against `main`

### PR Checklist

- [ ] [CLA signed](CLA.md) (the bot will prompt you on your first PR)
- [ ] Tests pass (`cargo test -- --test-threads=1`)
- [ ] No clippy warnings (`cargo clippy -- -D warnings`)
- [ ] Code is formatted (`cargo fmt`)
- [ ] New functionality has tests
- [ ] `unsafe` code is documented with a safety comment
- [ ] No key material in logs or debug output (use `[REDACTED]`)
- [ ] CHANGELOG.md updated (for user-facing changes)

## Code Guidelines

### Security-Sensitive Code

This is a cryptographic module. Extra care is required:

- **No key bytes in logs**: Use custom `Debug` impls that print `[REDACTED]`
- **Zeroize on drop**: All key material must use `RawKeyMaterial` (which provides mlock + ZeroizeOnDrop)
- **Constant-time comparison**: Use `subtle::ConstantTimeEq` for any secret comparison
- **`catch_unwind`**: All `extern "C"` functions must wrap their body in `catch_unwind`
- **No `unsafe` in crypto paths**: All `unsafe` code is confined to the ABI layer and mlock

### Style

- Follow existing patterns in the codebase
- `cargo fmt` is the formatter — no exceptions
- Prefer explicit error handling over `unwrap()`/`expect()` in library code
- Use `thiserror` for error types that map to `CK_RV` codes

### Testing

- Add tests for new functionality
- Integration tests go in `tests/`
- Test both success and error paths
- For ABI-level tests, use the patterns in existing test files (init token, open session, login, operate, cleanup)

## Architecture Overview

See [docs/architecture.md](docs/architecture.md) for a detailed module diagram. The key entry points:

- `src/core.rs` — `HsmCore` central state
- `src/pkcs11_abi/functions.rs` — C ABI exports (the FFI boundary)
- `src/crypto/` — all cryptographic operations
- `src/store/` — object storage and key material

## Contributor License Agreement (CLA)

All contributors must sign our [Contributor License Agreement](CLA.md) before their pull request can be merged. This is a one-time requirement.

When you open a pull request, the CLA Assistant bot will check whether you have signed. If not, it will post a comment with instructions — simply reply with the specified comment to sign.

The CLA ensures that Craton Software Company has the necessary rights to distribute your contributions under the project's license terms, including the ability to offer enterprise licensing.

## Why is `Cargo.lock` committed?

Craton HSM ships both as a library (`rlib`) and a shared library (`cdylib`). Since the cdylib is a final build artifact loaded by PKCS#11 consumers, we commit `Cargo.lock` to ensure reproducible builds. This is consistent with the [Cargo FAQ](https://doc.rust-lang.org/cargo/faq.html#why-have-cargolock-in-version-control) recommendation for binary/artifact projects.

## License

By contributing, you agree that your contributions will be licensed under the [Apache License, Version 2.0](LICENSE), and you confirm that you have signed the [CLA](CLA.md).
