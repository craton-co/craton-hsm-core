# Tested Platforms

## Build and Test Environments

### Primary Development Platform

| Property | Value |
|----------|-------|
| OS | Windows 11 Pro |
| Architecture | x86_64 |
| Rust Version | 1.75+ MSRV (tested with 1.83, Edition 2021) |
| Compiler Target | `x86_64-pc-windows-msvc` |
| Build Mode | Debug and Release |
| Test Results | All 617+ tests pass |

### Cross-Platform Support

| Platform | Target Triple | Build Status | Test Status | Notes |
|----------|--------------|--------------|-------------|-------|
| Windows 11 x64 | `x86_64-pc-windows-msvc` | ✅ | ✅ All pass | Primary platform |
| Linux x64 (glibc) | `x86_64-unknown-linux-gnu` | ✅ | ✅ Expected | Standard deployment target |
| Linux x64 (musl) | `x86_64-unknown-linux-musl` | ✅ | ✅ Expected | Static linking for containers |
| macOS x64 | `x86_64-apple-darwin` | ✅ | ✅ Expected | Intel Macs |
| macOS ARM64 | `aarch64-apple-darwin` | ✅ | ✅ Expected | Apple Silicon |

## Feature Matrix by Platform

| Feature | Linux | Windows | macOS |
|---------|-------|---------|-------|
| Core PKCS#11 | ✅ | ✅ | ✅ |
| Memory locking | `mlock()` / `munlock()` | `VirtualLock()` / `VirtualUnlock()` | `mlock()` / `munlock()` |
| Fork detection | ✅ (`getpid()` comparison) | N/A (no `fork()`) | ✅ (`getpid()` comparison) |
| File locking | `flock()` via fs2 | `LockFileEx()` via fs2 | `flock()` via fs2 |
| Persistent storage (redb) | ✅ | ✅ | ✅ |
| RustCrypto backend | ✅ | ✅ | ✅ |
| aws-lc-rs backend | ✅ | ✅ (requires LLVM) | ✅ |
| gRPC daemon | ✅ | ✅ (requires protoc) | ✅ |

## Crypto Backend Requirements

### RustCrypto Backend (default)

No additional system dependencies. Pure Rust implementation.

```bash
cargo build --release
```

### aws-lc-rs Backend (FIPS)

Requires:
- CMake
- C compiler (GCC, Clang, or MSVC)
- On Windows: LLVM/Clang (`LIBCLANG_PATH` must be set)

```bash
# Linux
cargo build --release --features awslc-backend

# Windows (with LLVM installed via Scoop)
set LIBCLANG_PATH=C:\Users\<user>\scoop\apps\llvm\current\bin
set AWS_LC_SYS_NO_ASM=1
cargo build --release --features awslc-backend
```

## Test Execution

### Standard Test Run

```bash
# IMPORTANT: PKCS#11 tests require single-threaded execution
# due to shared global OnceLock<Arc<HsmCore>> state
cargo test -- --test-threads=1
```

### Full Test Matrix

```bash
# RustCrypto backend (default)
cargo test -- --test-threads=1

# aws-lc-rs backend
cargo test --features awslc-backend -- --test-threads=1

# Zeroization tests (requires debug build, intentional UB)
cargo test --test zeroization -- --ignored --test-threads=1

# Persistence tests
cargo test --test persistence -- --test-threads=1

# Benchmarks
cargo bench
cargo bench --features awslc-backend  # comparative
```

### Known Slow Tests

| Test | Approximate Duration | Reason |
|------|---------------------|--------|
| RSA 3072 keygen | ~10s (debug) | Large prime generation |
| SLH-DSA operations | ~60s (debug) | Hash-based signature scheme |
| RSA 2048 POST KAT | ~2s (debug) | Key generation during POST |

Use `--release` for faster execution of these tests.

## Container Support

A multi-stage Dockerfile is provided at `deploy/Dockerfile`:

```dockerfile
# Build stage uses rust:1.83-slim
# Runtime stage uses gcr.io/distroless/cc-debian12
```

The container image includes only the compiled binary and required shared libraries (no shell, no package manager).

### GitHub Actions CI

Automated CI pipeline runs on every push and pull request:
- **Ubuntu-latest + Windows-latest**: Build and test (default + awslc-backend)
- **Linting**: `cargo fmt --check` + `cargo clippy -- -D warnings`
- **Documentation**: `cargo doc --no-deps`

See `.github/workflows/ci.yml` for full configuration.

## Dependency Versions

Key dependency versions as of v0.9.1:

| Dependency | Version | Purpose |
|-----------|---------|---------|
| redb | 2.x | Persistent key/object storage |
| fs2 | 0.4 | Cross-platform file locking |
| zeroize | 1.x | Cryptographic memory zeroization |
| parking_lot | 0.12 | Efficient mutex/rwlock |
| dashmap | 6.x | Concurrent hash map (sessions) |
| windows-sys | 0.59 | Windows API bindings (VirtualLock) |
| aws-lc-rs | 1.x | FIPS crypto backend (optional) |
| tonic | 0.12 | gRPC framework (daemon only) |
