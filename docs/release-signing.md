# Release Signing & Binary Verification

## Overview

Craton HSM release binaries (`.so`, `.dll`, `.dylib`) should be cryptographically signed to ensure integrity and authenticity. This prevents supply-chain attacks where a compromised binary is substituted for the genuine library.

## Signing Workflow

### 1. Build Reproducible Release

```bash
# Build release with locked dependencies
cargo build --release --locked --lib

# Verify the built artifact
sha256sum target/release/libcraton_hsm.so
```

### 2. Sign Release Binaries

**Option A: GPG Signing (Open Source)**

```bash
# Sign the shared library
gpg --detach-sign --armor target/release/libcraton_hsm.so

# Produces: libcraton_hsm.so.asc

# Verify (users)
gpg --verify libcraton_hsm.so.asc libcraton_hsm.so
```

**Option B: Sigstore/cosign (Keyless, Recommended)**

```bash
# Sign with Sigstore (uses OIDC identity, no key management needed)
cosign sign-blob --bundle libcraton_hsm.so.bundle target/release/libcraton_hsm.so

# Verify (users)
cosign verify-blob --bundle libcraton_hsm.so.bundle \
    --certificate-identity your-email@company.com \
    --certificate-oidc-issuer https://accounts.google.com \
    target/release/libcraton_hsm.so
```

**Option C: Windows Authenticode (Windows)**

```powershell
# Sign DLL with Authenticode (requires code signing certificate)
signtool sign /sha1 <thumbprint> /t http://timestamp.digicert.com \
    /fd sha256 target\release\craton_hsm.dll

# Verify (users)
signtool verify /pa target\release\craton_hsm.dll
```

### 3. Publish Checksums

Every release should include a `SHA256SUMS` file:

```
# SHA256SUMS
a1b2c3d4...  libcraton_hsm-0.9.0-x86_64-unknown-linux-gnu.so
e5f6a7b8...  craton_hsm-0.9.0-x86_64-pc-windows-msvc.dll
c9d0e1f2...  libcraton_hsm-0.9.0-aarch64-apple-darwin.dylib
```

## CI/CD Integration

### GitHub Actions Release Workflow

```yaml
name: Release

on:
  push:
    tags: ['v*']

jobs:
  build-and-sign:
    strategy:
      matrix:
        include:
          - os: ubuntu-latest
            target: x86_64-unknown-linux-gnu
            artifact: libcraton_hsm.so
          - os: windows-latest
            target: x86_64-pc-windows-msvc
            artifact: craton_hsm.dll
          - os: macos-latest
            target: aarch64-apple-darwin
            artifact: libcraton_hsm.dylib

    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4

      - name: Build release
        run: cargo build --release --locked --lib

      - name: Generate checksum
        run: sha256sum target/release/${{ matrix.artifact }} > SHA256SUMS

      - name: Sign with cosign
        uses: sigstore/cosign-installer@v3
      - run: cosign sign-blob --yes --bundle ${{ matrix.artifact }}.bundle target/release/${{ matrix.artifact }}

      - name: Upload release artifacts
        uses: actions/upload-artifact@v4
        with:
          name: ${{ matrix.target }}
          path: |
            target/release/${{ matrix.artifact }}
            ${{ matrix.artifact }}.bundle
            SHA256SUMS
```

## Verification for Users

### Before Loading the Library

Users should verify the library before loading it with `dlopen` / `LoadLibrary`:

```bash
# 1. Download the library and signature bundle
wget https://github.com/craton-co/craton-hsm-core/releases/download/v0.9.0/libcraton_hsm.so
wget https://github.com/craton-co/craton-hsm-core/releases/download/v0.9.0/libcraton_hsm.so.bundle

# 2. Verify signature
cosign verify-blob --bundle libcraton_hsm.so.bundle \
    --certificate-identity <release-identity> \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    libcraton_hsm.so

# 3. Verify checksum
sha256sum -c SHA256SUMS
```

### FIPS Considerations

For FIPS 140-3 Level 1, the module binary must be integrity-verified at load time. Craton HSM's Power-On Self-Tests (17 tests: integrity + 16 KATs) serve as a runtime integrity check — if the binary is corrupted, the KATs will fail and `POST_FAILED` will block all operations. This provides defense-in-depth beyond signature verification.

## Supply-Chain Security

| Layer | Defense |
|-------|---------|
| Source code | GitHub branch protection, signed commits |
| Dependencies | `cargo audit` (CVE check), `cargo deny` (license + advisory), `Cargo.lock` committed |
| Build | Reproducible builds with `--locked`, CI artifacts from GitHub Actions |
| Binary | Release signing (GPG/cosign/Authenticode) + SHA256 checksums |
| Runtime | FIPS POST KATs verify algorithm correctness at every `C_Initialize` |

## Recommended Key Management

For the release signing key itself:

- **GPG**: Use a hardware token (YubiKey) to store the signing key
- **Cosign**: Keyless mode (OIDC-based) eliminates key management entirely
- **Authenticode**: Store the code signing certificate in a hardware HSM (or... Craton HSM!)
- Rotate signing keys annually; publish public keys in a well-known location
- Use timestamp servers to ensure signatures remain valid after key expiry
