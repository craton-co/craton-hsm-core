# Installation Guide

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Rust | 1.75+ | 2021 edition; install via [rustup](https://rustup.rs/) |
| protoc | 3.x+ | Required only for building the gRPC daemon |
| CMake | 3.x+ | Required by `aws-lc-rs` (rustls TLS dependency) |
| Git | any | To clone the repository |

### Platform-specific setup

**Linux (Debian/Ubuntu)**
```bash
sudo apt-get install -y protobuf-compiler cmake build-essential
```

**macOS**
```bash
brew install protobuf cmake
```

**Windows**
```powershell
winget install Google.Protobuf Kitware.CMake
# Or: choco install protoc cmake
```

## Build from Source

```bash
# Clone
git clone https://github.com/craton-co/craton-hsm-core.git
cd craton-hsm-core

# Build core PKCS#11 library only
cargo build --release

# Build everything (library + daemon + admin CLI + spy wrapper)
cargo build --release --workspace
```

### Build artifacts

| Artifact | Linux | Windows | Description |
|----------|-------|---------|-------------|
| PKCS#11 library | `target/release/libcraton_hsm.so` | `target/release/craton_hsm.dll` | Load via `dlopen`/`LoadLibrary` |
| gRPC daemon | `target/release/craton-hsm-daemon` | `target/release/craton-hsm-daemon.exe` | Standalone network server |
| Admin CLI | `target/release/craton-hsm-admin` | `target/release/craton-hsm-admin.exe` | Token/key/PIN management |
| Spy wrapper | `target/release/libpkcs11_spy.so` | `target/release/pkcs11_spy.dll` | PKCS#11 call interceptor |

## Run Tests

```bash
# Full suite (617+ tests — MUST use single thread due to global PKCS#11 state)
cargo test -- --test-threads=1

# With aws-lc-rs backend
cargo test --features awslc-backend -- --test-threads=1

# Individual suites
cargo test --test crypto_vectors -- --test-threads=1
cargo test --test crypto_vectors_phase2 -- --test-threads=1
cargo test --test pkcs11_compliance -- --test-threads=1
cargo test --test multipart_sign_verify -- --test-threads=1
cargo test --test multipart_encrypt_decrypt -- --test-threads=1
cargo test --test supplementary_functions -- --test-threads=1
cargo test --test drbg -- --test-threads=1
```

## Run Benchmarks

```bash
# Full benchmark suite (criterion, ~5 minutes)
cargo bench

# Specific group
cargo bench -- rsa_sign
cargo bench -- aes_gcm
cargo bench -- ml_dsa

# Reports generated in target/criterion/
```

## Configuration

Craton HSM reads configuration from `craton_hsm.toml` (or the path in `CRATON_HSM_CONFIG`).

```toml
[token]
label = "My HSM Token"
storage_path = "craton_hsm_store"       # redb database directory
max_sessions = 100
max_rw_sessions = 10

[security]
pin_min_length = 8
pin_max_length = 64
max_failed_logins = 10               # lockout threshold
pbkdf2_iterations = 600000           # PIN hashing cost

[algorithms]
allow_weak_rsa = false               # block RSA < 2048
allow_sha1_signing = false           # block SHA-1 in signatures
enable_pqc = true                    # ML-DSA, ML-KEM, SLH-DSA

[audit]
enabled = true
log_path = "craton_hsm_audit.jsonl"
log_level = "all"                    # "all" | "crypto" | "auth" | "admin" | "none"

[daemon]
bind = "127.0.0.1:5696"
tls_cert = "tls.crt"                # PEM certificate
tls_key = "tls.key"                  # PEM private key
```

All fields have sensible defaults. A missing config file is not an error — Craton HSM starts with built-in defaults.

## Docker

```bash
# Build the image (from repository root)
docker build -t craton_hsm:latest -f deploy/Dockerfile .

# Run with default config
docker run -p 5696:5696 craton_hsm:latest

# Run with custom config and TLS
docker run -p 5696:5696 \
  -v /path/to/craton_hsm.toml:/etc/craton_hsm/craton_hsm.toml:ro \
  -v /path/to/tls:/etc/craton_hsm/tls:ro \
  craton_hsm:latest

# Run admin CLI inside the container
docker exec <container> /usr/local/bin/craton-hsm-admin status
```

The image is based on `gcr.io/distroless/cc-debian12:nonroot` — no shell, no package manager, runs as non-root (UID 65534).

## Kubernetes (Helm)

```bash
# Install the Helm chart
helm install my-hsm deploy/helm/craton_hsm/ \
  --set image.repository=your-registry/craton_hsm \
  --set image.tag=latest

# With TLS (create the secret first)
kubectl create secret tls craton_hsm-tls \
  --cert=tls.crt --key=tls.key
helm install my-hsm deploy/helm/craton_hsm/ \
  --set tls.enabled=true \
  --set tls.secretName=craton_hsm-tls

# With persistent storage
helm install my-hsm deploy/helm/craton_hsm/ \
  --set persistence.enabled=true \
  --set persistence.size=5Gi

# Verify
helm test my-hsm
kubectl logs deploy/my-hsm-craton_hsm
```

### Helm values

| Parameter | Default | Description |
|-----------|---------|-------------|
| `image.repository` | `craton_hsm` | Container image |
| `image.tag` | `0.9.1` | Image tag |
| `daemon.bind` | `0.0.0.0:5696` | gRPC listen address |
| `daemon.replicas` | `1` | Replica count |
| `tls.enabled` | `false` | Enable TLS |
| `tls.secretName` | `craton_hsm-tls` | K8s TLS secret name |
| `persistence.enabled` | `false` | Enable PVC for key store |
| `persistence.size` | `1Gi` | PVC size |
| `config.tokenLabel` | `Craton HSM Token` | PKCS#11 token label |
| `config.enablePqc` | `true` | Enable post-quantum algorithms |

## Using as a PKCS#11 Provider

### Generic

```bash
# Set the module path for any PKCS#11 consumer
export PKCS11_MODULE_PATH=/path/to/libcraton_hsm.so
```

### Java SunPKCS11

Java includes a built-in PKCS#11 provider (SunPKCS11) that works with any compliant module.

**SunPKCS11 config file** (`pkcs11.cfg`):
```
name = Craton HSM
library = /path/to/libcraton_hsm.so
slot = 0
```

**keytool** (JDK command-line key management):
```bash
# List token info
keytool -providerClass sun.security.pkcs11.SunPKCS11 \
        -providerArg pkcs11.cfg \
        -keystore NONE -storetype PKCS11 \
        -list -storepass 1234

# Generate RSA key pair
keytool -providerClass sun.security.pkcs11.SunPKCS11 \
        -providerArg pkcs11.cfg \
        -keystore NONE -storetype PKCS11 \
        -genkeypair -alias "my-key" -keyalg RSA -keysize 2048 \
        -sigalg SHA256withRSA -dname "CN=My App" \
        -storepass 1234

# Generate EC P-256 key pair
keytool -providerClass sun.security.pkcs11.SunPKCS11 \
        -providerArg pkcs11.cfg \
        -keystore NONE -storetype PKCS11 \
        -genkeypair -alias "ec-key" -keyalg EC -groupname secp256r1 \
        -sigalg SHA256withECDSA -dname "CN=My EC Key" \
        -storepass 1234

# Generate CSR (exercises signing through PKCS#11)
keytool -providerClass sun.security.pkcs11.SunPKCS11 \
        -providerArg pkcs11.cfg \
        -keystore NONE -storetype PKCS11 \
        -certreq -alias "my-key" -sigalg SHA256withRSA \
        -file request.csr -storepass 1234
```

**Programmatic Java access** (KeyStore + Signature API):
```java
import java.security.*;
import javax.crypto.*;

// Load SunPKCS11 provider
Provider provider = Security.getProvider("SunPKCS11")
    .configure("/path/to/pkcs11.cfg");
Security.addProvider(provider);

// Open KeyStore
KeyStore ks = KeyStore.getInstance("PKCS11", provider);
ks.load(null, "1234".toCharArray());

// Generate RSA key pair
KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", provider);
kpg.initialize(2048);
KeyPair kp = kpg.generateKeyPair();

// Sign data
Signature signer = Signature.getInstance("SHA256withRSA", provider);
signer.initSign(kp.getPrivate());
signer.update("data to sign".getBytes());
byte[] sig = signer.sign();

// Verify signature
Signature verifier = Signature.getInstance("SHA256withRSA", provider);
verifier.initVerify(kp.getPublic());
verifier.update("data to sign".getBytes());
boolean valid = verifier.verify(sig);  // true
```

**Supported Java algorithms** via Craton HSM:

| Java Algorithm | PKCS#11 Mechanism |
|---------------|------------------|
| `SHA256withRSA` | `CKM_SHA256_RSA_PKCS` |
| `SHA384withRSA` | `CKM_SHA384_RSA_PKCS` |
| `SHA512withRSA` | `CKM_SHA512_RSA_PKCS` |
| `SHA256withECDSA` | `CKM_ECDSA_SHA256` |
| `SHA384withECDSA` | `CKM_ECDSA_SHA384` |
| `SHA-256` | `CKM_SHA256` |
| `SHA-384` | `CKM_SHA384` |
| `SHA-512` | `CKM_SHA512` |

**Known limitations:**
- Post-quantum algorithms (ML-DSA, ML-KEM, SLH-DSA) are not supported by SunPKCS11
- Token must be initialized with a user PIN before Java can access it
- The `slot` in `pkcs11.cfg` must match a configured slot index (default: `0`; configurable via `slot_count` in `craton_hsm.toml`)

**Troubleshooting:**

| Error | Cause | Fix |
|-------|-------|-----|
| `PKCS11Exception: CKR_TOKEN_NOT_PRESENT` | Token not initialized | Run `pkcs11-tool --module ... --init-token` or `craton-hsm-admin token init` first |
| `PKCS11Exception: CKR_PIN_INCORRECT` | Wrong PIN in `-storepass` | Use the user PIN, not the SO PIN |
| `java.security.ProviderException` | Library path wrong in config | Verify `library` path in `pkcs11.cfg` points to actual `.so`/`.dylib` |
| `CKR_CRYPTOKI_NOT_INITIALIZED` | Fork after init (e.g., Tomcat) | Ensure `C_Initialize` is called in the child process |

**Running interop tests** (Linux/macOS only — these shell scripts are not supported on Windows):
```bash
bash tests/interop/java_sunpkcs11.sh
```

### OpenSSL & pkcs11-tool

Craton HSM is compatible with the most common PKCS#11 CLI tools. The most reliable is `pkcs11-tool` from the OpenSC project.

**Prerequisites:**
```bash
# Debian/Ubuntu
sudo apt-get install opensc gnutls-bin

# macOS
brew install opensc

# Verify
pkcs11-tool --version
```

**pkcs11-tool — Token initialization and key management:**
```bash
MODULE=/path/to/libcraton_hsm.so

# List available slots
pkcs11-tool --module $MODULE --list-slots

# List supported mechanisms
pkcs11-tool --module $MODULE --list-mechanisms

# Initialize token
pkcs11-tool --module $MODULE --init-token --label "MyToken" --so-pin 12345678

# Set user PIN
pkcs11-tool --module $MODULE --init-pin --pin 1234 --so-pin 12345678

# Generate RSA-2048 key pair
pkcs11-tool --module $MODULE --keypairgen --key-type RSA:2048 \
    --label "my-rsa-key" --id 01 --login --pin 1234

# Generate EC P-256 key pair
pkcs11-tool --module $MODULE --keypairgen --key-type EC:secp256r1 \
    --label "my-ec-key" --id 02 --login --pin 1234

# List all objects
pkcs11-tool --module $MODULE --list-objects --login --pin 1234
```

**pkcs11-tool — Sign and verify:**
```bash
# Create test data (32 bytes = SHA-256 hash length)
dd if=/dev/urandom of=data.bin bs=32 count=1

# RSA sign (SHA256-RSA-PKCS)
pkcs11-tool --module $MODULE --sign --mechanism SHA256-RSA-PKCS \
    --id 01 --login --pin 1234 \
    --input-file data.bin --output-file sig.bin

# RSA verify
pkcs11-tool --module $MODULE --verify --mechanism SHA256-RSA-PKCS \
    --id 01 --login --pin 1234 \
    --input-file data.bin --signature-file sig.bin

# ECDSA sign (raw hash, no wrapping)
pkcs11-tool --module $MODULE --sign --mechanism ECDSA \
    --id 02 --login --pin 1234 \
    --input-file data.bin --output-file ec_sig.bin

# SHA-256 digest
pkcs11-tool --module $MODULE --hash --mechanism SHA256 \
    --input-file data.bin --output-file digest.bin
```

**p11tool (GnuTLS):**
```bash
# List tokens
p11tool --provider=$MODULE --list-tokens

# List all objects (requires login for private objects)
p11tool --provider=$MODULE --list-all --login --set-pin=1234

# List mechanisms
p11tool --provider=$MODULE --list-mechanisms
```

**OpenSSL 3.x pkcs11-provider:**

OpenSSL 3.x supports PKCS#11 tokens via the `pkcs11-provider` module. This requires the provider to be installed separately.

```bash
# Install pkcs11-provider (Debian/Ubuntu)
sudo apt-get install openssl-pkcs11-provider

# Or build from source: https://github.com/latchset/pkcs11-provider
```

Create an OpenSSL config file (`openssl_pkcs11.cnf`):
```ini
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
pkcs11 = pkcs11_sect

[default_sect]
activate = 1

[pkcs11_sect]
module = /usr/lib/x86_64-linux-gnu/ossl-modules/pkcs11.so
pkcs11-module-path = /path/to/libcraton_hsm.so
pkcs11-module-token-pin = 1234
activate = 1
```

```bash
# List objects in token via OpenSSL
OPENSSL_CONF=openssl_pkcs11.cnf openssl storeutl \
    "pkcs11:token=MyToken;pin-value=1234"

# Sign with a key from the token
OPENSSL_CONF=openssl_pkcs11.cnf openssl pkeyutl -sign \
    -provider pkcs11 -inkey "pkcs11:token=MyToken;object=my-rsa-key" \
    -in data.bin -out sig.bin

# List loaded providers
OPENSSL_CONF=openssl_pkcs11.cnf openssl list -providers
```

**OpenSSL 1.1.x engine_pkcs11 (legacy):**
```bash
# Install (Debian/Ubuntu)
sudo apt-get install libengine-pkcs11-openssl

# Sign using the engine
openssl pkeyutl -engine pkcs11 -sign \
    -keyform engine \
    -inkey "pkcs11:token=MyToken;object=my-rsa-key;pin-value=1234" \
    -in data.bin -out sig.bin
```

### SSH Agent

```bash
# Add PKCS#11 module to SSH agent
ssh-add -s /path/to/libcraton_hsm.so
# Enter user PIN when prompted

# List keys from the HSM
ssh-add -L

# Remove PKCS#11 module
ssh-add -e /path/to/libcraton_hsm.so
```

**Known limitations:**
- SSH only uses RSA and ECDSA keys from the token (not Ed25519 via PKCS#11)
- The token must be initialized and contain at least one key pair
- Some SSH clients require the key to have `CKA_SIGN = true`

**OpenSSL / pkcs11-tool troubleshooting:**

| Error | Cause | Fix |
|-------|-------|-----|
| `No slot with a token was found` | Token not initialized | Run `pkcs11-tool --init-token` |
| `CKR_PIN_INCORRECT` | Wrong PIN | Use user PIN for operations, SO PIN for admin |
| `CKR_MECHANISM_INVALID` | Unsupported mechanism | Check `--list-mechanisms` for available mechanisms |
| `error loading pkcs11 module` | Wrong library path | Verify `--module` path; use absolute path |
| `CKR_CRYPTOKI_NOT_INITIALIZED` | Fork or re-exec | Call `C_Initialize` before operations |
| `Database is locked` | Another process has the DB open | Stop other Craton HSM instances or use `craton-hsm-daemon` |

**Running interop tests** (Linux/macOS only — these shell scripts are not supported on Windows):
```bash
bash tests/interop/openssl_pkcs11.sh
```

## Using the Admin CLI

```bash
# Initialize token (prompts for SO PIN)
craton-hsm-admin token init --label "Production HSM"

# Check status
craton-hsm-admin status
craton-hsm-admin status --json

# Key management
craton-hsm-admin key list
craton-hsm-admin key import --file private.pem --label "App Key" --type RSA
craton-hsm-admin key delete --handle 42

# PIN management
craton-hsm-admin pin change --user-type USER
craton-hsm-admin pin reset    # SO resets user PIN

# Audit log
craton-hsm-admin audit dump --last 100
craton-hsm-admin audit dump --last 50 --json
```

## Using the Spy Wrapper

The spy wrapper intercepts all PKCS#11 calls for debugging. It works with any PKCS#11 library, not just Craton HSM.

```bash
# Configure the spy
export PKCS11_SPY_TARGET=/path/to/libcraton_hsm.so   # real library
export PKCS11_SPY_LOG=spy.jsonl                     # log file

# Point your application to the spy instead
export PKCS11_MODULE_PATH=/path/to/libpkcs11_spy.so

# All PKCS#11 calls are logged as JSON lines:
# {"timestamp":"2025-01-15T10:30:01Z","function":"C_Sign","args":"mechanism=CKM_ECDSA","rv":"CKR_OK","duration_ms":2}
```

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `CKR_GENERAL_ERROR` on all calls | FIPS POST failed | Check binary integrity; rebuild |
| `CKR_PIN_LOCKED` | Too many failed login attempts | SO resets via `craton-hsm-admin pin reset` |
| `CKR_SESSION_COUNT` | Session limit reached | Close unused sessions; increase `max_sessions` |
| `CKR_CRYPTOKI_NOT_INITIALIZED` | `C_Initialize` not called | Call `C_Initialize(NULL)` first |
| `CKR_TOKEN_NOT_PRESENT` | Token not initialized | Run `craton-hsm-admin token init` |
| Daemon fails to start | protoc missing at build time | Install protobuf-compiler |
| Daemon TLS error | Invalid cert/key path | Check paths in `[daemon]` config |
