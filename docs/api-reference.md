# API Reference

Craton HSM exposes two primary interfaces: a **PKCS#11 C ABI** (the standard way to consume it) and a **Rust library API** (for embedding directly in Rust programs).

## PKCS#11 C ABI

The shared library (`libcraton_hsm.so` / `craton_hsm.dll` / `libcraton_hsm.dylib`) exports 70+ `#[no_mangle] extern "C"` functions conforming to PKCS#11 v3.0 (OASIS Standard).

Any PKCS#11-aware consumer (OpenSSL engines, Java SunPKCS11, Firefox NSS, `pkcs11-tool`, etc.) can load the library directly.

### Loading the Library

```bash
# pkcs11-tool (OpenSC)
pkcs11-tool --module /path/to/libcraton_hsm.so --list-slots

# OpenSSL (via engine or provider)
export PKCS11_MODULE_PATH=/path/to/libcraton_hsm.so

# Python (PyKCS11)
import PyKCS11
lib = PyKCS11.PyKCS11Lib()
lib.load("/path/to/libcraton_hsm.so")
```

### Exported Functions

#### Initialization

| Function | Description |
|----------|-------------|
| `C_Initialize` | Initialize the Cryptoki library (runs POST self-tests) |
| `C_Finalize` | Clean up and release resources |
| `C_GetInfo` | Return library version and manufacturer info |
| `C_GetFunctionList` | Return the function pointer table |

#### Slot and Token Management

| Function | Description |
|----------|-------------|
| `C_GetSlotList` | Enumerate available slots |
| `C_GetSlotInfo` | Query slot properties |
| `C_GetTokenInfo` | Query token label, serial, flags, capabilities |
| `C_GetMechanismList` | List supported mechanisms (41 mechanisms) |
| `C_GetMechanismInfo` | Query min/max key size, supported operations |
| `C_InitToken` | Initialize token with SO PIN and label |

#### Session Management

| Function | Description |
|----------|-------------|
| `C_OpenSession` | Open a new session (R/O or R/W) |
| `C_CloseSession` | Close a session |
| `C_CloseAllSessions` | Close all sessions on a slot |
| `C_GetSessionInfo` | Query session state and flags |
| `C_Login` | Authenticate as User or SO |
| `C_Logout` | End authenticated session |

#### PIN Management

| Function | Description |
|----------|-------------|
| `C_InitPIN` | SO initializes user PIN |
| `C_SetPIN` | Change user or SO PIN |

#### Object Management

| Function | Description |
|----------|-------------|
| `C_CreateObject` | Create an object from a template |
| `C_DestroyObject` | Delete an object |
| `C_CopyObject` | Duplicate an object with template overrides |
| `C_GetObjectSize` | Query object storage size |
| `C_GetAttributeValue` | Read object attributes |
| `C_SetAttributeValue` | Modify object attributes (if CKA_MODIFIABLE) |
| `C_FindObjectsInit` | Begin object search by template |
| `C_FindObjects` | Iterate search results |
| `C_FindObjectsFinal` | End object search |

#### Key Generation

| Function | Description |
|----------|-------------|
| `C_GenerateKey` | Generate symmetric key (AES, HMAC, generic secret) |
| `C_GenerateKeyPair` | Generate asymmetric key pair (RSA, EC, Ed25519, ML-DSA, SLH-DSA) |

#### Signing and Verification

| Function | Description |
|----------|-------------|
| `C_SignInit` | Initialize a signing operation |
| `C_Sign` | Single-part sign |
| `C_SignUpdate` | Multi-part sign (streaming) |
| `C_SignFinal` | Finalize multi-part sign |
| `C_VerifyInit` | Initialize a verification operation |
| `C_Verify` | Single-part verify |
| `C_VerifyUpdate` | Multi-part verify (streaming) |
| `C_VerifyFinal` | Finalize multi-part verify |

#### Encryption and Decryption

| Function | Description |
|----------|-------------|
| `C_EncryptInit` | Initialize encryption |
| `C_Encrypt` | Single-part encrypt |
| `C_EncryptUpdate` | Multi-part encrypt (streaming) |
| `C_EncryptFinal` | Finalize multi-part encrypt |
| `C_DecryptInit` | Initialize decryption |
| `C_Decrypt` | Single-part decrypt |
| `C_DecryptUpdate` | Multi-part decrypt (streaming) |
| `C_DecryptFinal` | Finalize multi-part decrypt |

#### Digesting

| Function | Description |
|----------|-------------|
| `C_DigestInit` | Initialize a digest operation |
| `C_Digest` | Single-part digest |
| `C_DigestUpdate` | Multi-part digest (streaming) |
| `C_DigestFinal` | Finalize multi-part digest |
| `C_DigestKey` | Include a key's value in the digest |

#### Key Wrapping

| Function | Description |
|----------|-------------|
| `C_WrapKey` | Export a key encrypted under another key (AES Key Wrap) |
| `C_UnwrapKey` | Import a wrapped key |

#### Key Derivation

| Function | Description |
|----------|-------------|
| `C_DeriveKey` | Derive a new key (ECDH with internal HKDF-SHA256 per SP 800-56C) |

#### Random Number Generation

| Function | Description |
|----------|-------------|
| `C_GenerateRandom` | Generate random bytes via SP 800-90A HMAC_DRBG |
| `C_SeedRandom` | Provide additional entropy to the DRBG |

#### Operation State

| Function | Description |
|----------|-------------|
| `C_GetOperationState` | Serialize active operation (HMAC-authenticated) |
| `C_SetOperationState` | Restore a serialized operation |

### Supported Mechanisms

41 PKCS#11 mechanisms registered via `C_GetMechanismList`:

| Category | Mechanisms |
|----------|-----------|
| RSA (10) | `CKM_RSA_PKCS_KEY_PAIR_GEN`, `CKM_RSA_PKCS`, `CKM_SHA256_RSA_PKCS`, `CKM_SHA384_RSA_PKCS`, `CKM_SHA512_RSA_PKCS`, `CKM_RSA_PKCS_PSS`, `CKM_SHA256_RSA_PKCS_PSS`, `CKM_SHA384_RSA_PKCS_PSS`, `CKM_SHA512_RSA_PKCS_PSS`, `CKM_RSA_PKCS_OAEP` |
| EC (7) | `CKM_EC_KEY_PAIR_GEN`, `CKM_ECDSA`, `CKM_ECDSA_SHA256`, `CKM_ECDSA_SHA384`, `CKM_ECDSA_SHA512`, `CKM_ECDH1_DERIVE`, `CKM_ECDH1_COFACTOR_DERIVE` |
| EdDSA (1) | `CKM_EDDSA` |
| AES (7) | `CKM_AES_KEY_GEN`, `CKM_AES_GCM`, `CKM_AES_CBC`, `CKM_AES_CBC_PAD`, `CKM_AES_CTR`, `CKM_AES_KEY_WRAP`, `CKM_AES_KEY_WRAP_PAD` |
| Digest (7) | `CKM_SHA_1`, `CKM_SHA256`, `CKM_SHA384`, `CKM_SHA512`, `CKM_SHA3_256`, `CKM_SHA3_384`, `CKM_SHA3_512` |
| PQC (9) | `CKM_ML_KEM_512`, `CKM_ML_KEM_768`, `CKM_ML_KEM_1024`, `CKM_ML_DSA_44`, `CKM_ML_DSA_65`, `CKM_ML_DSA_87`, `CKM_SLH_DSA_SHA2_128S`, `CKM_SLH_DSA_SHA2_256S`, `CKM_HYBRID_X25519_ML_KEM_768` |

## Rust Library API

When used as an `rlib` (Rust library), the public API is organized into these modules:

### `craton_hsm::core` — Central State

```rust
use craton_hsm::core::HsmCore;
use craton_hsm::config::HsmConfig;

// Default configuration
let hsm = HsmCore::new_default();

// Custom configuration
let config = HsmConfig::load("craton_hsm.toml")?;
let hsm = HsmCore::new(config);

// Custom crypto backend
let hsm = HsmCore::new_with_backend(config, my_backend);
```

### `craton_hsm::config` — Configuration

```rust
use craton_hsm::config::{HsmConfig, TokenConfig, SecurityConfig, AlgorithmConfig, AuditConfig};

let config = HsmConfig::default();
// Or load from file:
let config = HsmConfig::load("craton_hsm.toml")?;
// Or load with validation:
let config = HsmConfig::load_validated("craton_hsm.toml")?;
```

See [Configuration Reference](configuration-reference.md) for all fields.

### `craton_hsm::error` — Error Types

```rust
use craton_hsm::error::{HsmError, HsmResult};
```

`HsmError` maps 1:1 to PKCS#11 `CK_RV` return codes. See [Troubleshooting](troubleshooting.md) for common errors.

### `craton_hsm::crypto` — Cryptographic Operations

The `CryptoBackend` trait defines all cryptographic operations:

```rust
use craton_hsm::crypto::backend::CryptoBackend;

// Backend is selected at HsmCore creation time:
// - Default: RustCrypto (pure Rust)
// - Optional: aws-lc-rs (FIPS-validated, via craton_hsm-enterprise)
```

Sub-modules:
- `crypto::keygen` — key generation (RSA, EC, Ed25519, AES)
- `crypto::sign` — signing (RSA PKCS#1/PSS, ECDSA, EdDSA)
- `crypto::encrypt` — encryption (AES-GCM/CBC/CTR, RSA-OAEP)
- `crypto::digest` — hashing (SHA-1/2/3)
- `crypto::derive` — key derivation (ECDH with internal HKDF-SHA256)
- `crypto::wrap` — key wrapping (AES-KW, RFC 3394)
- `crypto::pqc` — post-quantum (ML-KEM, ML-DSA, SLH-DSA)
- `crypto::drbg` — SP 800-90A HMAC_DRBG
- `crypto::self_test` — power-on self-tests
- `crypto::pairwise_test` — pairwise consistency tests

### `craton_hsm::store` — Object Storage

```rust
use craton_hsm::store::object::StoredObject;
use craton_hsm::store::attributes::ObjectStore;
use craton_hsm::store::key_material::RawKeyMaterial;
use craton_hsm::store::encrypted_store::EncryptedStore;
```

### `craton_hsm::session` — Session Management

```rust
use craton_hsm::session::manager::SessionManager;
use craton_hsm::session::session::{Session, SessionState};
```

### `craton_hsm::token` — Token Management

```rust
use craton_hsm::token::token::Token;
use craton_hsm::token::slot::SlotManager;
```

### `craton_hsm::audit` — Audit Logging

```rust
use craton_hsm::audit::log::{AuditLog, AuditOperation, AuditResult};
```

## Generated Rustdoc

Full Rust API documentation with type signatures is available via:

```bash
cargo doc --open --no-deps
```

Or online at [docs.rs/craton_hsm](https://docs.rs/craton_hsm) (after crates.io publication).
