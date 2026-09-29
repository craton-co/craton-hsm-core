# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.10.3] - 2026-09-29

### Fixed

- **`CKM_AES_GCM` ignored `CK_GCM_PARAMS`, breaking OpenBao PKCS#11 auto-unseal**: the IV,
  AAD and tag length in `CK_GCM_PARAMS` were ignored; the token generated its own nonce and
  returned `nonce || ciphertext || tag`. Callers that choose the IV and store it next to the
  ciphertext (OpenBao, and any standard PKCS#11 client) could not decrypt: OpenBao's unseal failed
  with `CKR_ENCRYPTED_DATA_INVALID`. `pkcs11-tool` round trips appeared to work only because it
  fed the whole output back. When the mechanism parameter is a `CK_GCM_PARAMS` (current or
  pre-errata v2.40 layout), `C_Encrypt` / `C_Decrypt` now use the caller's IV and AAD and the
  ciphertext is `ciphertext || tag`, per PKCS#11. Only a 96-bit IV and 128-bit tag are
  supported (`CKR_MECHANISM_PARAM_INVALID` otherwise); an all-zero IV, or an IV already used with
  the same key, is refused. Callers that pass no `CK_GCM_PARAMS` keep the previous token-generated
  nonce layout, so existing ciphertexts still decrypt.
- **ML-DSA keys could not be used through OpenSSL `pkcs11-provider`**: post-quantum keys used
  vendor-defined key types (`CKA_KEY_TYPE` = 0x80000002 for ML-DSA) and had no
  `CKA_PARAMETER_SET`, so the provider rejected them with "Unsupported key type (2147483650)".
  Keys now use the PKCS#11 v3.2 representation:
  - `CKK_ML_KEM` (0x49), `CKK_ML_DSA` (0x4A), `CKK_SLH_DSA` (0x4B). Keys stored by earlier
    versions are mapped on load, and templates that still name the old values match.
  - `CKA_PARAMETER_SET` (`CKP_ML_DSA_44/65/87`, `CKP_ML_KEM_512/768/1024`,
    `CKP_SLH_DSA_SHA2_128S/256S`), readable and searchable, including on existing keys.
  - `CKA_VALUE` of an ML-KEM / ML-DSA / SLH-DSA public key returns the encoded public key.
  - New mechanisms `CKM_ML_DSA_KEY_PAIR_GEN`, `CKM_ML_DSA`, `CKM_ML_KEM_KEY_PAIR_GEN`,
    `CKM_SLH_DSA_KEY_PAIR_GEN` and `CKM_SLH_DSA`, taking the parameter set from
    `CKA_PARAMETER_SET`. `CKM_ML_DSA` / `CKM_SLH_DSA` accept an optional
    `CK_SIGN_ADDITIONAL_CONTEXT`; signing is deterministic with an empty context, so
    `CKH_HEDGE_REQUIRED` or a non-empty context returns `CKR_MECHANISM_PARAM_INVALID`.

  The vendor-defined mechanisms (`CKM_ML_DSA_87`, ...) are still accepted.
- **`C_GetFunctionList` reported version 3.0 for a v2.40 function table**: callers that trust the
  version (pkcs11-provider) cast it to `CK_FUNCTION_LIST_3_0` and read `C_GetInterface` past the
  end of the table. It now reports 2.40. `C_GetInfo` still reports Cryptoki 3.0.
- **Panic at process exit under OpenSSL `pkcs11-provider`**: the provider calls `C_Finalize`
  from OpenSSL's exit-time cleanup, after the calling thread's thread-locals are destroyed, and
  the per-thread HSM and session caches then panicked ("cannot access a Thread Local Storage
  value during or after destruction"). The caches now fall back to the uncached path.
- `CKA_COPYABLE` could not be read (`CKR_ATTRIBUTE_TYPE_INVALID`).
- `craton-hsm-admin` showed wrong key-type names for Ed25519, generic secret and PQC keys.

## [0.10.2] - 2026-09-27

### Fixed

- **PKCS#11 `CKA_EC_POINT` returned the raw point instead of the DER-encoded `ECPoint`**:
  PKCS#11 defines `CKA_EC_POINT` as the DER encoding of the ANSI X9.62 `ECPoint`, i.e. an
  `OCTET STRING` wrapping the SEC1 point (`04 61 04 ...` for P-384). The token returned the bare
  `04 || X || Y`, so OpenSC `pkcs11-tool --read-object` failed with "cannot obtain and parse
  EC_POINT" and OpenSSL `pkcs11-provider` failed with `ASN1_get_object: header too long`.
  `C_GetAttributeValue` now returns the DER form for EC and Edwards keys. Supplied values
  (`C_CreateObject`, `C_FindObjects` templates, `CKM_ECDH1_DERIVE` peer keys) are accepted in
  either DER or raw form, and objects persisted by earlier versions in either form keep working.
- **`CKM_ECDH1_DERIVE` did not accept the standard `CK_ECDH1_DERIVE_PARAMS`**: the mechanism
  parameter was read as the bare peer public key, so standard PKCS#11 callers (OpenSSL
  `pkcs11-provider`, OpenSC, Java SunPKCS11) that pass `CK_ECDH1_DERIVE_PARAMS` could not
  derive. `C_DeriveKey` now parses the struct and applies the requested KDF:
  - `CKD_NULL`: the key is the raw shared secret `Z`, truncated to `CKA_VALUE_LEN` by keeping the
    rightmost bytes (as SoftHSM does). Refused in FIPS-approved mode (SP 800-56C forbids using
    `Z` as a key directly).
  - `CKD_SHA256_KDF`, `CKD_SHA384_KDF`, `CKD_SHA512_KDF`: ANSI X9.63 KDF with optional
    `pSharedData`.
  - `CKD_SHA1_KDF` and `CKD_SHA224_KDF` return `CKR_MECHANISM_PARAM_INVALID`.

  The KDF runs above the crypto backend, so RustCrypto and AWS-LC now derive identical keys
  (previously RustCrypto applied an internal HKDF while AWS-LC truncated `Z`). `pPublicData` may
  be a raw or DER-encoded point. Callers that still pass the bare peer point as the parameter
  keep the previous backend-specific behaviour, so existing derived keys are unaffected; that
  legacy form is deprecated.
- **Derived keys could not be made readable, and were always 256-bit AES**: `C_DeriveKey`
  forced a derived key to be sensitive whenever the base key was, and rejected
  `CKA_EXTRACTABLE=true`. PKCS#11 has no such rule (only `CKA_ALWAYS_SENSITIVE` /
  `CKA_NEVER_EXTRACTABLE` propagate), and it made ECDH unusable for callers that read the agreed
  secret back, such as Java SunPKCS11 `KeyAgreement`. The template's `CKA_SENSITIVE` and
  `CKA_EXTRACTABLE` are now honoured. Derived keys may also be `CKK_GENERIC_SECRET` (up to 64
  bytes); a generic secret with no `CKA_VALUE_LEN` is the full shared secret (48 bytes for
  P-384) instead of being truncated to 32. Other key types return `CKR_TEMPLATE_INCONSISTENT`.
- **gRPC `DeriveKey` only accepted the bare peer key**: `DeriveKeyRequest` gains an
  `ecdh_params` field mirroring `CK_ECDH1_DERIVE_PARAMS`, with the same KDFs, key types and
  sensitivity handling as `C_DeriveKey`; the peer key may be raw or DER-encoded. Requests without
  it keep the previous behaviour. A template can now also mark the derived key non-sensitive,
  which the RPC previously refused.
- **gRPC `Login` / `Logout` did not update session state**: the RPCs changed only the token's
  login state, so sessions stayed public after `Login` and `InitPIN` always failed with "requires
  SO login". They now update every session on the slot as `C_Login` / `C_Logout` do: `Login`
  logs all sessions in, `Logout` resets them and zeroizes in-flight operations, and SO login is
  refused (`FAILED_PRECONDITION`) while a read-only session is open.

### Added

- **`algorithms.derived_keys_extractable_by_default`** (default `false`): when enabled, derived
  keys whose template leaves `CKA_SENSITIVE` / `CKA_EXTRACTABLE` unset are non-sensitive and
  extractable, so SunPKCS11 ECDH works without extra configuration. Rejected together with
  `fips_approved_only`. With the default, SunPKCS11 users instead add
  `attributes(generate, CKO_SECRET_KEY, CKK_GENERIC_SECRET) = { CKA_SENSITIVE = false
  CKA_EXTRACTABLE = true }` to their SunPKCS11 configuration.

## [0.10.1] - 2026-09-24

### Fixed

- **PKCS#11 ECDSA signatures returned ASN.1 DER instead of raw `r || s`**:
  Per PKCS#11 v3.0 §2.3.1, ECDSA mechanisms (`CKM_ECDSA`, `CKM_ECDSA_SHA*`) require
  the signature to be the raw concatenation of `r` and `s` as fixed-size big-endian integers
  (e.g., 64 bytes for P-256, 96 bytes for P-384). Previously, ECDSA sign returned ASN.1 DER-encoded
  signatures (`30 66 02 31 ...`), breaking interoperability with OpenSSL 3 and `pkcs11-provider`.
  Signing now returns raw `r || s`, and verification accepts raw `r || s` across both RustCrypto
  and AWS-LC backends (including single-shot and multi-part/prehashed operations).

## [0.10.0] - 2026-09-15 (Performance & Availability)

### Fixed

- **CRITICAL: release builds could not start.** `C_Initialize` returned
  `CKR_FUNCTION_FAILED` on any default release build. The power-on self-test ran
  an RSA PKCS#1 v1.5 known-answer test that *signs*, and release builds refuse
  RustCrypto RSA private-key operations (RUSTSEC-2023-0071 / Marvin), so the POST
  failed on every start. The KAT now branches on capability: the sign/verify
  roundtrip where RSA private-key operations are available, and a verify-only KAT
  against a checked-in fixed vector — with a negative case — where they are not.
  FIPS 140-3 requires a KAT per approved function the module *provides*, and when
  signing is refused it is not a provided service. (`crypto/self_test.rs`)
- **CRITICAL: one RSA key-pair attempt disabled the whole module.** With RSA
  private-key operations refused, `C_GenerateKeyPair` generated the key anyway
  and then failed its pairwise consistency test, which latched the FIPS error
  state — every subsequent call, including EC and AES, returned
  `CKR_FUNCTION_FAILED` for the life of the process. Unavailable mechanisms are
  now refused up front with `CKR_MECHANISM_INVALID` via
  `CryptoBackend::supports_rsa_private_ops()`, leaving the module usable.
  (`pkcs11_abi/functions.rs`, `crypto/backend.rs`, `crypto/rustcrypto_backend.rs`)
- **Audit chain could desynchronise after a transient write error.** The worker
  advanced its chain head before writing and did not roll it back on I/O failure,
  so the in-memory and on-disk chains diverged permanently after a single failed
  write. The chain head now advances only once the batch is durable.
  (`audit/log.rs`)
- **`C_GenerateKeyPair` persisted its two objects in separate transactions**, so
  a crash between them could leave a public key stored without its private half.
  Both now commit atomically. (`store/attributes.rs`, `pkcs11_abi/functions.rs`)
- Both benchmark suites aborted instead of running when RSA was unavailable, and
  the PKCS#11 ABI suite wrote its audit trail to the repository root — hundreds
  of megabytes per run, and a 100 MB rotation mid-run skewed later groups. The
  suites now skip RSA with an explanatory note and write to `target/`.
- 62 RSA tests (9 unit, 53 integration) failed under `cargo test --release`.
  They are now marked `ignore` under the same condition as the gate they depend
  on, so a release-mode run is green and each skip says why. The list was taken
  from an actual `--no-fail-fast` release run rather than guessed, so nothing is
  over-ignored.

- **Multi-part RSA now works on the AWS-LC backend, and no longer routes through
  RustCrypto.** `AwsLcBackend`'s prehashed RSA signing used the RustCrypto `rsa`
  crate, so `C_SignUpdate`/`C_SignFinal` with an RSA key returned
  `CKR_MECHANISM_INVALID` in release builds (refused by the RUSTSEC-2023-0071
  gate) and was silently Marvin-exposed in debug ones. PSS additionally drew its
  salt from `OsRng`, bypassing the SP 800-90A DRBG.

  Both signing paths now use `aws_lc_rs::rsa::KeyPair::sign_digest`, so they are
  constant-time and the salt is generated inside AWS-LC — the DRBG bypass is
  removed rather than relocated. Salt length is unchanged (digest length), so
  existing signatures and third-party verifiers are unaffected.

  Two caveats, documented in [fips-mode-guide.md](docs/fips-mode-guide.md):
  `sign_digest` is outside aws-lc-rs's FIPS-approved service set, so a
  validation scope covering every RSA signature should use single-shot `C_Sign`;
  and multi-part RSA *verification* still uses RustCrypto, because aws-lc-rs has
  no prehashed verification API. That is a public-key operation over non-secret
  inputs, so it is a scope matter rather than a security one.

- **The power-on self-tests now run against the configured crypto backend.**
  `run_post()` took no backend and every KAT called the RustCrypto free
  functions, so a deployment running AWS-LC self-tested an implementation it
  does not use — a broken or miscompiled AWS-LC would have passed POST cleanly.
  FIPS 140-3 wants a KAT per approved algorithm *the module implements*.

  `run_post_algorithms(&dyn CryptoBackend)` now dispatches the AES-GCM/CBC/CTR,
  SHA-2, ECDSA and RSA KATs through the backend. Both `C_Initialize` and the
  daemon select the backend once and hand the same instance to the KATs and to
  `HsmCore::new_with_backend`, so the tested and served implementations cannot
  diverge. The RSA KAT reads its capability from `supports_rsa_private_ops()`
  rather than the build-time gate, so AWS-LC now gets the full
  generate-sign-verify roundtrip instead of the verify-only fallback.

  The §9.4 integrity test is split into `run_post_integrity()` and still runs
  first, before the configuration is read — only the algorithm KATs need the
  backend, and reading a config file is not a cryptographic service.

  `HsmCore::select_crypto_backend` is now public, since any embedder running the
  POST must be able to resolve the backend before constructing a core.

### Changed

- **Audit records are written at `format_version: 1`.** The on-disk NDJSON line
  format is unchanged, so SIEM and log-shipping integrations are unaffected, and
  the verifier dispatches on each record's own version so existing logs and
  mixed-version files verify end to end.

  **Downgrading is one-way**: an older build verifies every record as version 0,
  so it will compute the wrong hash for a version 1 record and report the chain
  as tampered. Rotate the audit log before downgrading. See
  [migration-guide.md](docs/migration-guide.md).

- **RSA private-key mechanisms are now refused up front** with
  `CKR_MECHANISM_INVALID` in builds that do not provide them, instead of failing
  partway and disabling the module. Applications that relied on RSA in a default
  release build were already broken; they now get an actionable error. Build with
  `--no-default-features --features awslc-backend` for RSA.

- *(Rust API)* `AuditEvent` gained a public `format_version: u32` field. Struct
  literal construction must add it; set it to `AUDIT_LOG_FORMAT_VERSION`. PKCS#11
  ABI consumers are unaffected.

### Performance

- **Audit trail group commit.** The worker coalesces every event already queued
  behind the one it is writing into a single `write` + `fsync`, and keeps the log
  file open instead of reopening it per event. Sustained asynchronous throughput
  improved ~200x (1319 → 6.58 us/event, i.e. 758 → 152,000 events/s) and
  `record_sync` latency by 57% (1482 → 633 us). Durability is unchanged: a
  `record_sync` caller is still released only after its event is on stable
  storage. Most PKCS#11 operations emit an audit event -- signing, verification,
  encryption, decryption, key generation, object and session calls (`C_Digest`
  does not) -- so this removed a ~760 events/s ceiling from under them.
  (`audit/log.rs`)
- **Canonical binary audit chain encoding.** The chain hash input moved from
  `serde_json` to a fixed-width, length-prefixed, injective binary encoding
  (`AUDIT_LOG_FORMAT_VERSION = 1`), cutting per-event CPU by 68% (3.76 → 1.22
  us). The on-disk NDJSON line is unchanged — it is a SIEM interop contract — and
  verification dispatches on each record's own `format_version`, so existing logs
  and mixed-version files still verify. (`audit/log.rs`)
- **Daemon no longer blocks the async reactor.** All 23 gRPC handlers wrap their
  synchronous bodies in `tokio::task::block_in_place`. Previously a `Login`
  (600,000 PBKDF2 iterations) or `GenerateKeyPair` occupied a Tokio worker
  thread outright, so a few concurrent logins could stall unrelated connections
  including health checks and TLS handshakes. (`craton-hsm-daemon/src/server.rs`)
- **Batched object persistence.** `EncryptedStore::store_encrypted_batch` and
  `ObjectStore::insert_objects` commit multiple objects in one redb transaction,
  halving the `fsync` cost of key-pair generation.
- One heap allocation and one virtual call removed from every DRBG reseed
  (`HealthMonitoredRng`'s entropy source is now an inline enum).

### Added

- `docs/performance-tuning.md` — build flags, PGO, the profiling workflow,
  deployment tuning, and the optimisations that were **rejected** for security
  reasons, with the measurements behind each decision.
- `scripts/profile.sh` (CPU / allocation / I/O / lock profiling) and
  `scripts/pgo.sh` (three-stage profile-guided build).
- `[profile.profiling]` — release codegen with symbols retained, so profilers
  resolve Rust frames.
- Benchmark coverage for previously unmeasured behaviour: `C_FindObjects`
  (selective and broad), payload scaling from 256 B to 1 MB for AES-GCM and
  SHA-256, concurrency across 1–8 sessions, and the audit trail itself.
- A CI `bench` job that gates on benchmarks still compiling and running, and
  reports Criterion deltas against the merge base without gating on them.

### Notes

- Measurements above are medians from an A/B harness that alternates the order of
  the two binaries and cools between runs; see `docs/benchmarks.md` for why that
  matters on this reference machine.
- Two proposals were implemented, measured, and reverted because the data did not
  support them: buffering the DRBG adapter (RSA keygen makes only 423 RNG calls,
  under 1% of its time; EC keygen makes exactly one) and an attribute index for
  `C_FindObjects` (it would leak object existence to unauthenticated callers by
  timing). Both are documented in `docs/performance-tuning.md` so they are not
  re-attempted.

## [0.9.3] - 2026-06-24 (Persistent Storage)

### Added
- **Persistent token state** — when `persist_objects = true`, the token's
  initialization state (SO/User PIN PBKDF2 hashes, label, and the
  `initialized` / `user_pin_initialized` flags) is now written to a per-slot,
  owner-only `token_state_<slot>.json` and restored on startup. Previously this
  lived only in memory, so a token re-appeared uninitialized after every
  restart, making persistence unusable in practice. (`token/token_state_store.rs`, `token/token.rs`)
- **Encrypted object persistence wired end-to-end** — `HsmCore` now builds an
  `EncryptedStore`-backed object store when `persist_objects = true`, installs
  the object-encryption key at `C_Login`, and clears it at `C_Logout` /
  `C_InitToken`. Token objects (`CKA_TOKEN=true`) now survive restarts. (`core.rs`, `pkcs11_abi/functions.rs`)
- **Wrapped object master key (KEK)** — objects are encrypted under a random
  object master key (OMK) that is itself AES-256-GCM-wrapped by a PIN-derived
  key. A `C_SetPIN` only re-wraps the OMK (atomic, crash-safe) instead of
  re-encrypting stored objects. `C_InitToken` rotates the OMK, logically
  zeroizing prior ciphertext. (`store/encrypted_store.rs`, `token/token.rs`)
- `docs/persistence.md` — full documentation of the persistence model,
  key hierarchy, on-disk files, and security properties.

### Security
- Token-state and object persistence are gated behind the single opt-in
  `persist_objects` flag; the default remains fully in-memory. PIN-hash and
  token-state files are written atomically with owner-only permissions (mode
  0600 / owner-only DACL), and a failure to lock them down is fatal.

## [0.9.1] - 2026-03-20 (Security Audit Hardening)

### Security Fixes
- **CRITICAL: DRBG bypass in key generation** — RSA, EC P-256/P-384, and Ed25519 key generation was using `OsRng` directly, bypassing the SP 800-90A HMAC_DRBG health checks. All key generation now routes through a `DrbgRng` wrapper implementing `rand::RngCore + rand::CryptoRng`. (`crypto/keygen.rs`)
- **HIGH: Per-key AES-GCM nonce counters** — The GCM encryption counter was global (shared across all keys), meaning a multi-key workload could hit the 2^32 birthday bound prematurely. Changed to per-key counters using `DashMap<u64, AtomicU64>` keyed by SHA-256 hash of key material. Counters reset on `C_Initialize`. (`crypto/encrypt.rs`)
- **HIGH: Circular KATs replaced** — AES-CBC and AES-CTR POST self-tests were circular (encrypt→decrypt roundtrip), which would pass even if both paths had the same symmetric bug. Replaced with genuine known-answer tests using hardcoded expected ciphertexts. (`crypto/self_test.rs`)
- **HIGH: RSA PKCS#1 v1.5 KAT added** — POST was missing an RSA signing KAT entirely. Added RSA-2048 PKCS#1 v1.5 sign/verify roundtrip. POST now has 17 self-tests (integrity + 16 KATs). (`crypto/self_test.rs`)
- **MEDIUM: RSA public key size validation** — `validate_rsa_public_key_size` didn't strip leading zero bytes before counting significant bits, potentially accepting keys that appear larger than they are. (`crypto/sign.rs`)
- **MEDIUM: All-zero IV rejection at C_EncryptInit** — AES-CBC and AES-CTR previously accepted all-zero IVs at `C_EncryptInit` time (rejection only happened later in `C_Encrypt`). Zero IVs are now rejected early in `C_EncryptInit`. (`pkcs11_abi/functions.rs`)
- **MEDIUM: POST_FAILED reset on re-initialization** — `POST_FAILED` was never cleared, meaning after `C_Finalize` → `C_Initialize`, a previous POST failure would permanently block the module. Now reset before re-running POST. (`pkcs11_abi/functions.rs`)
- **MEDIUM: Session count race in close_all_sessions** — Fixed to track actual removed counts instead of zeroing all counters, which could affect session counts for other slots. (`session/manager.rs`)
- **LOW: Config path traversal hardening** — Added UNC path rejection (`\\server\share` and `//server/share`) and literal `..` segment check as defense-in-depth. (`config/config.rs`)
- **LOW: RSA DER key material copy eliminated** — Removed unnecessary `.clone()` of RSA private key DER bytes that created an unzeroized copy in memory. (`crypto/keygen.rs`)
- **LOW: AES-GCM max plaintext size check** — Added NIST SP 800-38D maximum plaintext length enforcement (2^36 - 32 bytes). (`crypto/encrypt.rs`)

### Changed
- Software integrity check (`crypto/integrity.rs`) now uses opt-in model: `.hmac` sidecar file presence triggers verification. Without the file, the check passes (development/test/non-FIPS deployments). With `fips` feature, the `.hmac` file is mandatory.
- POST self-test count increased from 15 to 17 (added RSA PKCS#1 v1.5 KAT, software integrity counts separately)

### Added
- **PKCS#11 conformance test suite** (`tests/pkcs11_conformance.rs`) — 46 comprehensive tests covering:
  - AES-CBC/CTR zero IV rejection
  - Double session close safety
  - PIN complexity and length validation
  - Init/finalize lifecycle and re-initialization
  - Null pointer handling for all info functions
  - Invalid slot/session/user type error paths
  - AES-GCM encrypt/decrypt roundtrip via ABI
  - RSA-2048 keygen + PKCS#1 v1.5 sign/verify via ABI
  - EC P-256 keygen + ECDSA sign/verify via ABI
  - SHA-256 digest via ABI
  - FindObjects lifecycle and DestroyObject
  - Operation state save/restore for digest
  - Multi-part digest (SHA-256)
  - Login lockout after max failed attempts
  - Mechanism list and info validation
  - Token info flags and version checks
  - Configuration validation (path traversal, absolute paths, UNC paths, PBKDF2 floor)
  - Audit log chain integrity and injection prevention
- Total test count: 617+ (46 new conformance tests)

## [0.9.0] - 2026-02-24 (Phases 12–13: Release Polish & Roadmap Items)

### Changed (Phase 12: Release Polish)
- Version synchronized across all workspace crates (0.9.0 / 0.3.0)
- License changed to Apache-2.0
- Added Cargo.toml metadata: repository, homepage, keywords, categories
- Added `[profile.release]` with LTO, codegen-units=1, strip=symbols
- Created ROADMAP.md documenting all 12 phases and future directions
- Updated docs (architecture, audit-scope, PRESENTATION, FIPS certification, security-policy) to v0.9.0

### Added (Phase 13: Actionable Roadmap Items)
- **Audit log export**: JSON, NDJSON (JSON Lines for SIEM), syslog RFC 5424 format
- **Audit chain verification**: `verify_chain()` validates SHA-256 hash chain integrity
- **Admin CLI audit commands**: `audit export-json`, `audit export-ndjson`, `audit export-syslog`, `audit verify-chain`
- **macOS CI**: Added `macos-latest` to GitHub Actions build matrix
- **Code coverage CI**: `cargo-tarpaulin` job with HTML/XML report artifacts
- **Future work guide**: `docs/future-work-guide.md` with detailed instructions for PQC upgrades, rand_core unification, FIPS certification, HSM clustering, and KMIP support
- 9 new audit export/chain tests — 580+ total

### Added (Phase 10-11)
- **Multi-slot support**: Configurable via `slot_count` in `[token]` section of craton_hsm.toml (default: 1, backward compatible)
- **C_GetOperationState / C_SetOperationState**: Save and restore digest/sign/verify operations mid-stream across sessions
- **HSM backup/restore**: `craton-hsm-admin backup` / `restore` subcommands with AES-256-GCM encrypted backup files (PBKDF2 key derivation)
- `ObjectStore::export_all_objects()` method for backup support
- 24 new tests: multi_slot (8), operation_state (8), backup_restore (8) — 571 total

### Changed
- `HsmCore` fields restricted to `pub(crate)` with public accessor methods (internal encapsulation)
- `#[must_use]` attribute on `HsmError` enum
- `#![forbid(unsafe_code)]` enforced on safe modules (audit, session, config, store, token)

### Removed
- Unused `bincode` dependency

### Known Issues
- PQC crates (ml-kem, ml-dsa, slh-dsa) remain at RC versions — no stable releases available as of March 2026
- Dual rand_core versions (0.6 + 0.10) required until PQC ecosystem unifies

## [0.8.0] - 2026-01-19

### Added
- 11 new comprehensive test suites (261 new tests, 547 total):
  - `pkcs11_info_functions` (25): C_GetInfo, C_GetSlotInfo, C_GetTokenInfo, C_GetMechanismInfo
  - `key_lifecycle_abi` (25): SP 800-57 date-based activation/deactivation through C ABI
  - `key_wrapping_abi` (22): C_WrapKey/C_UnwrapKey roundtrips and error paths
  - `key_derivation_abi` (19): ECDH P-256/P-384 derivation, cross-party validation
  - `rsa_abi_comprehensive` (28): RSA 2048/3072 sign/verify/encrypt/decrypt, OAEP, PSS
  - `digest_abi` (25): All 7 hash algorithms, single-part and multi-part
  - `attribute_management` (25): C_GetAttributeValue, C_SetAttributeValue, C_FindObjects
  - `random_and_session` (22): C_GenerateRandom, session management, PIN operations
  - `pqc_abi_comprehensive` (28): ML-DSA/ML-KEM/SLH-DSA/hybrid through C ABI
  - `audit_and_integrity` (24): AuditLog chain integrity, StoredObject lifecycle
  - `negative_edge_cases` (30): Cross-algo failures, boundary conditions, empty data

### Fixed
- CKA_START_DATE/CKA_END_DATE attributes now applied during C_GenerateKey and C_GenerateKeyPair
  (previously silently ignored in template override section)

## [0.7.0] - 2025-10-17

### Added
- **FIPS Approved Mode**: `fips_approved_only` config flag restricts operations to FIPS-approved algorithms only
- `is_fips_approved()` mechanism classifier and `validate_mechanism_for_policy()` enforcement in all Init/keygen functions
- `C_GetMechanismList` filters non-approved mechanisms when FIPS mode is active
- **Pairwise Consistency Tests (§9.6)**: Sign/verify or encap/decap roundtrip after every key pair generation (RSA, ECDSA P-256/P-384, Ed25519, ML-DSA, ML-KEM, SLH-DSA)
- **Software Integrity Test (§9.4)**: HMAC-SHA256 of module binary at POST time with `.hmac` sidecar verification
- `tools/compute-integrity-hmac.sh` and `.ps1` for computing integrity HMAC
- **Algorithm Indicator (IG 2.4.C)**: `fips_approved: bool` field in all crypto audit log entries (Sign, Verify, Encrypt, Decrypt, Digest, GenerateKey, GenerateKeyPair, WrapKey, UnwrapKey, DeriveKey)
- `last_operation_fips_approved` field on `Session` for runtime indicator querying
- `CKA_VENDOR_FIPS_APPROVED` (0x80000001) vendor-defined attribute constant
- **Intermediate Zeroization**: `Zeroizing<Vec<u8>>` for all `ActiveOperation` data and mechanism_param fields
- FIPS mode operator guide (`docs/fips-mode-guide.md`)
- 17 new tests: 11 FIPS approved mode tests, 6 pairwise consistency integration tests, 3 integrity unit tests

### Changed
- `HsmCore` stores `AlgorithmConfig` for runtime policy enforcement
- POST now runs software integrity check as first test (16 total self-tests)
- Security Policy updated to v3.0 with pairwise tests, integrity test, algorithm indicator, intermediate zeroization

## [0.6.0] - 2025-09-11

### Added
- `cargo audit` and `cargo deny` in CI pipeline (CVE check, license/advisory compliance)
- `deny.toml` configuration for dependency vetting
- Miri CI job for undefined behavior detection (`cargo +nightly miri test`)
- 2 new fuzz targets: `fuzz_session_lifecycle` (state machine edge cases, login/logout sequences) and `fuzz_buffer_overflow` (integer overflow, two-call pattern, null pointers)
- Security review checklist (`docs/security-review-checklist.md`) — pre-audit self-assessment
- Release signing documentation (`docs/release-signing.md`) — GPG, cosign, Authenticode
- Side-channel resistance documentation in security model — constant-time operations, RSA blinding, AES-NI
- Visual examples in PRESENTATION.md — Admin CLI output, Audit Log chain, FIPS POST, pkcs11-tool
- AddressSanitizer / MemorySanitizer usage instructions
- Supply-chain security documentation (dependency vetting, reproducible builds, binary signing)

### Changed
- Fuzz target count increased from 3 to 5
- CI pipeline expanded from 5 to 7 jobs (added security-audit, miri)
- PRESENTATION.md updated with visual examples, side-channel analysis, supply-chain table

## [0.5.0] - 2025-07-14

### Added
- PKCS#11 C ABI benchmarks via Criterion (10 benchmark groups through `C_GetFunctionList`)
- SoftHSMv2 head-to-head comparative benchmarks (controlled via `SOFTHSM2_LIB` env var)
- Java SunPKCS11 interop test script (`tests/interop/java_sunpkcs11.sh`)
- OpenSSL / pkcs11-tool interop test script (`tests/interop/openssl_pkcs11.sh`)
- Benchmark documentation (`docs/benchmarks.md`)
- CI benchmark job (runs on push to main, uploads Criterion reports as artifacts)
- Comprehensive Java SunPKCS11 usage guide in install docs (keytool + programmatic)
- Comprehensive OpenSSL / pkcs11-tool / p11tool usage guide in install docs
- SSH agent integration documentation

## [0.4.0] - 2025-06-06

### Added
- Multi-part sign/verify: `C_SignUpdate`, `C_SignFinal`, `C_VerifyUpdate`, `C_VerifyFinal`
- Multi-part encrypt/decrypt: `C_EncryptUpdate`, `C_EncryptFinal`, `C_DecryptUpdate`, `C_DecryptFinal`
- SP 800-90A HMAC_DRBG with prediction resistance and continuous health test
- DRBG POST known-answer test (KAT #15)
- `C_CopyObject` with PKCS#11 sensitivity/extractability enforcement
- `C_DigestKey` for feeding key material into digest operations
- SP 800-57 key lifecycle states (pre-activation, active, deactivated, compromised, destroyed)
- `CKA_START_DATE` / `CKA_END_DATE` attribute support with date-based lifecycle transitions
- Lifecycle enforcement in `C_SignInit`, `C_VerifyInit`, `C_EncryptInit`, `C_DecryptInit`
- README.md and CHANGELOG.md
- GitHub Actions CI pipeline (build, test, lint, docs on Ubuntu + Windows)
- 50+ new integration tests (multi-part sign/verify, encrypt/decrypt, supplementary functions, DRBG)

## [0.3.0] - 2025-04-28

### Added
- aws-lc-rs crypto backend (`awslc-backend` feature flag) for FIPS 140-3 Level 1
- `CryptoBackend` trait with 26 methods, wired into all 29 callsites
- Encrypted persistent storage (redb + AES-256-GCM with PBKDF2-derived keys)
- File-level locking (`fs2`) for multi-process safety
- Tamper-evident append-only audit log with chained SHA-256
- FIPS 140-3 Power-On Self-Tests: 14 KATs covering all approved algorithms
- Continuous RNG health test (SP 800-90B)
- Memory hardening: mlock/VirtualLock on key material, ZeroizeOnDrop, custom Debug impls
- Fork detection (Unix): PID comparison forces child processes to re-initialize
- Fuzzing harness for ABI boundary (3 cargo-fuzz targets)
- FIPS Security Policy document with CSP table
- Audit scope documentation and FIPS gap analysis
- Tested platforms documentation
- `PRESENTATION.md` with detailed architecture walkthrough

## [0.2.0] - 2025-03-21

### Added
- Criterion benchmarks for all crypto operations (RSA, ECDSA, Ed25519, AES, SHA, ML-DSA, ML-KEM)
- gRPC daemon with mutual TLS (`craton-hsm-daemon`)
- Admin CLI tool (`craton-hsm-admin`) for token, key, PIN, and audit management
- PKCS#11 spy/logging wrapper (`pkcs11-spy`)
- Dockerfile (multi-stage distroless) and Helm chart for Kubernetes deployment
- Operator runbook and installation guide
- Session state machine validation tests (42 tests)
- Attribute validation tests (24 tests)
- Concurrent session stress tests (6 tests)
- Error path coverage tests (50 tests)

## [0.1.0] - 2025-02-14

### Added
- Core PKCS#11 v3.0 C ABI with 70+ exported functions
- Session management with DashMap-based concurrent access
- Token/slot management with PIN lifecycle (SO + User)
- Object store with template-based search
- RSA keygen/sign/verify (2048/3072/4096), ECDSA (P-256/P-384), EdDSA (Ed25519)
- AES-256 encrypt/decrypt (GCM, CBC, CTR)
- SHA-256/384/512/SHA3-256 digest
- ECDH key derivation (P-256, P-384)
- AES key wrapping (RFC 3394)
- Post-quantum cryptography: ML-KEM-768, ML-DSA-44/65/87, SLH-DSA-SHA2-128s
- Hybrid X25519+ML-KEM-768 key exchange
- PBKDF2-SHA256 PIN hashing with constant-time comparison
