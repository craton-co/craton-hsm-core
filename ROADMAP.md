# Craton HSM Roadmap

## Completed Phases

### Phase 1: Core PKCS#11 Foundation (26 tasks)
HsmCore, SessionManager, ObjectStore, Token/PIN management, basic crypto (AES, RSA, ECDSA, Ed25519), C ABI layer with 70+ exported functions, error mapping, and initial test suite.

### Phase 2: Advanced Crypto & Key Management (15/16 tasks)
Multi-part operations (sign/verify/encrypt/decrypt/digest), key wrapping (C_WrapKey/C_UnwrapKey), key derivation (ECDH), OAEP/PSS padding, mechanism validation. 1 task deferred.

### Phase 3: Post-Quantum Cryptography (10/11 tasks)
ML-KEM (CRYSTALS-Kyber), ML-DSA (CRYSTALS-Dilithium), SLH-DSA (SPHINCS+), hybrid key exchange, PQC key generation and encapsulation through C ABI. 1 task deferred.

### Phase 4: Production Tooling (8 tasks)
gRPC daemon (tonic + rustls), admin CLI (clap), PKCS#11 spy wrapper (libloading), Docker multi-stage build, Helm chart, Criterion benchmarks.

### Phase 5: Hardening (3 workstreams)
216 tests passing, security hardening across crypto, session management, and storage.

### Phase 6: Enterprise & Audit Readiness (25 tasks)
FIPS backend (aws-lc-rs), storage overhaul (sled to redb), memory hardening (mlock/VirtualLock), cargo-fuzz targets, multi-process fork safety, audit documentation, FIPS POST KATs.

### Phase 7: PKCS#11 Completeness (22 tasks)
Full PKCS#11 v3.0 function coverage, FIPS approved mode, pairwise consistency tests, software integrity verification, algorithm indicators, intermediate zeroization.

### Phase 8: Interop & Benchmarking (7 tasks)
ABI benchmarks with SoftHSMv2 comparison, Java SunPKCS11 interop tests, OpenSSL 3.x provider interop tests, CI benchmark job.

### Phase 9: Security Polish (7 tasks)
cargo-audit + cargo-deny CI, Miri CI, additional fuzz targets, security review checklist, release signing guide, constant-time analysis documentation.

### Phase 10: Code Hardening & Roadmap Gaps (8 tasks)
HsmCore field encapsulation (pub(crate)), #[must_use] on HsmError, #![forbid(unsafe_code)] on safe modules, removed unused dependencies, multi-slot support, C_GetOperationState/C_SetOperationState, encrypted backup/restore.

### Phase 11: Test Coverage Doubling
Doubled test coverage from 286 to 547 tests across 11 new comprehensive test suites.

### Phase 12: Release Polish & Publishing Readiness (7 tasks)
Version synchronization, license clarification (Apache-2.0), Cargo.toml metadata, release profile optimization, roadmap documentation, docs updates.

### Phase 13: Actionable Roadmap Items
Audit log export (JSON, NDJSON, syslog RFC 5424), audit chain verification, admin CLI audit commands, macOS CI, code coverage CI (tarpaulin), future work guide. 580+ total tests.

## Current Status

- **126/130 tasks complete** (2 interop tests deferred, 2 Phase 2/3 items deferred)
- **717+ tests** passing
- **v0.9.1** released

## Future Directions

### Near-Term
- **Performance optimization** — narrow the gap vs SoftHSMv2 in RSA
  - *Runtime hot-path (P1–P3: ~40-50% total latency reduction)*
    - [ ] **Eliminate per-operation RSA key re-parsing**: `sign.rs` computes SHA-256 of DER on every sign/verify for cache lookup, then clones the `RsaPrivateKey`. Switch to handle-based `Arc<RsaPrivateKey>` cache keyed on `CK_OBJECT_HANDLE` — eliminates ~1.5-3 µs/op (~15-25%)
    - [ ] **Cache parsed RSA public keys**: `sign.rs` reconstructs `BigUint` modulus + exponent and `RsaPublicKey` on every verify call. Pre-parse at key import/generation, store in `StoredObject` — eliminates ~500-1000 ns/verify (~5-15%)
    - [ ] **Reduce lock acquisitions in C_Sign/C_Verify path**: `functions.rs` takes 4 locks per operation (DashMap session + RwLock session + DashMap object + RwLock object). Use `cached_object` from `C_SignInit` and TLS-cached session `Arc` — eliminates ~100-500 ns/op (~5-10%)
  - *Lock contention & concurrency (P4–P5: ~5-10%)*
    - [ ] **TLS session cache**: Cache `Arc<RwLock<Session>>` in thread-local alongside `CACHED_HSM` to skip DashMap shard lock on every C_* call
    - [ ] **Simplify `get_hsm()` TLS path**: Avoid `Arc::clone` on cache hit; use pinned reference or `RefCell` borrow
    - [ ] **Drop persist lock before disk I/O**: `store/attributes.rs:183-219` holds the per-object Mutex across `serde_json::to_vec` + redb `store_encrypted`; clone the 32-byte wrap key, release the lock, then do I/O so concurrent sessions don't serialize on the disk path
    - [ ] **O(1) `logout_all` via per-slot session index**: `session/manager.rs:341-356` iterates the entire DashMap under shard read-locks just to find sessions for one slot; maintain a `HashMap<CK_SLOT_ID, Vec<Handle>>` side index
  - *Allocation reduction (P6: ~3-5%)*
    - [ ] **Stack-allocate signature buffers**: ECDSA/Ed25519 signatures fit in ≤144 bytes; use `ArrayVec<u8, 512>` instead of heap `Vec<u8>` in sign functions
    - [ ] **Pass output buffer from C ABI to backend**: PKCS#11 callers already provide output buffers; thread them through to crypto backend to eliminate intermediate allocations
    - [ ] **Eliminate `.as_bytes().to_vec()` in sign/wrap hot paths**: `pkcs11_abi/functions.rs:1094, 4454, 5061, 5085, 5181, 5333` copy full key material per call before invoking crypto; thread `&[u8]` borrows through the crypto API instead
    - [ ] **Defer label conversion in lifecycle sweep**: `store/attributes.rs:413, 423` always materializes `String::from_utf8_lossy(...).to_string()` even when no debug logging fires; keep the `Cow` and only allocate at the log call site
    - [ ] **Binary serialization for `StoredObject`**: `store/attributes.rs:140-145` documents `serde_json`'s unzeroized intermediate buffers as a residual risk; switching to `bincode` / `postcard` removes both the per-persist perf cost and the residual key-fragment exposure
  - *Storage & lookup*
    - [ ] **Secondary attribute index for `C_FindObjectsInit`**: `store/attributes.rs:387-396` read-locks every object on every template match; add a `HashMap<(CKA_CLASS, CKA_KEY_TYPE), Vec<Handle>>` so highly selective templates skip non-matching objects entirely instead of scanning the full map
    - [ ] **Smarter cache eviction in `sign.rs`**: `evict_one_if_full` (`crypto/sign.rs:62-69`) uses `iter().next() + clone` under a DashMap shard lock — switch to `DashMap::retain` or a small LRU to avoid the runtime clone-per-eviction
    - [ ] **Optional batched commits in encrypted store**: `redb` fsyncs every `C_CreateObject` / `C_DestroyObject`; expose a config flag for bulk-provisioning workloads where `C_Finalize` (or an explicit flush threshold) is the natural sync point
  - *Build & CI*
    - [x] **CI test split**: Parallel-safe crypto tests (92 tests, `--test-threads=8`) vs serial PKCS#11 ABI tests (625 tests, `--test-threads=1`)
    - [ ] **`cargo-nextest` evaluation**: Per-process test isolation would eliminate `--test-threads=1` requirement entirely
    - [ ] **`[profile.test] opt-level = 1`**: Faster crypto-heavy test execution
- **Stable PQC crates**: Upgrade ml-kem, ml-dsa, slh-dsa from RC to stable when released
- **Unified rand_core**: Consolidate dual rand_core versions (0.6 + 0.10) when PQC ecosystem unifies

### Medium-Term
- **FIPS 140-3 certification**: Submit for CMVP validation with aws-lc-rs FIPS backend
- **HSM clustering**: Multi-node key replication for high availability
- **KMIP support**: Key Management Interoperability Protocol alongside PKCS#11

### Long-Term
- **Hardware acceleration**: Intel QAT, ARM CryptoCell integration
- **Cloud KMS bridge**: AWS KMS, Azure Key Vault, GCP Cloud KMS as backing stores
- **PKCS#11 v3.1**: Track and implement spec updates as published
- **Formal verification**: Model checking of critical state machines
