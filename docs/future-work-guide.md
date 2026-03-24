# Future Work Guide

Instructions for completing roadmap items that require external dependencies, certification processes, or significant design work.

## 1. Stable PQC Crate Upgrade

**Current state:** Craton HSM uses pre-release (release candidate) PQC crates:
- `ml-kem = "0.3.0-rc.0"` (ML-KEM / FIPS 203)
- `ml-dsa = "0.1.0-rc.7"` (ML-DSA / FIPS 204)
- `slh-dsa = "0.2.0-rc.4"` (SLH-DSA / FIPS 205)

**When to proceed:** These crates are maintained by the RustCrypto project. Monitor:
- https://github.com/RustCrypto/KEMs (ml-kem)
- https://github.com/RustCrypto/signatures (ml-dsa, slh-dsa)
- https://crates.io/crates/ml-kem, https://crates.io/crates/ml-dsa, https://crates.io/crates/slh-dsa

Look for versions without `-rc` or `-pre` suffixes (e.g., `ml-kem 0.3.0` or `1.0.0`).

**Steps to upgrade:**

1. Update `Cargo.toml` versions:
   ```toml
   ml-kem = { version = "NEW_VERSION", features = ["getrandom"] }
   ml-dsa = "NEW_VERSION"
   slh-dsa = "NEW_VERSION"
   ```

2. Check for API changes. Key areas in `src/crypto/pqc.rs`:
   - `ml_kem::kem::{Encapsulate, Decapsulate}` trait usage
   - `ml_dsa::{SigningKey, VerifyingKey}` API
   - `slh_dsa::{SigningKey, VerifyingKey}` API
   - RNG bridging (`rand_core_new` / `getrandom_new`) may change

3. Run the PQC test suites:
   ```bash
   cargo test --test pqc_phase3 -- --test-threads=1
   cargo test --test pqc_abi_comprehensive -- --test-threads=1
   ```

4. If the stable crates move to `rand_core 0.10` by default, you may be able to remove the `getrandom_new` / `rand_core_new` renamed dependency workaround (see Section 2 below).

5. Update `CHANGELOG.md` and `ROADMAP.md`.

---

## 2. Unified `rand_core` Consolidation

**Current state:** The project uses **two** `rand_core` versions simultaneously:
- `rand_core 0.6` — used by `ed25519-dalek`, `rsa`, `ecdsa`, `p256`, `p384`, `aes-gcm`
- `rand_core 0.10` (aliased as `rand_core_new`) — required by `ml-kem`, `ml-dsa`, `slh-dsa`

This dual-version situation exists because the PQC crates adopted `rand_core 0.10` before the rest of the RustCrypto ecosystem.

**When to proceed:** Wait for the mainline RustCrypto crates to release versions using `rand_core 0.10`:
- `rsa` (currently uses 0.6)
- `ecdsa` / `p256` / `p384` (currently use 0.6)
- `ed25519-dalek` (currently uses 0.6)
- `aes-gcm` (currently uses 0.6)

**Steps to consolidate:**

1. Update all crypto crates to versions that use `rand_core 0.10`.

2. Remove the renamed dependencies from `Cargo.toml`:
   ```toml
   # REMOVE these lines:
   getrandom_new = { package = "getrandom", version = "0.4", features = ["sys_rng"] }
   rand_core_new = { package = "rand_core", version = "0.10" }

   # UPDATE this:
   rand_core = { version = "0.10", features = ["getrandom"] }
   ```

3. Update `src/crypto/pqc.rs` — replace `rand_core_new::OsRng` with `rand_core::OsRng`.

4. Update `src/crypto/keygen.rs` and `src/crypto/sign.rs` — ensure the single `rand_core::OsRng` works with all backends.

5. Run the full test suite:
   ```bash
   cargo test -- --test-threads=1
   ```

---

## 3. FIPS 140-3 Certification Submission

**Current state:** Craton HSM has significant FIPS 140-3 readiness:
- Algorithm indicators (IG 2.4.C) on all crypto operations
- FIPS POST with 17 tests: integrity + 16 KATs (SP 800-140E)
- Continuous RNG health test (SP 800-90B)
- Approved algorithm enforcement mode
- `aws-lc-rs` FIPS backend option (FIPS 140-3 validated module)
- Zeroization of key material
- Tamper-evident audit log
- Gap analysis document: `docs/fips-gap-analysis.md`
- Certification guide: `docs/fips-140-3-certification.md`

**What cannot be done in code — requires external action:**

### Step 1: Select a CMVP-accredited testing laboratory
Contact one of the NVLAP-accredited Cryptographic and Security Testing (CST) laboratories:
- List: https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules
- Common labs: Leidos, UL, Lightship Security, Acumen Security, atsec

### Step 2: Prepare documentation package
The lab will require:
- **Security Policy** — `docs/security-policy.md` (draft exists, needs formal formatting)
- **Finite State Model** — formal state machine diagram of HSM states
- **Design documentation** — `docs/architecture.md` (exists, may need expansion)
- **Entropy source justification** — document the DRBG and OS entropy sources
- **Algorithm validation certificates** — submit algorithm implementations to ACVP (Automated Cryptographic Validation Protocol) at https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program

### Step 3: ACVP Algorithm Validation
Before module validation, each algorithm needs its own ACVP certificate:
1. Register at https://acvts.nist.gov/
2. Run ACVP test vectors against Craton HSM's implementations
3. Obtain algorithm certificates for: AES, SHA-2, RSA, ECDSA, HMAC, HKDF, PBKDF2
4. PQC algorithms (ML-KEM, ML-DSA, SLH-DSA) may need separate ACVP validation

### Step 4: Lab engagement
- Lab performs source code review, operational testing, and documentation review
- Typical timeline: 6-18 months
- Typical cost: $50,000-$200,000+ depending on scope and Level (1 vs 2)
- Craton HSM targets Level 1 (software module, no physical security)

### Step 5: Address lab findings
The lab will produce IUT (Implementation Under Test) reports. Address all findings, resubmit, iterate.

### Step 6: CMVP review
After lab approval, NIST/CCCS reviews the submission. Additional timeline: 3-12 months.

---

## 4. HSM Clustering / High Availability

**Current state:** Craton HSM is a single-instance, single-process HSM. The `craton-hsm-daemon` provides network access via gRPC but there is no multi-node coordination.

**Design considerations:**

### Architecture options

**Option A: Active-Passive with shared storage**
- Primary node handles all requests
- Secondary node monitors primary, takes over on failure
- Shared encrypted storage (redb database on shared filesystem or replicated block device)
- Simplest to implement, but shared storage is a single point of failure

**Option B: Active-Active with key replication**
- Multiple nodes accept requests simultaneously
- Key material replicated via encrypted channels (mTLS gRPC)
- Requires distributed consensus for key generation (to ensure all nodes have the key)
- Use Raft consensus (e.g., `openraft` crate) for leader election and log replication
- More complex but provides true HA

**Option C: Proxy/load-balancer model**
- External load balancer routes PKCS#11 requests to healthy backend nodes
- Each node has independent key store, synced periodically
- Simplest networking, but eventual consistency may cause issues

### Implementation steps (recommended: Option B)

1. **Add a `cluster` module** (`src/cluster/`):
   - `src/cluster/mod.rs` — cluster configuration and node identity
   - `src/cluster/replication.rs` — key material sync protocol
   - `src/cluster/consensus.rs` — Raft-based leader election (using `openraft`)
   - `src/cluster/health.rs` — heartbeat and failure detection

2. **Extend `craton-hsm-daemon`**:
   - Add cluster membership gRPC endpoints (Join, Leave, Status)
   - Add key replication gRPC endpoints (SyncKey, AckSync)
   - Configuration: `[cluster]` section in `craton_hsm.toml`

3. **Key dependencies to add**:
   ```toml
   openraft = "0.10"  # Raft consensus
   ```

4. **Critical design decisions**:
   - How to handle split-brain scenarios
   - Key material encryption during replication (double-encrypt: TLS + application-level AES-GCM)
   - Audit log merging across nodes
   - Session affinity vs session migration

---

## 5. KMIP (Key Management Interoperability Protocol) Support

**Current state:** Craton HSM only supports the PKCS#11 v3.0 API. No KMIP support exists.

**What is KMIP:** OASIS standard for key management operations. Used by enterprise KMS products (e.g., HashiCorp Vault, Thales, Gemalto). Defined in OASIS KMIP Specification v2.1.

**Implementation approach:**

### Step 1: Protocol support
KMIP uses TTLV (Tag-Type-Length-Value) encoding over TLS. Options:
- **Manual TTLV codec**: Implement encode/decode for KMIP message types
- **Existing crate**: Check for `kmip` or `kmip-ttlv` crates on crates.io (ecosystem is limited)

### Step 2: Core operations to support
Map KMIP operations to existing HsmCore methods:
| KMIP Operation | HsmCore Equivalent |
|---|---|
| Create | `create_object()` |
| CreateKeyPair | `generate_key_pair()` |
| Get | `get_object()` |
| Destroy | `destroy_object()` |
| Encrypt | `encrypt_init()` + `encrypt()` |
| Decrypt | `decrypt_init()` + `decrypt()` |
| Sign | `sign_init()` + `sign()` |
| MAC | `sign_init()` + `sign()` (HMAC) |
| Activate / Revoke | `KeyLifecycleState` transitions |

### Step 3: Create KMIP server
- New workspace crate: `craton_hsm-kmip/`
- TLS listener on port 5696 (KMIP default)
- TTLV message parsing → HsmCore operation → TTLV response
- Authentication: client certificate (mTLS)

### Step 4: Configuration
Add to `craton_hsm.toml`:
```toml
[kmip]
enabled = true
listen = "0.0.0.0:5696"
tls_cert = "certs/kmip-server.pem"
tls_key = "certs/kmip-server-key.pem"
client_ca = "certs/client-ca.pem"
```

### Step 5: Testing
- Use `pykmip` (Python KMIP client) for interop testing
- Use `kmip-go` for Go client testing
- Create integration test scripts similar to `tests/interop/`

### Step 6: Compliance
KMIP has conformance profiles. Target:
- **Baseline Server** profile (minimum operations)
- **Symmetric Key Lifecycle Server** profile
- **Asymmetric Key Lifecycle Server** profile

---

## Priority Order

| Priority | Item | Blocked By | Effort |
|---|---|---|---|
| 1 | Stable PQC crates | Upstream releases | Low (version bumps) |
| 2 | Unified rand_core | Upstream releases | Low-Medium |
| 3 | KMIP support | Design + implementation | High (new protocol) |
| 4 | HSM clustering | Design + implementation | Very High |
| 5 | FIPS 140-3 cert | Lab engagement + budget | External process |
