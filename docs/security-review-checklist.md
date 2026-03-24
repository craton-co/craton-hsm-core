# Security Review Checklist

Pre-audit self-assessment for Craton HSM. Work through this checklist before engaging a third-party auditor — auditors charge by time, so the cleaner the codebase, the more value you get.

---

## Automated Tooling

### Required (run in CI)

| Tool | Purpose | CI Job | Command |
|------|---------|--------|---------|
| `cargo audit` | CVE database check for dependencies | `security-audit` | `cargo audit` |
| `cargo deny` | License compliance + advisory check | `security-audit` | `cargo deny check advisories licenses` |
| `cargo clippy -- -D warnings` | Logic and style issues | `lint` | `cargo clippy -- -D warnings` |
| `cargo fmt --check` | Formatting consistency | `lint` | `cargo fmt --check` |
| Miri | Undefined behavior detection | `miri` | `cargo +nightly miri test --lib` |

### Recommended (run locally before audits)

| Tool | Purpose | Command |
|------|---------|---------|
| `cargo fuzz` | Coverage-guided fuzzing (5 targets) | `cargo fuzz run <target> -- -max_total_time=3600` |
| AddressSanitizer | Memory safety in unsafe blocks | `RUSTFLAGS="-Z sanitizer=address" cargo +nightly test` |
| MemorySanitizer | Uninitialized memory detection | `RUSTFLAGS="-Z sanitizer=memory" cargo +nightly test` |
| `cargo deny check bans` | Duplicate dependency detection | `cargo deny check bans` |
| `cargo geiger` | Count unsafe blocks | `cargo geiger` |

### Sanitizer Usage

```bash
# AddressSanitizer — catches use-after-free, buffer overflow in unsafe blocks
RUSTFLAGS="-Z sanitizer=address" cargo +nightly test --lib -- --test-threads=1

# MemorySanitizer — catches uninitialized memory reads
RUSTFLAGS="-Z sanitizer=memory" cargo +nightly test --lib -- --test-threads=1

# ThreadSanitizer — catches data races (useful for DashMap interactions)
RUSTFLAGS="-Z sanitizer=thread" cargo +nightly test --lib -- --test-threads=1
```

**Note:** Sanitizers require nightly Rust and Linux. They catch issues that Miri may miss (and vice versa). Run both before an audit.

---

## Fuzz Targets (5 targets)

| Target | Focus | Duration |
|--------|-------|----------|
| `fuzz_c_abi` | C ABI entry points (CreateObject, FindObjects, Digest, Random) | 1 hour minimum |
| `fuzz_crypto_ops` | Encrypt/decrypt roundtrips, digest, sign failure paths | 1 hour minimum |
| `fuzz_attributes` | Template creation, attribute reading, template matching | 1 hour minimum |
| `fuzz_session_lifecycle` | State machine edge cases, login/logout, operation sequencing | 2 hours minimum |
| `fuzz_buffer_overflow` | Integer overflow, buffer sizes, two-call pattern, null pointers | 2 hours minimum |

**Priority order for fuzzing:**
1. `fuzz_buffer_overflow` — historically where PKCS#11 implementations break
2. `fuzz_session_lifecycle` — state confusion bugs are the second most common class
3. `fuzz_c_abi` — general ABI boundary robustness
4. `fuzz_attributes` — template parsing edge cases
5. `fuzz_crypto_ops` — crypto failure path robustness

```bash
# Run all targets (1 hour each)
for target in fuzz_buffer_overflow fuzz_session_lifecycle fuzz_c_abi fuzz_attributes fuzz_crypto_ops; do
    cargo fuzz run $target -- -max_total_time=3600
done
```

---

## Manual Review Priorities

These are the areas where bugs actually hide in HSM implementations. Listed in order of severity.

### 1. Session State Machine Edge Cases

**What to check:**
- What happens if `C_Sign` is called after `C_SignFinal`?
- What happens if `C_DigestInit` is called twice without completing?
- What if `C_EncryptInit` fails — is the session state clean for the next operation?
- Do concurrent sessions share any state they shouldn't?
- Is `C_CloseAllSessions` atomic with respect to ongoing operations?

**Where to look:**
- `src/session/session.rs` — `Session` struct and state transitions
- `src/session/manager.rs` — `SessionManager` (DashMap-based)
- `src/pkcs11_abi/functions.rs` — every `*Init` / `*Update` / `*Final` pair

**Known mitigations:**
- 5-state session FSM (Public R/O, Public R/W, User R/O, User R/W, SO R/W)
- Active operation state tracked per-session
- `catch_unwind` on every ABI function prevents panic propagation

### 2. Attribute Template Parsing

**What to check:**
- Malformed attributes: wrong `value_len`, null `p_value` with non-zero length
- Contradictory attributes: `CKA_SENSITIVE=true` + `CKA_EXTRACTABLE=true`
- Missing required attributes: `CKA_CLASS` omitted
- Extra attributes: unknown `CK_ATTRIBUTE_TYPE` values
- Date attributes: non-8-byte values, invalid date formats

**Where to look:**
- `src/store/attributes.rs` — `apply_attribute()`, `create_object()`
- `src/store/object.rs` — `matches_template()`, `check_lifecycle()`
- `src/pkcs11_abi/functions.rs` — `parse_template()` helper

**Known mitigations:**
- `CKA_CLASS` required (returns `CKR_TEMPLATE_INCOMPLETE`)
- Unknown attributes stored in `extra_attributes: HashMap`
- Boolean attributes read from `value[0] != 0` (single byte)
- CK_ULONG read via `read_ck_ulong()` helper with size check

### 3. Error Path Zeroization

**What to check:**
- If a panic is caught by `catch_unwind` before `ZeroizeOnDrop` runs, is key material leaked?
- Do all `Result::Err` paths in crypto functions zeroize intermediate key material?
- Is `RawKeyMaterial::drop()` actually called on all error paths?
- Does `ObjectStore::destroy_object()` zeroize before removing?
- Are RSA DER private key bytes passed by ownership (not cloned) to `RawKeyMaterial`?

**Where to look:**
- `src/store/object.rs` — `RawKeyMaterial` impl (Zeroize, custom Drop, mlock)
- `src/crypto/keygen.rs` — key generation error paths, DER bytes ownership transfer
- `src/crypto/encrypt.rs` — encryption/decryption error paths
- `src/pkcs11_abi/functions.rs` — `catch_unwind` blocks

**Known mitigations:**
- `RawKeyMaterial` implements `ZeroizeOnDrop` (automatic on drop)
- `mlock()` / `VirtualLock()` prevents key material from being swapped to disk
- Custom `Debug` impl shows `[REDACTED]`
- `catch_unwind` ensures panics don't bypass destructors (Rust destructors run during unwinding)
- RSA DER bytes moved directly into `RawKeyMaterial` (no `.clone()` creating unzeroized copy) — fixed in v0.9.1

### 4. DRBG Reseeding Logic & Key Generation Routing

**What to check:**
- Is the DRBG reseeded after every `generate()` call when prediction resistance is requested?
- Does the continuous health test actually detect stuck/repeated output?
- Is the DRBG state zeroized on reseed?
- What happens if `OsRng` fails during reseeding?
- Do ALL key generation functions (RSA, EC P-256, EC P-384, Ed25519, AES) use DRBG?
- Is `OsRng` used directly anywhere for key material? (It should not be.)

**Where to look:**
- `src/crypto/drbg.rs` — `HmacDrbg` implementation
- `src/crypto/keygen.rs` — `DrbgRng` wrapper, all key generation functions
- `src/crypto/self_test.rs` — DRBG KAT and continuous test

**Known mitigations:**
- HMAC_DRBG (NIST SP 800-90A) with HMAC-SHA256
- `DrbgRng` wrapper implements `rand::RngCore + rand::CryptoRng`, routing through DRBG — fixed in v0.9.1 (previously RSA/EC/Ed25519 used `OsRng` directly)
- Prediction resistance mode forces reseed from OsRng on every call
- Continuous health test compares consecutive outputs (SP 800-90B §4.3)
- DRBG state (K, V) implements `ZeroizeOnDrop`

### 5. PIN Lockout Bypass

**What to check:**
- Timing attacks: does a wrong PIN take the same time as a correct PIN?
- Concurrent login attempts: can parallel logins bypass the lockout counter?
- State after token reinitialization: is the lockout counter reset?
- Can the SO login reset the user lockout?

**Where to look:**
- `src/token/token.rs` — `verify_pin()`, lockout counter
- `src/pkcs11_abi/functions.rs` — `C_Login`, `C_InitToken`

**Known mitigations:**
- `subtle::ConstantTimeEq` for PIN comparison (via PBKDF2 hash comparison)
- Configurable lockout threshold (default: 10 attempts)
- `C_InitPIN` (SO-only) resets user lockout
- PBKDF2-HMAC-SHA256 with 600K iterations (expensive to brute-force)

### 6. Integer Overflow in Length Fields

**What to check:**
- `CK_ULONG` is 32-bit on Windows MSVC, 64-bit on Linux/macOS — are all casts safe?
- `as usize` casts from `CK_ULONG` — what if the value exceeds `usize::MAX`?
- `value_len` in `CK_ATTRIBUTE` — does the code trust caller-provided lengths?
- Buffer size calculations: `count * size_of::<T>()` — can this overflow?

**Where to look:**
- `src/pkcs11_abi/functions.rs` — every `as usize` cast, every `slice::from_raw_parts`
- `src/pkcs11_abi/types.rs` — type aliases (`CK_ULONG = c_ulong`)

**Known mitigations:**
- All `slice::from_raw_parts` calls use validated lengths
- Two-call pattern returns required size first, validates on second call
- `parse_template()` bounds-checks each attribute's `value_len`

---

## Audit Scope Recommendation

For a third-party audit, prioritize these files (ordered by risk):

| Priority | File | Lines | Risk Level |
|----------|------|-------|------------|
| 1 | `src/pkcs11_abi/functions.rs` | ~4000 | **Critical** — 43 unsafe blocks, all FFI |
| 2 | `src/store/attributes.rs` | ~444 | **High** — template parsing, access control |
| 3 | `src/store/object.rs` | ~408 | **High** — key material handling, lifecycle |
| 4 | `src/crypto/encrypt.rs` | ~250 | **Medium** — encryption/decryption paths |
| 5 | `src/crypto/sign.rs` | ~200 | **Medium** — signature operations |
| 6 | `src/crypto/keygen.rs` | ~200 | **Medium** — key generation |
| 7 | `src/token/token.rs` | ~200 | **Medium** — PIN management, auth state |
| 8 | `src/session/session.rs` | ~150 | **Medium** — session state machine |
| 9 | `src/crypto/drbg.rs` | ~150 | **Medium** — DRBG implementation |
| 10 | `src/store/encrypted_store.rs` | ~200 | **Medium** — persistent storage encryption |

Total critical code: ~6,000 lines (manageable for a focused audit).

---

## Pre-Audit Preparation Checklist

- [ ] Run `cargo audit` — zero known vulnerabilities
- [ ] Run `cargo deny check` — all licenses approved, no advisories
- [ ] Run `cargo clippy -- -D warnings` — zero warnings
- [ ] Run `cargo +nightly miri test --lib` — no undefined behavior detected
- [ ] Fuzz all 5 targets for ≥1 hour each — no crashes
- [ ] Run sanitizers (ASan, MSan) on test suite — no violations
- [ ] Review all 43 `unsafe` blocks in `functions.rs` manually
- [ ] Verify `RawKeyMaterial::drop()` is called on all error paths
- [ ] Verify constant-time PIN comparison under timing analysis
- [ ] Document any known limitations or deviations from PKCS#11 spec
- [ ] Run PKCS#11 conformance tests: `cargo test --release --test pkcs11_conformance -- --test-threads=1`
- [ ] Verify all key generation uses `DrbgRng` (not `OsRng` directly)
- [ ] Verify AES-CBC/CTR KATs use hardcoded expected values (not circular roundtrips)
- [ ] Verify per-key AES-GCM nonce counters are in use (not global counter)
