# Migration Guide

## Migrating to the current development version

### Audit log format

New audit entries are written with `format_version: 1`, a compact binary payload
encoding for the hash chain. The on-disk NDJSON line format is unchanged, so SIEM
and log-shipping integrations are unaffected.

Existing logs keep verifying: the verifier dispatches on each entry's own
`format_version`, and a file that mixes version 0 and version 1 entries — what an
in-place upgrade produces — verifies end to end.

**Downgrading does not work.** Older builds verify every entry as version 0, so
they will read a version 1 entry, compute the wrong hash, and report the chain as
tampered. Rotate the audit log before downgrading and archive the version 1 file.

### RSA availability

Release builds of the default RustCrypto backend now refuse RSA private-key
operations with `CKR_MECHANISM_INVALID` rather than failing them mid-operation.
Previously an RSA `C_GenerateKeyPair` in a release build put the module into its
error state, disabling every algorithm. If your application uses RSA signing,
decryption, or key generation, build with `--no-default-features --features
awslc-backend`. See
[troubleshooting.md](troubleshooting.md#rsa-operations-return-ckr_mechanism_invalid).

### Library API (Rust consumers only)

`AuditEvent` gained a public `format_version: u32` field. Code that constructs an
`AuditEvent` with a struct literal must add it; set it to
`AUDIT_LOG_FORMAT_VERSION` for new events. PKCS#11 ABI consumers are unaffected.

---

## Migrating from 0.9.0 to 0.9.1

v0.9.1 is a security hardening release. It is fully backward-compatible with v0.9.0 at the PKCS#11 ABI level. No application code changes are required.

### Breaking Changes

None. All PKCS#11 function signatures and behavior are unchanged.

### Security Fixes Applied

These fixes affect internal behavior but are transparent to consumers:

| Fix | Impact | Action Required |
|-----|--------|-----------------|
| DRBG bypass eliminated | All key generation now routes through HMAC_DRBG | None (automatic) |
| Per-key GCM nonce counters | Prevents nonce reuse across AES-GCM operations | None (automatic) |
| AES-CBC/CTR self-tests upgraded | POST now uses genuine KATs with hardcoded expected ciphertexts | None (automatic) |
| RSA PKCS#1 v1.5 KAT added | POST now covers RSA signing | None (automatic) |
| Config path validation hardened | Rejects `..` traversal, UNC paths, symlinks, sensitive directories | Review config file paths |
| PBKDF2 iteration floor raised | Minimum now 100,000 (was unchecked) | Update config if `pbkdf2_iterations < 100000` |

### Configuration Changes

**Potentially breaking** if your config uses values now rejected:

1. **`pbkdf2_iterations`**: Must be >= 100,000. If your config had a lower value, increase it.
2. **`storage_path`**: Paths containing `..`, symlinks, or pointing to sensitive directories (`.git`, `.ssh`, `.aws`, `.gnupg`) are now rejected. Use simple relative paths.
3. **File permissions**: Config files must be owner-readable only (0o600 on Unix; no Everyone/Users write on Windows).

### Recommended Steps

1. Review your `craton_hsm.toml` for paths and iteration counts
2. Rebuild from source: `cargo build --release`
3. Run the test suite: `cargo test -- --test-threads=1`
4. Verify POST passes on startup (check logs for self-test results)

## Migrating to 1.0.0 (Future)

The following changes are planned for the 1.0 release:

### Expected Breaking Changes

1. **PQC crate stabilization**: The `ml-kem`, `ml-dsa`, and `slh-dsa` dependencies will be updated from release candidates to stable versions. This may change PQC key serialization formats. Keys generated with RC versions should be re-generated.

2. **rand_core unification**: The dual `rand_core` 0.6 / 0.10 dependency will be resolved. This is an internal change but may affect custom `CryptoBackend` implementations.

3. **MSRV bump**: The minimum supported Rust version may increase from 1.75 to align with dependency requirements.

### Migration Checklist

- [ ] Export any PQC keys via `C_WrapKey` or backup before upgrading
- [ ] Re-generate PQC keys after upgrading (format may change)
- [ ] Review `CryptoBackend` trait if you have a custom implementation
- [ ] Update Rust toolchain to the new MSRV
- [ ] Run full test suite after upgrade

### Backup Before Upgrading

Always create an encrypted backup before any major version upgrade:

```bash
# Via craton-hsm-admin CLI
craton-hsm-admin backup --pin <SO_PIN> --output backup-pre-1.0.enc

# Restore if needed
craton-hsm-admin restore --pin <SO_PIN> --input backup-pre-1.0.enc
```

See [Operator Runbook](operator-runbook.md) for detailed backup/restore procedures.
