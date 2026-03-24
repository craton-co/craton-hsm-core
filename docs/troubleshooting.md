# Troubleshooting

## Common PKCS#11 Error Codes

When a `C_*` function fails, it returns a `CK_RV` error code. Below are the most common ones, their causes, and fixes.

### Initialization Errors

| CK_RV | Constant | Cause | Fix |
|-------|----------|-------|-----|
| 257 | `CKR_CRYPTOKI_NOT_INITIALIZED` | Called a function before `C_Initialize` | Call `C_Initialize(NULL)` first |
| 258 | `CKR_CRYPTOKI_ALREADY_INITIALIZED` | `C_Initialize` called twice | Call `C_Finalize` before re-initializing |
| 5 | `CKR_GENERAL_ERROR` | Power-on self-test (POST) failed | Check binary integrity; the library may be corrupted. Rebuild from source. |

### Session Errors

| CK_RV | Constant | Cause | Fix |
|-------|----------|-------|-----|
| 3 | `CKR_SLOT_ID_INVALID` | Slot ID does not exist | Use `C_GetSlotList` to enumerate valid slot IDs |
| 11 | `CKR_SESSION_HANDLE_INVALID` | Session handle is stale or invalid | Re-open the session with `C_OpenSession` |
| 14 | `CKR_SESSION_COUNT` | Maximum session limit reached | Close unused sessions or increase `max_sessions` in config |
| 15 | `CKR_SESSION_READ_ONLY` | Attempted write operation on R/O session | Open session with `CKF_RW_SESSION` flag |

### Authentication Errors

| CK_RV | Constant | Cause | Fix |
|-------|----------|-------|-----|
| 160 | `CKR_PIN_INCORRECT` | Wrong PIN provided | Verify PIN; note exponential backoff after failed attempts |
| 161 | `CKR_PIN_INVALID` | PIN does not meet complexity requirements | PIN must be 4-256 bytes, >=3 distinct bytes, >=2 character classes |
| 162 | `CKR_PIN_LEN_RANGE` | PIN length outside allowed bounds | Check `min_pin_length` / `max_pin_length` in security config |
| 163 | `CKR_PIN_LOCKED` | Too many failed login attempts | Re-initialize token via `C_InitToken` (SO) or wait for lockout reset |
| 256 | `CKR_USER_NOT_LOGGED_IN` | Private object access without login | Call `C_Login` with the User PIN first |
| 1 | `CKR_FUNCTION_FAILED` | PIN rate-limited | Wait for the backoff period to expire (100ms base, doubles per failure, max 5s) |

### Cryptographic Errors

| CK_RV | Constant | Cause | Fix |
|-------|----------|-------|-----|
| 112 | `CKR_MECHANISM_INVALID` | Unsupported or disabled mechanism | Check `C_GetMechanismList`; verify algorithm policy in config |
| 113 | `CKR_MECHANISM_PARAM_INVALID` | Wrong or missing mechanism parameters | Verify parameter struct (e.g., `CK_RSA_PKCS_PSS_PARAMS`) |
| 98 | `CKR_KEY_HANDLE_INVALID` | Key handle not found | Re-query with `C_FindObjects` |
| 99 | `CKR_KEY_TYPE_INCONSISTENT` | Key type doesn't match mechanism | RSA key for RSA mechanisms, EC key for ECDSA, etc. |
| 101 | `CKR_KEY_FUNCTION_NOT_PERMITTED` | Key lacks permission for this operation | Set `CKA_SIGN`/`CKA_ENCRYPT`/etc. when creating the key |
| 32 | `CKR_DATA_LEN_RANGE` | Input data exceeds maximum (64 MiB) | Reduce data size or use multi-part operations |
| 64 | `CKR_SIGNATURE_INVALID` | Signature verification failed | Check key, data, and mechanism match the signing operation |
| 304 | `CKR_OPERATION_NOT_INITIALIZED` | No active operation for Update/Final | Call the corresponding `*Init` function first |
| 288 | `CKR_OPERATION_ACTIVE` | Called `*Init` while another operation is active | Call `*Final` to complete or abandon the active operation |
| 80 | `CKR_BUFFER_TOO_SMALL` | Output buffer is too small | Call with NULL output buffer first to query required size |

### Key Lifecycle Errors

| CK_RV | Constant | Cause | Fix |
|-------|----------|-------|-----|
| 101 | `CKR_KEY_FUNCTION_NOT_PERMITTED` | Key is deactivated or compromised | Check `CKA_START_DATE` / `CKA_END_DATE`; generate a new key if expired |
| 82 | `CKR_ATTRIBUTE_READ_ONLY` | Attempted to modify a read-only attribute | Only modifiable attributes (CKA_LABEL, CKA_ID, etc.) can be changed |

## Build Issues

### `cargo build` fails with missing `protoc`

```
error: failed to run custom build command for `craton-hsm-daemon`
```

**Fix**: Install Protocol Buffers compiler:
```bash
# Ubuntu/Debian
sudo apt install protobuf-compiler

# macOS
brew install protobuf

# Windows (via chocolatey)
choco install protoc
```

### `cargo test` fails with linker errors on Windows

```
LINK : fatal error LNK1181: cannot open input file 'craton_hsm.lib'
```

**Fix**: Ensure you're building with the MSVC toolchain:
```bash
rustup default stable-x86_64-pc-windows-msvc
```

### `cargo test` fails with `craton_hsm-awslc` not found

```
error: failed to load manifest for dependency `craton_hsm-awslc`
```

**Fix**: The FIPS backend is in a separate private repository. For open-source builds, this dev-dependency is commented out by default. If you need the FIPS backend, clone [craton_hsm-enterprise](https://github.com/craton-co/craton-hsm-core-enterprise) alongside this repo and uncomment the dependency in `Cargo.toml`.

### Tests must run single-threaded

PKCS#11 uses global state (`C_Initialize`/`C_Finalize` affect the entire process). Tests must run with:

```bash
cargo test -- --test-threads=1
```

Multi-threaded test execution will cause intermittent failures due to shared global HSM state.

## Runtime Issues

### POST failure on startup (`CKR_GENERAL_ERROR` from every function)

The Power-On Self-Test (POST) runs during `C_Initialize`. If any self-test fails, the library enters a degraded state where all subsequent `C_*` calls return `CKR_GENERAL_ERROR`.

**Common causes**:
- Binary was modified after build (integrity check failure)
- Corrupted download or incomplete deployment

**Fix**: Rebuild from source or re-download the binary. Verify with SHA-256 checksum.

### Audit log permission denied

```
Failed to open audit log: permission denied
```

**Fix**: The audit log file is restricted to owner-only (0o600 on Unix, owner-only ACL on Windows). Ensure the process user owns the file:

```bash
# Unix
chown $(whoami) craton_hsm_audit.jsonl
chmod 600 craton_hsm_audit.jsonl

# Or let Craton HSM create the file fresh (delete and restart)
```

### Token persistence not working (objects lost on restart)

**Check**:
1. `storage_path` is set in `[token]` config section
2. The path is writable and not a symlink
3. No other process holds an exclusive lock on the `.redb` file

```toml
[token]
storage_path = "craton_hsm_store"
```

### Memory locking warnings

```
WARN: mlock failed: Operation not permitted
```

**Cause**: The process lacks permission to lock memory pages.

**Fix (Linux)**:
```bash
# Option 1: Set capability
sudo setcap cap_ipc_lock=ep /path/to/your_binary

# Option 2: Increase limits
echo "* soft memlock unlimited" | sudo tee -a /etc/security/limits.conf
```

**Fix (Windows)**: Grant the "Lock pages in memory" user right via Local Security Policy (`secpol.msc` > Local Policies > User Rights Assignment).

This is a non-fatal warning. The HSM continues to operate but key material may be paged to swap.

### Fork detection errors (Unix)

After `fork()`, the child process detects a PID mismatch and returns `CKR_CRYPTOKI_NOT_INITIALIZED`.

**Fix**: Call `C_Initialize` in the child process after fork. See [Fork Safety](fork-safety.md) for details and deployment patterns.

### Database lock contention

```
error: Failed to acquire exclusive lock on store file
```

**Cause**: Another process already has the store file open.

**Fix**: Only one process can access a persistent store at a time. Use the gRPC daemon (`craton-hsm-daemon`) for multi-process access. See [Fork Safety](fork-safety.md) for deployment patterns.

## Configuration Issues

### Config file rejected: permission too broad

```
Configuration error: file has group/world-writable permissions
```

**Fix (Unix)**:
```bash
chmod 600 craton_hsm.toml
```

**Fix (Windows)**: Remove Everyone and Users group write permissions via file properties or:
```cmd
icacls craton_hsm.toml /inheritance:r /grant:r "%USERNAME%:F"
```

### Config file rejected: path traversal

```
Configuration error: path contains '..' component
```

**Fix**: Use relative paths without `..` traversal. Absolute paths and UNC paths (`\\server\share`) are also rejected. Symlinks in the path are rejected.

### PBKDF2 iterations out of range

```
Configuration error: pbkdf2_iterations (50000) is below the minimum of 100000
```

**Fix**: Set `pbkdf2_iterations` to at least 100,000 (recommended: 600,000). Maximum: 10,000,000.

## Getting Help

- [GitHub Issues](https://github.com/craton-co/craton-hsm-core/issues) — bug reports and feature requests
- [Security Advisories](https://github.com/craton-co/craton-hsm-core/security/advisories/new) — vulnerability reports (private)
- [Configuration Reference](configuration-reference.md) — all config fields and defaults
- [Operator Runbook](operator-runbook.md) — day-to-day operations guide
