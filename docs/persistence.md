# Persistent Storage

By default, Craton HSM operates entirely in memory. All token objects (keys, certificates, data) are lost when the process exits. This matches the behavior of most software HSM prototypes and keeps the out-of-box experience simple, but it makes the module unsuitable for production use without enabling persistence.

Persistence is opt-in: set `persist_objects = true` in `craton_hsm.toml`. This single flag enables **full persistence** — both the token's initialization state (SO/User PIN hashes, label, and the `initialized` / `user PIN initialized` flags) and objects tagged `CKA_TOKEN=true` survive restarts. With the default `persist_objects = false`, the token is entirely in memory: it re-appears uninitialized on restart and no objects are saved. (Lockout counters always persist, independently of this flag, so brute-force counters cannot be reset by crashing the process.)

> **FIPS builds cannot use this feature.** Compiling with `--features fips` (which `--all-features` silently includes) makes `HsmConfig::load()` skip `craton_hsm.toml` entirely and use hardcoded secure defaults — `persist_objects` is always `false`, `storage_path` is always a default path, and nothing in the file is honored. This is by design: FIPS builds must not read attacker-controlled config from disk. A `tracing::warn!` fires at `C_Initialize` when this happens (visible on stderr — the library installs a default WARN-level subscriber for consumers, like `pkcs11-tool`, that don't register their own). If you need persistence, build **without** the `fips` feature.

## How It Works

### Object encryption — wrapped master key

The persistent store is backed by [redb](https://github.com/cberner/redb), an embedded key-value database written in Rust. Objects are never stored in plaintext: each one is individually encrypted with **AES-256-GCM**.

Objects are encrypted under a random 32-byte **object master key (OMK)**, not directly under the PIN. The OMK is generated once when the user PIN is first set (`C_InitPIN`) and is itself stored **wrapped** (AES-256-GCM) by a key-encryption key (KEK) derived from the user PIN via **PBKDF2-HMAC-SHA256**. The KEK uses the configured `[security] pbkdf2_iterations` work factor (default 600,000) and a stable per-token salt. This indirection means a PIN change only re-wraps the small OMK blob — stored objects never need to be re-encrypted, and a `C_SetPIN` is therefore atomic and crash-safe.

```
user PIN                                   object master key (OMK, random 32 bytes)
    │                                          │  (generated once at C_InitPIN)
    ▼                                          │
PBKDF2-HMAC-SHA256                             ├──▶ AES-256-GCM encrypt(object)
(pbkdf2_iterations, stable per-token salt)     │         → nonce || ciphertext ──▶ redb
    │                                          │
    ▼                                          └──▶ OMK held in memory (Zeroizing<[u8;32]>),
key-encryption key (KEK) ──┐                          cleared on logout
    │                      │
    │   unwrap(KEK, wrapped_OMK) ──▶ OMK  (at login)
    │
    └── wrap(KEK, OMK) ──▶ wrapped_OMK  (stored in token_state, re-wrapped on C_SetPIN)
```

The on-disk format for each object is `nonce (12 bytes) || ciphertext`. The nonce is generated fresh per write via the SP 800-90A HMAC_DRBG with prediction resistance, so two writes of the same plaintext produce different ciphertexts. Object handles in the store are random 16-byte hex strings (not sequential integers), which prevents enumeration of stored objects by guessing the store key.

### Token initialization state

When `persist_objects = true`, each token's initialization state is written to `token_state_<slot>.json` in the `storage_path` directory, with the same owner-only permissions and atomic write (temp file + rename) as the lockout file. It holds the PBKDF2 SO/User PIN hashes (`salt || derived_key`), the 32-byte label, the init flags, the stable KEK salt, and the wrapped OMK. The PIN hashes are not plaintext secrets but are an offline brute-force target, which is why the file is locked down to owner-only (mode 0600 / owner-only DACL) and a failure to apply those permissions is fatal. On startup the token restores this state; a missing or corrupt file is treated as "uninitialized".

## What Gets Persisted

| State | Persisted when `persist_objects = true`? |
|-------|------------------------------------------|
| Token objects (`CKA_TOKEN = CK_TRUE`) | Yes, on `C_CreateObject` / key generation / import |
| Session objects (`CKA_TOKEN = CK_FALSE`) | Never |
| Token init state (SO/User PIN hashes, label, init flags) | Yes, on `C_InitToken` / `C_InitPIN` / `C_SetPIN` |
| Lockout counters | Always (independent of `persist_objects`) |

`C_InitToken` destroys all persisted objects, rotates the object master key (making any residual on-disk ciphertext cryptographically inaccessible), and resets the token state to "initialized with a new SO PIN" (equivalent to factory reset). `C_InitToken` on an already-initialized token requires the current SO PIN; it resets user data but does not change the SO PIN.

## Enabling Persistence

Add the following to `craton_hsm.toml`:

```toml
[token]
persist_objects = true
storage_path = "/var/lib/craton-hsm/store"   # Unix example
# storage_path = "C:\\ProgramData\\craton-hsm\\store"  # Windows example
```

The `storage_path` directory must exist before the HSM starts. Create it once during deployment:

```bash
# Unix
sudo mkdir -p /var/lib/craton-hsm
sudo chown hsm-service:hsm-service /var/lib/craton-hsm
sudo chmod 750 /var/lib/craton-hsm
```

```powershell
# Windows (as Administrator)
New-Item -ItemType Directory -Force "C:\ProgramData\craton-hsm"
icacls "C:\ProgramData\craton-hsm" /inheritance:r /grant:r "NETWORK SERVICE:(OI)(CI)F"
```

`storage_path` is a **directory**. On first run the HSM creates the following files inside it, each with restrictive permissions (0600 on Unix, owner-only DACL on Windows):

| File | Contents |
|------|----------|
| `objects.redb` | the encrypted object database (redb) |
| `objects.redb.lock` | exclusive process lock (see [File Locking](#file-locking)) |
| `token_state_<slot>.json` | per-slot token init state (PIN hashes, label, flags, wrapped OMK) |
| `lockout_state.json` | failed-login counters and lockout flags |

Failure to set restrictive permissions on any of these is fatal — the module refuses to start rather than leave HSM state world-readable.

### Default Storage Paths

If `storage_path` is not configured explicitly, the default is:

| Platform | Default path |
|----------|-------------|
| Unix | `/var/lib/craton-hsm/store` (when parent directory exists) |
| Windows | `%PROGRAMDATA%\craton-hsm\store` (when parent directory exists) |
| Fallback (either) | `craton_hsm_store` (CWD-relative, with a startup warning) |

The CWD-relative fallback is a privesc foothold in multi-user environments. Always configure an explicit absolute path for production deployments.

### Path Validation Rules

`storage_path` is validated at startup. The following are rejected:

- `..` traversal components (e.g. `../../etc`)
- UNC paths (`\\server\share` or `//server/share`)
- Null bytes anywhere in the path
- Any path component that is a symlink
- Relative paths whose first component names a sensitive directory (`.git`, `.ssh`, `.gnupg`, `.aws`, `.config`, `.env`)

## File Locking

An exclusive file lock is held on `<storage_path>/objects.redb.lock` for the lifetime of the process. A second process attempting to open the same database will fail at `C_Initialize` with `CKR_GENERAL_ERROR`. This prevents two HSM instances from corrupting the store concurrently.

The lock file is intentionally left on disk after the process exits — deleting it after releasing the lock would create a TOCTOU race. It is reused on next startup.

## PBKDF2 Work Factor

A single `[security] pbkdf2_iterations` knob governs both PIN-hash storage and the object KEK derivation:

```toml
[security]
pbkdf2_iterations = 600000   # applies to PIN hashes and the object KEK
```

| Setting | Release default | Minimum (release) | Maximum |
|---------|----------------|-------------------|---------|
| `pbkdf2_iterations` | 600,000 | 100,000 | 10,000,000 |

Higher iteration counts increase resistance to offline brute-force attacks at the cost of slower login. The 600,000 default meets OWASP 2023 guidance for PBKDF2-HMAC-SHA256. In debug builds the default drops to 1 iteration for fast tests — never run a debug build in production.

## Backup and Restore

The `src/store/backup.rs` module provides encrypted export of token objects, independent of the redb store. A backup is a self-contained binary blob with the format:

```
[4 bytes]  magic "RHBK"
[4 bytes]  version (1) as u32 LE
[32 bytes] PBKDF2 salt
[12 bytes] AES-GCM nonce
[N bytes]  AES-256-GCM ciphertext of JSON payload
```

The JSON payload is encrypted with a key derived from a backup passphrase via PBKDF2-HMAC-SHA256. The passphrase must be at least 16 characters and meet one of two complexity policies:

- **Policy A**: at least 3 of 4 character classes (lowercase, uppercase, digit, symbol) with ≥ 6 unique characters
- **Policy B**: at least 24 characters with ≥ 12 unique characters (covers Diceware passphrases)

Backup files include the token serial number. Restoring to a different token is rejected by default (cross-token restore protection). Each backup has a unique ID; attempting to restore the same backup twice is rejected as a replay attack. Backups older than 30 days are rejected unless age checking is explicitly disabled.

The `PersistentReplayGuard` struct tracks consumed backup IDs across restarts using an append-only file, preventing replay attacks even after process restart.

## Security Properties

| Property | Implementation |
|----------|---------------|
| Confidentiality | AES-256-GCM per object under a random object master key (OMK) |
| Integrity | AES-GCM authentication tag (128-bit) |
| Key wrapping | OMK wrapped (AES-256-GCM) by a PIN-derived KEK; re-wrapped (not re-encrypted) on `C_SetPIN` |
| Key derivation | PBKDF2-HMAC-SHA256, 1,000,000 iterations, stable per-token salt |
| Nonce freshness | HMAC_DRBG (SP 800-90A) with prediction resistance |
| Handle privacy | Random 16-byte hex store keys (no sequential enumeration) |
| File isolation | Exclusive file lock; 0600 / owner-only ACL on DB, lock, and `token_state` files |
| PIN-hash storage | PBKDF2 `salt \|\| derived_key`; owner-only `token_state_<slot>.json` |
| Key zeroization | `Zeroizing<[u8;32]>` cleared on logout and on drop; OMK rotated on `C_InitToken` |
| Backup replay | Per-backup UUID tracked in a persistent replay guard |

Objects are encrypted under a random object master key (OMK), which is itself wrapped by the PIN-derived KEK. Because the OMK is stable, **changing the user PIN only re-wraps the OMK** — existing object ciphertext is never re-encrypted, so `C_SetPIN` is a single small atomic write rather than a bulk re-encryption pass. `C_InitToken` rotates the OMK, which logically zeroizes all prior ciphertext.

## Limitations

- **Single process only**: the exclusive file lock prevents concurrent access. For multi-process deployments, use the gRPC daemon (`craton-hsm-daemon`) as a single owner of the store.
- **Single object master key**: all objects share one OMK (wrapped by the PIN-derived KEK). If you need per-object or per-user key isolation, wrap objects with application-layer KEKs via PKCS#11 `C_WrapKey` / `C_UnwrapKey`.
- **Token-state persistence is coupled to object persistence**: both are enabled together by `persist_objects = true`. There is currently no way to persist token init state while keeping objects in memory.
- **No online backup streaming**: backup is a point-in-time snapshot. Objects created after the backup started will not appear in it.
- **No clustering or replication**: the store is local to one host. For HA, use the gRPC daemon behind a load balancer with a shared filesystem — but note that concurrent access from two daemon processes to the same redb file is still blocked by the file lock.

## Troubleshooting

**`C_Initialize` fails with `CKR_GENERAL_ERROR` and log shows "locked by another process"**

Another process has the store open. Stop it, or point this instance at a different `storage_path`.

**Objects do not survive restart**

Check that `persist_objects = true` is set in `craton_hsm.toml` and that the PKCS#11 application creates objects with `CKA_TOKEN=CK_TRUE`. Session objects (`CKA_TOKEN=CK_FALSE`) are never persisted regardless of configuration.

**Token re-appears uninitialized after restart (must re-run `C_InitToken` / `C_InitPIN`)**

This is expected with the default `persist_objects = false` — token init state lives only in memory. Set `persist_objects = true` to persist the SO/User PIN hashes, label, and init flags across restarts. Token-state persistence and object persistence are enabled together by this one flag.

**`CKR_PIN_INCORRECT` from `C_InitToken` on a token you believe is fresh**

A `token_state_<slot>.json` from a previous run is present in `storage_path` and reports the token as already initialized, so `C_InitToken` is verifying the *existing* SO PIN. Supply the original SO PIN, or remove the `storage_path` directory to factory-reset (this also destroys all persisted objects).

**`C_Initialize` fails: "Failed to set restrictive permissions"**

The HSM refuses to run if it cannot set 0600 / owner-only ACL on the database file. This can happen on network filesystems (NFS, SMB), some container overlays, or when running as a user who does not own the path. Use a local filesystem or configure an explicit `storage_path` on a local volume.

**Startup warning: "falling back to relative 'craton_hsm_store'"**

The system storage directory does not exist. Either provision it (see [Enabling Persistence](#enabling-persistence)) or set `storage_path` explicitly to an absolute path.

## See Also

- [Configuration Reference](configuration-reference.md) — all `craton_hsm.toml` fields
- [Security Model](security-model.md) — threat model and key protection
- [Operator Runbook](operator-runbook.md) — day-to-day operations including backup procedures
- [Fork Safety](fork-safety.md) — multi-process constraints and the gRPC daemon pattern
- [Troubleshooting](troubleshooting.md) — common errors and diagnostic steps
