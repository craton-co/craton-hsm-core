# Operator Runbook

This runbook covers day-to-day operations for Craton HSM administrators: token setup, PIN management, key lifecycle, audit, daemon operations, and troubleshooting.

## Token Initialization

### First-time setup

```bash
# 1. Initialize the token with a Security Officer (SO) PIN
craton-hsm-admin token init --label "Production HSM"
# Prompts: Enter SO PIN (4-64 characters, not echoed)
# Prompts: Confirm SO PIN

# 2. Verify initialization
craton-hsm-admin token info
# Output:
#   Token Label:    Production HSM
#   Initialized:    true
#   Login State:    Public
#   Objects:        0
#   Sessions:       0/100

# 3. Machine-readable output
craton-hsm-admin status --json
```

### Re-initialization

Re-initializing a token destroys all stored objects and resets PINs.

```bash
craton-hsm-admin token init --label "Production HSM"
# WARNING: This will destroy all objects in the token.
# Enter SO PIN to confirm.
```

## PIN Management

### PIN requirements

| Property | Default | Config key |
|----------|---------|------------|
| Minimum length | 4 | `security.pin_min_length` |
| Maximum length | 64 | `security.pin_max_length` |
| Lockout threshold | 10 failed attempts | `security.max_failed_logins` |
| Hash algorithm | PBKDF2-HMAC-SHA256 | Not configurable |
| Hash iterations | 600,000 | `security.pbkdf2_iterations` |

### Change SO PIN

```bash
craton-hsm-admin pin change --user-type SO
# Prompts: Current SO PIN
# Prompts: New SO PIN
# Prompts: Confirm new SO PIN
```

### Change User PIN

```bash
craton-hsm-admin pin change --user-type USER
# Prompts: Current User PIN
# Prompts: New User PIN
# Prompts: Confirm new User PIN
```

### Reset a locked User PIN (SO action)

After `max_failed_logins` consecutive failures, the user PIN is locked. Only the SO can unlock it.

```bash
craton-hsm-admin pin reset
# Prompts: SO PIN (authenticates as SO)
# Prompts: New User PIN
# Prompts: Confirm new User PIN
```

### PIN lockout recovery

1. Identify the lockout: application receives `CKR_PIN_LOCKED`
2. SO authenticates: `craton-hsm-admin pin reset`
3. Set a new user PIN
4. Communicate the new PIN to the user through a secure channel

## Key Management

### List all keys

```bash
craton-hsm-admin key list
# Output:
#   Handle  Type    Label               Size
#   ------  ----    -----               ----
#   1       RSA     App Signing Key     2048
#   2       EC      TLS ECDSA Key       256
#   3       AES     Data Encryption     256

craton-hsm-admin key list --json
```

### Import a key

```bash
# RSA private key (PEM or DER)
craton-hsm-admin key import --file private.pem --label "App Signing Key" --type RSA

# EC private key
craton-hsm-admin key import --file ec-key.pem --label "TLS Key" --type EC

# AES symmetric key (raw bytes)
craton-hsm-admin key import --file aes.key --label "Data Encryption" --type AES
```

### Delete a key

```bash
# Interactive confirmation
craton-hsm-admin key delete --handle 42
# Are you sure you want to delete object 42? [y/N]

# Skip confirmation (for automation)
craton-hsm-admin key delete --handle 42 --force
```

### Key lifecycle states (SP 800-57)

Craton HSM supports date-based key lifecycle management per SP 800-57:

| State | When | Permitted Operations |
|-------|------|---------------------|
| **Pre-activation** | Before `CKA_START_DATE` | None |
| **Active** | Between start and end dates | All permitted operations |
| **Deactivated** | After `CKA_END_DATE` | Verify, decrypt, unwrap only |
| **Compromised** | Manually set | None |
| **Destroyed** | After `C_DestroyObject` | Handle invalid |

Set lifecycle dates at key creation:
```bash
# Via C_CreateObject or C_GenerateKey template:
# CKA_START_DATE = "20260301" (YYYYMMDD, 8 ASCII bytes)
# CKA_END_DATE   = "20270301"
```

**Important**: Deactivated keys can still verify signatures and decrypt data (for processing existing protected data), but cannot create new signatures or encrypt new data.

### Key lifecycle best practices

1. **Label keys clearly**: include purpose and creation date
2. **Set expiry dates**: use `CKA_END_DATE` to enforce key rotation schedules
3. **Rotate regularly**: create new key, re-encrypt data, destroy old key
4. **Separate duties**: SO manages PINs; users manage their own keys
5. **Audit key operations**: check audit log for unexpected create/destroy events
6. **Back up before deletion**: export public key before destroying key pair

## Audit Log

### View audit entries

```bash
# Last 100 entries
craton-hsm-admin audit dump --last 100

# JSON output for processing
craton-hsm-admin audit dump --last 50 --json
```

### Audit log structure

Each entry contains:
- **timestamp**: Unix epoch (seconds)
- **session_handle**: which session performed the operation
- **operation**: what was done (Login, GenerateKey, Sign, etc.)
- **key_id**: which key was involved (if applicable)
- **result**: Success or Failure with CK_RV code
- **previous_hash**: SHA-256 of the prior entry (tamper detection)

### Integrity verification

The audit log uses chained SHA-256 hashes. Each entry's `previous_hash` equals `SHA-256(previous_entry)`. A broken chain means the log has been tampered with.

To verify integrity programmatically:
1. Read all entries in order
2. For each entry after the first, compute `SHA-256(entry[n-1])`
3. Compare with `entry[n].previous_hash`
4. Any mismatch indicates tampering

## Daemon Operations

### Start the daemon

```bash
# With config file
craton-hsm-daemon /etc/craton_hsm/craton_hsm.toml

# With default config
craton-hsm-daemon
```

### Configuration (`[daemon]` section)

```toml
[daemon]
bind = "127.0.0.1:5696"     # Listen address
tls_cert = "tls.crt"        # PEM certificate path
tls_key = "tls.key"          # PEM private key path
```

### Health check

```bash
# gRPC health probe (requires grpcurl)
grpcurl -plaintext localhost:5696 craton_hsm.HsmService/GetTokenInfo

# TCP connectivity check
nc -z localhost 5696
```

### TLS setup

```bash
# Generate self-signed certificate (for testing)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout tls.key -out tls.crt -days 365 -nodes \
  -subj "/CN=craton_hsm"

# Reference in config
# [daemon]
# tls_cert = "tls.crt"
# tls_key = "tls.key"
```

### Daemon as systemd service

```ini
# /etc/systemd/system/craton_hsm.service
[Unit]
Description=Craton HSM gRPC Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/craton-hsm-daemon /etc/craton_hsm/craton_hsm.toml
User=craton_hsm
Group=craton_hsm
Restart=on-failure
RestartSec=5

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/craton_hsm
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now craton_hsm
sudo systemctl status craton_hsm
journalctl -u craton_hsm -f
```

## Kubernetes Operations

### Deploy

```bash
helm install my-hsm deploy/helm/craton_hsm/ \
  --set image.repository=registry.example.com/craton_hsm \
  --set image.tag=0.9.1 \
  --set tls.enabled=true \
  --set tls.secretName=craton_hsm-tls
```

### Monitor

```bash
# Logs
kubectl logs -l app=craton_hsm -f

# Status
kubectl get pods -l app=craton_hsm
```

### Upgrade

```bash
helm upgrade my-hsm deploy/helm/craton_hsm/ \
  --set image.tag=0.9.1
```

## Troubleshooting

### FIPS POST failure

**Symptom**: All PKCS#11 calls return `CKR_GENERAL_ERROR` immediately.

**Cause**: One of the 17 power-on self-tests failed during `C_Initialize`. This indicates binary corruption or a broken cryptographic dependency.

**Actions**:
1. Check binary integrity (checksum against known good build)
2. Rebuild from source: `cargo build --release`
3. Run self-test directly: `cargo test --release -- crypto::self_test`
4. If running in Docker, rebuild the image

### PIN locked

**Symptom**: `CKR_PIN_LOCKED` on `C_Login`.

**Action**: Have the SO reset the user PIN:
```bash
craton-hsm-admin pin reset
```

### Session exhaustion

**Symptom**: `CKR_SESSION_COUNT` when opening sessions.

**Actions**:
1. Close unused sessions from the application side
2. Check for session leaks (sessions opened but never closed)
3. Increase `max_sessions` in config

### Token not initialized

**Symptom**: `CKR_TOKEN_NOT_RECOGNIZED` or empty slot info.

**Action**:
```bash
craton-hsm-admin token init --label "My Token"
```

### Daemon: connection refused

**Checklist**:
1. Is the daemon running? `ps aux | grep craton-hsm-daemon`
2. Correct bind address? Check `[daemon].bind` in config
3. Firewall rules? Port 5696 must be open
4. TLS mismatch? Client must use TLS if server has it enabled

### Daemon: TLS handshake failure

**Checklist**:
1. Certificate and key match? Compare modulus hashes
2. Certificate expired? `openssl x509 -in tls.crt -enddate -noout`
3. Client trusts the CA? Add the CA cert to client's trust store

### Object store empty after restart

**Expected behavior** in in-memory mode: state is volatile.

**Solution**: Enable the encrypted persistent store:
```toml
[token]
storage_path = "/var/lib/craton_hsm/store"
```

Or re-import keys after restart.

### Slow RSA key generation

RSA-3072 and RSA-4096 key generation is CPU-intensive (seconds in debug mode, faster in release).

**Mitigation**: Always use `--release` builds in production. Pre-generate keys during maintenance windows if possible.
