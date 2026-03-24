# Craton HSM — Kreya gRPC Manual Tests

## Setup

### 1. Install Kreya

Download from [kreya.app](https://kreya.app/) (Windows, macOS, Linux).

### 2. Open the Project

Open `kreya/Craton HSM-gRPC.krproj` in Kreya. The proto file is imported automatically from `craton-hsm-daemon/proto/craton_hsm.proto`.

### 3. Select Environment

Two environments are provided:

| Environment | Endpoint | Use case |
|-------------|----------|----------|
| **default** | `http://localhost:9898` | Local development |
| **remote** | `http://185.177.116.16:9898` | Remote test server |

Select the environment in the Kreya environment dropdown before running tests.

### 4. Update Variables

After running `02-OpenSession`, copy the `session_handle` from the response and update the `session_handle` variable in the active environment. All subsequent requests reference `{{session_handle}}`.

---

## PIN Reference

| Role | Plaintext | Base64 (in requests) |
|------|-----------|----------------------|
| SO | `SoP1n!Fips#2024` | `U29QMW4hRmlwcyMyMDI0` |
| User | `UsrP1n!Fips#2024` | `VXNyUDFuIUZpcHMjMjAyNA==` |

---

## Tests — Run In Order

### 01-InitToken

Initialize the token with SO PIN and label.

| Field | Value |
|-------|-------|
| Method | `craton_hsm.HsmService/InitToken` |
| Expected | `{}` (empty = success) |

### 02-OpenSession

Open a read-write session on slot 0.

| Field | Value |
|-------|-------|
| Method | `craton_hsm.HsmService/OpenSession` |
| Expected | `{ "sessionHandle": "<number>" }` |

**Copy the `sessionHandle` value and update the `session_handle` environment variable.**

### 03-LoginSO

Log in as Security Officer.

| Field | Value |
|-------|-------|
| Method | `craton_hsm.HsmService/Login` |
| user_type | `0` (SO) |
| Expected | `{}` |

### 04-GetTokenInfo

Query token metadata.

| Field | Value |
|-------|-------|
| Method | `craton_hsm.HsmService/GetTokenInfo` |
| Expected | JSON with `label`, `initialized: true`, `loginState`, `sessionCount` |

### 05-GenerateRandom

Generate 32 random bytes via HMAC_DRBG.

| Field | Value |
|-------|-------|
| Method | `craton_hsm.HsmService/GenerateRandom` |
| length | `32` |
| Expected | `{ "randomData": "<base64>" }` |

### 06-DigestSHA256

SHA-256 digest of "Hello Craton HSM".

| Field | Value |
|-------|-------|
| Method | `craton_hsm.HsmService/Digest` |
| mechanism_type | `592` (`0x250` = CKM_SHA256) |
| data | `SGVsbG8gQ3JhdG9uIEhTTQ==` (base64 of "Hello Craton HSM") |
| Expected | `{ "digest": "<base64 32-byte hash>" }` |

Verify: `echo -n 'Hello Craton HSM' | sha256sum`

### 07-DigestSHA512

SHA-512 digest of "Hello Craton HSM".

| Field | Value |
|-------|-------|
| Method | `craton_hsm.HsmService/Digest` |
| mechanism_type | `608` (`0x260` = CKM_SHA512) |
| Expected | `{ "digest": "<base64 64-byte hash>" }` |

### 08-FindObjects

List all objects (empty on fresh token).

| Field | Value |
|-------|-------|
| Method | `craton_hsm.HsmService/FindObjects` |
| Expected (fresh token) | `{ "objectHandles": [] }` |

### 09-GenerateKey (AES)

Attempt AES key generation.

| Field | Value |
|-------|-------|
| Method | `craton_hsm.HsmService/GenerateKey` |
| mechanism_type | `4224` (`0x1080` = CKM_AES_KEY_GEN) |
| Expected | gRPC error (template requirements) |

### 10-Sign (RSA)

Attempt RSA signing (requires key to exist).

| Field | Value |
|-------|-------|
| Method | `craton_hsm.HsmService/Sign` |
| mechanism_type | `1` (CKM_RSA_PKCS) |
| Expected | gRPC error (no key) |

---

## Error Case Tests

### 11-BadSessionHandle

Use an invalid session handle.

| Field | Value |
|-------|-------|
| Method | `craton_hsm.HsmService/GenerateRandom` |
| session_handle | `999999` |
| Expected | gRPC error (session not found) |

### 12-WrongPIN

Attempt login with incorrect PIN.

| Field | Value |
|-------|-------|
| Method | `craton_hsm.HsmService/Login` |
| pin | `d3JvbmdwaW4=` (base64 of "wrongpin") |
| Expected | gRPC error (PIN invalid) |

After 5 failed attempts, the account enters a cooldown lockout.

### 13-ExceedMaxRandom

Request more random bytes than the limit allows.

| Field | Value |
|-------|-------|
| Method | `craton_hsm.HsmService/GenerateRandom` |
| length | `99999999` |
| Expected | gRPC error (exceeds 1 MiB limit) |

---

## Cleanup

### 14-Logout

| Method | `craton_hsm.HsmService/Logout` |
|--------|-----|
| Expected | `{}` |

### 15-CloseSession

| Method | `craton_hsm.HsmService/CloseSession` |
|--------|-----|
| Expected | `{}` |

### 16-UseClosedSession (should fail)

Attempt to use the closed session handle.

| Method | `craton_hsm.HsmService/GenerateRandom` |
|--------|-----|
| Expected | gRPC error (session not found) |

---

## Project Structure

```
kreya/
  Craton HSM-gRPC.krproj          # Kreya project file (open this)
  directory.krpref              # Default gRPC endpoint config
  default.krenv                 # Local environment (localhost:9898)
  remote.krenv                  # Remote test server environment
  craton_hsm/HsmService/
    01-InitToken/               # Each test is a directory with:
      InitToken.krop            #   - Operation definition (.krop)
      InitToken-request.json    #   - Request payload (.json)
    02-OpenSession/
    03-LoginSO/
    ...
    16-UseClosedSession/
```

## Mechanism Type Reference

| Constant | Hex | Decimal | Algorithm |
|----------|-----|---------|-----------|
| CKM_RSA_PKCS | 0x0001 | 1 | RSA PKCS#1 v1.5 |
| CKM_SHA256 | 0x0250 | 592 | SHA-256 digest |
| CKM_SHA512 | 0x0260 | 608 | SHA-512 digest |
| CKM_AES_KEY_GEN | 0x1080 | 4224 | AES key generation |
| CKM_AES_GCM | 0x1087 | 4231 | AES-GCM encrypt/decrypt |
| CKM_ECDSA | 0x1041 | 4161 | ECDSA sign/verify |
| CKM_EDDSA | 0x1057 | 4183 | EdDSA sign/verify |

See [API Reference](api-reference.md) for the full mechanism list.
