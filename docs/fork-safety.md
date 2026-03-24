# Fork Safety & Multi-Process Constraints

## Overview

Craton HSM is a **single-process, multi-threaded** PKCS#11 module. This document describes the constraints and protections related to fork(2) and multi-process access.

## Fork Detection (Unix)

### Problem

On Unix systems, `fork(2)` duplicates the process address space. A child process inherits the parent's memory, including the initialized `parking_lot::Mutex<Option<Arc<HsmCore>>>`. However, the child has:

- **Stale locks**: `DashMap` shard locks, `Mutex`, and `RwLock` are in undefined state after fork
- **Stale file descriptors**: Any open database or log files are shared with the parent
- **Stale RNG state**: The RNG may produce identical output in parent and child
- **Stale audit chain**: Two processes appending to the same audit log corrupt the hash chain

### Mitigation

Craton HSM records the process ID during `C_Initialize`. On every subsequent PKCS#11 call, the current PID is compared against the stored PID. If they differ (fork detected), the call returns `CKR_CRYPTOKI_NOT_INITIALIZED`.

```
Parent process:
  C_Initialize → stores PID 1234 → CKR_OK
  C_OpenSession → PID check passes → CKR_OK
  fork()
    │
    ├── Parent (PID 1234):
    │     C_Sign → PID 1234 == 1234 → proceeds normally
    │
    └── Child (PID 5678):
          C_Sign → PID 5678 != 1234 → CKR_CRYPTOKI_NOT_INITIALIZED
          C_Initialize → re-initializes, stores PID 5678 → CKR_OK
          C_OpenSession → PID check passes → CKR_OK
```

The child process **must** call `C_Initialize` to create a fresh `HsmCore` with clean state. This is the same behavior as OpenSC's PKCS#11 module and is recommended by the PKCS#11 specification's guidance on library initialization.

### Windows

On Windows, `fork(2)` does not exist. Process creation via `CreateProcess` starts a new address space, so each process loads and initializes `libcraton_hsm.dll` independently. The PID check uses `GetCurrentProcessId()` and provides defense-in-depth.

## Multi-Process Database Access

### Problem

Two processes loading `libcraton_hsm.so`/`.dll` and pointing at the same `storage_path` could corrupt the persistent database (redb). Both would open the same files, and concurrent writes without coordination lead to data loss.

### Mitigation

When persistence is enabled (`persist_objects = true`), the `EncryptedStore` acquires an exclusive file lock (`fs2::FileExt::try_lock_exclusive()`) during initialization. If a second process attempts to open the same database, it receives a clear error at `C_Initialize` time:

```
Process A:
  C_Initialize → opens DB, acquires file lock → CKR_OK

Process B:
  C_Initialize → tries to lock same DB → file lock fails
  → returns CKR_GENERAL_ERROR with logged message:
    "Database at <path> is locked by another process"
```

### Recommended Deployment Patterns

| Scenario | Approach |
|----------|----------|
| Single application | Direct `dlopen` / `LoadLibrary` — simplest, best performance |
| Multiple applications, same machine | Run `craton-hsm-daemon` (gRPC), all apps connect as clients |
| Container/Kubernetes | Sidecar pattern: one `craton-hsm-daemon` container per pod |
| Multiple machines | One `craton-hsm-daemon` per machine; consider external secret manager for cross-machine |

## gRPC Daemon (Multi-Process Access)

For multi-process access to the same token, use `craton-hsm-daemon`:

```
┌──────────┐  ┌──────────┐  ┌──────────┐
│  App A   │  │  App B   │  │  App C   │
│  (gRPC)  │  │  (gRPC)  │  │  (gRPC)  │
└────┬─────┘  └────┬─────┘  └────┬─────┘
     │              │              │
     └──────────────┼──────────────┘
                    │ TLS (mutual auth)
                    ▼
          ┌────────────────────┐
          │   craton-hsm-daemon   │
          │                    │
          │   HsmCore (single) │
          │   File lock held   │
          │   Audit log        │
          └────────────────────┘
```

The daemon serializes all operations through a single `HsmCore` instance, ensuring:
- No concurrent database corruption
- Atomic session state transitions
- Single audit log with unbroken hash chain
- Proper RNG state (no fork-induced duplication)

## Summary of Invariants

1. **Fork detection**: Child processes after `fork()` receive `CKR_CRYPTOKI_NOT_INITIALIZED` and must re-initialize
2. **File locking**: Only one process can open a persistent database at a time
3. **gRPC for multi-process**: Multiple applications must use `craton-hsm-daemon` for shared access
4. **No shared memory**: Each process loading the library gets isolated token state
5. **Re-initialization required**: After fork, child must call `C_Initialize` before any other operation
