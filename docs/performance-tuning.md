# Performance Tuning and Profiling

This guide covers how to build Craton HSM for speed, how to profile it when it
is not fast enough, and which deployment knobs actually move the numbers. For
*measured* results, see [benchmarks.md](benchmarks.md).

It also records the changes that were **evaluated and rejected**, because in an
HSM several of the obvious optimisations trade away a security property. Those
are called out explicitly so they are not rediscovered and silently applied.

---

## 1. Build configuration

### Release profile

The shipped `[profile.release]` already enables the settings that matter:

| Setting | Value | Why |
|---|---|---|
| `lto` | `true` | Cross-crate inlining, notably into the RustCrypto primitives. |
| `codegen-units` | `1` | Maximises inlining at the cost of build time. |
| `strip` | `"symbols"` | Smaller shipped artifact. Disabled in the profiling profile below. |
| `opt-level` | `3` (cargo default for release) | — |

### CPU-specific instructions

`target-cpu=native` unlocks AES-NI, AVX2, ADX/MULX, and SHA-NI where the host
supports them. It is **not** a default because the resulting binary may fault on
an older CPU:

```bash
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

Measured effect on the reference machine: ML-KEM-768 decapsulation improved 25%
from AVX2 codegen alone. If you distribute one binary across a heterogeneous
fleet, target the oldest microarchitecture you support (e.g.
`-C target-cpu=x86-64-v2`) rather than `native`.

SHA-256 throughput is the single largest environmental variable in this
codebase: it backs the audit chain, the object-store key derivation, and every
`CKM_SHA256_*` mechanism. A CPU with the SHA-NI extension is roughly 5–10x
faster at it than one without. Intel added SHA-NI to mainstream Core parts only
with Ice Lake; AMD has had it since Zen 1. If you are benchmarking on an older
Intel laptop part, expect every SHA-256-bound number to be several times worse
than on a current server.

### Crypto backend

The `awslc-backend` feature swaps RustCrypto for AWS-LC's assembly-optimised
primitives, and is the largest single-flag win available:

```bash
cargo build --release --no-default-features --features awslc-backend
```

Measured speedups (direct Rust API): RSA-2048 verify **8.3x**, ECDSA P-256
verify **4.5x**, RSA-2048 keygen **2.3x**, AES-GCM decrypt 4 KB **1.8x**.

This is also the backend to use for RSA private-key operations. Release builds
of the RustCrypto backend refuse RSA private-key operations by default (see
`src/crypto/sign.rs`) because the `rsa` crate is subject to the Marvin timing
attack, RUSTSEC-2023-0071. That is a deliberate fail-closed default, not a
performance setting — do not enable `insecure-rustcrypto-rsa-private-ops` to
work around it in production.

See [fips-mode-guide.md](fips-mode-guide.md) for the FIPS-validated build.

### Profile-guided optimisation

`scripts/pgo.sh` runs the full three-stage PGO build:

```bash
./scripts/pgo.sh
```

Stage 2 drives the PKCS#11 ABI benchmark suite as the training workload. A PGO
profile only helps for the workload that produced it, so if your deployment has
a different operation mix, supply your own driver:

```bash
CRATON_PGO_WORKLOAD=./my-driver ./scripts/pgo.sh
```

PGO profiles go stale as the code changes. Regenerate whenever hot paths move,
always re-benchmark to confirm the gain is real, and never ship a binary built
from a profile you cannot reproduce.

---

## 2. Profiling

### Build for profiling

`[profile.profiling]` is release codegen with symbols retained. Use it with
frame pointers so sampled stacks resolve:

```bash
RUSTFLAGS="-C force-frame-pointers=yes" cargo build --profile profiling
```

`scripts/profile.sh` does this for you and drives the four profiler modes:

```bash
./scripts/profile.sh cpu   [bench-filter]   # perf record + flame graph
./scripts/profile.sh alloc [bench-filter]   # valgrind DHAT allocation profile
./scripts/profile.sh io    [bench-filter]   # strace syscall + fsync accounting
./scripts/profile.sh lock  [bench-filter]   # mutex / futex contention
```

Outputs land in `target/profiles/`. The `bench-filter` argument narrows the
Criterion workload, e.g. `./scripts/profile.sh cpu pkcs11_rsa_sign`.

The script requires Linux tooling (`perf`, `valgrind`, `strace`). On macOS use
`cargo instruments`; on Windows use Windows Performance Recorder or VTune
against the same `--profile profiling` binary.

### Making measurements reproducible

Small operations here are microseconds, so measurement noise easily exceeds the
effect being measured. Before trusting a comparison:

- **Pin the clock.** Set the CPU governor to `performance` and disable turbo.
  On a laptop, thermal throttling alone can shift results by 2–3x between the
  first and third run — this was observed while producing the numbers in
  `benchmarks.md`, where a measurement taken immediately after a long compile
  read 3x faster than the same measurement on a warm machine.
- **Run the workload more than once** and compare medians, not single runs.
- **Keep tracing off.** Release builds compile out everything above `info`, but
  an `info`-level subscriber attached to a hot path still costs real time.
- **Use the same config.** `persist_objects` and `audit.enabled` each change the
  cost of an operation by orders of magnitude (see below).

### Where the time actually goes

For a fast operation such as AES-GCM or SHA-256, the PKCS#11 ABI overhead —
session lookup, object fetch, audit record — used to dominate the cryptography
itself. The layers, roughly, are:

```
C_Sign
 ├─ thread-local HSM lookup            ~0      (cached; generation-counted)
 ├─ session + object lookup            ~0      (cached in ActiveOperation by C_SignInit)
 ├─ key parse                          ~0      (RSA keys cached by (slot, handle))
 ├─ cryptographic operation                    <- what you want to be measuring
 └─ audit record (async)               ~0.2 us (enqueue only; worker does the work)
```

If a profile shows time somewhere other than the cryptographic operation, that
is the regression.

---

## 3. Deployment tuning

### Storage

Two subsystems `fsync`, and both are latency-bound rather than throughput-bound:

- **The audit trail** (`audit.log_path`), on every batch of audit events.
- **The object store** (`token.storage_path`), on every token-object write,
  when `token.persist_objects = true`.

Put both on NVMe. On a device where `fsync` costs ~1 ms, a single synchronous
audit write costs ~1 ms no matter how fast the cryptography is.

The audit worker performs **group commit**: it coalesces every event already
queued behind the one it is writing into a single `write` + `fsync`. This is a
throughput optimisation, not a durability trade — a `record_sync` caller is
still released only after its event is on stable storage. It raised sustained
audit throughput from roughly 760 to 152,000 events/second on the reference
machine (1319 -> 6.58 us per event). See benchmarks.md for the method.

Do **not** mount the audit or store directory with `nobarrier`, or otherwise
disable write barriers, to make this faster. Doing so makes `fsync` a lie, and
the entire point of the synchronous audit path is that a security-relevant
operation is not acknowledged until its forensic record is durable.

### Separate the two devices

If audit volume is high, put the audit log and the object store on *different*
devices. They contend for the same I/O queue otherwise, and audit writes are
frequent and small while object writes are rare and large.

### CPU

- Governor: `performance`. On-demand scaling adds latency to bursty workloads
  that are otherwise idle between requests — which is the typical HSM pattern.
- Do not oversubscribe cores. Public-key operations are CPU-bound and do not
  benefit from SMT siblings competing for the same execution units.

### Concurrency

The core library is safe for concurrent access from multiple threads: sessions
live in a `DashMap`, objects behind per-object `RwLock`s, and the audit trail
behind a single background worker. Consumers should open one session per thread
rather than serialising through one.

The **daemon** runs on a multi-threaded Tokio runtime, and every RPC handler
wraps its synchronous body in `block_in_place` so that long CPU-bound work does
not occupy a reactor thread. The worst offender is authentication, not
cryptography: `Login`, `InitPIN`, and `SetPIN` each run 600,000 PBKDF2-HMAC-
SHA256 iterations, which is deliberately expensive and takes hundreds of
milliseconds. `GenerateKeyPair` is comparable. Keep
`max_concurrent_connections` bounded: each in-flight blocking request occupies
a thread.

Lowering `security.pbkdf2_iterations` would make logins faster and is the wrong
trade — the iteration count is what makes an offline attack on a captured PIN
hash expensive. Leave it at the default.

The single audit worker thread is the remaining serialisation point. It sustains
tens of thousands of events per second, which is far above what the cryptography
can generate, but it is where to look first if concurrent throughput plateaus.
`pkcs11_concurrent_encrypt` and `pkcs11_concurrent_sign` in the ABI benchmark
suite exist to catch exactly that.

### Configuration knobs with large performance effects

| Setting | Effect |
|---|---|
| `audit.enabled = false` | Removes the audit worker and its `fsync` entirely. Only appropriate where an external audit path exists — an HSM without an audit trail fails most compliance regimes. |
| `token.persist_objects = false` | Token objects stay in memory; no store `fsync`. Objects do not survive restart. |
| `algorithms.crypto_backend = "awslc"` | Selects the AWS-LC backend at runtime when compiled in. See above. |
| `token.slot_count` | Each slot is an independent token with its own object store. More slots means more per-slot state, not more throughput. |

---

## 4. Optimisations considered and rejected

These were evaluated against measurements and deliberately not applied. Each
would trade a security property for speed.

### An attribute index for `C_FindObjects`

`ObjectStore::find_objects_for_slot` scans every object and evaluates the full
template against each one, including objects that will be filtered out. That is
deliberate: the work is identical whether or not the caller is logged in, so
timing the call cannot reveal how many private objects the token holds.

An index keyed on `CKA_CLASS`, `CKA_LABEL`, or `CKA_ID` would make the search
cost proportional to the number of objects carrying the searched value. An
unauthenticated caller could then use timing to learn that objects with a given
label or ID exist, even when every one of them is private and invisible to it.
That is strictly more information than the current implementation leaks.

The scan is not the bottleneck it was assumed to be — see the
`pkcs11_find_objects_selective` and `pkcs11_find_objects_by_class` benchmarks.
If it does become one, the correct fix is to reduce the per-object constant
factor while still visiting every object, not to skip objects.

### `parking_lot::Mutex` for the CBC/CTR IV tracker

`CBC_CTR_IV_TRACKER` in `src/crypto/encrypt.rs` uses `std::sync::Mutex`
specifically for its poisoning. If a thread panics while holding that lock, the
IV set may be missing entries, and silently recovering the lock would let a
previously used IV be accepted again — a two-time pad for CTR mode. The code
fails closed on a poisoned lock instead. `parking_lot` has no poisoning, so
switching would remove that check. The lock is also not hot: the enclosing
`Sha256::digest(key)` dominates it.

The same reasoning applies to the daemon's login-throttle maps.

### Buffering the DRBG adapter

`HmacDrbg::generate` reseeds from OS entropy on every call (prediction
resistance), costing ~15 µs largely independent of the requested size. Removing
that reseed is not on the table — prediction resistance is a claimed property of
the module — but buffering a block of output in `DrbgRng` and serving small
requests from it would keep the property while making far fewer DRBG calls.

That was implemented and measured, and then reverted, because the premise was
wrong. Counting the actual requests:

| Operation | RNG calls | Bytes | Wall time |
|---|---:|---:|---:|
| RSA-2048 key generation | 423 | 54 KB | ~760 ms |
| EC P-256 key generation | **1** | 32 B | ~56 µs |

RSA key generation is bound by Miller-Rabin bignum arithmetic, not randomness:
even at zero DRBG cost the saving is under 1%. EC key generation makes a single
32-byte request, so a 512-byte refill buffer generates 16x more output than is
consumed — measured as a ~10% *regression* on that path.

What was kept is the uncontroversial part: the entropy source behind
`HealthMonitoredRng` is now an inline enum rather than a `Box<dyn EntropySource>`,
removing one heap allocation and one virtual call from every reseed.

Do not reintroduce output buffering without a profile showing a consumer that
actually makes many small requests.

### Relaxing audit durability

Batching audit `fsync`s on a *timer* — acknowledging events before they are
durable — was rejected. The group-commit implementation gets the same throughput
without it, because it only ever coalesces events that were already queued.

---

## 5. Regression testing

The benchmark suites are the regression gate. Run them before and after any
change to a hot path:

```bash
RUSTFLAGS="-C target-cpu=native" cargo bench --bench crypto_bench
RUSTFLAGS="-C target-cpu=native" cargo bench --bench pkcs11_abi_bench
```

Criterion stores the previous run in `target/criterion/` and reports a
percentage change with a confidence interval, so a second invocation is a
direct before/after comparison.

Groups that exist specifically to catch systemic regressions:

| Group | Catches |
|---|---|
| `pkcs11_find_objects_selective` / `_by_class` | Object-lookup scaling |
| `pkcs11_aes_gcm_encrypt_sizes` / `pkcs11_sha256_digest_sizes` | Per-byte vs per-call regressions, 256 B → 1 MB |
| `pkcs11_concurrent_encrypt` / `pkcs11_concurrent_sign` | New serialisation points; a flat curve across 1→8 threads means contention |

See [benchmarks.md](benchmarks.md) for the current reference numbers.
