#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Craton Software Company
#
# profile.sh — Collect CPU, allocation, and I/O profiles of Craton HSM.
#
# Every mode builds with `--profile profiling` (release codegen + full debug
# info, see Cargo.toml) and `-C force-frame-pointers=yes`, so sampled stacks
# resolve to Rust function names and unwind through inlined frames without
# needing `--call-graph dwarf`.
#
# Usage (from repo root):
#   ./scripts/profile.sh cpu   [bench-filter]   # perf record + flamegraph
#   ./scripts/profile.sh alloc [bench-filter]   # heap profile via valgrind/DHAT
#   ./scripts/profile.sh io    [bench-filter]   # syscall + fsync accounting
#   ./scripts/profile.sh lock  [bench-filter]   # mutex/rwlock contention
#
# `bench-filter` is passed to the Criterion harness to narrow the workload,
# e.g. `./scripts/profile.sh cpu pkcs11_rsa_sign`.
#
# Outputs land in target/profiles/.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

MODE="${1:-cpu}"
FILTER="${2:-}"
OUT_DIR="target/profiles"
mkdir -p "$OUT_DIR"

# Release codegen + frame pointers. `target-cpu=native` matches how the
# benchmarks in docs/benchmarks.md are built; drop it if you need a profile
# that is portable across hosts.
export RUSTFLAGS="${RUSTFLAGS:-} -C force-frame-pointers=yes -C target-cpu=native"

# Reproducibility: the audit trail and tracing subscriber both perturb the
# measurement, and tracing is compiled out above `info` in release anyway.
export RUST_LOG="${RUST_LOG:-error}"

# The PKCS#11 ABI benchmark loads the built shared library and calls
# C_Initialize, whose power-on self-test refuses to start an unsigned local
# build without this development bypass. See docs/benchmarks.md.
export CRATON_HSM_INTEGRITY_BYPASS="${CRATON_HSM_INTEGRITY_BYPASS:-unsafe-dev-only}"

need() {
    command -v "$1" &>/dev/null || {
        echo "Error: '$1' is required for mode '$MODE' but was not found in PATH." >&2
        echo "$2" >&2
        exit 1
    }
}

build_bench() {
    echo "==> Building benches with --profile profiling"
    cargo build --profile profiling --benches
}

# Locate the most recently built binary for a bench target.
bench_bin() {
    local name="$1"
    local bin
    bin="$(find target/profiling/deps -maxdepth 1 -type f -name "${name}-*" \
        ! -name '*.d' ! -name '*.pdb' -print0 2>/dev/null |
        xargs -0 -r ls -t 2>/dev/null | head -n1)"
    if [[ -z "$bin" ]]; then
        echo "Error: could not find a built '$name' binary under target/profiling/deps." >&2
        exit 1
    fi
    printf '%s' "$bin"
}

case "$MODE" in
# ── CPU sampling ─────────────────────────────────────────────────────────────
cpu)
    need perf "Install linux-tools for your kernel (e.g. 'apt install linux-tools-common linux-tools-\$(uname -r)')."
    build_bench
    BIN="$(bench_bin pkcs11_abi_bench)"
    echo "==> perf record ($BIN ${FILTER:-<all>})"
    # -F 99: 99 Hz sampling, coprime with common timer frequencies so the
    # sampler does not lock onto a periodic workload.
    # -g:    capture call graphs (frame-pointer based, see RUSTFLAGS above).
    perf record -F 99 -g --call-graph fp -o "$OUT_DIR/perf.data" -- \
        "$BIN" --bench ${FILTER:+"$FILTER"}
    perf script -i "$OUT_DIR/perf.data" >"$OUT_DIR/perf.script"

    if command -v flamegraph.pl &>/dev/null && command -v stackcollapse-perf.pl &>/dev/null; then
        stackcollapse-perf.pl "$OUT_DIR/perf.script" |
            flamegraph.pl --title "Craton HSM ${FILTER:-all}" >"$OUT_DIR/flamegraph.svg"
        echo "==> Flame graph: $OUT_DIR/flamegraph.svg"
    else
        echo "==> Raw samples: $OUT_DIR/perf.script"
        echo "    For a flame graph, put Brendan Gregg's FlameGraph scripts on PATH:"
        echo "      git clone https://github.com/brendangregg/FlameGraph"
        echo "      export PATH=\"\$PWD/FlameGraph:\$PATH\""
    fi
    echo "==> Top symbols:"
    perf report -i "$OUT_DIR/perf.data" --stdio --sort symbol 2>/dev/null | head -40 || true
    ;;

# ── Allocation profiling ─────────────────────────────────────────────────────
alloc)
    need valgrind "Install valgrind (DHAT is bundled with it)."
    build_bench
    BIN="$(bench_bin crypto_bench)"
    echo "==> valgrind --tool=dhat ($BIN ${FILTER:-<all>})"
    # Criterion's default sample count is far too slow under valgrind; cut it
    # down so the run finishes while still exercising every allocation site.
    valgrind --tool=dhat --dhat-out-file="$OUT_DIR/dhat.out" -- \
        "$BIN" --bench --sample-size 10 --measurement-time 1 ${FILTER:+"$FILTER"}
    echo "==> DHAT output: $OUT_DIR/dhat.out"
    echo "    View it at https://nnethercote.github.io/dh_view/dh_view.html"
    ;;

# ── I/O and fsync accounting ─────────────────────────────────────────────────
io)
    need strace "Install strace."
    build_bench
    BIN="$(bench_bin pkcs11_abi_bench)"
    echo "==> strace -c -f ($BIN ${FILTER:-<all>})"
    # -c summarises syscall counts and time; the audit trail and the redb
    # object store are both fsync-bound, so watch fsync/fdatasync/openat here.
    strace -c -f -o "$OUT_DIR/strace.summary" -- \
        "$BIN" --bench --sample-size 10 --measurement-time 1 ${FILTER:+"$FILTER"} || true
    cat "$OUT_DIR/strace.summary"
    echo
    echo "==> Per-call fsync trace: $OUT_DIR/strace.fsync"
    strace -f -e trace=fsync,fdatasync,openat,write -T -o "$OUT_DIR/strace.fsync" -- \
        "$BIN" --bench --sample-size 10 --measurement-time 1 ${FILTER:+"$FILTER"} || true
    ;;

# ── Lock contention ──────────────────────────────────────────────────────────
lock)
    need perf "Install linux-tools for your kernel."
    build_bench
    BIN="$(bench_bin pkcs11_abi_bench)"
    echo "==> perf lock record ($BIN ${FILTER:-<all>})"
    echo "    Note: parking_lot and DashMap park via futex, so 'perf lock' needs"
    echo "    CONFIG_LOCKDEP; if it reports nothing, use the futex tracepoints below."
    perf lock record -o "$OUT_DIR/perf-lock.data" -- \
        "$BIN" --bench ${FILTER:+"$FILTER"} 2>/dev/null ||
        perf record -e 'syscalls:sys_enter_futex' -g -o "$OUT_DIR/perf-lock.data" -- \
            "$BIN" --bench ${FILTER:+"$FILTER"}
    perf lock report -i "$OUT_DIR/perf-lock.data" 2>/dev/null |
        head -40 || perf report -i "$OUT_DIR/perf-lock.data" --stdio | head -40
    ;;

*)
    echo "Unknown mode '$MODE'. Expected one of: cpu, alloc, io, lock." >&2
    exit 2
    ;;
esac
