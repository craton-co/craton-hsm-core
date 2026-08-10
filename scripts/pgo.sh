#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Craton Software Company
#
# pgo.sh — Build libcraton_hsm with profile-guided optimisation.
#
# PGO is a three-stage process:
#   1. build an instrumented library;
#   2. run a representative workload against it to emit .profraw files;
#   3. merge the profiles and rebuild using them.
#
# The workload in stage 2 is the PKCS#11 ABI benchmark suite, which exercises
# the same entry points real consumers use (C_SignInit/C_Sign, C_Encrypt,
# C_Digest, C_GenerateKeyPair, C_FindObjects). A profile is only as good as the
# workload that produced it: if your deployment is dominated by a different mix,
# point CRATON_PGO_WORKLOAD at your own driver instead.
#
# Usage (from repo root):
#   ./scripts/pgo.sh                       # full 3-stage build
#   ./scripts/pgo.sh --keep-profiles       # keep target/pgo-data for inspection
#   CRATON_PGO_WORKLOAD=./my-driver ./scripts/pgo.sh
#
# Requirements: llvm-profdata matching the toolchain's LLVM version. Install it
# with `rustup component add llvm-tools-preview`; this script locates the copy
# rustup ships so it cannot mismatch the compiler.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

KEEP_PROFILES=0
[[ "${1:-}" == "--keep-profiles" ]] && KEEP_PROFILES=1

PROFILE_DIR="$REPO_ROOT/target/pgo-data"
MERGED="$PROFILE_DIR/merged.profdata"

# ── Locate llvm-profdata from the active toolchain ───────────────────────────
find_profdata() {
    local sysroot
    sysroot="$(rustc --print sysroot)"
    local found
    found="$(find "$sysroot" -name 'llvm-profdata*' -type f 2>/dev/null | head -n1)"
    if [[ -n "$found" ]]; then
        printf '%s' "$found"
        return
    fi
    if command -v llvm-profdata &>/dev/null; then
        echo "Warning: using llvm-profdata from PATH; if it does not match the" >&2
        echo "         toolchain's LLVM version the merge will fail." >&2
        command -v llvm-profdata
        return
    fi
    echo "Error: llvm-profdata not found. Run: rustup component add llvm-tools-preview" >&2
    exit 1
}
LLVM_PROFDATA="$(find_profdata)"
echo "==> Using llvm-profdata: $LLVM_PROFDATA"

# `target-cpu=native` is applied to both stages. It must match, or the
# instrumented and optimised builds will have different inlining decisions and
# the profile will not apply cleanly.
BASE_FLAGS="-C target-cpu=native"

# ── Stage 1: instrumented build ──────────────────────────────────────────────
rm -rf "$PROFILE_DIR"
mkdir -p "$PROFILE_DIR"

# The instrumentation flags must stay in RUSTFLAGS for stage 2 as well. Cargo
# fingerprints builds on RUSTFLAGS, so running the workload without them would
# silently rebuild an *uninstrumented* binary and collect nothing. Exporting
# once keeps both stages on the same artifacts.
export RUSTFLAGS="$BASE_FLAGS -C profile-generate=$PROFILE_DIR"

# `cargo bench` builds with the `bench` profile, so build that here rather than
# `--release`; otherwise stage 2 rebuilds from scratch anyway.
echo "==> Stage 1/3: building instrumented benchmarks"
cargo build --benches --profile bench

# ── Stage 2: run the representative workload ─────────────────────────────────
#
# The PKCS#11 ABI benchmark loads the built shared library and calls
# C_Initialize, whose power-on self-test refuses to start an unsigned local
# build without this development bypass. See docs/benchmarks.md.
export CRATON_HSM_INTEGRITY_BYPASS="${CRATON_HSM_INTEGRITY_BYPASS:-unsafe-dev-only}"
export LLVM_PROFILE_FILE="$PROFILE_DIR/%m_%p.profraw"

echo "==> Stage 2/3: running workload to collect profiles"
if [[ -n "${CRATON_PGO_WORKLOAD:-}" ]]; then
    echo "    (custom workload: $CRATON_PGO_WORKLOAD)"
    "$CRATON_PGO_WORKLOAD"
else
    # A short measurement window is enough: PGO cares about which branches and
    # call edges are hot, not about statistically stable timings.
    cargo bench --bench pkcs11_abi_bench -- --sample-size 10 --measurement-time 2
    cargo bench --bench crypto_bench -- --sample-size 10 --measurement-time 2
fi

unset LLVM_PROFILE_FILE

RAW_COUNT="$(find "$PROFILE_DIR" -name '*.profraw' | wc -l | tr -d ' ')"
if [[ "$RAW_COUNT" == "0" ]]; then
    echo "Error: the workload produced no .profraw files — nothing to optimise from." >&2
    echo "       Check that the workload actually loaded the instrumented library." >&2
    exit 1
fi
echo "    collected $RAW_COUNT profile file(s)"

# ── Stage 3: merge and rebuild ───────────────────────────────────────────────
echo "==> Stage 3/3: merging profiles and rebuilding"
"$LLVM_PROFDATA" merge -o "$MERGED" "$PROFILE_DIR"

# `-C llvm-args=-pgo-warn-missing-function` surfaces functions that changed
# enough since stage 1 that their profile no longer applies — a signal that the
# profile is stale and should be regenerated.
RUSTFLAGS="$BASE_FLAGS -C profile-use=$MERGED -C llvm-args=-pgo-warn-missing-function" \
    cargo build --release

echo
echo "==> PGO build complete. Optimised artifacts are in target/release/."
echo "    Validate the gain before shipping it:"
echo "      cargo bench --bench pkcs11_abi_bench   # compare against the non-PGO baseline"
echo
echo "    A PGO profile is workload-specific and goes stale as the code changes."
echo "    Regenerate it whenever the hot paths move, and never ship a binary"
echo "    built from a profile you cannot reproduce."

if [[ "$KEEP_PROFILES" == "0" ]]; then
    # Keep the merged profile (small, reproducible input) but drop the raw
    # files, which are large and machine-specific.
    find "$PROFILE_DIR" -name '*.profraw' -delete
    echo "    Raw profiles removed; merged profile kept at $MERGED"
else
    echo "    Profiles kept in $PROFILE_DIR"
fi
