#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Craton Software Company
#
# local-ci.sh — Run all CI jobs locally (mirrors .github/workflows/ci.yml + security-audit.yml)
#
# Usage:
#   ./scripts/local-ci.sh              # Run all jobs
#   ./scripts/local-ci.sh fmt          # Run a single job
#   ./scripts/local-ci.sh fmt test     # Run specific jobs
#
# Available jobs:
#   fmt        Format check (cargo fmt --check)
#   test       Build & test (cargo test --workspace)
#   clippy     Clippy lint with -D warnings
#   semver     Semver compatibility check
#   miri       Miri undefined-behavior check on crypto modules
#   docs       Build rustdoc
#   audit      Security audit (cargo-audit + cargo-deny)
#   bench      Benchmarks (cargo bench, no SoftHSMv2 comparison)
#
# Prerequisites:
#   - Rust stable + nightly (rustup)
#   - protoc (for gRPC daemon)
#   - cargo-semver-checks:  cargo install cargo-semver-checks
#   - cargo-audit:          cargo install cargo-audit
#   - cargo-deny:           cargo install cargo-deny

set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ── State ─────────────────────────────────────────────────────────────────────
PASS=()
FAIL=()
SKIP=()
TOTAL_START=$SECONDS

# ── Helpers ───────────────────────────────────────────────────────────────────
header() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  ▶ $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

run_job() {
    local name="$1"
    shift
    local start=$SECONDS
    header "$name"

    if "$@"; then
        local elapsed=$(( SECONDS - start ))
        echo -e "${GREEN}  ✓ ${name} passed${NC} (${elapsed}s)"
        PASS+=("$name")
        return 0
    else
        local elapsed=$(( SECONDS - start ))
        echo -e "${RED}  ✗ ${name} FAILED${NC} (${elapsed}s)"
        FAIL+=("$name")
        return 1
    fi
}

skip_job() {
    echo -e "${YELLOW}  ⊘ $1 skipped ($2)${NC}"
    SKIP+=("$1")
}

has_cmd() {
    command -v "$1" &>/dev/null
}

# ── Job implementations ──────────────────────────────────────────────────────

job_fmt() {
    cargo fmt --check
}

job_test() {
    export CARGO_TERM_COLOR=always
    export RUST_BACKTRACE=1
    cargo test --workspace -- --test-threads=1
}

job_clippy() {
    # Deny correctness and suspicious lints (safety-critical for a crypto project).
    # Other clippy categories remain warnings until pre-existing issues are resolved.
    # -A deprecated: upstream generic-array deprecation from transitive deps
    cargo clippy --workspace -- \
        -D clippy::correctness -D clippy::suspicious \
        -A deprecated -A clippy::incompatible_msrv \
        -A clippy::not_unsafe_ptr_arg_deref
}

job_semver() {
    if ! has_cmd cargo-semver-checks; then
        skip_job "semver" "cargo-semver-checks not installed (cargo install cargo-semver-checks)"
        return 0
    fi
    # Non-blocking until 1.0 — report but don't fail
    cargo semver-checks check-release --package craton-hsm || true
}

job_miri() {
    # Check nightly is available
    if ! rustup run nightly rustc --version &>/dev/null; then
        skip_job "miri" "Rust nightly not installed (rustup toolchain install nightly)"
        return 0
    fi
    if ! rustup run nightly cargo miri --version &>/dev/null; then
        skip_job "miri" "Miri not installed (rustup +nightly component add miri)"
        return 0
    fi

    export MIRIFLAGS="-Zmiri-disable-isolation -Zmiri-symbolic-alignment-check"
    cargo +nightly miri test --lib -- --test-threads=1 crypto::zeroize crypto::digest crypto::integrity
}

job_docs() {
    RUSTDOCFLAGS="--cfg docsrs" cargo doc --no-deps
}

job_audit() {
    local audit_ok=true

    if has_cmd cargo-audit; then
        echo -e "${BOLD}  Running cargo-audit...${NC}"
        cargo audit \
            --ignore RUSTSEC-2023-0071 \
            --ignore RUSTSEC-2026-0042 \
            --ignore RUSTSEC-2026-0044 \
            --ignore RUSTSEC-2026-0045 \
            --ignore RUSTSEC-2026-0046 \
            --ignore RUSTSEC-2026-0047 \
            --ignore RUSTSEC-2026-0048 \
            --ignore RUSTSEC-2026-0049 \
            --ignore RUSTSEC-2025-0134 \
            || audit_ok=false
    else
        echo -e "${YELLOW}  cargo-audit not installed — skipping CVE check${NC}"
    fi

    if has_cmd cargo-deny; then
        echo -e "${BOLD}  Running cargo-deny...${NC}"
        cargo deny check advisories licenses || audit_ok=false
    else
        echo -e "${YELLOW}  cargo-deny not installed — skipping license/advisory check${NC}"
    fi

    if ! has_cmd cargo-audit && ! has_cmd cargo-deny; then
        skip_job "audit" "neither cargo-audit nor cargo-deny installed"
        return 0
    fi

    $audit_ok
}

job_bench() {
    cargo bench --bench crypto_bench
}

# ── Job registry ──────────────────────────────────────────────────────────────

ALL_JOBS=(fmt test clippy semver miri docs audit bench)

declare -A JOB_FN
JOB_FN[fmt]=job_fmt
JOB_FN[test]=job_test
JOB_FN[clippy]=job_clippy
JOB_FN[semver]=job_semver
JOB_FN[miri]=job_miri
JOB_FN[docs]=job_docs
JOB_FN[audit]=job_audit
JOB_FN[bench]=job_bench

declare -A JOB_NAME
JOB_NAME[fmt]="Format Check"
JOB_NAME[test]="Build & Test"
JOB_NAME[clippy]="Clippy Lint"
JOB_NAME[semver]="Semver Compliance"
JOB_NAME[miri]="Miri (UB Check)"
JOB_NAME[docs]="Documentation Build"
JOB_NAME[audit]="Security Audit"
JOB_NAME[bench]="Benchmarks"

# ── Main ──────────────────────────────────────────────────────────────────────

echo -e "${BOLD}Craton HSM — Local CI Runner${NC}"
echo -e "Mirrors .github/workflows/ci.yml + security-audit.yml"
echo ""

# Parse args: if specific jobs given, run only those
if [[ $# -gt 0 ]]; then
    JOBS_TO_RUN=("$@")
else
    JOBS_TO_RUN=("${ALL_JOBS[@]}")
fi

# Validate job names
for job in "${JOBS_TO_RUN[@]}"; do
    if [[ -z "${JOB_FN[$job]+x}" ]]; then
        echo -e "${RED}Unknown job: ${job}${NC}"
        echo "Available jobs: ${ALL_JOBS[*]}"
        exit 1
    fi
done

# Preflight checks
echo -e "${BOLD}Preflight:${NC}"
echo -n "  rustc:    " && rustc --version
echo -n "  cargo:    " && cargo --version
if has_cmd protoc; then
    echo -n "  protoc:   " && protoc --version
else
    echo -e "  protoc:   ${YELLOW}not found (gRPC daemon tests may fail)${NC}"
fi
echo ""

# Run each job — fmt is the fast gate, fail early
CONTINUE=true
for job in "${JOBS_TO_RUN[@]}"; do
    if [[ "$CONTINUE" == false && "$job" != "audit" ]]; then
        skip_job "${JOB_NAME[$job]}" "prior job failed"
        continue
    fi

    run_job "${JOB_NAME[$job]}" "${JOB_FN[$job]}" || {
        # fmt failure is a hard stop (mirrors CI dependency graph)
        if [[ "$job" == "fmt" ]]; then
            echo -e "${RED}  Format check failed — fix with: cargo fmt${NC}"
            CONTINUE=false
        fi
    }
done

# ── Summary ───────────────────────────────────────────────────────────────────
TOTAL_ELAPSED=$(( SECONDS - TOTAL_START ))

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  CI Summary  (${TOTAL_ELAPSED}s total)${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

if [[ ${#PASS[@]} -gt 0 ]]; then
    for j in "${PASS[@]}"; do
        echo -e "  ${GREEN}✓${NC} $j"
    done
fi
if [[ ${#SKIP[@]} -gt 0 ]]; then
    for j in "${SKIP[@]}"; do
        echo -e "  ${YELLOW}⊘${NC} $j (skipped)"
    done
fi
if [[ ${#FAIL[@]} -gt 0 ]]; then
    for j in "${FAIL[@]}"; do
        echo -e "  ${RED}✗${NC} $j"
    done
fi

echo ""
if [[ ${#FAIL[@]} -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}  All CI checks passed!${NC}"
    exit 0
else
    echo -e "${RED}${BOLD}  ${#FAIL[@]} job(s) failed: ${FAIL[*]}${NC}"
    exit 1
fi
