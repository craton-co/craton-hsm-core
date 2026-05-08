#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Craton Software Company
#
# local-ci.sh — Run the GitHub Actions CI pipeline locally inside Docker.
#
# By default this script wraps work in deploy/Dockerfile.ci (Rust, protoc, Miri,
# cargo-audit/deny/tarpaulin/semver-checks). That matches the tooling and Linux
# environment used on ubuntu-latest runners.
#
# Usage (from repo root):
#   ./scripts/local-ci.sh                  # fmt + tests + lint + audit + semver + miri + docs + coverage
#   ./scripts/local-ci.sh quick            # fmt + tests + clippy
#   ./scripts/local-ci.sh fmt|test|clippy|audit|semver|miri|docs|coverage
#
# Force running on the host (not recommended; install the same tools as the image):
#   CRATON_CI_CONTAINER=1 ./scripts/local-ci.sh quick

set -euo pipefail

# ── Docker bootstrap (host) ───────────────────────────────────────────────────
if [[ "${CRATON_CI_CONTAINER:-}" != "1" ]]; then
    if ! command -v docker &>/dev/null; then
        echo "Error: docker is required to run local CI (mirrors GitHub Actions)."
        exit 1
    fi

    REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
    cd "$REPO_ROOT"

    echo "==> Building CI image (deploy/Dockerfile.ci)..."
    docker build -t craton_hsm_ci:latest -f deploy/Dockerfile.ci .

    DOCKER_TTY=()
    if [[ -t 0 && -t 1 ]]; then
        DOCKER_TTY=(-it)
    else
        DOCKER_TTY=(-i)
    fi

    echo "==> Running CI in container..."
    exec docker run --rm "${DOCKER_TTY[@]}" \
        --privileged \
        -e CRATON_CI_CONTAINER=1 \
        -v "$REPO_ROOT":/app \
        -v craton-cargo-registry:/usr/local/cargo/registry \
        -v craton-cargo-git:/usr/local/cargo/git \
        -v craton-ci-target:/app/target \
        craton_hsm_ci:latest "$@"
fi

# ── In-container runner (mirrors .github/workflows/ci.yml + security-audit) ─

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

declare -a JOB_NAMES=()
declare -a JOB_RESULTS=()
FAILED=0
START_TIME=$SECONDS
export PROTOC=${PROTOC:-/usr/bin/protoc}

log_header() {
    echo ""
    echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  $1${NC}"
    echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
}

log_pass() {
    echo -e "  ${GREEN}✓ PASS${NC}: $1"
    JOB_NAMES+=("$1")
    JOB_RESULTS+=("pass")
}

log_fail() {
    echo -e "  ${RED}✗ FAIL${NC}: $1"
    JOB_NAMES+=("$1")
    JOB_RESULTS+=("fail")
    FAILED=1
}

log_skip() {
    echo -e "  ${YELLOW}○ SKIP${NC}: $1 ($2)"
    JOB_NAMES+=("$1")
    JOB_RESULTS+=("skip")
}

log_warn() {
    echo -e "  ${YELLOW}⚠ WARN${NC}: $1 (non-blocking, matches CI continue-on-error)"
    JOB_NAMES+=("$1")
    JOB_RESULTS+=("warn")
}

job_fmt() {
    log_header "Format Check (cargo fmt --check)"
    if cargo fmt --check 2>&1; then
        log_pass "Format Check"
    else
        log_fail "Format Check"
    fi
}

# Mirrors CI shards: separate cargo test invocations avoid PKCS#11 singleton issues.
job_test() {
    log_header "Build & Test"
    local test_ok=true

    echo -e "\n${BOLD}  Shard 1: Unit & crypto tests (parallel-safe)${NC}"
    if cargo test --lib \
        --test crypto_vectors \
        --test drbg_tests \
        --test concurrent_stress \
        --test zeroization \
        --test integrity_tests \
        --test multi_slot \
        -- --test-threads=8 2>&1; then
        echo -e "  ${GREEN}✓${NC} Unit & crypto tests passed"
    else
        echo -e "  ${RED}✗${NC} Unit & crypto tests failed"
        test_ok=false
    fi

    echo -e "\n${BOLD}  Audit & FIPS POST tests (serial — shared IV tracker)${NC}"
    if cargo test \
        --test audit_and_integrity \
        -- --test-threads=1 2>&1; then
        echo -e "  ${GREEN}✓${NC} Audit & FIPS POST tests passed"
    else
        echo -e "  ${RED}✗${NC} Audit & FIPS POST tests failed"
        test_ok=false
    fi

    echo -e "\n${BOLD}  Shard 2: PKCS#11 ABI — compliance${NC}"
    if cargo test \
        --test attribute_management \
        --test attribute_validation \
        --test digest_abi \
        --test fips_approved_mode \
        --test negative_edge_cases \
        --test operation_state \
        --test pkcs11_compliance \
        --test pkcs11_compliance_extended \
        --test pkcs11_conformance \
        --test pkcs11_error_paths \
        --test pkcs11_info_functions \
        --test random_and_session \
        --test session_state_machine \
        --test supplementary_functions \
        -- --test-threads=1 2>&1; then
        echo -e "  ${GREEN}✓${NC} PKCS#11 compliance tests passed"
    else
        echo -e "  ${RED}✗${NC} PKCS#11 compliance tests failed"
        test_ok=false
    fi

    echo -e "\n${BOLD}  Shard 3: PKCS#11 ABI — crypto ops${NC}"
    if cargo test \
        --test backup_restore \
        --test concurrent_session_stress \
        --test crypto_vectors_phase2 \
        --test key_derivation_abi \
        --test key_lifecycle_abi \
        --test key_wrapping_abi \
        --test multipart_encrypt_decrypt \
        --test multipart_sign_verify \
        --test pairwise_consistency \
        --test persistence \
        --test pqc_abi_comprehensive \
        --test pqc_phase3 \
        --test rsa_abi_comprehensive \
        --test security_properties \
        -- --test-threads=1 2>&1; then
        echo -e "  ${GREEN}✓${NC} PKCS#11 crypto ops tests passed"
    else
        echo -e "  ${RED}✗${NC} PKCS#11 crypto ops tests failed"
        test_ok=false
    fi

    echo -e "\n${BOLD}  Workspace member tests${NC}"
    if cargo test \
        -p craton-hsm-admin \
        -p pkcs11-spy \
        -p craton-hsm-daemon \
        -- --test-threads=1 2>&1; then
        echo -e "  ${GREEN}✓${NC} Workspace member tests passed"
    else
        echo -e "  ${RED}✗${NC} Workspace member tests failed"
        test_ok=false
    fi

    if $test_ok; then
        log_pass "Build & Test"
    else
        log_fail "Build & Test"
    fi
}

job_clippy() {
    log_header "Clippy (cargo clippy --workspace)"
    if cargo clippy --workspace -- \
        -D clippy::correctness -D clippy::suspicious \
        -A deprecated -A clippy::incompatible_msrv \
        -A clippy::not_unsafe_ptr_arg_deref 2>&1; then
        log_pass "Clippy"
    else
        log_fail "Clippy"
    fi
}

job_audit() {
    log_header "Security Audit (cargo-audit + cargo-deny)"

    local audit_ok=true

    if command -v cargo-audit &>/dev/null; then
        echo -e "\n${BOLD}  cargo audit${NC}"
        if cargo audit \
            --ignore RUSTSEC-2023-0071 \
            --ignore RUSTSEC-2026-0042 \
            --ignore RUSTSEC-2026-0044 \
            --ignore RUSTSEC-2026-0045 \
            --ignore RUSTSEC-2026-0046 \
            --ignore RUSTSEC-2026-0047 \
            --ignore RUSTSEC-2026-0048 \
            --ignore RUSTSEC-2026-0049 \
            --ignore RUSTSEC-2025-0134 2>&1; then
            echo -e "  ${GREEN}✓${NC} cargo-audit passed"
        else
            echo -e "  ${RED}✗${NC} cargo-audit failed"
            audit_ok=false
        fi
    else
        echo -e "  ${YELLOW}○${NC} cargo-audit not installed"
        audit_ok=false
    fi

    if command -v cargo-deny &>/dev/null; then
        echo -e "\n${BOLD}  cargo deny check${NC}"
        if cargo deny check advisories licenses 2>&1; then
            echo -e "  ${GREEN}✓${NC} cargo-deny passed"
        else
            echo -e "  ${RED}✗${NC} cargo-deny failed"
            audit_ok=false
        fi
    else
        echo -e "  ${YELLOW}○${NC} cargo-deny not installed"
        audit_ok=false
    fi

    if $audit_ok; then
        log_pass "Security Audit"
    else
        log_fail "Security Audit"
    fi
}

job_semver() {
    log_header "Semver Compliance (cargo-semver-checks)"
    if ! command -v cargo-semver-checks &>/dev/null; then
        log_skip "Semver Checks" "cargo-semver-checks not in PATH"
        return
    fi
    # Non-blocking in CI until 1.0 (semver-checks job continues on error).
    if cargo semver-checks check-release --package craton-hsm --baseline-rev main 2>&1; then
        log_pass "Semver Checks"
    else
        log_warn "Semver Checks"
    fi
}

job_miri() {
    log_header "Miri (Undefined Behavior Check)"
    export MIRIFLAGS="-Zmiri-disable-isolation -Zmiri-symbolic-alignment-check"
    if cargo +nightly miri test --lib -- --test-threads=1 crypto::zeroize crypto::digest crypto::integrity 2>&1; then
        log_pass "Miri"
    else
        log_fail "Miri"
    fi
}

job_docs() {
    log_header "Documentation Build (cargo doc)"
    if RUSTDOCFLAGS="--cfg docsrs" cargo doc --no-deps 2>&1; then
        log_pass "Documentation Build"
    else
        log_fail "Documentation Build"
    fi
}

job_coverage() {
    log_header "Code Coverage (cargo-tarpaulin)"
    if ! command -v cargo-tarpaulin &>/dev/null; then
        log_skip "Coverage" "cargo-tarpaulin not in PATH"
        return
    fi
    if cargo tarpaulin --out xml --out html --skip-clean --timeout 300 \
        --exclude-files 'tests/fips_*' -- --test-threads=1 2>&1; then
        log_pass "Coverage"
        if [[ -f tarpaulin-report.html ]]; then
            echo -e "  Report: ${BOLD}tarpaulin-report.html${NC}"
        fi
    else
        log_fail "Coverage"
    fi
}

print_summary() {
    local elapsed=$(( SECONDS - START_TIME ))
    local mins=$(( elapsed / 60 ))
    local secs=$(( elapsed % 60 ))

    echo ""
    echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  CI Results Summary                         ${mins}m ${secs}s${NC}"
    echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"

    for i in "${!JOB_NAMES[@]}"; do
        case "${JOB_RESULTS[$i]}" in
            pass) echo -e "  ${GREEN}✓ PASS${NC}  ${JOB_NAMES[$i]}" ;;
            fail) echo -e "  ${RED}✗ FAIL${NC}  ${JOB_NAMES[$i]}" ;;
            warn) echo -e "  ${YELLOW}⚠ WARN${NC}  ${JOB_NAMES[$i]}" ;;
            skip) echo -e "  ${YELLOW}○ SKIP${NC}  ${JOB_NAMES[$i]}" ;;
        esac
    done

    echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"

    if [[ $FAILED -eq 0 ]]; then
        echo -e "  ${GREEN}${BOLD}All blocking checks passed.${NC}"
    else
        echo -e "  ${RED}${BOLD}Some checks failed.${NC}"
    fi
    echo ""
}

cd "$(git rev-parse --show-toplevel 2>/dev/null || pwd)"

export CARGO_TERM_COLOR=always
export RUST_BACKTRACE=1

case "${1:-all}" in
    fmt)      job_fmt ;;
    test)     job_test ;;
    clippy)   job_clippy ;;
    audit)    job_audit ;;
    semver)   job_semver ;;
    miri)     job_miri ;;
    docs)     job_docs ;;
    coverage) job_coverage ;;
    quick)
        job_fmt
        job_test
        job_clippy
        ;;
    all)
        job_fmt
        job_test
        job_clippy
        job_audit
        job_semver
        job_miri
        job_docs
        job_coverage
        ;;
    *)
        echo "Usage: $0 {all|quick|fmt|test|clippy|audit|semver|miri|docs|coverage}"
        exit 1
        ;;
esac

print_summary
exit "$FAILED"
