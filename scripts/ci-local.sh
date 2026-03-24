#!/usr/bin/env bash
# ============================================================================
# ci-local.sh — Run GitHub Actions CI pipeline locally
# ============================================================================
#
# Mirrors .github/workflows/ci.yml and security-audit.yml jobs.
# Run before pushing to catch issues without burning GH Actions minutes.
#
# Usage:
#   ./scripts/ci-local.sh              # Run all jobs
#   ./scripts/ci-local.sh fmt          # Run only format check
#   ./scripts/ci-local.sh test         # Run only build & test
#   ./scripts/ci-local.sh clippy       # Run only clippy
#   ./scripts/ci-local.sh audit        # Run only security audit
#   ./scripts/ci-local.sh miri         # Run only Miri
#   ./scripts/ci-local.sh docs         # Run only doc build
#   ./scripts/ci-local.sh coverage     # Run only coverage
#   ./scripts/ci-local.sh semver       # Run only semver checks
#   ./scripts/ci-local.sh quick        # fmt + test + clippy (fastest useful check)
#
# Requirements:
#   - Rust stable toolchain with rustfmt + clippy
#   - Rust nightly toolchain with miri (for miri job)
#   - protoc (Protocol Buffers compiler)
#   - cargo-audit, cargo-deny (for audit job)
#   - cargo-tarpaulin (for coverage job)
#   - cargo-semver-checks (for semver job)
#
# Install all requirements:
#   rustup component add rustfmt clippy
#   rustup toolchain install nightly --component miri
#   cargo install cargo-audit cargo-deny cargo-tarpaulin cargo-semver-checks
# ============================================================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Track results
declare -a JOB_NAMES=()
declare -a JOB_RESULTS=()
FAILED=0
START_TIME=$SECONDS

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
    echo -e "  ${YELLOW}⚠ WARN${NC}: $1 (non-blocking)"
    JOB_NAMES+=("$1")
    JOB_RESULTS+=("warn")
}

# ── Job: Format Check ───────────────────────────────────────────────────────
job_fmt() {
    log_header "Format Check (cargo fmt --check)"
    if cargo fmt --check 2>&1; then
        log_pass "Format Check"
    else
        log_fail "Format Check"
    fi
}

# ── Job: Build & Test ────────────────────────────────────────────────────────
job_test() {
    log_header "Build & Test (cargo test --workspace)"
    if cargo test --workspace -- --test-threads=1 2>&1; then
        log_pass "Build & Test"
    else
        log_fail "Build & Test"
    fi
}

# ── Job: Clippy ──────────────────────────────────────────────────────────────
job_clippy() {
    log_header "Clippy (cargo clippy --workspace)"
    # Non-blocking in CI (continue-on-error: true)
    if cargo clippy --workspace 2>&1; then
        log_pass "Clippy"
    else
        log_warn "Clippy"
    fi
}

# ── Job: Security Audit ─────────────────────────────────────────────────────
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
        echo -e "  ${YELLOW}○${NC} cargo-audit not installed (cargo install cargo-audit)"
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
        echo -e "  ${YELLOW}○${NC} cargo-deny not installed (cargo install cargo-deny)"
        audit_ok=false
    fi

    if $audit_ok; then
        log_pass "Security Audit"
    else
        log_fail "Security Audit"
    fi
}

# ── Job: Semver Checks ───────────────────────────────────────────────────────
job_semver() {
    log_header "Semver Compliance (cargo-semver-checks)"
    if ! command -v cargo-semver-checks &>/dev/null; then
        log_skip "Semver Checks" "cargo install cargo-semver-checks"
        return
    fi
    # Non-blocking in CI (continue-on-error: true)
    if cargo semver-checks check-release --package craton_hsm 2>&1; then
        log_pass "Semver Checks"
    else
        log_warn "Semver Checks"
    fi
}

# ── Job: Miri ────────────────────────────────────────────────────────────────
job_miri() {
    log_header "Miri (Undefined Behavior Check)"
    if ! rustup run nightly rustc --version &>/dev/null; then
        log_skip "Miri" "rustup toolchain install nightly --component miri"
        return
    fi
    export MIRIFLAGS="-Zmiri-disable-isolation -Zmiri-symbolic-alignment-check"
    if cargo +nightly miri test --lib -- --test-threads=1 crypto::zeroize crypto::digest crypto::integrity 2>&1; then
        log_pass "Miri"
    else
        log_fail "Miri"
    fi
}

# ── Job: Documentation Build ─────────────────────────────────────────────────
job_docs() {
    log_header "Documentation Build (cargo doc)"
    if RUSTDOCFLAGS="--cfg docsrs" cargo doc --no-deps 2>&1; then
        log_pass "Documentation Build"
    else
        log_fail "Documentation Build"
    fi
}

# ── Job: Code Coverage ───────────────────────────────────────────────────────
job_coverage() {
    log_header "Code Coverage (cargo-tarpaulin)"
    if ! command -v cargo-tarpaulin &>/dev/null; then
        log_skip "Coverage" "cargo install cargo-tarpaulin"
        return
    fi
    if cargo tarpaulin --out xml --out html --skip-clean --timeout 300 \
        --exclude-files 'tests/fips_*' -- --test-threads=1 2>&1; then
        log_pass "Coverage"
        if [ -f tarpaulin-report.html ]; then
            echo -e "  Report: ${BOLD}tarpaulin-report.html${NC}"
        fi
    else
        log_fail "Coverage"
    fi
}

# ── Summary ──────────────────────────────────────────────────────────────────
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
            warn) echo -e "  ${YELLOW}⚠ WARN${NC}  ${JOB_NAMES[$i]} (non-blocking)" ;;
            skip) echo -e "  ${YELLOW}○ SKIP${NC}  ${JOB_NAMES[$i]}" ;;
        esac
    done

    echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"

    if [ $FAILED -eq 0 ]; then
        echo -e "  ${GREEN}${BOLD}All blocking checks passed — safe to push.${NC}"
    else
        echo -e "  ${RED}${BOLD}Some checks failed — fix before pushing.${NC}"
    fi
    echo ""
}

# ── Main ─────────────────────────────────────────────────────────────────────
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
        # Run in same order as CI, with fmt as the fast gate
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
exit $FAILED
