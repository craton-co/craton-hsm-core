#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Craton Software Company
#
# local-ci.sh — Run the GitHub Actions CI pipeline locally inside Docker.
#
# By default this script wraps work in deploy/Dockerfile.ci (Rust, protoc, Miri,
# cargo-audit/deny/semver-checks). That matches the tooling and Linux
# environment used on ubuntu-latest runners.
#
# Usage (from repo root):
#   ./scripts/local-ci.sh                  # fmt + tests + lint + audit + semver + miri + docs
#   ./scripts/local-ci.sh quick            # fmt + tests + clippy
#   ./scripts/local-ci.sh fmt|test|clippy|audit|semver|miri|docs
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

    TARGET="${1:-all}"
    RUN_SHARD3=0
    if [[ "$TARGET" == "all" || "$TARGET" == "quick" || "$TARGET" == "test" ]]; then
        RUN_SHARD3=1
    fi

    DOCKER_ARGS=(
        --rm
        --privileged
        -e CRATON_CI_CONTAINER=1
        -v "$REPO_ROOT":/app
        -v craton-cargo-registry:/usr/local/cargo/registry
        -v craton-cargo-git:/usr/local/cargo/git
    )

    if [[ $RUN_SHARD3 -eq 1 ]]; then
        MAIN_PREFIX=$'\033[36m[MAIN]\033[0m'
        SHARD3_PREFIX=$'\033[35m[SHARD3]\033[0m'

        # Capture each container's full output to a temp log (in addition to
        # streaming it prefixed) so we can name the exact failing job(s) at the
        # end instead of a generic "one or more failed".
        MAIN_LOG="$(mktemp)"
        SHARD3_LOG="$(mktemp)"

        echo "==> Starting Container 1 (Main Jobs)..."
        (
            set -euo pipefail
            docker run "${DOCKER_ARGS[@]}" \
                -v craton-ci-target-main:/app/target \
                craton_hsm_ci:latest run_main "$TARGET" 2>&1 \
                | tee "$MAIN_LOG" | sed "s/^/${MAIN_PREFIX} /"
        ) &
        PID_MAIN=$!

        echo "==> Starting Container 2 (Test Shard 3)..."
        (
            set -euo pipefail
            docker run "${DOCKER_ARGS[@]}" \
                -v craton-ci-target-shard3:/app/target \
                craton_hsm_ci:latest run_shard3 "$TARGET" 2>&1 \
                | tee "$SHARD3_LOG" | sed "s/^/${SHARD3_PREFIX} /"
        ) &
        PID_SHARD3=$!

        MAIN_RC=0
        SHARD3_RC=0
        wait $PID_MAIN || MAIN_RC=$?
        wait $PID_SHARD3 || SHARD3_RC=$?

        # Strip ANSI colour codes (the literal ESC byte works with any sed).
        strip_ansi() { sed $'s/\033\\[[0-9;]*m//g'; }
        # Print the distinct job names a container's summary marked "✗ FAIL".
        failed_jobs() { strip_ansi <"$1" | grep -aE '✗ FAIL' | sed -E 's/.*✗ FAIL[: ]+//; s/[[:space:]]+$//' | sort -u; }
        # Report a failed container: list its failing jobs, or fall back to the
        # raw exit code if none could be parsed (e.g. the container died early).
        report_container() {
            local label="$1" log="$2" rc="$3"
            local jobs
            jobs="$(failed_jobs "$log" || true)"
            if [[ -n "$jobs" ]]; then
                while IFS= read -r j; do
                    echo -e "    \033[0;31m✗\033[0m ${label}: ${j}"
                done <<<"$jobs"
            else
                echo -e "    \033[0;31m✗\033[0m ${label}: container exited with status ${rc} (see output above)"
            fi
        }

        if [[ $MAIN_RC -ne 0 || $SHARD3_RC -ne 0 ]]; then
            echo -e "\n\033[0;31m✗ CI failed. Failing job(s):\033[0m"
            [[ $MAIN_RC -ne 0 ]] && report_container "Main container" "$MAIN_LOG" "$MAIN_RC"
            [[ $SHARD3_RC -ne 0 ]] && report_container "Shard 3 container" "$SHARD3_LOG" "$SHARD3_RC"
            rm -f "$MAIN_LOG" "$SHARD3_LOG"
            exit 1
        else
            echo -e "\n\033[0;32m✓ All container jobs passed.\033[0m"
            rm -f "$MAIN_LOG" "$SHARD3_LOG"
            exit 0
        fi
    else
        DOCKER_TTY=()
        if [[ -t 0 && -t 1 ]]; then
            DOCKER_TTY=(-it)
        else
            DOCKER_TTY=(-i)
        fi

        echo "==> Running CI in container (Main Only)..."
        exec docker run "${DOCKER_TTY[@]}" "${DOCKER_ARGS[@]}" \
            -v craton-ci-target-main:/app/target \
            craton_hsm_ci:latest run_main "$TARGET"
    fi
fi

# ── In-container runner (mirrors .github/workflows/ci.yml + security-audit) ─

# Unsigned debug/test builds embed the placeholder integrity key; POST needs this bypass.
export CRATON_HSM_INTEGRITY_BYPASS=unsafe-dev-only

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

# Mirrors CI shards: main tests (everything excluding shard 3)
job_test_main() {
    log_header "Build & Test (Main)"
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
        --test token_state_persistence \
        -- --test-threads=1 2>&1; then
        echo -e "  ${GREEN}✓${NC} PKCS#11 compliance tests passed"
    else
        echo -e "  ${RED}✗${NC} PKCS#11 compliance tests failed"
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
        log_pass "Build & Test (Main)"
    else
        log_fail "Build & Test (Main)"
    fi
}

job_test_shard3() {
    log_header "Build & Test (Shard 3)"
    local test_ok=true

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

    if $test_ok; then
        log_pass "Build & Test (Shard 3)"
    else
        log_fail "Build & Test (Shard 3)"
    fi
}

print_summary() {
    local title_suffix="${1:-}"
    local elapsed=$(( SECONDS - START_TIME ))
    local mins=$(( elapsed / 60 ))
    local secs=$(( elapsed % 60 ))

    local header_title="CI Results Summary"
    if [[ -n "$title_suffix" ]]; then
        header_title="CI Results Summary ($title_suffix)"
    fi

    echo ""
    echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
    printf "${BOLD}  %-43s %sm %ss${NC}\n" "$header_title" "$mins" "$secs"
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

MODE="${1:-all}"
TARGET="${2:-all}"

execute_main() {
    case "$1" in
        fmt)      job_fmt ;;
        test)     job_test_main ;;
        clippy)   job_clippy ;;
        audit)    job_audit ;;
        semver)   job_semver ;;
        miri)     job_miri ;;
        docs)     job_docs ;;
        quick)
            job_fmt
            job_test_main
            job_clippy
            ;;
        all)
            job_fmt
            job_test_main
            job_clippy
            job_audit
            job_semver
            job_miri
            job_docs
            ;;
        *)
            echo "Usage: $0 {all|quick|fmt|test|clippy|audit|semver|miri|docs}"
            exit 1
            ;;
    esac
}

execute_shard3() {
    case "$1" in
        test|quick|all)
            job_test_shard3
            ;;
    esac
}

if [[ "$MODE" == "run_main" ]]; then
    execute_main "$TARGET"
    print_summary "Main"
    exit "$FAILED"
elif [[ "$MODE" == "run_shard3" ]]; then
    execute_shard3 "$TARGET"
    print_summary "Shard 3"
    exit "$FAILED"
else
    # Fallback to local host execution (if bypassed docker entirely)
    execute_main "$MODE"
    execute_shard3 "$MODE"
    print_summary "Combined"
    exit "$FAILED"
fi
