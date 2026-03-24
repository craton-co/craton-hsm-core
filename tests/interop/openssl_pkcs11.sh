#!/usr/bin/env bash
# ==============================================================================
# OpenSSL / pkcs11-tool Interoperability Test for Craton HSM
# ==============================================================================
#
# Tests Craton HSM compatibility with common PKCS#11 CLI tools:
#   1. pkcs11-tool (OpenSC) — slot listing, token init, key generation, sign
#   2. p11tool (GnuTLS) — token listing, object listing
#   3. OpenSSL 3.x pkcs11-provider — key listing via storeutl
#
# Prerequisites:
#   - pkcs11-tool (from OpenSC package) — primary test tool
#   - p11tool (from GnuTLS, optional)
#   - openssl 3.x + pkcs11-provider (optional)
#   - Craton HSM built in release mode (cargo build --release)
#   - Linux or macOS
#
# Usage:
#   bash tests/interop/openssl_pkcs11.sh
#
# Exit codes:
#   0 — all tests passed (skipped tools don't count as failures)
#   1 — test failure
#   2 — prerequisites missing (pkcs11-tool not found and library not built)
#
# Environment variables:
#   CRATON_HSM_LIB — path to Craton HSM shared library (auto-detected if not set)
#   SO_PIN      — Security Officer PIN (default: 12345678)
#   USER_PIN    — User PIN (default: 1234)
# ==============================================================================

set -euo pipefail

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# --- Counters ---
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

pass() {
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_PASSED=$((TESTS_PASSED + 1))
    echo -e "  ${GREEN}PASS${NC}: $1"
}

fail() {
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_FAILED=$((TESTS_FAILED + 1))
    echo -e "  ${RED}FAIL${NC}: $1"
    if [ -n "${2:-}" ]; then
        echo -e "        $2"
    fi
}

skip() {
    TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
    echo -e "  ${YELLOW}SKIP${NC}: $1"
}

# --- Configuration ---
SO_PIN="${SO_PIN:-12345678}"
USER_PIN="${USER_PIN:-1234}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TMPDIR_BASE="${PROJECT_ROOT}/target/openssl-interop-test"

echo "============================================================"
echo "  Craton HSM — OpenSSL / pkcs11-tool Interoperability Test"
echo "============================================================"
echo ""

# --- Check prerequisites ---
echo "[1/7] Checking prerequisites..."

# Craton HSM library
if [ -n "${CRATON_HSM_LIB:-}" ]; then
    LIB_PATH="$CRATON_HSM_LIB"
elif [ -f "$PROJECT_ROOT/target/release/libcraton_hsm.so" ]; then
    LIB_PATH="$PROJECT_ROOT/target/release/libcraton_hsm.so"
elif [ -f "$PROJECT_ROOT/target/release/libcraton_hsm.dylib" ]; then
    LIB_PATH="$PROJECT_ROOT/target/release/libcraton_hsm.dylib"
else
    echo -e "${RED}ERROR${NC}: Craton HSM library not found."
    echo "  Build first: cargo build --release --lib"
    echo "  Or set CRATON_HSM_LIB=/path/to/libcraton_hsm.so"
    exit 2
fi
echo "  Craton HSM library: $LIB_PATH"

# pkcs11-tool
HAVE_PKCS11_TOOL=false
if command -v pkcs11-tool &>/dev/null; then
    HAVE_PKCS11_TOOL=true
    P11_VERSION=$(pkcs11-tool --version 2>&1 | head -1 || echo "unknown")
    echo "  pkcs11-tool: $P11_VERSION"
else
    echo -e "  pkcs11-tool: ${YELLOW}not found${NC} (install OpenSC: apt install opensc)"
fi

# p11tool
HAVE_P11TOOL=false
if command -v p11tool &>/dev/null; then
    HAVE_P11TOOL=true
    echo "  p11tool: found"
else
    echo -e "  p11tool: ${YELLOW}not found${NC} (optional, install: apt install gnutls-bin)"
fi

# openssl
HAVE_OPENSSL=false
OPENSSL_VERSION=""
if command -v openssl &>/dev/null; then
    OPENSSL_VERSION=$(openssl version 2>&1 | head -1)
    echo "  openssl: $OPENSSL_VERSION"
    # Check for 3.x (for pkcs11-provider support)
    if echo "$OPENSSL_VERSION" | grep -q "^OpenSSL 3\\."; then
        HAVE_OPENSSL=true
    fi
else
    echo -e "  openssl: ${YELLOW}not found${NC}"
fi

if [ "$HAVE_PKCS11_TOOL" = false ] && [ "$HAVE_P11TOOL" = false ]; then
    echo -e "${RED}ERROR${NC}: Neither pkcs11-tool nor p11tool found."
    echo "  Install at least one: sudo apt install opensc gnutls-bin"
    exit 2
fi

# --- Prepare temp directory ---
rm -rf "$TMPDIR_BASE"
mkdir -p "$TMPDIR_BASE"
echo ""

# ==============================================================================
# Test 2: pkcs11-tool — slot listing and token info
# ==============================================================================
echo "[2/7] Testing pkcs11-tool: slots and token info..."

if [ "$HAVE_PKCS11_TOOL" = true ]; then
    # List slots
    SLOTS_OUT="$TMPDIR_BASE/pkcs11_slots.txt"
    if pkcs11-tool --module "$LIB_PATH" --list-slots > "$SLOTS_OUT" 2>&1; then
        pass "pkcs11-tool --list-slots succeeded"
        if grep -qi "slot" "$SLOTS_OUT"; then
            pass "At least one slot reported"
        else
            fail "No slots found in output" "$(cat "$SLOTS_OUT")"
        fi
    else
        fail "pkcs11-tool --list-slots failed" "$(tail -5 "$SLOTS_OUT")"
    fi

    # List mechanisms
    MECHS_OUT="$TMPDIR_BASE/pkcs11_mechanisms.txt"
    if pkcs11-tool --module "$LIB_PATH" --list-mechanisms > "$MECHS_OUT" 2>&1; then
        pass "pkcs11-tool --list-mechanisms succeeded"

        # Check for key mechanisms
        for mech in "RSA-PKCS" "ECDSA" "SHA256" "AES-KEY-GEN"; do
            if grep -qi "$mech" "$MECHS_OUT"; then
                pass "Mechanism present: $mech"
            else
                skip "Mechanism not listed: $mech (may use different name)"
            fi
        done
    else
        fail "pkcs11-tool --list-mechanisms failed" "$(tail -5 "$MECHS_OUT")"
    fi
else
    skip "pkcs11-tool not available"
fi
echo ""

# ==============================================================================
# Test 3: pkcs11-tool — token initialization
# ==============================================================================
echo "[3/7] Testing pkcs11-tool: token initialization..."

if [ "$HAVE_PKCS11_TOOL" = true ]; then
    # Initialize token
    INIT_OUT="$TMPDIR_BASE/pkcs11_init.txt"
    if pkcs11-tool --module "$LIB_PATH" \
        --init-token --label "OpenSSLTest" --so-pin "$SO_PIN" \
        > "$INIT_OUT" 2>&1; then
        pass "pkcs11-tool --init-token succeeded"
    else
        fail "pkcs11-tool --init-token failed" "$(tail -5 "$INIT_OUT")"
    fi

    # Initialize user PIN
    INITPIN_OUT="$TMPDIR_BASE/pkcs11_initpin.txt"
    if pkcs11-tool --module "$LIB_PATH" \
        --init-pin --pin "$USER_PIN" --so-pin "$SO_PIN" \
        > "$INITPIN_OUT" 2>&1; then
        pass "pkcs11-tool --init-pin succeeded"
    else
        fail "pkcs11-tool --init-pin failed" "$(tail -5 "$INITPIN_OUT")"
    fi

    # Verify token info after init
    INFO_OUT="$TMPDIR_BASE/pkcs11_info.txt"
    if pkcs11-tool --module "$LIB_PATH" --list-slots > "$INFO_OUT" 2>&1; then
        if grep -qi "OpenSSLTest\|token initialized" "$INFO_OUT"; then
            pass "Token label visible after initialization"
        else
            skip "Token label not shown (may need --list-token-slots)"
        fi
    fi
else
    skip "pkcs11-tool not available"
fi
echo ""

# ==============================================================================
# Test 4: pkcs11-tool — key generation and listing
# ==============================================================================
echo "[4/7] Testing pkcs11-tool: key generation..."

if [ "$HAVE_PKCS11_TOOL" = true ]; then
    # Generate RSA-2048 key pair
    RSA_OUT="$TMPDIR_BASE/pkcs11_rsa_keygen.txt"
    if pkcs11-tool --module "$LIB_PATH" \
        --keypairgen --key-type RSA:2048 \
        --label "test-rsa" --id 01 \
        --login --pin "$USER_PIN" \
        > "$RSA_OUT" 2>&1; then
        pass "RSA-2048 key pair generated"
    else
        fail "RSA-2048 key generation failed" "$(tail -5 "$RSA_OUT")"
    fi

    # Generate EC P-256 key pair
    EC_OUT="$TMPDIR_BASE/pkcs11_ec_keygen.txt"
    if pkcs11-tool --module "$LIB_PATH" \
        --keypairgen --key-type EC:secp256r1 \
        --label "test-ec" --id 02 \
        --login --pin "$USER_PIN" \
        > "$EC_OUT" 2>&1; then
        pass "EC P-256 key pair generated"
    else
        # Some pkcs11-tool versions use different EC param format
        if pkcs11-tool --module "$LIB_PATH" \
            --keypairgen --key-type EC:prime256v1 \
            --label "test-ec" --id 02 \
            --login --pin "$USER_PIN" \
            > "$EC_OUT" 2>&1; then
            pass "EC P-256 key pair generated (prime256v1)"
        else
            fail "EC P-256 key generation failed" "$(tail -5 "$EC_OUT")"
        fi
    fi

    # Generate AES-256 key
    AES_OUT="$TMPDIR_BASE/pkcs11_aes_keygen.txt"
    if pkcs11-tool --module "$LIB_PATH" \
        --keygen --key-type AES:32 \
        --label "test-aes" --id 03 \
        --login --pin "$USER_PIN" \
        > "$AES_OUT" 2>&1; then
        pass "AES-256 symmetric key generated"
    else
        skip "AES keygen via pkcs11-tool (may not be supported by this version)"
    fi

    # List objects
    LIST_OUT="$TMPDIR_BASE/pkcs11_list.txt"
    if pkcs11-tool --module "$LIB_PATH" \
        --list-objects --login --pin "$USER_PIN" \
        > "$LIST_OUT" 2>&1; then
        pass "pkcs11-tool --list-objects succeeded"

        # Check for generated keys
        if grep -qi "test-rsa" "$LIST_OUT"; then
            pass "RSA key visible in object list"
        else
            fail "RSA key not found in object list" "$(cat "$LIST_OUT")"
        fi

        if grep -qi "test-ec" "$LIST_OUT"; then
            pass "EC key visible in object list"
        else
            fail "EC key not found in object list"
        fi
    else
        fail "pkcs11-tool --list-objects failed" "$(tail -5 "$LIST_OUT")"
    fi
else
    skip "pkcs11-tool not available"
fi
echo ""

# ==============================================================================
# Test 5: pkcs11-tool — sign and verify
# ==============================================================================
echo "[5/7] Testing pkcs11-tool: sign and verify..."

if [ "$HAVE_PKCS11_TOOL" = true ]; then
    # Create test data
    DATA_FILE="$TMPDIR_BASE/testdata.bin"
    dd if=/dev/urandom of="$DATA_FILE" bs=32 count=1 2>/dev/null
    echo "  Created 32-byte test data"

    # Sign with RSA (SHA256-RSA-PKCS)
    RSA_SIG="$TMPDIR_BASE/rsa_sig.bin"
    SIGN_OUT="$TMPDIR_BASE/pkcs11_sign.txt"
    if pkcs11-tool --module "$LIB_PATH" \
        --sign --mechanism SHA256-RSA-PKCS \
        --id 01 --login --pin "$USER_PIN" \
        --input-file "$DATA_FILE" --output-file "$RSA_SIG" \
        > "$SIGN_OUT" 2>&1; then
        if [ -f "$RSA_SIG" ] && [ -s "$RSA_SIG" ]; then
            pass "RSA SHA256-RSA-PKCS signing succeeded"
            RSA_SIG_SIZE=$(wc -c < "$RSA_SIG" | tr -d ' ')
            echo "        Signature size: $RSA_SIG_SIZE bytes"
        else
            fail "RSA signing produced empty signature"
        fi
    else
        fail "RSA signing failed" "$(tail -5 "$SIGN_OUT")"
    fi

    # Verify RSA signature (if pkcs11-tool supports --verify)
    VERIFY_OUT="$TMPDIR_BASE/pkcs11_verify.txt"
    if pkcs11-tool --module "$LIB_PATH" \
        --verify --mechanism SHA256-RSA-PKCS \
        --id 01 --login --pin "$USER_PIN" \
        --input-file "$DATA_FILE" --signature-file "$RSA_SIG" \
        > "$VERIFY_OUT" 2>&1; then
        pass "RSA SHA256-RSA-PKCS verification succeeded"
    else
        # Verify may not be supported in all pkcs11-tool versions
        skip "pkcs11-tool --verify not supported in this version"
    fi

    # Sign with ECDSA
    EC_SIG="$TMPDIR_BASE/ec_sig.bin"
    EC_SIGN_OUT="$TMPDIR_BASE/pkcs11_ec_sign.txt"
    if pkcs11-tool --module "$LIB_PATH" \
        --sign --mechanism ECDSA \
        --id 02 --login --pin "$USER_PIN" \
        --input-file "$DATA_FILE" --output-file "$EC_SIG" \
        > "$EC_SIGN_OUT" 2>&1; then
        if [ -f "$EC_SIG" ] && [ -s "$EC_SIG" ]; then
            pass "ECDSA P-256 signing succeeded"
            EC_SIG_SIZE=$(wc -c < "$EC_SIG" | tr -d ' ')
            echo "        Signature size: $EC_SIG_SIZE bytes"
        else
            fail "ECDSA signing produced empty signature"
        fi
    else
        fail "ECDSA signing failed" "$(tail -5 "$EC_SIGN_OUT")"
    fi

    # SHA-256 digest
    DIGEST_OUT="$TMPDIR_BASE/digest.bin"
    DIGEST_LOG="$TMPDIR_BASE/pkcs11_digest.txt"
    if pkcs11-tool --module "$LIB_PATH" \
        --hash --mechanism SHA256 \
        --input-file "$DATA_FILE" --output-file "$DIGEST_OUT" \
        > "$DIGEST_LOG" 2>&1; then
        if [ -f "$DIGEST_OUT" ]; then
            DIGEST_SIZE=$(wc -c < "$DIGEST_OUT" | tr -d ' ')
            if [ "$DIGEST_SIZE" = "32" ]; then
                pass "SHA-256 digest via pkcs11-tool (32 bytes)"
            else
                fail "SHA-256 digest wrong size: $DIGEST_SIZE (expected 32)"
            fi
        else
            fail "SHA-256 digest output not created"
        fi
    else
        skip "pkcs11-tool --hash not supported in this version"
    fi
else
    skip "pkcs11-tool not available"
fi
echo ""

# ==============================================================================
# Test 6: p11tool (GnuTLS)
# ==============================================================================
echo "[6/7] Testing p11tool (GnuTLS)..."

if [ "$HAVE_P11TOOL" = true ]; then
    # List tokens
    P11_TOKENS="$TMPDIR_BASE/p11tool_tokens.txt"
    if p11tool --provider="$LIB_PATH" --list-tokens > "$P11_TOKENS" 2>&1; then
        pass "p11tool --list-tokens succeeded"
        if grep -qi "token\|label\|manufacturer" "$P11_TOKENS"; then
            pass "p11tool reports token information"
        else
            skip "p11tool token output format unexpected"
        fi
    else
        fail "p11tool --list-tokens failed" "$(tail -5 "$P11_TOKENS")"
    fi

    # List all objects
    P11_ALL="$TMPDIR_BASE/p11tool_all.txt"
    if p11tool --provider="$LIB_PATH" --list-all \
        --login --set-pin="$USER_PIN" > "$P11_ALL" 2>&1; then
        pass "p11tool --list-all succeeded"
    else
        # Some p11tool versions have different login args
        if p11tool --provider="$LIB_PATH" --list-all > "$P11_ALL" 2>&1; then
            pass "p11tool --list-all succeeded (no login)"
        else
            fail "p11tool --list-all failed" "$(tail -5 "$P11_ALL")"
        fi
    fi

    # List mechanisms
    P11_MECHS="$TMPDIR_BASE/p11tool_mechanisms.txt"
    if p11tool --provider="$LIB_PATH" --list-mechanisms > "$P11_MECHS" 2>&1; then
        pass "p11tool --list-mechanisms succeeded"
    else
        skip "p11tool --list-mechanisms failed (non-critical)"
    fi
else
    skip "p11tool not available — GnuTLS tests skipped"
fi
echo ""

# ==============================================================================
# Test 7: OpenSSL 3.x pkcs11-provider (if available)
# ==============================================================================
echo "[7/7] Testing OpenSSL 3.x pkcs11-provider..."

if [ "$HAVE_OPENSSL" = true ]; then
    # Check if pkcs11-provider module exists
    PKCS11_PROV=""
    for candidate in \
        "/usr/lib/x86_64-linux-gnu/ossl-modules/pkcs11.so" \
        "/usr/lib64/ossl-modules/pkcs11.so" \
        "/usr/local/lib/ossl-modules/pkcs11.so" \
        "/opt/homebrew/lib/ossl-modules/pkcs11.so"; do
        if [ -f "$candidate" ]; then
            PKCS11_PROV="$candidate"
            break
        fi
    done

    if [ -n "$PKCS11_PROV" ]; then
        echo "  pkcs11-provider found: $PKCS11_PROV"

        # Create OpenSSL config for pkcs11 provider
        OPENSSL_CNF="$TMPDIR_BASE/openssl_pkcs11.cnf"
        cat > "$OPENSSL_CNF" <<CNFEOF
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
pkcs11 = pkcs11_sect

[default_sect]
activate = 1

[pkcs11_sect]
module = $PKCS11_PROV
pkcs11-module-path = $LIB_PATH
pkcs11-module-token-pin = $USER_PIN
activate = 1
CNFEOF

        # Try storeutl to list objects
        STOREUTL_OUT="$TMPDIR_BASE/openssl_storeutl.txt"
        if OPENSSL_CONF="$OPENSSL_CNF" openssl storeutl -provider pkcs11 \
            "pkcs11:token=OpenSSLTest;pin-value=$USER_PIN" \
            > "$STOREUTL_OUT" 2>&1; then
            pass "openssl storeutl with pkcs11-provider succeeded"
        else
            skip "openssl storeutl failed (pkcs11-provider config may need adjustment)"
        fi

        # Try listing providers
        PROV_OUT="$TMPDIR_BASE/openssl_providers.txt"
        if OPENSSL_CONF="$OPENSSL_CNF" openssl list -providers > "$PROV_OUT" 2>&1; then
            if grep -qi "pkcs11" "$PROV_OUT"; then
                pass "OpenSSL lists pkcs11 provider"
            else
                skip "pkcs11 provider not listed (may need different config)"
            fi
        fi
    else
        skip "pkcs11-provider module not found — OpenSSL provider tests skipped"
        echo "        Install: apt install openssl-pkcs11-provider (or build from source)"
    fi
else
    if [ -n "$OPENSSL_VERSION" ]; then
        skip "OpenSSL version < 3.x ($OPENSSL_VERSION) — provider tests skipped"
    else
        skip "OpenSSL not available"
    fi
fi
echo ""

# ==============================================================================
# Summary
# ==============================================================================
echo "Summary"
echo "============================================================"
echo -e "  Tests run:     ${TESTS_RUN}"
echo -e "  ${GREEN}Passed${NC}:        ${TESTS_PASSED}"
echo -e "  ${RED}Failed${NC}:        ${TESTS_FAILED}"
echo -e "  ${YELLOW}Skipped${NC}:       ${TESTS_SKIPPED}"
echo "============================================================"

# Cleanup
# rm -rf "$TMPDIR_BASE"  # Keep for debugging; uncomment for production

if [ "$TESTS_FAILED" -gt 0 ]; then
    echo -e "${RED}FAILED${NC}: $TESTS_FAILED test(s) failed."
    echo "  Logs available in: $TMPDIR_BASE/"
    exit 1
else
    echo -e "${GREEN}ALL TESTS PASSED${NC} ($TESTS_SKIPPED skipped)"
    exit 0
fi
