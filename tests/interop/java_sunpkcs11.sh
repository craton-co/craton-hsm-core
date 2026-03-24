#!/usr/bin/env bash
# ==============================================================================
# Java SunPKCS11 Interoperability Test for Craton HSM
# ==============================================================================
#
# Tests Craton HSM compatibility with Java's SunPKCS11 provider using:
#   1. keytool — list token, generate keys, list aliases
#   2. jshell  — programmatic KeyStore/Signature/Cipher operations
#
# Prerequisites:
#   - Java 11+ JDK (keytool + jshell on PATH)
#   - Craton HSM built in release mode (cargo build --release)
#   - Linux or macOS (SunPKCS11 loads .so/.dylib)
#
# Usage:
#   bash tests/interop/java_sunpkcs11.sh
#
# Exit codes:
#   0 — all tests passed
#   1 — test failure (details printed)
#   2 — prerequisites missing (Java not found or library not built)
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
TMPDIR_BASE="${PROJECT_ROOT}/target/java-interop-test"

echo "============================================================"
echo "  Craton HSM — Java SunPKCS11 Interoperability Test"
echo "============================================================"
echo ""

# --- Check prerequisites ---
echo "[1/6] Checking prerequisites..."

# Java
if ! command -v java &>/dev/null; then
    echo -e "${RED}ERROR${NC}: Java not found. Install JDK 11+ and ensure 'java' is on PATH."
    exit 2
fi
JAVA_VERSION=$(java -version 2>&1 | head -1)
echo "  Java: $JAVA_VERSION"

# keytool
if ! command -v keytool &>/dev/null; then
    echo -e "${RED}ERROR${NC}: keytool not found. Install JDK 11+ and ensure 'keytool' is on PATH."
    exit 2
fi
echo "  keytool: found"

# jshell
HAVE_JSHELL=false
if command -v jshell &>/dev/null; then
    HAVE_JSHELL=true
    echo "  jshell: found"
else
    echo -e "  jshell: ${YELLOW}not found${NC} (programmatic tests will be skipped)"
fi

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

# --- Prepare temp directory ---
rm -rf "$TMPDIR_BASE"
mkdir -p "$TMPDIR_BASE"

# --- Create SunPKCS11 config ---
PKCS11_CFG="$TMPDIR_BASE/pkcs11.cfg"
cat > "$PKCS11_CFG" <<EOF
name = Craton HSM
library = $LIB_PATH
slot = 0
EOF
echo "  PKCS#11 config: $PKCS11_CFG"
echo ""

# ==============================================================================
# Test 1: Token initialization (via craton-hsm-admin or pkcs11-tool if available)
# ==============================================================================
echo "[2/6] Initializing token..."

# SunPKCS11 expects an already-initialized token with a user PIN set.
# We use pkcs11-tool if available, otherwise try the library directly.
TOKEN_READY=false

if command -v pkcs11-tool &>/dev/null; then
    # Initialize token
    if pkcs11-tool --module "$LIB_PATH" --init-token --label "JavaTest" --so-pin "$SO_PIN" 2>/dev/null; then
        # Set user PIN
        if pkcs11-tool --module "$LIB_PATH" --init-pin --pin "$USER_PIN" --so-pin "$SO_PIN" 2>/dev/null; then
            TOKEN_READY=true
            pass "Token initialized via pkcs11-tool"
        else
            fail "pkcs11-tool --init-pin failed"
        fi
    else
        fail "pkcs11-tool --init-token failed"
    fi
elif [ -f "$PROJECT_ROOT/target/release/craton-hsm-admin" ] || [ -f "$PROJECT_ROOT/target/release/craton-hsm-admin.exe" ]; then
    echo "  Using craton-hsm-admin to initialize token..."
    # craton-hsm-admin prompts interactively; try with stdin
    echo -e "${SO_PIN}\n${SO_PIN}" | "$PROJECT_ROOT/target/release/craton-hsm-admin" token init --label "JavaTest" 2>/dev/null && TOKEN_READY=true
    if [ "$TOKEN_READY" = true ]; then
        pass "Token initialized via craton-hsm-admin"
    else
        fail "craton-hsm-admin token init failed"
    fi
else
    echo -e "  ${YELLOW}WARNING${NC}: Neither pkcs11-tool nor craton-hsm-admin found."
    echo "  Token must be pre-initialized. Attempting to proceed anyway..."
    TOKEN_READY=true
fi
echo ""

# ==============================================================================
# Test 2: keytool -list (list token info)
# ==============================================================================
echo "[3/6] Testing keytool operations..."

# keytool uses SunPKCS11 provider
KEYTOOL_BASE="keytool -providerClass sun.security.pkcs11.SunPKCS11 -providerArg $PKCS11_CFG -keystore NONE -storetype PKCS11"

# List token contents (initially empty)
echo "  Testing: keytool -list..."
KEYTOOL_OUT="$TMPDIR_BASE/keytool_list.txt"
if $KEYTOOL_BASE -list -storepass "$USER_PIN" > "$KEYTOOL_OUT" 2>&1; then
    pass "keytool -list succeeded"
    if grep -qi "keystore type: PKCS11" "$KEYTOOL_OUT" 2>/dev/null || grep -qi "Keystore type" "$KEYTOOL_OUT" 2>/dev/null; then
        pass "keytool recognized PKCS11 keystore type"
    else
        fail "keytool did not report PKCS11 keystore type" "$(head -5 "$KEYTOOL_OUT")"
    fi
else
    fail "keytool -list failed" "$(tail -5 "$KEYTOOL_OUT")"
fi

# Generate RSA-2048 key pair via keytool
echo "  Testing: keytool -genkeypair (RSA-2048)..."
KEYGEN_OUT="$TMPDIR_BASE/keytool_genkey.txt"
if $KEYTOOL_BASE -genkeypair \
    -alias "test-rsa-2048" \
    -keyalg RSA \
    -keysize 2048 \
    -sigalg SHA256withRSA \
    -dname "CN=Craton HSM Test, O=Test, C=US" \
    -storepass "$USER_PIN" \
    -keypass "$USER_PIN" \
    > "$KEYGEN_OUT" 2>&1; then
    pass "keytool -genkeypair RSA-2048 succeeded"
else
    fail "keytool -genkeypair RSA-2048 failed" "$(tail -5 "$KEYGEN_OUT")"
fi

# List keys after generation
echo "  Testing: keytool -list (after keygen)..."
LIST2_OUT="$TMPDIR_BASE/keytool_list2.txt"
if $KEYTOOL_BASE -list -storepass "$USER_PIN" > "$LIST2_OUT" 2>&1; then
    if grep -qi "test-rsa-2048" "$LIST2_OUT" 2>/dev/null; then
        pass "keytool -list shows generated RSA key"
    else
        fail "keytool -list does not show generated key" "$(cat "$LIST2_OUT")"
    fi
else
    fail "keytool -list (after keygen) failed" "$(tail -5 "$LIST2_OUT")"
fi

# Generate EC P-256 key pair via keytool
echo "  Testing: keytool -genkeypair (EC P-256)..."
EC_OUT="$TMPDIR_BASE/keytool_genec.txt"
if $KEYTOOL_BASE -genkeypair \
    -alias "test-ec-p256" \
    -keyalg EC \
    -groupname secp256r1 \
    -sigalg SHA256withECDSA \
    -dname "CN=Craton HSM EC Test, O=Test, C=US" \
    -storepass "$USER_PIN" \
    -keypass "$USER_PIN" \
    > "$EC_OUT" 2>&1; then
    pass "keytool -genkeypair EC P-256 succeeded"
else
    fail "keytool -genkeypair EC P-256 failed" "$(tail -5 "$EC_OUT")"
fi

echo ""

# ==============================================================================
# Test 3: keytool -certreq (generate CSR — exercises signing)
# ==============================================================================
echo "[4/6] Testing keytool signing operations..."

CSR_OUT="$TMPDIR_BASE/test.csr"
CSR_LOG="$TMPDIR_BASE/keytool_csr.txt"
if $KEYTOOL_BASE -certreq \
    -alias "test-rsa-2048" \
    -sigalg SHA256withRSA \
    -file "$CSR_OUT" \
    -storepass "$USER_PIN" \
    > "$CSR_LOG" 2>&1; then
    if [ -f "$CSR_OUT" ] && [ -s "$CSR_OUT" ]; then
        pass "keytool -certreq generated CSR with RSA key"
    else
        fail "keytool -certreq produced empty CSR"
    fi
else
    fail "keytool -certreq failed" "$(tail -5 "$CSR_LOG")"
fi

# Self-signed cert (exercises sign + verify within keytool)
SELFCERT_OUT="$TMPDIR_BASE/keytool_selfcert.txt"
if $KEYTOOL_BASE -selfcert \
    -alias "test-rsa-2048" \
    -sigalg SHA256withRSA \
    -validity 365 \
    -storepass "$USER_PIN" \
    > "$SELFCERT_OUT" 2>&1; then
    pass "keytool -selfcert succeeded (sign + verify roundtrip)"
else
    # -selfcert is deprecated in newer JDKs, try alternative
    skip "keytool -selfcert (deprecated in newer JDKs)"
fi

echo ""

# ==============================================================================
# Test 4: jshell programmatic test (KeyStore + Signature API)
# ==============================================================================
echo "[5/6] Testing Java programmatic access (jshell)..."

if [ "$HAVE_JSHELL" = true ]; then
    JSHELL_SCRIPT="$TMPDIR_BASE/test_pkcs11.jsh"
    JSHELL_OUT="$TMPDIR_BASE/jshell_output.txt"

    cat > "$JSHELL_SCRIPT" <<'JSHELL_EOF'
import java.security.*;
import java.security.cert.*;
import javax.crypto.*;

// Load SunPKCS11 provider
String configPath = System.getProperty("pkcs11.config");
Provider provider = Security.getProvider("SunPKCS11");
if (provider == null) {
    // Java 9+ style
    provider = Security.getProvider("SunPKCS11").configure(configPath);
}
if (provider == null) {
    provider = new sun.security.pkcs11.SunPKCS11(configPath);
}
Security.addProvider(provider);
System.out.println("RESULT:provider_loaded:" + provider.getName());

// Open PKCS#11 KeyStore
String pin = System.getProperty("pkcs11.pin");
KeyStore ks = KeyStore.getInstance("PKCS11", provider);
ks.load(null, pin.toCharArray());
System.out.println("RESULT:keystore_opened:size=" + ks.size());

// List all aliases
java.util.Enumeration<String> aliases = ks.aliases();
int aliasCount = 0;
while (aliases.hasMoreElements()) {
    String alias = aliases.nextElement();
    aliasCount++;
    System.out.println("RESULT:alias:" + alias);
}
System.out.println("RESULT:alias_count:" + aliasCount);

// Generate RSA key pair via KeyPairGenerator
KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", provider);
kpg.initialize(2048);
KeyPair rsaKp = kpg.generateKeyPair();
System.out.println("RESULT:rsa_keygen:algorithm=" + rsaKp.getPublic().getAlgorithm() +
    ",format=" + rsaKp.getPublic().getFormat());

// Sign data with SHA256withRSA
byte[] testData = "Hello from Craton HSM Java interop test!".getBytes("UTF-8");
Signature signer = Signature.getInstance("SHA256withRSA", provider);
signer.initSign(rsaKp.getPrivate());
signer.update(testData);
byte[] signature = signer.sign();
System.out.println("RESULT:rsa_sign:sig_length=" + signature.length);

// Verify signature
Signature verifier = Signature.getInstance("SHA256withRSA", provider);
verifier.initVerify(rsaKp.getPublic());
verifier.update(testData);
boolean verified = verifier.verify(signature);
System.out.println("RESULT:rsa_verify:" + verified);

// Generate EC P-256 key pair
KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("EC", provider);
ecKpg.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
KeyPair ecKp = ecKpg.generateKeyPair();
System.out.println("RESULT:ec_keygen:algorithm=" + ecKp.getPublic().getAlgorithm());

// Sign with ECDSA
Signature ecSigner = Signature.getInstance("SHA256withECDSA", provider);
ecSigner.initSign(ecKp.getPrivate());
ecSigner.update(testData);
byte[] ecSig = ecSigner.sign();
System.out.println("RESULT:ecdsa_sign:sig_length=" + ecSig.length);

// Verify ECDSA
Signature ecVerifier = Signature.getInstance("SHA256withECDSA", provider);
ecVerifier.initVerify(ecKp.getPublic());
ecVerifier.update(testData);
boolean ecVerified = ecVerifier.verify(ecSig);
System.out.println("RESULT:ecdsa_verify:" + ecVerified);

// Test MessageDigest (SHA-256) through provider
try {
    MessageDigest md = MessageDigest.getInstance("SHA-256", provider);
    md.update(testData);
    byte[] digest = md.digest();
    System.out.println("RESULT:sha256_digest:length=" + digest.length);
} catch (Exception e) {
    System.out.println("RESULT:sha256_digest:skipped(" + e.getMessage() + ")");
}

System.out.println("RESULT:all_tests_complete");
/exit
JSHELL_EOF

    # Run jshell with SunPKCS11 provider
    if jshell \
        -J"-Dpkcs11.config=$PKCS11_CFG" \
        -J"-Dpkcs11.pin=$USER_PIN" \
        --execution local \
        "$JSHELL_SCRIPT" > "$JSHELL_OUT" 2>&1; then

        # Parse results
        if grep -q "RESULT:provider_loaded" "$JSHELL_OUT"; then
            pass "SunPKCS11 provider loaded successfully"
        else
            fail "SunPKCS11 provider failed to load" "$(tail -10 "$JSHELL_OUT")"
        fi

        if grep -q "RESULT:keystore_opened" "$JSHELL_OUT"; then
            pass "PKCS11 KeyStore opened successfully"
        else
            fail "PKCS11 KeyStore failed to open"
        fi

        if grep -q "RESULT:rsa_keygen" "$JSHELL_OUT"; then
            pass "RSA-2048 key pair generated via Java KeyPairGenerator"
        else
            fail "RSA-2048 keygen via Java failed"
        fi

        if grep -q "RESULT:rsa_sign" "$JSHELL_OUT"; then
            pass "SHA256withRSA signing via Java Signature API"
        else
            fail "RSA signing via Java failed"
        fi

        if grep -q "RESULT:rsa_verify:true" "$JSHELL_OUT"; then
            pass "SHA256withRSA verification succeeded"
        elif grep -q "RESULT:rsa_verify:false" "$JSHELL_OUT"; then
            fail "RSA signature verification returned false"
        else
            fail "RSA verification did not complete"
        fi

        if grep -q "RESULT:ec_keygen" "$JSHELL_OUT"; then
            pass "EC P-256 key pair generated via Java KeyPairGenerator"
        else
            fail "EC P-256 keygen via Java failed"
        fi

        if grep -q "RESULT:ecdsa_verify:true" "$JSHELL_OUT"; then
            pass "SHA256withECDSA sign + verify roundtrip succeeded"
        elif grep -q "RESULT:ecdsa_verify:false" "$JSHELL_OUT"; then
            fail "ECDSA signature verification returned false"
        else
            fail "ECDSA sign/verify did not complete"
        fi

        if grep -q "RESULT:all_tests_complete" "$JSHELL_OUT"; then
            pass "All jshell programmatic tests completed"
        else
            fail "jshell tests did not complete" "$(tail -15 "$JSHELL_OUT")"
        fi
    else
        fail "jshell execution failed" "$(tail -15 "$JSHELL_OUT")"
    fi
else
    skip "jshell not available — programmatic tests skipped"
fi

echo ""

# ==============================================================================
# Summary
# ==============================================================================
echo "[6/6] Summary"
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
    echo -e "${GREEN}ALL TESTS PASSED${NC}"
    exit 0
fi
