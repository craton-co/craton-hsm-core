#!/bin/bash
# sign-integrity.sh
# Signs a Craton HSM binary with Ed25519 and writes a .sig sidecar file.
#
# Usage:
#   ./tools/sign-integrity.sh [path-to-library] [private-key-pem]
#
# If path is not specified, defaults to:
#   target/release/libcraton_hsm.so (Linux)
#   target/release/libcraton_hsm.dylib (macOS)
#
# Private key is loaded from (in order):
#   1. Second argument (path to PEM file)
#   2. CRATON_HSM_SIGNING_KEY environment variable (path to PEM file)
#   3. ~/.craton_hsm/integrity-signing-key.pem
#
# The output .sig file is placed next to the library.

set -euo pipefail

LIB_PATH="${1:-}"

if [ -z "$LIB_PATH" ]; then
    if [ "$(uname)" = "Darwin" ]; then
        LIB_PATH="target/release/libcraton_hsm.dylib"
    else
        LIB_PATH="target/release/libcraton_hsm.so"
    fi
fi

if [ ! -f "$LIB_PATH" ]; then
    echo "ERROR: Library not found at $LIB_PATH"
    echo "Build first: cargo build --release --lib"
    exit 1
fi

# Locate private key
PRIVKEY_PATH="${2:-}"
if [ -z "$PRIVKEY_PATH" ] && [ -n "${CRATON_HSM_SIGNING_KEY:-}" ]; then
    PRIVKEY_PATH="$CRATON_HSM_SIGNING_KEY"
fi
if [ -z "$PRIVKEY_PATH" ]; then
    PRIVKEY_PATH="$HOME/.craton_hsm/integrity-signing-key.pem"
fi

if [ ! -f "$PRIVKEY_PATH" ]; then
    echo "ERROR: Ed25519 private key not found at $PRIVKEY_PATH"
    echo "Generate one with: ./tools/generate-integrity-keypair.sh"
    exit 1
fi

# Compute SHA-256 hash of the binary
HASH_HEX=$(sha256sum "$LIB_PATH" | awk '{print $1}')
HASH_BYTES=$(echo "$HASH_HEX" | xxd -r -p)

# Sign the SHA-256 hash with Ed25519
# Write hash bytes to a temp file for openssl to sign
OLD_UMASK=$(umask)
umask 077
HASH_TMPFILE=$(mktemp)
umask "$OLD_UMASK"
trap 'rm -f "$HASH_TMPFILE" "${HASH_TMPFILE}.sig"' EXIT

printf "%s" "$HASH_HEX" | xxd -r -p > "$HASH_TMPFILE"

# Sign using openssl pkeyutl (Ed25519 uses pure signing, no separate digest)
openssl pkeyutl -sign \
    -inkey "$PRIVKEY_PATH" \
    -in "$HASH_TMPFILE" \
    -out "${HASH_TMPFILE}.sig" \
    -rawin 2>/dev/null

if [ ! -s "${HASH_TMPFILE}.sig" ]; then
    echo "ERROR: Signing failed."
    exit 1
fi

# Convert signature to hex
SIG_HEX=$(od -An -tx1 < "${HASH_TMPFILE}.sig" | tr -d ' \n')

# Clean up temp files
rm -f "$HASH_TMPFILE" "${HASH_TMPFILE}.sig"

if [ ${#SIG_HEX} -ne 128 ]; then
    echo "ERROR: Unexpected signature length (${#SIG_HEX} hex chars, expected 128)."
    exit 1
fi

# Write .sig sidecar file
SIG_PATH="${LIB_PATH%.*}.sig"
printf "%s" "$SIG_HEX" > "$SIG_PATH"
chmod 600 "$SIG_PATH"

echo "Signed:      $LIB_PATH"
echo "Signature:   $SIG_PATH"
echo "Binary size: $(wc -c < "$LIB_PATH") bytes"
echo "SHA-256:     $HASH_HEX"
