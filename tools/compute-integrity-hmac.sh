#!/bin/bash
# compute-integrity-hmac.sh
# Computes HMAC-SHA256 of the Craton HSM library and writes a .hmac sidecar file.
#
# Usage:
#   ./tools/compute-integrity-hmac.sh [path-to-library]
#
# If path is not specified, defaults to:
#   target/release/libcraton_hsm.so (Linux)
#   target/release/libcraton_hsm.dylib (macOS)
#
# The output .hmac file is placed next to the library.

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

# The HMAC key must match INTEGRITY_HMAC_KEY in src/crypto/integrity.rs.
# SECURITY: Never hardcode this key. Supply it via CRATON_HSM_INTEGRITY_KEY env var
# or a key file (--key-file). The key must be kept secret and not committed to VCS.
if [ -n "${CRATON_HSM_INTEGRITY_KEY:-}" ]; then
    HMAC_KEY="$CRATON_HSM_INTEGRITY_KEY"
elif [ -n "${1:-}" ] && [ -f "${2:-}" ]; then
    # Allow: ./compute-integrity-hmac.sh <lib-path> <key-file>
    HMAC_KEY=$(cat "$2")
elif [ -f "$HOME/.craton_hsm/integrity-key" ]; then
    HMAC_KEY=$(cat "$HOME/.craton_hsm/integrity-key")
else
    echo "ERROR: HMAC integrity key not provided."
    echo "Set CRATON_HSM_INTEGRITY_KEY environment variable, or place key in ~/.craton_hsm/integrity-key"
    exit 1
fi

if [ -z "$HMAC_KEY" ]; then
    echo "ERROR: HMAC key is empty."
    exit 1
fi

# Compute HMAC-SHA256 using OpenSSL.
# SECURITY: The key is passed via a temporary file and fed to openssl via
# stdin or -macopt hexkey: to prevent exposure in /proc/<pid>/cmdline or `ps aux`.
# Never pass the key as a command-line argument (e.g. -hmac "$KEY") — the
# argument is visible to other users via `ps` while the process is running.
OLD_UMASK=$(umask)
umask 077
KEY_TMPFILE=$(mktemp)
umask "$OLD_UMASK"
trap 'rm -f "$KEY_TMPFILE"' EXIT
printf "%s" "$HMAC_KEY" > "$KEY_TMPFILE"
chmod 600 "$KEY_TMPFILE"

# Convert key to hex so we can use -macopt hexkey: (key never in argv)
HMAC_KEY_HEX=$(od -An -tx1 < "$KEY_TMPFILE" | tr -d ' \n')
rm -f "$KEY_TMPFILE"

# Use openssl dgst with hexkey option — key stays out of the process argument list.
# SECURITY: No fallback to `-hmac "$KEY"` — that would expose the key in
# /proc/<pid>/cmdline and `ps aux` output, defeating the entire point of the
# hexkey approach.
HMAC_HEX=$(openssl dgst -sha256 -mac HMAC -macopt "hexkey:${HMAC_KEY_HEX}" "$LIB_PATH" 2>/dev/null | awk '{print $NF}') || true

# Clear sensitive key material from shell variables immediately after use.
# `unset` removes the variable from the shell's symbol table; setting to ""
# first overwrites the value in case the shell implementation retains it.
HMAC_KEY_HEX=""
unset HMAC_KEY_HEX
HMAC_KEY=""
unset HMAC_KEY

if [ -z "$HMAC_HEX" ]; then
    echo "ERROR: HMAC computation failed."
    exit 1
fi

# Write .hmac sidecar file (strip extension, add .hmac)
HMAC_PATH="${LIB_PATH%.*}.hmac"
printf "%s" "$HMAC_HEX" > "$HMAC_PATH"
chmod 600 "$HMAC_PATH"

echo "Written to:  $HMAC_PATH"
echo "Library:     $LIB_PATH"
echo "Size:        $(wc -c < "$LIB_PATH") bytes"
