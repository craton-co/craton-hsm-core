#!/bin/bash
# generate-integrity-keypair.sh
# Generates an Ed25519 keypair for binary integrity signing.
#
# Usage:
#   ./tools/generate-integrity-keypair.sh [output-dir]
#
# Outputs:
#   - Private key PEM  → <output-dir>/integrity-signing-key.pem
#   - Public key bytes → printed as Rust const to embed in integrity.rs
#
# The private key must NEVER be committed to VCS or distributed.
# Keep it in the build pipeline only.

set -euo pipefail

OUTPUT_DIR="${1:-$HOME/.craton_hsm}"
mkdir -p "$OUTPUT_DIR"
chmod 700 "$OUTPUT_DIR"

PRIVKEY_PATH="$OUTPUT_DIR/integrity-signing-key.pem"

if [ -f "$PRIVKEY_PATH" ]; then
    echo "WARNING: Private key already exists at $PRIVKEY_PATH"
    echo "To regenerate, delete it first."
    echo ""
    echo "Extracting public key from existing keypair..."
else
    # Generate Ed25519 private key
    openssl genpkey -algorithm Ed25519 -out "$PRIVKEY_PATH" 2>/dev/null
    chmod 600 "$PRIVKEY_PATH"
    echo "Generated private key: $PRIVKEY_PATH"
fi

# Extract raw 32-byte public key and format as Rust const
PUBKEY_HEX=$(openssl pkey -in "$PRIVKEY_PATH" -pubout -outform DER 2>/dev/null | tail -c 32 | od -An -tx1 | tr -d ' \n')

echo ""
echo "=== Public key (hex) ==="
echo "$PUBKEY_HEX"
echo ""
echo "=== Paste this into src/crypto/integrity.rs ==="
echo "const INTEGRITY_PUBLIC_KEY: [u8; 32] = ["

# Format as Rust byte array (4 bytes per line)
i=0
line=""
for byte in $(echo "$PUBKEY_HEX" | sed 's/\(..\)/\1 /g'); do
    line="${line}0x${byte}, "
    i=$((i + 1))
    if [ $((i % 8)) -eq 0 ]; then
        echo "    ${line}"
        line=""
    fi
done
if [ -n "$line" ]; then
    echo "    ${line}"
fi
echo "];"
echo ""
echo "=== SECURITY ==="
echo "Private key: $PRIVKEY_PATH"
echo "  - NEVER commit this to version control"
echo "  - Keep in build pipeline / CI secrets only"
echo "  - Back up securely — losing it requires re-signing all binaries"
