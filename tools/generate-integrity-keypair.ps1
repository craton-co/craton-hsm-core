# generate-integrity-keypair.ps1
# Generates an Ed25519 keypair for binary integrity signing.
#
# Usage:
#   .\tools\generate-integrity-keypair.ps1 [-OutputDir <path>]
#
# Requires: OpenSSL on PATH (e.g., from Git for Windows or standalone install)
#
# The private key must NEVER be committed to VCS or distributed.

param(
    [string]$OutputDir
)

if (-not $OutputDir) {
    $OutputDir = Join-Path $env:USERPROFILE ".craton_hsm"
}

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

$privKeyPath = Join-Path $OutputDir "integrity-signing-key.pem"

if (Test-Path $privKeyPath) {
    Write-Host "WARNING: Private key already exists at $privKeyPath"
    Write-Host "To regenerate, delete it first."
    Write-Host ""
    Write-Host "Extracting public key from existing keypair..."
} else {
    # Generate Ed25519 private key
    & openssl genpkey -algorithm Ed25519 -out $privKeyPath 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to generate keypair. Ensure OpenSSL is on PATH."
        exit 1
    }
    Write-Host "Generated private key: $privKeyPath"
}

# Extract raw 32-byte public key in DER format, take last 32 bytes
$derBytes = & openssl pkey -in $privKeyPath -pubout -outform DER 2>$null
if (-not $derBytes -or $derBytes.Length -lt 32) {
    # Fallback: write to temp file and read
    $tmpDer = [System.IO.Path]::GetTempFileName()
    & openssl pkey -in $privKeyPath -pubout -outform DER -out $tmpDer 2>$null
    $derBytes = [System.IO.File]::ReadAllBytes($tmpDer)
    Remove-Item $tmpDer -Force
}

# Ed25519 DER public key: last 32 bytes are the raw key
$pubKeyBytes = $derBytes[($derBytes.Length - 32)..($derBytes.Length - 1)]
$pubKeyHex = ($pubKeyBytes | ForEach-Object { $_.ToString("x2") }) -join ""

Write-Host ""
Write-Host "=== Public key (hex) ==="
Write-Host $pubKeyHex
Write-Host ""
Write-Host "=== Paste this into src/crypto/integrity.rs ==="
Write-Host "const INTEGRITY_PUBLIC_KEY: [u8; 32] = ["

for ($i = 0; $i -lt $pubKeyBytes.Length; $i += 8) {
    $end = [Math]::Min($i + 8, $pubKeyBytes.Length)
    $line = ($pubKeyBytes[$i..($end-1)] | ForEach-Object { "0x" + $_.ToString("x2") }) -join ", "
    Write-Host "    $line,"
}

Write-Host "];"
Write-Host ""
Write-Host "=== SECURITY ==="
Write-Host "Private key: $privKeyPath"
Write-Host "  - NEVER commit this to version control"
Write-Host "  - Keep in build pipeline / CI secrets only"
Write-Host "  - Back up securely - losing it requires re-signing all binaries"
