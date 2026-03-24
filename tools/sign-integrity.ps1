# sign-integrity.ps1
# Signs a Craton HSM binary with Ed25519 and writes a .sig sidecar file.
#
# Usage:
#   .\tools\sign-integrity.ps1 [-LibPath <path>] [-PrivKeyPath <path>]
#
# If -LibPath is not specified, defaults to:
#   target\release\craton_hsm.dll (Windows)
#
# Private key is loaded from (in order):
#   1. -PrivKeyPath argument
#   2. CRATON_HSM_SIGNING_KEY environment variable
#   3. ~\.craton_hsm\integrity-signing-key.pem

param(
    [string]$LibPath,
    [string]$PrivKeyPath
)

# Default library path
if (-not $LibPath) {
    $LibPath = "target\release\craton_hsm.dll"
}

if (-not (Test-Path $LibPath)) {
    Write-Error "Library not found at $LibPath. Build first: cargo build --release --lib"
    exit 1
}

# Locate private key
if (-not $PrivKeyPath -and $env:CRATON_HSM_SIGNING_KEY) {
    $PrivKeyPath = $env:CRATON_HSM_SIGNING_KEY
}
if (-not $PrivKeyPath) {
    $PrivKeyPath = Join-Path $env:USERPROFILE ".craton_hsm\integrity-signing-key.pem"
}

if (-not (Test-Path $PrivKeyPath)) {
    Write-Error "Ed25519 private key not found at $PrivKeyPath. Generate one with: .\tools\generate-integrity-keypair.ps1"
    exit 1
}

$resolvedLib = (Resolve-Path $LibPath).Path

# Compute SHA-256 hash of the binary
$libBytes = [System.IO.File]::ReadAllBytes($resolvedLib)
$sha256 = [System.Security.Cryptography.SHA256]::Create()
$hashBytes = $sha256.ComputeHash($libBytes)
$hashHex = ($hashBytes | ForEach-Object { $_.ToString("x2") }) -join ""

# Write hash to temp file for openssl to sign
$hashTmpFile = [System.IO.Path]::GetTempFileName()
$sigTmpFile = [System.IO.Path]::GetTempFileName()

try {
    [System.IO.File]::WriteAllBytes($hashTmpFile, $hashBytes)

    # Sign with openssl pkeyutl
    & openssl pkeyutl -sign `
        -inkey $PrivKeyPath `
        -in $hashTmpFile `
        -out $sigTmpFile `
        -rawin 2>$null

    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $sigTmpFile) -or (Get-Item $sigTmpFile).Length -eq 0) {
        Write-Error "Signing failed."
        exit 1
    }

    # Read signature and convert to hex
    $sigBytes = [System.IO.File]::ReadAllBytes($sigTmpFile)
    $sigHex = ($sigBytes | ForEach-Object { $_.ToString("x2") }) -join ""

    if ($sigHex.Length -ne 128) {
        Write-Error "Unexpected signature length ($($sigHex.Length) hex chars, expected 128)."
        exit 1
    }

    # Write .sig sidecar file
    $sigPath = [System.IO.Path]::ChangeExtension($resolvedLib, "sig")
    Set-Content -Path $sigPath -Value $sigHex -NoNewline

    Write-Host "Signed:      $resolvedLib"
    Write-Host "Signature:   $sigPath"
    Write-Host "Binary size: $($libBytes.Length) bytes"
    Write-Host "SHA-256:     $hashHex"
}
finally {
    # Clean up temp files and sensitive data
    Remove-Item $hashTmpFile -Force -ErrorAction SilentlyContinue
    Remove-Item $sigTmpFile -Force -ErrorAction SilentlyContinue
    [Array]::Clear($libBytes, 0, $libBytes.Length)
    [Array]::Clear($hashBytes, 0, $hashBytes.Length)
    $sha256.Dispose()
    $libBytes = $null
    $hashBytes = $null
    [System.GC]::Collect()
}
