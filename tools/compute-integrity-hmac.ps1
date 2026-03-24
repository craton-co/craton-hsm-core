# compute-integrity-hmac.ps1
# Computes HMAC-SHA256 of the Craton HSM library and writes a .hmac sidecar file.
#
# Usage:
#   .\tools\compute-integrity-hmac.ps1 [-LibPath <path>]
#
# If -LibPath is not specified, defaults to:
#   target/release/craton_hsm.dll (Windows)
#
# The output .hmac file is placed next to the library.

param(
    [string]$LibPath,
    [string]$KeyFile
)

# Default path
if (-not $LibPath) {
    $LibPath = "target\release\craton_hsm.dll"
}

if (-not (Test-Path $LibPath)) {
    Write-Error "Library not found at $LibPath. Build first: cargo build --release --lib"
    exit 1
}

# The HMAC key must match INTEGRITY_HMAC_KEY in src/crypto/integrity.rs.
# SECURITY: Never hardcode this key. Supply it via CRATON_HSM_INTEGRITY_KEY env var
# or a key file (-KeyFile). The key must be kept secret and not committed to VCS.
$keyString = $env:CRATON_HSM_INTEGRITY_KEY
if (-not $keyString -and $KeyFile -and (Test-Path $KeyFile)) {
    $keyString = (Get-Content -Path $KeyFile -Raw).Trim()
}
$defaultKeyPath = Join-Path $env:USERPROFILE ".craton_hsm\integrity-key"
if (-not $keyString -and (Test-Path $defaultKeyPath)) {
    $keyString = (Get-Content -Path $defaultKeyPath -Raw).Trim()
}
if (-not $keyString) {
    Write-Error "HMAC integrity key not provided. Set CRATON_HSM_INTEGRITY_KEY environment variable, or place key in ~\.craton_hsm\integrity-key"
    exit 1
}
$keyBytes = [System.Text.Encoding]::ASCII.GetBytes($keyString)

# Read library binary
$libBytes = [System.IO.File]::ReadAllBytes((Resolve-Path $LibPath).Path)

# Compute HMAC-SHA256
$hmac = New-Object System.Security.Cryptography.HMACSHA256
$hmac.Key = $keyBytes
$hash = $hmac.ComputeHash($libBytes)
$hexHash = ($hash | ForEach-Object { $_.ToString("x2") }) -join ""

# Write .hmac sidecar file
$hmacPath = [System.IO.Path]::ChangeExtension((Resolve-Path $LibPath).Path, "hmac")
Set-Content -Path $hmacPath -Value $hexHash -NoNewline

# Clear sensitive variables from memory.
# SECURITY: .NET strings are immutable and may persist in managed heap until GC.
# We clear byte arrays explicitly and force a GC collection to minimize the
# window where key material is recoverable from memory or core dumps.
$hmac.Dispose()
[Array]::Clear($keyBytes, 0, $keyBytes.Length)
[Array]::Clear($hash, 0, $hash.Length)
[Array]::Clear($libBytes, 0, $libBytes.Length)
$keyString = $null
$keyBytes = $null
$hash = $null
$libBytes = $null
Remove-Variable -Name keyString, keyBytes, hash, libBytes -ErrorAction SilentlyContinue
# Request garbage collection to reclaim immutable string copies sooner.
# This is best-effort — the GC may defer collection.
[System.GC]::Collect()

Write-Host "Written to:  $hmacPath"
Write-Host "Library:     $((Resolve-Path $LibPath).Path)"
