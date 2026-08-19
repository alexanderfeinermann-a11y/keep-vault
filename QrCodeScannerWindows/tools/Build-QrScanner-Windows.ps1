#Requires -Version 7.0
<#
.SYNOPSIS
    Builds, tests and signs the Windows QR-Scanner.

.DESCRIPTION
    The scanner is a separate program from Keep Vault: its own project, its own
    output folder, its own dependency set. This script therefore builds only the
    scanner and never touches Keep Vault's build.

    The tests run before anything is published. They are the rule the app exists
    for - which of the two printed codes is taken - and a build that skips them
    would ship a scanner whose answer to that question nobody checked.

    Signing is optional here because the private keys live on the release
    machine. Without -Sign the result is a working, unsigned build; with it, the
    executable gets the same detached RSA-PSS/SHA-512 and ML-DSA-87 signature
    Keep Vault checks for before it will vouch for the scanner.
#>
[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string] $Configuration = 'Release',

    [switch] $Sign,

    [string] $CertificateThumbprint,

    [string] $PfxPath,

    [switch] $SkipTests
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$scannerRoot = Split-Path -Parent $PSScriptRoot
$repoRoot = Split-Path -Parent $scannerRoot
$distribution = Join-Path $scannerRoot 'dist'

Write-Host "Building the QR-Scanner from $scannerRoot"

if (-not $SkipTests) {
    Write-Host 'Running the arbiter and decoder tests …'
    & dotnet run --project (Join-Path $scannerRoot 'QrScanner.Tests.csproj') --configuration $Configuration
    if ($LASTEXITCODE -ne 0) {
        throw 'The scanner tests failed; nothing was published.'
    }
}

if (Test-Path -LiteralPath $distribution) {
    Remove-Item -LiteralPath $distribution -Recurse -Force
}

& pwsh -NoProfile -File (Join-Path $PSScriptRoot 'New-QrScannerIcon.ps1') `
    -OutputPath (Join-Path $scannerRoot 'Assets\QR-Scanner.ico')
if ($LASTEXITCODE -ne 0) {
    throw 'The scanner icon could not be generated.'
}

& dotnet publish (Join-Path $scannerRoot 'QrScanner.csproj') `
    --configuration $Configuration `
    --runtime win-x64 `
    --self-contained true `
    --output $distribution
if ($LASTEXITCODE -ne 0) {
    throw 'The scanner build failed.'
}

$executable = Join-Path $distribution 'QR-Scanner.exe'
if (-not (Test-Path -LiteralPath $executable)) {
    throw "The scanner executable was not produced: $executable"
}

# The scanner must not be able to reach Keep Vault's own components, and the
# simplest way to keep that true is to check it: nothing named like a Keep Vault
# native tool belongs in this output.
$strayNatives = Get-ChildItem -LiteralPath $distribution -File |
    Where-Object { $_.Name -match '^(kalyna|threefish|argon2|mars|shacal2|aes|chachapoly|mldsa87)_ref\.dll$' -or $_.Name -eq 'zpaq.exe' }
if ($strayNatives) {
    throw "Keep Vault native components appeared in the scanner output: $($strayNatives.Name -join ', ')"
}

if ($Sign) {
    $signBinaries = Join-Path $repoRoot 'tools\Sign-Binaries.ps1'
    $hybridSignature = Join-Path $repoRoot 'tools\New-HybridSignature.ps1'
    foreach ($script in @($signBinaries, $hybridSignature)) {
        if (-not (Test-Path -LiteralPath $script)) {
            throw "Signing was requested but $script is missing."
        }
    }

    $signArgs = @('-NoProfile', '-File', $signBinaries, '-Targets', $executable)
    if ($CertificateThumbprint) { $signArgs += @('-CertificateThumbprint', $CertificateThumbprint) }
    if ($PfxPath) { $signArgs += @('-PfxPath', $PfxPath) }
    & pwsh @signArgs
    if ($LASTEXITCODE -ne 0) { throw 'Authenticode signing of the scanner failed.' }

    & pwsh -NoProfile -File $hybridSignature -TargetPath $executable
    if ($LASTEXITCODE -ne 0) { throw 'Hybrid signing of the scanner failed.' }

    if (-not (Test-Path -LiteralPath ($executable + '.khsig'))) {
        throw 'The scanner has no detached hybrid signature; Keep Vault will refuse to vouch for it.'
    }
}

Write-Host "QR-Scanner published to $distribution"
if (-not $Sign) {
    Write-Host 'Not signed. Keep Vault will report the scanner as unverified until it is signed on the release machine.'
}
