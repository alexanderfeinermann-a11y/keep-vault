param(
    [string] $ReleaseDirectory = "dist\Keep Vault-portable-win-x64",
    [string] $ReleaseZip = "dist\Keep Vault-portable-win-x64.zip",
    [string] $Verifier = "dist\Keep Vault Release Verifier-win-x64.exe"
)

$ErrorActionPreference = "Stop"
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$analysisRoot = [IO.Path]::GetFullPath((Join-Path $root "build-analysis"))
$testRoot = [IO.Path]::GetFullPath((Join-Path $analysisRoot "release-tamper-test"))
$expectedTestRoot = [IO.Path]::GetFullPath((Join-Path $root "build-analysis\release-tamper-test"))
if ($testRoot -ne $expectedTestRoot -or [IO.Path]::GetDirectoryName($testRoot) -ne $analysisRoot) {
    throw "Refusing to use an unexpected tamper-test directory: $testRoot"
}

$sourceDirectory = [IO.Path]::GetFullPath((Join-Path $root $ReleaseDirectory))
$sourceZip = [IO.Path]::GetFullPath((Join-Path $root $ReleaseZip))
$verifierPath = [IO.Path]::GetFullPath((Join-Path $root $Verifier))
$copy = Join-Path $testRoot "portable"
$log = Join-Path $analysisRoot "final-release-tamper-tests.log"

foreach ($required in @($sourceDirectory, $sourceZip, $verifierPath)) {
    if (-not (Test-Path -LiteralPath $required)) {
        throw "Required release-test input is missing: $required"
    }
}

function Invoke-Verifier {
    param([string] $Target)

    $output = & $verifierPath $Target 2>&1 | Out-String
    return [pscustomobject]@{ Output = $output; ExitCode = $LASTEXITCODE }
}

function Assert-Blocked {
    param([string] $Label, [string] $Target)

    $result = Invoke-Verifier -Target $Target
    "=== $Label ===`r`n$($result.Output)`r`nexit=$($result.ExitCode)" | Add-Content -LiteralPath $log
    if ($result.ExitCode -ne 3 -or $result.Output -notmatch "RESULT: BLOCKED") {
        throw "$Label was not blocked by the external verifier."
    }

    Write-Host "${Label}: BLOCKED (exit 3)"
}

if (Test-Path -LiteralPath $testRoot) {
    Remove-Item -LiteralPath $testRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $testRoot | Out-Null
Remove-Item -LiteralPath $log -ErrorAction SilentlyContinue

try {
    Copy-Item -LiteralPath $sourceDirectory -Destination $copy -Recurse
    $baseline = Invoke-Verifier -Target $copy
    if ($baseline.ExitCode -ne 0 -or $baseline.Output -notmatch "RESULT: TRUSTED") {
        throw "The release baseline is not trusted before tamper testing: $($baseline.Output)"
    }

    $app = Join-Path $copy "Keep Vault.exe"
    [byte[]] $original = [IO.File]::ReadAllBytes($app)
    try {
        [byte[]] $changed = [byte[]] $original.Clone()
        $changed[4096] = $changed[4096] -bxor 1
        [IO.File]::WriteAllBytes($app, $changed)
        Assert-Blocked -Label "EXE bit flip" -Target $copy
    }
    finally {
        [IO.File]::WriteAllBytes($app, $original)
    }

    $manifestSignature = "$app.sha3.khsig"
    $manifestSignatureBackup = Join-Path $testRoot "manifest-signature.backup"
    Move-Item -LiteralPath $manifestSignature -Destination $manifestSignatureBackup
    try {
        Assert-Blocked -Label "Missing manifest signature" -Target $copy
    }
    finally {
        Move-Item -LiteralPath $manifestSignatureBackup -Destination $manifestSignature
    }

    $hybridSidecar = "$app.khsig"
    [byte[]] $signature = [IO.File]::ReadAllBytes($hybridSidecar)
    try {
        [byte[]] $changedSignature = [byte[]] $signature.Clone()
        $changedSignature[$changedSignature.Length - 1] = $changedSignature[$changedSignature.Length - 1] -bxor 1
        [IO.File]::WriteAllBytes($hybridSidecar, $changedSignature)
        Assert-Blocked -Label "Hybrid signature bit flip" -Target $copy
    }
    finally {
        [IO.File]::WriteAllBytes($hybridSidecar, $signature)
    }

    $tamperedZip = Join-Path $testRoot "portable-tampered.zip"
    foreach ($suffix in @("", ".khsig", ".sha3", ".sha3.khsig", ".skein", ".skein.khsig")) {
        Copy-Item -LiteralPath "$sourceZip$suffix" -Destination "$tamperedZip$suffix"
    }
    [byte[]] $zipBytes = [IO.File]::ReadAllBytes($tamperedZip)
    $zipOffset = [Math]::Min(65536, $zipBytes.Length - 1)
    $zipBytes[$zipOffset] = $zipBytes[$zipOffset] -bxor 1
    [IO.File]::WriteAllBytes($tamperedZip, $zipBytes)
    Assert-Blocked -Label "ZIP bit flip" -Target $tamperedZip

    $restored = Invoke-Verifier -Target $copy
    if ($restored.ExitCode -ne 0 -or $restored.Output -notmatch "RESULT: TRUSTED") {
        throw "The restored test copy is not trusted: $($restored.Output)"
    }

    Write-Host "All release tamper-resistance tests passed."
}
finally {
    if ($testRoot -eq $expectedTestRoot -and (Test-Path -LiteralPath $testRoot)) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}
