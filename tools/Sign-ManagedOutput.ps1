param(
    [string] $Configuration = "Release",
    [switch] $CreateDevelopmentCertificate,
    [switch] $AllowUntimestamped,
    [string] $PfxPath,
    [string] $PfxPassword,
    [string] $CertificateThumbprint,
    [string] $ExpectedSignerSha256,
    [string] $ExpectedSignerSha3_512,
    [string] $ExpectedSignerSkein1024,
    [string] $ExpectedMldsa87Sha256,
    [string] $ExpectedMldsa87Sha3_512,
    [string] $ExpectedMldsa87Skein1024
)

$ErrorActionPreference = "Stop"
$root = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")
$outputDirectory = Join-Path $root "KalynaArchiver\bin\$Configuration\net9.0-windows"
$signScript = Join-Path $root "tools\Sign-Binaries.ps1"
$sha3Script = Join-Path $root "tools\Generate-Sha3Manifest.ps1"
$skeinScript = Join-Path $root "tools\Generate-SkeinManifest.ps1"
$hybridScript = Join-Path $root "tools\New-HybridSignature.ps1"
$nativeNames = @(
    "zpaq.exe",
    "argon2.exe",
    "argon2_ref.dll",
    "kalyna_ref.dll",
    "threefish_ref.dll"
)
$nativeSuffixes = @(
    "",
    ".khsig",
    ".sha3",
    ".sha3.khsig",
    ".skein",
    ".skein.khsig"
)

if (-not (Test-Path -LiteralPath $outputDirectory)) {
    throw "Managed output directory does not exist: $outputDirectory"
}

# Keep each native binary and its authenticated manifests from one build generation.
# Timestamp-based MSBuild copies can otherwise combine a freshly copied PE with stale sidecars.
foreach ($nativeName in $nativeNames) {
    foreach ($suffix in $nativeSuffixes) {
        $source = Join-Path $root "tools\$nativeName$suffix"
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
            throw "Required signed native artifact is missing: $source"
        }

        $destination = Join-Path $outputDirectory "$nativeName$suffix"
        $temporary = "$destination.sync-$([Guid]::NewGuid().ToString('N'))"
        try {
            Copy-Item -LiteralPath $source -Destination $temporary
            [System.IO.File]::Move($temporary, $destination, $true)
        }
        finally {
            Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        }

        $sourceHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
        $destinationHash = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash
        if (-not [string]::Equals($sourceHash, $destinationHash, [StringComparison]::Ordinal)) {
            throw "Native artifact synchronization verification failed: $destination"
        }
    }
}

$paths = Get-ChildItem -LiteralPath $outputDirectory -File |
    Where-Object { $_.Extension -in @(".exe", ".dll") -and $_.Name -notin $nativeNames } |
    Select-Object -ExpandProperty FullName

if (-not $paths) {
    throw "No managed application binaries were found in $outputDirectory."
}

$parameters = @{
    Path = $paths
    Configuration = $Configuration
}

foreach ($entry in @{
    PfxPath = $PfxPath
    PfxPassword = $PfxPassword
    CertificateThumbprint = $CertificateThumbprint
    ExpectedSignerSha256 = $ExpectedSignerSha256
    ExpectedSignerSha3_512 = $ExpectedSignerSha3_512
    ExpectedSignerSkein1024 = $ExpectedSignerSkein1024
    ExpectedMldsa87Sha256 = $ExpectedMldsa87Sha256
    ExpectedMldsa87Sha3_512 = $ExpectedMldsa87Sha3_512
    ExpectedMldsa87Skein1024 = $ExpectedMldsa87Skein1024
}.GetEnumerator()) {
    if (-not [string]::IsNullOrWhiteSpace($entry.Value)) {
        $parameters[$entry.Key] = $entry.Value
    }
}

if ($CreateDevelopmentCertificate) {
    $parameters.CreateDevelopmentCertificate = $true
}

if ($AllowUntimestamped) {
    $parameters.AllowUntimestamped = $true
}

& $signScript @parameters

foreach ($path in $paths) {
    & $sha3Script -ExecutablePath $path
    & $skeinScript -ExecutablePath $path

    $hybridParameters = @{
        Path = @("$path.sha3", "$path.skein")
        NoBuild = $true
    }
    foreach ($entry in @{
        ExpectedSignerSha256 = $ExpectedSignerSha256
        ExpectedSignerSha3_512 = $ExpectedSignerSha3_512
        ExpectedSignerSkein1024 = $ExpectedSignerSkein1024
        ExpectedMldsa87Sha256 = $ExpectedMldsa87Sha256
        ExpectedMldsa87Sha3_512 = $ExpectedMldsa87Sha3_512
        ExpectedMldsa87Skein1024 = $ExpectedMldsa87Skein1024
    }.GetEnumerator()) {
        if (-not [string]::IsNullOrWhiteSpace($entry.Value)) {
            $hybridParameters[$entry.Key] = $entry.Value
        }
    }
    if ($PfxPath) {
        $hybridParameters.PfxPath = $PfxPath
        $hybridParameters.PfxPassword = $PfxPassword
    }
    else {
        $hybridParameters.CertificateThumbprint = if ($CertificateThumbprint) {
            $CertificateThumbprint
        }
        else {
            [xml] $properties = Get-Content -LiteralPath (Join-Path $root "Directory.Build.props")
            $properties.Project.PropertyGroup.SelectSingleNode("KalynaSigningCertificateThumbprint").InnerText
        }
    }

    & $hybridScript @hybridParameters
}
