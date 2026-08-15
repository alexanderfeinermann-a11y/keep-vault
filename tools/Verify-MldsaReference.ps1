$ErrorActionPreference = "Stop"

$root = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")
$referenceRoot = Join-Path $root "external\ML-DSA-reference"
$commitPath = Join-Path $referenceRoot "PINNED_COMMIT.txt"
$sha256ManifestPath = Join-Path $referenceRoot "SOURCE_SHA256SUMS"
$sha3ManifestPath = Join-Path $referenceRoot "SOURCE_SHA3_512SUMS"
$skeinManifestPath = Join-Path $referenceRoot "SOURCE_SKEIN1024SUMS"
$signingProject = Join-Path $root "KalynaSigningTool\KalynaSigningTool.csproj"
$signingTool = Join-Path $root "KalynaSigningTool\bin\Release\net9.0-windows\KalynaSigningTool.dll"
$expectedCommit = "d35ba3fe5449bee3e6d43e1f296c3ca818bd36be"

if ((Get-Content -LiteralPath $commitPath -Raw).Trim() -cne $expectedCommit) {
    throw "The ML-DSA reference commit pin is not the reviewed FIPS 204 source revision."
}

function Read-PinnedHashes {
    param(
        [string] $Path,
        [int] $HexLength,
        [string] $Algorithm
    )

    $entries = Get-Content -LiteralPath $Path | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    if ($entries.Count -ne 21) {
        throw "The ML-DSA $Algorithm source manifest must contain exactly 21 reviewed files."
    }

    $hashes = @{}
    foreach ($entry in $entries) {
        if ($entry -notmatch "^([0-9A-F]{$HexLength})  (ref/[A-Za-z0-9._/-]+)$") {
            throw "Invalid ML-DSA $Algorithm source manifest entry: $entry"
        }

        if ($hashes.ContainsKey($Matches[2])) {
            throw "Duplicate ML-DSA $Algorithm source manifest path: $($Matches[2])"
        }

        $hashes.Add($Matches[2], $Matches[1])
    }

    return $hashes
}

$sha256Pins = Read-PinnedHashes -Path $sha256ManifestPath -HexLength 64 -Algorithm "SHA-256"
$sha3Pins = Read-PinnedHashes -Path $sha3ManifestPath -HexLength 128 -Algorithm "SHA3-512"
$skeinPins = Read-PinnedHashes -Path $skeinManifestPath -HexLength 256 -Algorithm "Skein-1024"
if ($sha256Pins.Count -ne $sha3Pins.Count -or $sha256Pins.Count -ne $skeinPins.Count) {
    throw "The ML-DSA SHA-256, SHA3-512, and Skein-1024 source manifests cover different file counts."
}

& dotnet build $signingProject -c Release --nologo
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $signingTool -PathType Leaf)) {
    throw "KalynaSigningTool build failed before ML-DSA source-pin verification."
}

foreach ($manifestRelative in $sha256Pins.Keys) {
    if (-not $sha3Pins.ContainsKey($manifestRelative) -or -not $skeinPins.ContainsKey($manifestRelative)) {
        throw "The ML-DSA triple source-pin manifests do not cover the same path: $manifestRelative"
    }

    $relative = $manifestRelative.Replace('/', [IO.Path]::DirectorySeparatorChar)
    $sourcePath = Join-Path $referenceRoot $relative
    if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
        throw "Pinned ML-DSA reference source is missing: $relative"
    }

    $fingerprints = & dotnet $signingTool fingerprint --file $sourcePath
    if ($LASTEXITCODE -ne 0) {
        throw "Triple fingerprint generation failed for pinned ML-DSA source: $relative"
    }

    $toolSha256 = ($fingerprints | Where-Object { $_ -like "sha256=*" }).Substring(7)
    $toolSha3 = ($fingerprints | Where-Object { $_ -like "sha3_512=*" }).Substring(9)
    $actualSkein = ($fingerprints | Where-Object { $_ -like "skein1024=*" }).Substring(10)
    $actualSha256 = (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash
    $sourceBytes = [IO.File]::ReadAllBytes($sourcePath)
    try {
        $actualSha3 = [Convert]::ToHexString([Security.Cryptography.SHA3_512]::HashData($sourceBytes))
    }
    finally {
        [Array]::Clear($sourceBytes, 0, $sourceBytes.Length)
    }

    if ($actualSha256 -cne $sha256Pins[$manifestRelative] -or
        $toolSha256 -cne $actualSha256 -or
        $actualSha3 -cne $sha3Pins[$manifestRelative] -or
        $toolSha3 -cne $actualSha3 -or
        $actualSkein -cne $skeinPins[$manifestRelative]) {
        throw "Pinned ML-DSA reference source changed (SHA-256/SHA3-512/Skein-1024): $relative"
    }
}

Write-Host "ML-DSA reference source SHA-256/SHA3-512/Skein-1024 pins verified: pq-crystals/dilithium@$expectedCommit"
