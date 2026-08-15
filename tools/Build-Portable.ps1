param(
    [string] $Configuration = "Release",
    [string] $Runtime = "win-x64",
    [string] $OutputName = "Keep Vault-portable-win-x64",
    [switch] $SkipSigning,
    [switch] $CreateDevelopmentCertificate,
    [switch] $TrustDevelopmentCertificate,
    [string] $PfxPath,
    [string] $PfxPassword,
    [string] $CertificateThumbprint,
    [string] $ExpectedSignerSha256,
    [string] $ExpectedSignerSha3_512,
    [string] $ExpectedSignerSkein1024,
    [string] $ExpectedMldsa87Sha256,
    [string] $ExpectedMldsa87Sha3_512,
    [string] $ExpectedMldsa87Skein1024,
    [string] $MldsaPrivateKeyPath,
    [string] $MldsaPublicKeyPath,
    [string] $MldsaReferencePath
)

$ErrorActionPreference = "Stop"

if ($OutputName -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9._ -]{0,126}[A-Za-z0-9])?$' -or
    $OutputName -in @('.', '..')) {
    throw "OutputName must be a simple 1-128 character file name containing only letters, digits, spaces, dots, underscores, or hyphens, without trailing punctuation."
}

$root = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")
$distRoot = Join-Path $root "dist"
$publishDir = Join-Path $distRoot $OutputName
$zipPath = Join-Path $distRoot "$OutputName.zip"
$zipSha3Path = "$zipPath.sha3"
$zipSkeinPath = "$zipPath.skein"
$zipHybridPath = "$zipPath.khsig"
$project = Join-Path $root "KalynaArchiver\KalynaArchiver.csproj"
$verifierProject = Join-Path $root "KalynaReleaseVerifier\KalynaReleaseVerifier.csproj"
$verifierPublishDir = Join-Path $distRoot ".KalynaReleaseVerifier-publish"
$externalVerifierPath = Join-Path $distRoot "Keep Vault Release Verifier-win-x64.exe"
$signScript = Join-Path $root "tools\Sign-Binaries.ps1"
$manifestScript = Join-Path $root "tools\Generate-Sha3Manifest.ps1"
$skeinManifestScript = Join-Path $root "tools\Generate-SkeinManifest.ps1"
$hybridSignatureScript = Join-Path $root "tools\New-HybridSignature.ps1"

if ($TrustDevelopmentCertificate) {
    throw "Trusting the development root in CurrentUser\\Root is forbidden. Portable development builds use only the compiled signer pins."
}

function Normalize-Thumbprint {
    param([string] $Thumbprint)
    $normalized = $Thumbprint -replace "\s", ""
    if ($normalized -notmatch '^[0-9A-Fa-f]{40}$') {
        throw "Certificate thumbprint must contain exactly 40 hexadecimal characters."
    }

    return $normalized.ToUpperInvariant()
}

function Normalize-Digest {
    param(
        [string] $Digest,
        [int] $Length,
        [string] $Name
    )
    $normalized = $Digest -replace "\s", ""
    if ($normalized -notmatch "^[0-9A-Fa-f]{$Length}$") {
        throw "$Name must contain exactly $Length hexadecimal characters."
    }

    return $normalized.ToUpperInvariant()
}

[xml] $buildProperties = Get-Content -LiteralPath (Join-Path $root "Directory.Build.props")
$propertyGroup = $buildProperties.Project.PropertyGroup
$defaultCertificateThumbprint = Normalize-Thumbprint ($propertyGroup.SelectSingleNode("KalynaSigningCertificateThumbprint").InnerText)
$defaultSignerSha256 = Normalize-Digest ($propertyGroup.SelectSingleNode("KalynaExpectedSignerSha256").InnerText) 64 "Expected SHA-256 SPKI fingerprint"
$defaultSignerSha3 = Normalize-Digest ($propertyGroup.SelectSingleNode("KalynaExpectedSignerSha3_512").InnerText) 128 "Expected SHA3-512 SPKI fingerprint"
$defaultSignerSkein = Normalize-Digest ($propertyGroup.SelectSingleNode("KalynaExpectedSignerSkein1024").InnerText) 256 "Expected Skein-1024 SPKI fingerprint"
$defaultMldsaSha256 = Normalize-Digest ($propertyGroup.SelectSingleNode("KalynaExpectedMldsa87Sha256").InnerText) 64 "Expected ML-DSA-87 SHA-256 fingerprint"
$defaultMldsaSha3 = Normalize-Digest ($propertyGroup.SelectSingleNode("KalynaExpectedMldsa87Sha3_512").InnerText) 128 "Expected ML-DSA-87 SHA3-512 fingerprint"
$defaultMldsaSkein = Normalize-Digest ($propertyGroup.SelectSingleNode("KalynaExpectedMldsa87Skein1024").InnerText) 256 "Expected ML-DSA-87 Skein-1024 fingerprint"

$effectiveCertificateThumbprint = if ($CertificateThumbprint) {
    Normalize-Thumbprint $CertificateThumbprint
}
else {
    $defaultCertificateThumbprint
}

$usingDefaultCertificate = -not $PfxPath -and $effectiveCertificateThumbprint -eq $defaultCertificateThumbprint
$effectiveSignerSha256 = if ($ExpectedSignerSha256) {
    Normalize-Digest $ExpectedSignerSha256 64 "Expected SHA-256 SPKI fingerprint"
}
elseif ($usingDefaultCertificate) {
    $defaultSignerSha256
}
else {
    $null
}

$effectiveSignerSha3 = if ($ExpectedSignerSha3_512) {
    Normalize-Digest $ExpectedSignerSha3_512 128 "Expected SHA3-512 SPKI fingerprint"
}
elseif ($usingDefaultCertificate) {
    $defaultSignerSha3
}
else {
    $null
}

$effectiveSignerSkein = if ($ExpectedSignerSkein1024) {
    Normalize-Digest $ExpectedSignerSkein1024 256 "Expected Skein-1024 SPKI fingerprint"
}
elseif ($usingDefaultCertificate) {
    $defaultSignerSkein
}
else {
    $null
}

$effectiveMldsaSha256 = if ($ExpectedMldsa87Sha256) {
    Normalize-Digest $ExpectedMldsa87Sha256 64 "Expected ML-DSA-87 SHA-256 fingerprint"
}
else {
    $defaultMldsaSha256
}

$effectiveMldsaSha3 = if ($ExpectedMldsa87Sha3_512) {
    Normalize-Digest $ExpectedMldsa87Sha3_512 128 "Expected ML-DSA-87 SHA3-512 fingerprint"
}
else {
    $defaultMldsaSha3
}

$effectiveMldsaSkein = if ($ExpectedMldsa87Skein1024) {
    Normalize-Digest $ExpectedMldsa87Skein1024 256 "Expected ML-DSA-87 Skein-1024 fingerprint"
}
else {
    $defaultMldsaSkein
}

if ((-not $PfxPath -and -not $effectiveCertificateThumbprint) -or
    -not $effectiveSignerSha256 -or -not $effectiveSignerSha3 -or -not $effectiveSignerSkein -or
    -not $effectiveMldsaSha256 -or -not $effectiveMldsaSha3 -or -not $effectiveMldsaSkein) {
    throw "Portable builds require SHA-256/SHA3-512/Skein-1024 pins for both RSA and ML-DSA-87."
}

function Assert-InRoot {
    param([string] $Path)
    $full = [System.IO.Path]::GetFullPath($Path)
    $rootFull = [System.IO.Path]::GetFullPath($root)
    $relative = [System.IO.Path]::GetRelativePath($rootFull, $full)
    $parentPrefix = "..$([System.IO.Path]::DirectorySeparatorChar)"
    if ($relative -eq "." -or
        $relative -eq ".." -or
        $relative.StartsWith($parentPrefix, [System.StringComparison]::Ordinal) -or
        [System.IO.Path]::IsPathRooted($relative)) {
        throw "Refusing to operate outside repository root. Path=$full Root=$rootFull"
    }

    $current = $full
    while (-not [string]::IsNullOrEmpty($current)) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Refusing to operate through a reparse point. Path=$($item.FullName)"
            }
        }

        if ([string]::Equals($current.TrimEnd('\'), $rootFull.TrimEnd('\'), [System.StringComparison]::OrdinalIgnoreCase)) {
            break
        }

        $current = [System.IO.Path]::GetDirectoryName($current)
    }
}

Assert-InRoot $distRoot
Assert-InRoot $publishDir
Assert-InRoot $zipPath
Assert-InRoot $zipSha3Path
Assert-InRoot $zipSkeinPath
Assert-InRoot $zipHybridPath
Assert-InRoot $verifierPublishDir
Assert-InRoot $externalVerifierPath

New-Item -ItemType Directory -Force -Path $distRoot | Out-Null
if (Test-Path -LiteralPath $publishDir) {
    Remove-Item -LiteralPath $publishDir -Recurse -Force
}

foreach ($oldPackageFile in @(
    $zipPath,
    $zipSha3Path,
    $zipSkeinPath,
    $zipHybridPath,
    "$zipSha3Path.khsig",
    "$zipSkeinPath.khsig",
    $externalVerifierPath,
    "$externalVerifierPath.sha3",
    "$externalVerifierPath.skein",
    "$externalVerifierPath.khsig",
    "$externalVerifierPath.sha3.khsig",
    "$externalVerifierPath.skein.khsig")) {
    if (Test-Path -LiteralPath $oldPackageFile) {
        Remove-Item -LiteralPath $oldPackageFile -Force
    }
}

if (Test-Path -LiteralPath $verifierPublishDir) {
    Remove-Item -LiteralPath $verifierPublishDir -Recurse -Force
}

$publishArgs = @(
    "publish",
    $project,
    "-c", $Configuration,
    "-r", $Runtime,
    "--self-contained", "true",
    "-p:PublishSingleFile=true",
    "-p:IncludeNativeLibrariesForSelfExtract=true",
    "-p:PublishReadyToRun=false",
    "-p:PublishTrimmed=false",
    "-o", $publishDir
)
$publishArgs += "-p:KalynaExpectedSignerSha256=$effectiveSignerSha256"
$publishArgs += "-p:KalynaExpectedSignerSha3_512=$effectiveSignerSha3"
$publishArgs += "-p:KalynaExpectedSignerSkein1024=$effectiveSignerSkein"
$publishArgs += "-p:KalynaExpectedMldsa87Sha256=$effectiveMldsaSha256"
$publishArgs += "-p:KalynaExpectedMldsa87Sha3_512=$effectiveMldsaSha3"
$publishArgs += "-p:KalynaExpectedMldsa87Skein1024=$effectiveMldsaSkein"

& dotnet @publishArgs
if ($LASTEXITCODE -ne 0) {
    throw "Portable publish failed."
}

$appExe = Join-Path $publishDir "Keep Vault.exe"
if (-not (Test-Path -LiteralPath $appExe)) {
    throw "Portable publish did not produce $appExe."
}

$verifierPublishArgs = @(
    "publish",
    $verifierProject,
    "-c", $Configuration,
    "-r", $Runtime,
    "--self-contained", "true",
    "-p:PublishSingleFile=true",
    "-p:IncludeNativeLibrariesForSelfExtract=true",
    "-p:PublishReadyToRun=false",
    "-p:PublishTrimmed=false",
    "-p:KalynaExpectedSignerSha256=$effectiveSignerSha256",
    "-p:KalynaExpectedSignerSha3_512=$effectiveSignerSha3",
    "-p:KalynaExpectedSignerSkein1024=$effectiveSignerSkein",
    "-p:KalynaExpectedMldsa87Sha256=$effectiveMldsaSha256",
    "-p:KalynaExpectedMldsa87Sha3_512=$effectiveMldsaSha3",
    "-p:KalynaExpectedMldsa87Skein1024=$effectiveMldsaSkein",
    "-o", $verifierPublishDir
)
& dotnet @verifierPublishArgs
if ($LASTEXITCODE -ne 0) {
    throw "Portable release-verifier publish failed."
}

$publishedVerifier = Join-Path $verifierPublishDir "Keep Vault Release Verifier.exe"
if (-not (Test-Path -LiteralPath $publishedVerifier)) {
    throw "Release-verifier publish did not produce $publishedVerifier."
}
$packagedVerifier = Join-Path $publishDir "Keep Vault Release Verifier.exe"
Copy-Item -LiteralPath $publishedVerifier -Destination $packagedVerifier
Remove-Item -LiteralPath $verifierPublishDir -Recurse -Force

$portableBinaries = Get-ChildItem -LiteralPath $publishDir -File |
    Where-Object { $_.Extension -in @(".exe", ".dll") } |
    Select-Object -ExpandProperty FullName

Get-ChildItem -LiteralPath $publishDir -Recurse -Force -Include "*.pdb", "createdump.exe" |
    Remove-Item -Force

if (-not $SkipSigning) {
    foreach ($binary in $portableBinaries) {
        $signArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $signScript, "-Path", $binary)
        if ($CreateDevelopmentCertificate) {
            $signArgs += "-CreateDevelopmentCertificate"
        }
        if ($TrustDevelopmentCertificate) {
            $signArgs += "-TrustDevelopmentCertificate"
        }
        if ($PfxPath) {
            $signArgs += @("-PfxPath", $PfxPath)
        }
        if ($PfxPassword) {
            $signArgs += @("-PfxPassword", $PfxPassword)
        }
        if ($CertificateThumbprint) {
            $signArgs += @("-CertificateThumbprint", $CertificateThumbprint)
        }
        elseif (-not $PfxPath -and -not $CreateDevelopmentCertificate) {
            $signArgs += @("-CertificateThumbprint", $effectiveCertificateThumbprint)
        }
        $signArgs += @(
            "-ExpectedSignerSha256", $effectiveSignerSha256,
            "-ExpectedSignerSha3_512", $effectiveSignerSha3,
            "-ExpectedSignerSkein1024", $effectiveSignerSkein,
            "-ExpectedMldsa87Sha256", $effectiveMldsaSha256,
            "-ExpectedMldsa87Sha3_512", $effectiveMldsaSha3,
            "-ExpectedMldsa87Skein1024", $effectiveMldsaSkein
        )
        if ($MldsaPrivateKeyPath) { $signArgs += @("-MldsaPrivateKeyPath", $MldsaPrivateKeyPath) }
        if ($MldsaPublicKeyPath) { $signArgs += @("-MldsaPublicKeyPath", $MldsaPublicKeyPath) }
        if ($MldsaReferencePath) { $signArgs += @("-MldsaReferencePath", $MldsaReferencePath) }

        & pwsh @signArgs
        if ($LASTEXITCODE -ne 0) {
            throw "Portable binary signing failed for $binary."
        }
    }
}

foreach ($target in $portableBinaries) {
    & pwsh -NoProfile -ExecutionPolicy Bypass -File $manifestScript -ExecutablePath $target
    if ($LASTEXITCODE -ne 0) {
        throw "SHA3 manifest generation failed for $target."
    }

    & pwsh -NoProfile -ExecutionPolicy Bypass -File $skeinManifestScript -ExecutablePath $target
    if ($LASTEXITCODE -ne 0) {
        throw "Skein manifest generation failed for $target."
    }

    if (-not $SkipSigning) {
        $manifestHybridParameters = @{
            Path = @("$target.sha3", "$target.skein")
            ExpectedSignerSha256 = $effectiveSignerSha256
            ExpectedSignerSha3_512 = $effectiveSignerSha3
            ExpectedSignerSkein1024 = $effectiveSignerSkein
            ExpectedMldsa87Sha256 = $effectiveMldsaSha256
            ExpectedMldsa87Sha3_512 = $effectiveMldsaSha3
            ExpectedMldsa87Skein1024 = $effectiveMldsaSkein
            NoBuild = $true
        }
        if ($PfxPath) {
            $manifestHybridParameters.PfxPath = $PfxPath
            if ($PfxPassword) { $manifestHybridParameters.PfxPassword = $PfxPassword }
        }
        else {
            $manifestHybridParameters.CertificateThumbprint = $effectiveCertificateThumbprint
        }
        if ($MldsaPrivateKeyPath) { $manifestHybridParameters.MldsaPrivateKeyPath = $MldsaPrivateKeyPath }
        if ($MldsaPublicKeyPath) { $manifestHybridParameters.MldsaPublicKeyPath = $MldsaPublicKeyPath }
        if ($MldsaReferencePath) { $manifestHybridParameters.MldsaReferencePath = $MldsaReferencePath }
        & $hybridSignatureScript @manifestHybridParameters
        if ($LASTEXITCODE -ne 0) {
            throw "Hybrid manifest signing failed for $target."
        }
    }
}

$readmePath = Join-Path $publishDir "PORTABLE_README.txt"
@"
Keep Vault Portable
=========================

Start:
  Keep Vault.exe

This folder is self-contained for Windows x64 and does not require installing the .NET runtime.
Keep the EXE, native tools, .sha3, .skein, and .khsig files together. Every executable
requires RSA-4096/SHA-512 Authenticode plus a detached RSA-PSS/SHA-512 and ML-DSA-87
signature. Hash manifests and other release artifacts are also signed by RSA-PSS and
ML-DSA-87. Keep Vault Release Verifier.exe checks a folder or the ZIP before launch.

Windows certificate selector (not a trust pin): $effectiveCertificateThumbprint
Pinned RSA SHA-256(SPKI): $effectiveSignerSha256
Pinned RSA SHA3-512(SPKI): $effectiveSignerSha3
Pinned RSA Skein-1024(SPKI): $effectiveSignerSkein
Pinned ML-DSA-87 SHA-256: $effectiveMldsaSha256
Pinned ML-DSA-87 SHA3-512: $effectiveMldsaSha3
Pinned ML-DSA-87 Skein-1024: $effectiveMldsaSkein

The bundled local development signer is deliberately not installed as a globally trusted
Windows root. Explorer can therefore report an untrusted development chain while the app
accepts only its exact compiled pins. Public distribution requires a protected production
code-signing key and an appropriate Windows trust chain.

Encrypted containers use format 7 only and offer Kalyna-512/512 or Threefish-1024. Both
use a user password plus two independent generated 512-bit hexadecimal factors. Print key
sheet A and key sheet B separately and store them separately. The blank page between them
prevents duplex front/back sharing.

One atomic generation consumes five evenly filled mouse pools with at least 512 distinct
samples each: factor A, factor B, salt, nonce 1, and nonce 2. The visible counters then
restart at zero because those samples were consumed, while the matching salt and nonce stay
available exactly once in locked RAM and remain bound to the displayed factors A and B.
The key input is Argon2id(SHA3-512(UserPassword, A) ||
SHA3-512(UserPassword, B), Salt), using length-prefixing and domain separation.

Nonce creation hashes nonce pool 1 and nonce pool 2 separately with SHA3-512, concatenates
the two digests, and XORs all 128 bytes with one 128-byte BCryptGenRandom result. Kalyna
stores the first 64 bytes; Threefish stores all 128 bytes.

Physical printing creates no PDF file in this app. Windows print spoolers and drivers are
outside the app's storage control and can use their own temporary storage.

The native binaries use static CRT linkage, CFG, CET compatibility, ASLR and NX. The app
also restricts DLL search to System32 and blocks remote/low-integrity images where Windows
supports those policies. ZPAQ remains a native C++ parser and is not an AppContainer.

NTFS alternate data streams are intentionally omitted during archive creation and rejected
during extraction. OneDrive/cloud versions, backups, shadow copies and print spooling can
retain data outside this app's control.

Cryptographic erase only applies to encrypted version-7 ZPAQ containers. True SSD hardware secure
erase is a whole-drive firmware/vendor operation, not a reliable per-file app operation.

KPAR2 is this app's custom RS(20,3) recovery format, not standard PAR2. At 1 TB, 15 percent
recovery redundancy requires about 150 GiB of additional storage and several full I/O passes.
Encrypted archives always use dual-authenticated KPAR2 metadata (HMAC-SHA3-512 and keyed
Skein-1024 with domain-separated recovery keys). Plain archives explicitly receive error
correction only. Eight redundant 4096-byte locators and an independently RS(20,3)-protected
metadata area keep the manifest and both certifications recoverable after any three failed
4096-byte sidecar blocks. Unauthenticated emergency recovery only writes a new file; an
encrypted emergency candidate must still pass the container's two embedded MACs.
Unreadable source regions are isolated in 4096-byte units and repaired in the new candidate.
A .kzpaq file without valid encrypted magic and without usable KPAR2 metadata is blocked
instead of being passed to ZPAQ as a plain archive.
"@ | Set-Content -LiteralPath $readmePath -Encoding ASCII

if (-not $SkipSigning) {
    $missingHybridTargets = Get-ChildItem -LiteralPath $publishDir -Recurse -File |
        Where-Object {
            -not $_.Name.EndsWith(".khsig", [System.StringComparison]::OrdinalIgnoreCase) -and
            -not (Test-Path -LiteralPath "$($_.FullName).khsig")
        } |
        Select-Object -ExpandProperty FullName
    if ($missingHybridTargets) {
        $catchAllParameters = @{
            Path = $missingHybridTargets
            ExpectedSignerSha256 = $effectiveSignerSha256
            ExpectedSignerSha3_512 = $effectiveSignerSha3
            ExpectedSignerSkein1024 = $effectiveSignerSkein
            ExpectedMldsa87Sha256 = $effectiveMldsaSha256
            ExpectedMldsa87Sha3_512 = $effectiveMldsaSha3
            ExpectedMldsa87Skein1024 = $effectiveMldsaSkein
            NoBuild = $true
        }
        if ($PfxPath) {
            $catchAllParameters.PfxPath = $PfxPath
            $catchAllParameters.PfxPassword = $PfxPassword
        }
        else {
            $catchAllParameters.CertificateThumbprint = $effectiveCertificateThumbprint
        }
        if ($MldsaPrivateKeyPath) { $catchAllParameters.MldsaPrivateKeyPath = $MldsaPrivateKeyPath }
        if ($MldsaPublicKeyPath) { $catchAllParameters.MldsaPublicKeyPath = $MldsaPublicKeyPath }
        if ($MldsaReferencePath) { $catchAllParameters.MldsaReferencePath = $MldsaReferencePath }
        & $hybridSignatureScript @catchAllParameters
        if ($LASTEXITCODE -ne 0) {
            throw "Hybrid catch-all signing failed for portable release artifacts."
        }
    }
}

Compress-Archive -LiteralPath $publishDir -DestinationPath $zipPath -CompressionLevel Optimal

& pwsh -NoProfile -ExecutionPolicy Bypass -File $manifestScript -ExecutablePath $zipPath
if ($LASTEXITCODE -ne 0) {
    throw "SHA3 manifest generation failed for portable ZIP $zipPath."
}

& pwsh -NoProfile -ExecutionPolicy Bypass -File $skeinManifestScript -ExecutablePath $zipPath
if ($LASTEXITCODE -ne 0) {
    throw "Skein manifest generation failed for portable ZIP $zipPath."
}

if (-not $SkipSigning) {
    $zipHybridParameters = @{
        Path = @($zipPath, $zipSha3Path, $zipSkeinPath)
        ExpectedSignerSha256 = $effectiveSignerSha256
        ExpectedSignerSha3_512 = $effectiveSignerSha3
        ExpectedSignerSkein1024 = $effectiveSignerSkein
        ExpectedMldsa87Sha256 = $effectiveMldsaSha256
        ExpectedMldsa87Sha3_512 = $effectiveMldsaSha3
        ExpectedMldsa87Skein1024 = $effectiveMldsaSkein
        NoBuild = $true
    }
    if ($PfxPath) {
        $zipHybridParameters.PfxPath = $PfxPath
        $zipHybridParameters.PfxPassword = $PfxPassword
    }
    else {
        $zipHybridParameters.CertificateThumbprint = $effectiveCertificateThumbprint
    }
    if ($MldsaPrivateKeyPath) { $zipHybridParameters.MldsaPrivateKeyPath = $MldsaPrivateKeyPath }
    if ($MldsaPublicKeyPath) { $zipHybridParameters.MldsaPublicKeyPath = $MldsaPublicKeyPath }
    if ($MldsaReferencePath) { $zipHybridParameters.MldsaReferencePath = $MldsaReferencePath }
    & $hybridSignatureScript @zipHybridParameters
    if ($LASTEXITCODE -ne 0) {
        throw "Hybrid signing failed for portable ZIP and manifests."
    }

    Copy-Item -LiteralPath $packagedVerifier -Destination $externalVerifierPath
    Copy-Item -LiteralPath "$packagedVerifier.sha3" -Destination "$externalVerifierPath.sha3"
    Copy-Item -LiteralPath "$packagedVerifier.skein" -Destination "$externalVerifierPath.skein"
    Copy-Item -LiteralPath "$packagedVerifier.khsig" -Destination "$externalVerifierPath.khsig"
    Copy-Item -LiteralPath "$packagedVerifier.sha3.khsig" -Destination "$externalVerifierPath.sha3.khsig"
    Copy-Item -LiteralPath "$packagedVerifier.skein.khsig" -Destination "$externalVerifierPath.skein.khsig"
}

[pscustomobject]@{
    PublishDirectory = $publishDir
    ZipPath = $zipPath
    ZipSha3 = $zipSha3Path
    ZipSkein = $zipSkeinPath
    ZipHybridSignature = $zipHybridPath
    ExternalVerifier = $externalVerifierPath
    AppExe = $appExe
    SizeMB = [math]::Round(((Get-ChildItem -LiteralPath $publishDir -Recurse -File | Measure-Object -Property Length -Sum).Sum / 1MB), 2)
    ZipSizeMB = [math]::Round(((Get-Item -LiteralPath $zipPath).Length / 1MB), 2)
} | Format-List
