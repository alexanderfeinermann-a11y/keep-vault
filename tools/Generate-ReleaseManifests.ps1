param(
    [string] $Configuration = "Release",
    [string] $CertificateThumbprint,
    [string] $PfxPath,
    [string] $PfxPassword,
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
$root = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")
$manifestScript = Join-Path $root "tools\Generate-Sha3Manifest.ps1"
$skeinManifestScript = Join-Path $root "tools\Generate-SkeinManifest.ps1"
$hybridSignatureScript = Join-Path $root "tools\New-HybridSignature.ps1"

if (-not $CertificateThumbprint -and -not $PfxPath) {
    [xml] $buildProperties = Get-Content -LiteralPath (Join-Path $root "Directory.Build.props")
    $CertificateThumbprint = $buildProperties.Project.PropertyGroup.SelectSingleNode("KalynaSigningCertificateThumbprint").InnerText
}

$targets = [System.Collections.Generic.List[string]]@(
    (Join-Path $root "tools\zpaq.exe"),
    (Join-Path $root "tools\argon2.exe"),
    (Join-Path $root "tools\kalyna_ref.dll"),
    (Join-Path $root "tools\threefish_ref.dll"),
    (Join-Path $root "tools\argon2_ref.dll"),
    (Join-Path $root "tools\mldsa87_ref.dll")
)

$applicationDirectory = Join-Path $root "KalynaArchiver\bin\$Configuration\net9.0-windows"
if (Test-Path -LiteralPath $applicationDirectory) {
    Get-ChildItem -LiteralPath $applicationDirectory -File |
        Where-Object { $_.Extension -in @(".exe", ".dll") } |
        ForEach-Object { $targets.Add($_.FullName) }
}

foreach ($target in ($targets | Select-Object -Unique)) {
    if (Test-Path -LiteralPath $target) {
        & pwsh -NoProfile -ExecutionPolicy Bypass -File $manifestScript -ExecutablePath $target
        if ($LASTEXITCODE -ne 0) {
            throw "SHA3-512 manifest generation failed for $target."
        }

        & pwsh -NoProfile -ExecutionPolicy Bypass -File $skeinManifestScript -ExecutablePath $target
        if ($LASTEXITCODE -ne 0) {
            throw "Skein-1024 manifest generation failed for $target."
        }

        $hybridParameters = @{
            Path = @("$target.sha3", "$target.skein")
            NoBuild = $true
        }
        if ($PfxPath) {
            $hybridParameters.PfxPath = $PfxPath
            $hybridParameters.PfxPassword = $PfxPassword
        }
        else {
            $hybridParameters.CertificateThumbprint = $CertificateThumbprint
        }
        if ($MldsaPrivateKeyPath) { $hybridParameters.MldsaPrivateKeyPath = $MldsaPrivateKeyPath }
        if ($MldsaPublicKeyPath) { $hybridParameters.MldsaPublicKeyPath = $MldsaPublicKeyPath }
        if ($MldsaReferencePath) { $hybridParameters.MldsaReferencePath = $MldsaReferencePath }
        if ($ExpectedSignerSha256) { $hybridParameters.ExpectedSignerSha256 = $ExpectedSignerSha256 }
        if ($ExpectedSignerSha3_512) { $hybridParameters.ExpectedSignerSha3_512 = $ExpectedSignerSha3_512 }
        if ($ExpectedSignerSkein1024) { $hybridParameters.ExpectedSignerSkein1024 = $ExpectedSignerSkein1024 }
        if ($ExpectedMldsa87Sha256) { $hybridParameters.ExpectedMldsa87Sha256 = $ExpectedMldsa87Sha256 }
        if ($ExpectedMldsa87Sha3_512) { $hybridParameters.ExpectedMldsa87Sha3_512 = $ExpectedMldsa87Sha3_512 }
        if ($ExpectedMldsa87Skein1024) { $hybridParameters.ExpectedMldsa87Skein1024 = $ExpectedMldsa87Skein1024 }
        & $hybridSignatureScript @hybridParameters
        if ($LASTEXITCODE -ne 0) {
            throw "Hybrid manifest signing failed for $target."
        }
    }
}
