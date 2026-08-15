[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Mandatory = $true)]
    [string[]] $Path,
    [string] $CertificateThumbprint,
    [string] $PfxPath,
    [string] $PfxPassword,
    [string] $MldsaPrivateKeyPath,
    [string] $MldsaPublicKeyPath,
    [string] $MldsaReferencePath,
    [string] $ExpectedSignerSha256,
    [string] $ExpectedSignerSha3_512,
    [string] $ExpectedSignerSkein1024,
    [string] $ExpectedMldsa87Sha256,
    [string] $ExpectedMldsa87Sha3_512,
    [string] $ExpectedMldsa87Skein1024,
    [switch] $NoBuild
)

$ErrorActionPreference = "Stop"
$root = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")
$signingProject = Join-Path $root "KalynaSigningTool\KalynaSigningTool.csproj"
$signingTool = Join-Path $root "KalynaSigningTool\bin\Release\net9.0-windows\KalynaSigningTool.dll"

if (-not $MldsaPrivateKeyPath) {
    $MldsaPrivateKeyPath = Join-Path $env:LOCALAPPDATA "KalynaZpaqVault\Signing\mldsa87-development.dpapi"
}
if (-not $MldsaPublicKeyPath) {
    $MldsaPublicKeyPath = Join-Path $root "tools\mldsa87-public.key"
}
if (-not $MldsaReferencePath) {
    $MldsaReferencePath = Join-Path $root "tools\mldsa87_ref.dll"
}

if (-not $NoBuild -or -not (Test-Path -LiteralPath $signingTool)) {
    & dotnet build $signingProject -c Release --nologo
    if ($LASTEXITCODE -ne 0) {
        throw "KalynaSigningTool build failed."
    }
}

foreach ($required in @($MldsaPrivateKeyPath, $MldsaPublicKeyPath, $MldsaReferencePath, $signingTool)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required hybrid-signing component is missing: $required"
    }
}

[xml] $buildProperties = Get-Content -LiteralPath (Join-Path $root "Directory.Build.props")
$propertyGroup = $buildProperties.Project.PropertyGroup
if (-not $ExpectedSignerSha256) { $ExpectedSignerSha256 = $propertyGroup.SelectSingleNode("KalynaExpectedSignerSha256").InnerText }
if (-not $ExpectedSignerSha3_512) { $ExpectedSignerSha3_512 = $propertyGroup.SelectSingleNode("KalynaExpectedSignerSha3_512").InnerText }
if (-not $ExpectedSignerSkein1024) { $ExpectedSignerSkein1024 = $propertyGroup.SelectSingleNode("KalynaExpectedSignerSkein1024").InnerText }
if (-not $ExpectedMldsa87Sha256) { $ExpectedMldsa87Sha256 = $propertyGroup.SelectSingleNode("KalynaExpectedMldsa87Sha256").InnerText }
if (-not $ExpectedMldsa87Sha3_512) { $ExpectedMldsa87Sha3_512 = $propertyGroup.SelectSingleNode("KalynaExpectedMldsa87Sha3_512").InnerText }
if (-not $ExpectedMldsa87Skein1024) { $ExpectedMldsa87Skein1024 = $propertyGroup.SelectSingleNode("KalynaExpectedMldsa87Skein1024").InnerText }

$oldPfxPassword = $env:KALYNA_HYBRID_PFX_PASSWORD
try {
    if ($PfxPath) {
        $env:KALYNA_HYBRID_PFX_PASSWORD = $PfxPassword
    }

    foreach ($target in $Path) {
        $resolvedTarget = (Resolve-Path -LiteralPath $target).Path
        $signaturePath = "$resolvedTarget.khsig"
        $arguments = @(
            $signingTool,
            "sign",
            "--file", $resolvedTarget,
            "--signature", $signaturePath,
            "--private-key", $MldsaPrivateKeyPath,
            "--public-key", $MldsaPublicKeyPath,
            "--reference-dll", $MldsaReferencePath
        )
        if ($PfxPath) {
            $arguments += @("--pfx", (Resolve-Path -LiteralPath $PfxPath).Path, "--pfx-password-env", "KALYNA_HYBRID_PFX_PASSWORD")
        }
        elseif ($CertificateThumbprint) {
            $arguments += @("--certificate-thumbprint", $CertificateThumbprint)
        }
        else {
            throw "Hybrid signing requires CertificateThumbprint or PfxPath."
        }

        & dotnet @arguments
        if ($LASTEXITCODE -ne 0) {
            throw "Hybrid RSA/ML-DSA signing failed for $resolvedTarget."
        }

        & dotnet $signingTool verify `
            --file $resolvedTarget `
            --signature $signaturePath `
            --public-key $MldsaPublicKeyPath `
            --rsa-sha256 $ExpectedSignerSha256 `
            --rsa-sha3 $ExpectedSignerSha3_512 `
            --rsa-skein $ExpectedSignerSkein1024 `
            --mldsa-sha256 $ExpectedMldsa87Sha256 `
            --mldsa-sha3 $ExpectedMldsa87Sha3_512 `
            --mldsa-skein $ExpectedMldsa87Skein1024
        if ($LASTEXITCODE -ne 0) {
            throw "Hybrid signature verification failed for $resolvedTarget."
        }
    }
}
finally {
    $env:KALYNA_HYBRID_PFX_PASSWORD = $oldPfxPassword
}
