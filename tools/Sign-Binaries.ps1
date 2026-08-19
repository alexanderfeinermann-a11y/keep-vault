param(
    [string[]] $Path,
    [string] $Configuration = "Release",
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
    [string] $MldsaReferencePath,
    [switch] $CreateDevelopmentCertificate,
    [switch] $TrustDevelopmentCertificate,
    [switch] $AllowUntimestamped,
    [string] $TimestampUrl = "http://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"
$root = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")
$skeinManifestScript = Join-Path $root "tools\Generate-SkeinManifest.ps1"
$hybridSignatureScript = Join-Path $root "tools\New-HybridSignature.ps1"

if ($TrustDevelopmentCertificate) {
    throw "Trusting the development root in CurrentUser\\Root is forbidden. Development signatures are accepted only through the compiled SHA-256/SHA3-512/Skein-1024 SPKI pins."
}

function Normalize-Hex {
    param(
        [string] $Value,
        [int] $Length,
        [string] $Name
    )
    $normalized = $Value -replace "\s", ""
    if ($normalized -notmatch "^[0-9A-Fa-f]{$Length}$") {
        throw "$Name must contain exactly $Length hexadecimal characters."
    }

    return $normalized.ToUpperInvariant()
}

[xml] $buildProperties = Get-Content -LiteralPath (Join-Path $root "Directory.Build.props")
$propertyGroup = $buildProperties.Project.PropertyGroup
$defaultSha256 = $propertyGroup.SelectSingleNode("KalynaExpectedSignerSha256").InnerText
$defaultSha3 = $propertyGroup.SelectSingleNode("KalynaExpectedSignerSha3_512").InnerText
$defaultSkein = $propertyGroup.SelectSingleNode("KalynaExpectedSignerSkein1024").InnerText
$defaultMldsaSha256 = $propertyGroup.SelectSingleNode("KalynaExpectedMldsa87Sha256").InnerText
$defaultMldsaSha3 = $propertyGroup.SelectSingleNode("KalynaExpectedMldsa87Sha3_512").InnerText
$defaultMldsaSkein = $propertyGroup.SelectSingleNode("KalynaExpectedMldsa87Skein1024").InnerText
$expectedSha256 = Normalize-Hex $(if ($ExpectedSignerSha256) { $ExpectedSignerSha256 } else { $defaultSha256 }) 64 "Expected SHA-256 SPKI fingerprint"
$expectedSha3 = Normalize-Hex $(if ($ExpectedSignerSha3_512) { $ExpectedSignerSha3_512 } else { $defaultSha3 }) 128 "Expected SHA3-512 SPKI fingerprint"
$expectedSkein = Normalize-Hex $(if ($ExpectedSignerSkein1024) { $ExpectedSignerSkein1024 } else { $defaultSkein }) 256 "Expected Skein-1024 SPKI fingerprint"
$expectedMldsaSha256 = Normalize-Hex $(if ($ExpectedMldsa87Sha256) { $ExpectedMldsa87Sha256 } else { $defaultMldsaSha256 }) 64 "Expected ML-DSA-87 SHA-256 fingerprint"
$expectedMldsaSha3 = Normalize-Hex $(if ($ExpectedMldsa87Sha3_512) { $ExpectedMldsa87Sha3_512 } else { $defaultMldsaSha3 }) 128 "Expected ML-DSA-87 SHA3-512 fingerprint"
$expectedMldsaSkein = Normalize-Hex $(if ($ExpectedMldsa87Skein1024) { $ExpectedMldsa87Skein1024 } else { $defaultMldsaSkein }) 256 "Expected ML-DSA-87 Skein-1024 fingerprint"

function Get-SignerPins {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate)

    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($Certificate)
    if (-not $rsa) {
        throw "The code-signing certificate must use an RSA public key."
    }

    $spki = $rsa.ExportSubjectPublicKeyInfo()
    $temporarySpki = Join-Path $env:TEMP "kalyna-signer-spki-$([Guid]::NewGuid().ToString('N')).bin"
    try {
        [System.IO.File]::WriteAllBytes($temporarySpki, $spki)
        & pwsh -NoProfile -ExecutionPolicy Bypass -File $skeinManifestScript `
            -ExecutablePath $temporarySpki `
            -ProviderPath (Join-Path $root "tools\threefish_ref.dll") | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Skein-1024 signer fingerprint generation failed."
        }

        return [pscustomobject]@{
            Thumbprint = Normalize-Hex $Certificate.Thumbprint 40 "Signer thumbprint"
            Sha256 = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($spki))
            Sha3 = [Convert]::ToHexString([System.Security.Cryptography.SHA3_512]::HashData($spki))
            Skein = (Get-Content -LiteralPath "$temporarySpki.skein" -Raw).Trim().ToUpperInvariant()
        }
    }
    finally {
        [Array]::Clear($spki, 0, $spki.Length)
        $rsa.Dispose()
        Remove-Item -LiteralPath $temporarySpki, "$temporarySpki.skein" -Force -ErrorAction SilentlyContinue
    }
}

function Find-SignTool {
    $kitsRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"
    if (-not (Test-Path -LiteralPath $kitsRoot)) {
        throw "Windows SDK signtool.exe was not found."
    }

    $tool = Get-ChildItem -LiteralPath $kitsRoot -Recurse -Filter signtool.exe |
        Where-Object { $_.FullName -match "\\x64\\signtool\.exe$" } |
        Sort-Object FullName -Descending |
        Select-Object -First 1

    if (-not $tool) {
        throw "x64 signtool.exe was not found under $kitsRoot."
    }

    return $tool.FullName
}

function Get-DevelopmentCertificate {
    $rootSubject = "CN=Keep Vault Development Root SHA512"
    $subject = "CN=Keep Vault Development Signing SHA512"
    $root = Get-ChildItem Cert:\CurrentUser\My |
        Where-Object { $_.Subject -eq $rootSubject -and $_.HasPrivateKey } |
        Sort-Object NotAfter -Descending |
        Select-Object -First 1

    if (-not $root) {
        $root = New-SelfSignedCertificate `
            -Type Custom `
            -Subject $rootSubject `
            -KeyAlgorithm RSA `
            -KeyLength 4096 `
            -KeyUsage CertSign,CRLSign,DigitalSignature `
            -HashAlgorithm SHA512 `
            -KeyExportPolicy NonExportable `
            -CertStoreLocation Cert:\CurrentUser\My `
            -TextExtension @("2.5.29.19={critical}{text}ca=1") `
            -NotAfter (Get-Date).AddYears(10)
    }

    $cert = Get-ChildItem Cert:\CurrentUser\My |
        Where-Object { $_.Subject -eq $subject -and $_.Issuer -eq $root.Subject -and $_.HasPrivateKey } |
        Sort-Object NotAfter -Descending |
        Select-Object -First 1

    if (-not $cert) {
        $cert = New-SelfSignedCertificate `
            -Type CodeSigningCert `
            -Subject $subject `
            -Signer $root `
            -KeyAlgorithm RSA `
            -KeyLength 4096 `
            -HashAlgorithm SHA512 `
            -KeyExportPolicy NonExportable `
            -CertStoreLocation Cert:\CurrentUser\My `
            -NotAfter (Get-Date).AddYears(3)
    }

    $trustedDevelopmentRoot = Get-ChildItem Cert:\CurrentUser\Root |
        Where-Object { $_.Thumbprint -eq $root.Thumbprint } |
        Select-Object -First 1
    if ($trustedDevelopmentRoot) {
        throw "The Keep Vault development root is installed in CurrentUser\\Root. Remove thumbprint $($root.Thumbprint) from that trust store before signing."
    }

    return $cert
}

function Assert-DevelopmentRootNotTrusted {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate)

    if ($Certificate.Subject -ne "CN=Keep Vault Development Signing SHA512" -or
        $Certificate.Issuer -ne "CN=Keep Vault Development Root SHA512") {
        return
    }

    $trustedDevelopmentRoot = Get-ChildItem Cert:\CurrentUser\Root |
        Where-Object { $_.Subject -eq $Certificate.Issuer } |
        Select-Object -First 1
    if ($trustedDevelopmentRoot) {
        throw "The Keep Vault development root is globally trusted in CurrentUser\\Root (thumbprint $($trustedDevelopmentRoot.Thumbprint)). Remove it before signing."
    }
}

function Get-DefaultTargets {
    # Every executable in tools\, not a list of names: a native component that
    # is built but not signed is one the app will refuse to load, and the list
    # is exactly the thing nobody remembers to extend.
    $candidates = [System.Collections.Generic.List[string]]@()
    $toolsDirectory = Join-Path $root "tools"
    Get-ChildItem -LiteralPath $toolsDirectory -File |
        Where-Object { $_.Extension -in @(".exe", ".dll") } |
        Sort-Object -Property Name |
        ForEach-Object { $candidates.Add($_.FullName) }

    $applicationDirectory = Join-Path $root "KalynaArchiver\bin\$Configuration\net9.0-windows"
    if (Test-Path -LiteralPath $applicationDirectory) {
        Get-ChildItem -LiteralPath $applicationDirectory -File |
            Where-Object { $_.Extension -in @(".exe", ".dll") } |
            ForEach-Object { $candidates.Add($_.FullName) }
    }

    return $candidates |
        Where-Object { Test-Path -LiteralPath $_ } |
        Select-Object -Unique
}

function Invoke-SignTool {
    param(
        [string] $SignTool,
        [string] $Target,
        [string[]] $CredentialArgs
    )

    $existingSignature = Get-AuthenticodeSignature -LiteralPath $Target
    if ($existingSignature.Status -ne "NotSigned") {
        & $SignTool remove "/s" "/q" $Target
        if ($LASTEXITCODE -ne 0) {
            throw "signtool could not remove the existing signature from $Target."
        }
    }

    $commonArgs = @("sign", "/fd", "SHA512")
    if ($TimestampUrl) {
        $timestampArgs = $commonArgs + @("/td", "SHA512", "/tr", $TimestampUrl) + $CredentialArgs + @($Target)
        & $SignTool @timestampArgs
        if ($LASTEXITCODE -eq 0) {
            return
        }

        if (-not $AllowUntimestamped) {
            throw "Timestamped signing failed for $Target. Untimestamped fallback is disabled."
        }

        Write-Warning "Timestamped signing failed for $Target. Explicitly allowed untimestamped fallback is being used."
    }

    $args = $commonArgs + $CredentialArgs + @($Target)
    & $SignTool @args
    if ($LASTEXITCODE -ne 0) {
        throw "signtool failed for $Target with exit code $LASTEXITCODE."
    }
}

if (-not $Path -or $Path.Count -eq 0) {
    $Path = Get-DefaultTargets
}

if (-not $Path -or $Path.Count -eq 0) {
    throw "No binaries found to sign."
}

$signTool = Find-SignTool
$credentialArgs = @()

if ($PfxPath) {
    $resolvedPfx = Resolve-Path -LiteralPath $PfxPath
    $credentialArgs = @("/f", $resolvedPfx)
    if ($PfxPassword) {
        $credentialArgs += @("/p", $PfxPassword)
    }
}
elseif ($CertificateThumbprint) {
    $normalizedCertificateThumbprint = $CertificateThumbprint -replace "\s", ""
    $selectedCertificate = Get-ChildItem "Cert:\CurrentUser\My\$normalizedCertificateThumbprint" -ErrorAction Stop
    Assert-DevelopmentRootNotTrusted $selectedCertificate
    $credentialArgs = @("/sha1", $normalizedCertificateThumbprint, "/s", "My")
}
elseif ($CreateDevelopmentCertificate) {
    $cert = Get-DevelopmentCertificate
    Assert-DevelopmentRootNotTrusted $cert
    $credentialArgs = @("/sha1", $cert.Thumbprint, "/s", "My")
}
else {
    throw "Provide -PfxPath, -CertificateThumbprint, or -CreateDevelopmentCertificate."
}

foreach ($target in $Path) {
    $resolvedTarget = Resolve-Path -LiteralPath $target
    Invoke-SignTool -SignTool $signTool -Target $resolvedTarget -CredentialArgs $credentialArgs
    $signature = Get-AuthenticodeSignature -LiteralPath $resolvedTarget
    if ($signature.Status -eq "NotSigned" -or -not $signature.SignerCertificate) {
        throw "Signing did not produce an Authenticode signer certificate for $resolvedTarget."
    }

    Assert-DevelopmentRootNotTrusted $signature.SignerCertificate
    if ($signature.SignerCertificate.SignatureAlgorithm.Value -ne "1.2.840.113549.1.1.13") {
        throw "The Authenticode signer certificate is not signed with SHA-512/RSA: $resolvedTarget"
    }
    $pins = Get-SignerPins $signature.SignerCertificate
    if (($pins.Sha256 -cne $expectedSha256) -or
        ($pins.Sha3 -cne $expectedSha3) -or
        ($pins.Skein -cne $expectedSkein)) {
        throw "Signed file does not match the mandatory SHA-256/SHA3-512/Skein-1024 SPKI signer pins: $resolvedTarget"
    }

    $signer = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { "unknown signer" }
    $hybridParameters = @{
        Path = $resolvedTarget
        ExpectedSignerSha256 = $expectedSha256
        ExpectedSignerSha3_512 = $expectedSha3
        ExpectedSignerSkein1024 = $expectedSkein
        ExpectedMldsa87Sha256 = $expectedMldsaSha256
        ExpectedMldsa87Sha3_512 = $expectedMldsaSha3
        ExpectedMldsa87Skein1024 = $expectedMldsaSkein
        NoBuild = $true
    }
    if ($PfxPath) {
        $hybridParameters.PfxPath = $PfxPath
        $hybridParameters.PfxPassword = $PfxPassword
    }
    else {
        $hybridParameters.CertificateThumbprint = $signature.SignerCertificate.Thumbprint
    }
    if ($MldsaPrivateKeyPath) { $hybridParameters.MldsaPrivateKeyPath = $MldsaPrivateKeyPath }
    if ($MldsaPublicKeyPath) { $hybridParameters.MldsaPublicKeyPath = $MldsaPublicKeyPath }
    if ($MldsaReferencePath) { $hybridParameters.MldsaReferencePath = $MldsaReferencePath }
    & $hybridSignatureScript @hybridParameters
    if ($LASTEXITCODE -ne 0) {
        throw "Hybrid signing failed for $resolvedTarget."
    }

    Write-Host "Signed $resolvedTarget [$($signature.Status)] $signer [RSA-4096/SHA-512 + ML-DSA-87 valid]"
}
