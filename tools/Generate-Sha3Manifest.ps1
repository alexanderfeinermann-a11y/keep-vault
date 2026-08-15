param(
    [Parameter(Mandatory = $true)]
    [string] $ExecutablePath
)

$ErrorActionPreference = "Stop"

try {
    $null = [System.Security.Cryptography.SHA3_512]
}
catch {
    throw "SHA3-512 is not available in this PowerShell runtime. Run this script with PowerShell 7 / .NET 8+ (pwsh)."
}

$resolved = Resolve-Path -LiteralPath $ExecutablePath
$stream = [System.IO.File]::OpenRead($resolved)
try {
    $digest = [System.Security.Cryptography.SHA3_512]::HashData($stream)
    $hex = [Convert]::ToHexString($digest)
    Set-Content -LiteralPath "$resolved.sha3" -Value $hex -NoNewline -Encoding ASCII
    Write-Host "SHA3-512 manifest written to $resolved.sha3"
}
finally {
    $stream.Dispose()
}
