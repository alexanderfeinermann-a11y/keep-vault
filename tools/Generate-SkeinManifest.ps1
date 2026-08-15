param(
    [Parameter(Mandatory = $true)]
    [string] $ExecutablePath,
    [string] $ProviderPath
)

$ErrorActionPreference = "Stop"
$resolved = Resolve-Path -LiteralPath $ExecutablePath

if (-not $ProviderPath) {
    $candidate = Join-Path (Split-Path -Parent $resolved) "threefish_ref.dll"
    if (Test-Path -LiteralPath $candidate) {
        $ProviderPath = $candidate
    }
    else {
        $ProviderPath = Join-Path $PSScriptRoot "threefish_ref.dll"
    }
}

$provider = Resolve-Path -LiteralPath $ProviderPath

if (-not ("SkeinManifestDelegates" -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class SkeinManifestDelegates
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate IntPtr Create();

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int Update(IntPtr state, byte[] input, UIntPtr length);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int Final(IntPtr state, byte[] output, UIntPtr outputLength);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void Destroy(IntPtr state);
}
"@
}

$module = [System.Runtime.InteropServices.NativeLibrary]::Load($provider)
$state = [IntPtr]::Zero
$stream = $null
$buffer = New-Object byte[] (1024 * 1024)
$digest = New-Object byte[] 128
try {
    $createPointer = [System.Runtime.InteropServices.NativeLibrary]::GetExport($module, "skein_1024_create")
    $updatePointer = [System.Runtime.InteropServices.NativeLibrary]::GetExport($module, "skein_1024_update")
    $finalPointer = [System.Runtime.InteropServices.NativeLibrary]::GetExport($module, "skein_1024_final")
    $destroyPointer = [System.Runtime.InteropServices.NativeLibrary]::GetExport($module, "skein_1024_destroy")
    $create = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($createPointer, [SkeinManifestDelegates+Create])
    $update = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($updatePointer, [SkeinManifestDelegates+Update])
    $final = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($finalPointer, [SkeinManifestDelegates+Final])
    $destroy = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($destroyPointer, [SkeinManifestDelegates+Destroy])

    $state = $create.Invoke()
    if ($state -eq [IntPtr]::Zero) {
        throw "The official Skein-1024 provider could not allocate a hash state."
    }

    $stream = [System.IO.File]::OpenRead($resolved)
    while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
        $result = $update.Invoke($state, $buffer, [UIntPtr]::new([uint64]$read))
        if ($result -ne 0) {
            throw "The official Skein-1024 provider returned update error $result."
        }
    }

    $result = $final.Invoke($state, $digest, [UIntPtr]::new([uint64]$digest.Length))
    if ($result -ne 0) {
        throw "The official Skein-1024 provider returned finalization error $result."
    }

    $hex = [Convert]::ToHexString($digest)
    Set-Content -LiteralPath "$resolved.skein" -Value $hex -NoNewline -Encoding ASCII
    Write-Host "Skein-1024 manifest written to $resolved.skein"
}
finally {
    if ($stream) {
        $stream.Dispose()
    }

    if ($state -ne [IntPtr]::Zero -and $destroy) {
        $destroy.Invoke($state)
    }

    [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($buffer)
    [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($digest)
    if ($module -ne [IntPtr]::Zero) {
        [System.Runtime.InteropServices.NativeLibrary]::Free($module)
    }
}
