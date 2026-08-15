param(
    [string] $AppPath
)

$ErrorActionPreference = "Stop"
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
if ([string]::IsNullOrWhiteSpace($AppPath)) {
    $AppPath = Join-Path $root "dist\Keep Vault-portable-win-x64\Keep Vault.exe"
}

$resolvedApp = [IO.Path]::GetFullPath($AppPath)
$relativeApp = [IO.Path]::GetRelativePath($root, $resolvedApp)
if ([IO.Path]::IsPathRooted($relativeApp) -or
    $relativeApp -eq ".." -or
    $relativeApp.StartsWith("..$([IO.Path]::DirectorySeparatorChar)", [StringComparison]::Ordinal)) {
    throw "The shortcut target must remain inside the Keep Vault workspace: $resolvedApp"
}

if (-not (Test-Path -LiteralPath $resolvedApp -PathType Leaf)) {
    throw "Keep Vault executable not found: $resolvedApp"
}

$desktop = [Environment]::GetFolderPath([Environment+SpecialFolder]::DesktopDirectory)
$programs = [Environment]::GetFolderPath([Environment+SpecialFolder]::Programs)
if ([string]::IsNullOrWhiteSpace($desktop) -or [string]::IsNullOrWhiteSpace($programs)) {
    throw "Windows did not provide the Desktop or Start Menu Programs directory."
}

$shortcutPaths = @(
    (Join-Path $desktop "Keep Vault.lnk"),
    (Join-Path $programs "Keep Vault.lnk")
)
$workingDirectory = [IO.Path]::GetDirectoryName($resolvedApp)
$shell = New-Object -ComObject WScript.Shell
try {
    foreach ($shortcutPath in $shortcutPaths) {
        $directory = [IO.Path]::GetDirectoryName($shortcutPath)
        [IO.Directory]::CreateDirectory($directory) | Out-Null
        $temporaryPath = Join-Path $directory ".Keep Vault.$([Guid]::NewGuid().ToString('N')).lnk"
        $shortcut = $shell.CreateShortcut($temporaryPath)
        try {
            $shortcut.TargetPath = $resolvedApp
            $shortcut.WorkingDirectory = $workingDirectory
            $shortcut.IconLocation = "$resolvedApp,0"
            $shortcut.Description = "Keep Vault"
            $shortcut.Save()
            [IO.File]::Move($temporaryPath, $shortcutPath, $true)
        }
        finally {
            [Runtime.InteropServices.Marshal]::FinalReleaseComObject($shortcut) | Out-Null
            if (Test-Path -LiteralPath $temporaryPath) {
                [IO.File]::Delete($temporaryPath)
            }
        }
    }
}
finally {
    [Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell) | Out-Null
}

foreach ($legacyPath in @(
    (Join-Path $desktop "Kalyna ZPAQ Vault.lnk"),
    (Join-Path $programs "Kalyna ZPAQ Vault.lnk"),
    (Join-Path $desktop "Kryptonite Vault.lnk"),
    (Join-Path $programs "Kryptonite Vault.lnk")
)) {
    if (Test-Path -LiteralPath $legacyPath -PathType Leaf) {
        [IO.File]::Delete($legacyPath)
    }
}

$shortcutPaths | ForEach-Object { Get-Item -LiteralPath $_ }
