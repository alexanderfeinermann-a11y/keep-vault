#Requires -Version 7.0
<#
.SYNOPSIS
    Draws the QR-Scanner icon: a real QR code on a rounded tile.

.DESCRIPTION
    The icon is generated rather than committed as a binary, so what it contains
    is readable in this file instead of being taken on trust. The code encodes
    the app's name; anyone who points a scanner at the icon gets "QR-Scanner"
    back, which is the honest thing for a QR code sitting in a taskbar to say.

    Correction level L on a short string keeps the module count low (version 1,
    21x21). That matters: at 16 pixels a denser code collapses into grey mush,
    while these modules stay individually visible.

    The same design as the macOS scanner's make-icon.swift, drawn with GDI+ and
    the QR encoder the test project already depends on.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $OutputPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$message = 'QR-Scanner'
$sizes = @(16, 32, 48, 64, 128, 256)

$scannerRoot = Split-Path -Parent $PSScriptRoot
$packages = Join-Path $env:USERPROFILE '.nuget\packages\qrcoder'
$qrCoder = Get-ChildItem -LiteralPath $packages -Recurse -Filter 'QRCoder.dll' -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match 'net(6|8|9)\.0' } |
    Select-Object -First 1
if (-not $qrCoder) {
    # Restoring the test project is what puts QRCoder in the package cache; the
    # shipped scanner never encodes a code and has no such reference.
    & dotnet restore (Join-Path $scannerRoot 'QrScanner.Tests.csproj') | Out-Null
    $qrCoder = Get-ChildItem -LiteralPath $packages -Recurse -Filter 'QRCoder.dll' -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match 'net(6|8|9)\.0' } |
        Select-Object -First 1
}
if (-not $qrCoder) {
    throw 'QRCoder was not found in the NuGet cache; restore QrScanner.Tests.csproj first.'
}

Add-Type -Path $qrCoder.FullName
Add-Type -AssemblyName System.Drawing

$generator = [QRCoder.QRCodeGenerator]::new()
$data = $generator.CreateQrCode($message, [QRCoder.QRCodeGenerator+ECCLevel]::L)
$modules = $data.ModuleMatrix.Count

$bitmaps = [System.Collections.Generic.List[System.Drawing.Bitmap]]::new()
foreach ($side in $sizes) {
    $bitmap = [System.Drawing.Bitmap]::new($side, $side, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $graphics.Clear([System.Drawing.Color]::Transparent)

    # The rounded tile the code sits on.
    $inset = [Math]::Max(1, [int]($side * 0.06))
    $radius = [Math]::Max(2, [int]($side * 0.22))
    $rectangle = [System.Drawing.Rectangle]::new($inset, $inset, $side - (2 * $inset), $side - (2 * $inset))
    $path = [System.Drawing.Drawing2D.GraphicsPath]::new()
    $path.AddArc($rectangle.X, $rectangle.Y, $radius, $radius, 180, 90)
    $path.AddArc($rectangle.Right - $radius, $rectangle.Y, $radius, $radius, 270, 90)
    $path.AddArc($rectangle.Right - $radius, $rectangle.Bottom - $radius, $radius, $radius, 0, 90)
    $path.AddArc($rectangle.X, $rectangle.Bottom - $radius, $radius, $radius, 90, 90)
    $path.CloseFigure()
    $tile = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(255, 11, 20, 34))
    $graphics.FillPath($tile, $path)

    # The code itself, with a quiet zone inside the tile so it stays scannable.
    $quiet = [Math]::Max(1, [int]($side * 0.16))
    $codeSide = $side - (2 * $quiet)
    $moduleSize = $codeSide / $modules
    $ink = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(255, 232, 238, 246))
    for ($row = 0; $row -lt $modules; $row++) {
        for ($column = 0; $column -lt $modules; $column++) {
            if (-not $data.ModuleMatrix[$row][$column]) { continue }
            $graphics.FillRectangle(
                $ink,
                [single]($quiet + ($column * $moduleSize)),
                [single]($quiet + ($row * $moduleSize)),
                [single]([Math]::Ceiling($moduleSize)),
                [single]([Math]::Ceiling($moduleSize)))
        }
    }

    $ink.Dispose(); $tile.Dispose(); $path.Dispose(); $graphics.Dispose()
    $bitmaps.Add($bitmap)
}

$directory = Split-Path -Parent $OutputPath
if ($directory -and -not (Test-Path -LiteralPath $directory)) {
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
}

# ICO, written by hand: .NET can save a single-image icon but not a multi-size
# one, and an icon that only exists at 256 pixels looks wrong everywhere else.
$stream = [System.IO.File]::Create($OutputPath)
try {
    $writer = [System.IO.BinaryWriter]::new($stream)
    $writer.Write([uint16]0)
    $writer.Write([uint16]1)
    $writer.Write([uint16]$bitmaps.Count)

    $encoded = [System.Collections.Generic.List[byte[]]]::new()
    foreach ($bitmap in $bitmaps) {
        $buffer = [System.IO.MemoryStream]::new()
        $bitmap.Save($buffer, [System.Drawing.Imaging.ImageFormat]::Png)
        $encoded.Add($buffer.ToArray())
        $buffer.Dispose()
    }

    $offset = 6 + (16 * $bitmaps.Count)
    for ($index = 0; $index -lt $bitmaps.Count; $index++) {
        $side = $sizes[$index]
        $writer.Write([byte]($(if ($side -ge 256) { 0 } else { $side })))
        $writer.Write([byte]($(if ($side -ge 256) { 0 } else { $side })))
        $writer.Write([byte]0)
        $writer.Write([byte]0)
        $writer.Write([uint16]1)
        $writer.Write([uint16]32)
        $writer.Write([uint32]$encoded[$index].Length)
        $writer.Write([uint32]$offset)
        $offset += $encoded[$index].Length
    }

    foreach ($bytes in $encoded) {
        $writer.Write($bytes)
    }

    $writer.Flush()
}
finally {
    $stream.Dispose()
    foreach ($bitmap in $bitmaps) { $bitmap.Dispose() }
    $data.Dispose()
    $generator.Dispose()
}

Write-Host "Icon written to $OutputPath ($($sizes -join ', ') pixels)"
