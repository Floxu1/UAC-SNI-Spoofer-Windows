param(
    [string]$DistRoot = (Join-Path $PSScriptRoot 'dist'),
    [string]$WorkRoot = (Join-Path $PSScriptRoot 'build'),
    [string]$OutputPath = (Join-Path $PSScriptRoot 'github_release'),
    [string]$WixPath = 'wix',
    [switch]$UsePreparedEngines
)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
& .\build.ps1 -DistRoot $DistRoot -WorkRoot $WorkRoot -UsePreparedEngines:$UsePreparedEngines
python -m tools.prepare_github_release --dist (Join-Path $DistRoot 'UAC-Spoofer-Desktop') --output $OutputPath --wix $WixPath
if ($LASTEXITCODE -ne 0) { throw 'Release packaging failed.' }
