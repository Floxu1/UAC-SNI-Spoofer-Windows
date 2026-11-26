param(
    [string]$DistPath = "",
    [string]$OutputPath = "",
    [string]$WixPath = 'wix'
)

$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Set-Location $projectRoot
if (-not $DistPath) { $DistPath = Join-Path $projectRoot 'dist\UAC-Spoofer-Desktop' }
if (-not $OutputPath) { $OutputPath = Join-Path $projectRoot 'github_release' }
python -m tools.prepare_github_release --dist $DistPath --output $OutputPath --wix $WixPath
if ($LASTEXITCODE -ne 0) { throw 'Release packaging failed.' }
