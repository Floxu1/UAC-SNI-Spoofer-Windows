param(
    [string]$DistRoot = (Join-Path $PSScriptRoot 'dist'),
    [string]$WorkRoot = (Join-Path $PSScriptRoot 'build'),
    [switch]$UsePreparedEngines
)

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

Write-Host "Installing Python requirements..."
python -m pip install -r .\requirements.txt 'Pillow>=10,<13'

if ($LASTEXITCODE -ne 0) {
    throw "pip failed with exit code $LASTEXITCODE"
}

if (-not $UsePreparedEngines) {
    Write-Host "Preparing network engines..."
    & .\install-engine.ps1
}

$distDir = Join-Path ([IO.Path]::GetFullPath($DistRoot)) 'UAC-Spoofer-Desktop'
Write-Host "Building application..."
python -m PyInstaller `
    --noconfirm `
    --clean `
    --distpath $DistRoot `
    --workpath $WorkRoot `
    .\UAC-Spoofer-Desktop.spec

if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller failed with exit code $LASTEXITCODE"
}

$exe = Join-Path `
    $distDir `
    'UAC-Spoofer-Desktop.exe'

if (-not (Test-Path -LiteralPath $exe)) {
    throw "Build finished without producing $exe"
}

Write-Host "Building the standalone update worker..."
python -m PyInstaller --noconfirm --clean --onefile --windowed --noupx --name UAC-Update `
    --paths $PSScriptRoot --distpath $distDir --workpath $WorkRoot --specpath $WorkRoot `
    (Join-Path $PSScriptRoot 'tools\update_worker.py')
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath (Join-Path $distDir 'UAC-Update.exe'))) {
    throw 'The update worker build failed.'
}

Write-Host ""
Write-Host "Build ready: $exe"
