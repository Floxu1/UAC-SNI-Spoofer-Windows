$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
if (-not (Test-Path '.\bin\xray.exe')) {
    & "$PSScriptRoot\install-engine.ps1"
}
python .\main.py
