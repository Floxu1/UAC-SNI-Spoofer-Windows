$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
python -m pip install -r .\requirements.txt
if (-not (Test-Path '.\bin\xray.exe')) { & .\install-engine.ps1 }
python -m pytest .\tests -q
python -m PyInstaller --noconfirm --clean .\UAC-Spoofer-Desktop.spec
Write-Host "`nBuild ready: $PSScriptRoot\dist\UAC-Spoofer-Desktop\UAC-Spoofer-Desktop.exe"
