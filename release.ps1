$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
& .\build.ps1
python .\tools\prepare_github_release.py
