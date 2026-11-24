param(
    [string]$Destination
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
if (-not $Destination) { $Destination = Join-Path $repo 'bin/uac-pow-guard.exe' }
$source = Join-Path $PSScriptRoot 'pow-guard.c'
$staging = Join-Path $repo 'build/pow-parity/wfp'
New-Item -ItemType Directory -Path $staging -Force | Out-Null
$hash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
$staged = Join-Path $staging "$hash.exe"

if (-not (Test-Path -LiteralPath $staged)) {
    $cl = Get-Command cl.exe -ErrorAction SilentlyContinue
    if (-not $cl) { throw 'Build the POW Windows Filtering Platform helper from an x64 MSVC shell.' }
    $obj = Join-Path $staging 'pow-guard.obj'
    & $cl.Source /nologo /O2 /MT /W4 /WX "/Fo$obj" "/Fe$staged" $source fwpuclnt.lib iphlpapi.lib rpcrt4.lib
    if ($LASTEXITCODE -ne 0) { throw "Could not build the POW WFP helper ($LASTEXITCODE)." }
}
if ((& $staged --version) -ne 'pow-wfp/1' -or $LASTEXITCODE -ne 0) {
    throw 'The POW WFP helper did not identify its protocol.'
}
New-Item -ItemType Directory -Path (Split-Path -Parent $Destination) -Force | Out-Null
Copy-Item -LiteralPath $staged -Destination $Destination -Force
