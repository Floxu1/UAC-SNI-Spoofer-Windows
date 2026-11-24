param(
    [string]$Destination,
    [switch]$Test,
    [switch]$Offline
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$source = Join-Path $repo 'core/direct'
if (-not $Destination) { $Destination = Join-Path $repo 'bin/uac-direct.exe' }
$target = Join-Path $repo 'build/pow-parity/cargo'
$files = @(
    'core/direct/Cargo.toml'
    'core/direct/Cargo.lock'
    'core/direct/src/route.rs'
    'core/direct/src/bin/uac-direct.rs'
)
$files += (Get-Content -Raw -LiteralPath (Join-Path $repo 'core/aether/SOURCE.json') |
    ConvertFrom-Json).files.PSObject.Properties.Name
$entries = foreach ($name in ($files | Sort-Object)) {
    $hash = (Get-FileHash -LiteralPath (Join-Path $repo $name) -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash $name"
}
$sha = [Security.Cryptography.SHA256]::Create()
try {
    $sourceId = [BitConverter]::ToString(
        $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($entries -join "`n"))
    ).Replace('-', '').ToLowerInvariant()
} finally {
    $sha.Dispose()
}

$expected = "direct-config/1 $sourceId"
if (-not $Test -and (Test-Path -LiteralPath $Destination)) {
    $installed = & $Destination --direct-contract 2>$null
    if ($LASTEXITCODE -eq 0 -and $installed -eq $expected) {
        Write-Host "Direct $installed"
        return
    }
}

$params = @('--release', '--locked', '--manifest-path', (Join-Path $source 'Cargo.toml'),
    '--target-dir', $target, '--bin', 'uac-direct')
if ($Offline) { $params += '--offline' }
$priorId = $env:UAC_DIRECT_SOURCE_ID
$env:UAC_DIRECT_SOURCE_ID = $sourceId
try {
    if ($Test) {
        & cargo test @params
        if ($LASTEXITCODE -ne 0) { throw "Direct native tests failed ($LASTEXITCODE)." }
    }
    & cargo build @params
    if ($LASTEXITCODE -ne 0) { throw "Direct native build failed ($LASTEXITCODE)." }
    $built = Join-Path $target 'release/uac-direct.exe'
    $contract = & $built --direct-contract
    if ($LASTEXITCODE -ne 0 -or $contract -ne $expected) {
        throw 'Staged Direct executable failed its source and contract check.'
    }
    New-Item -ItemType Directory -Path (Split-Path -Parent $Destination) -Force | Out-Null
    Copy-Item -LiteralPath $built -Destination $Destination -Force
    Write-Host "Direct $contract"
} finally {
    $env:UAC_DIRECT_SOURCE_ID = $priorId
}
