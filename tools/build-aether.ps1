param(
    [string]$Destination,
    [switch]$Test
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$source = Join-Path $repo 'core/aether'
$manifestPath = Join-Path $source 'SOURCE.json'
$target = Join-Path $repo 'build/pow-parity/cargo'
if (-not $Destination) { $Destination = Join-Path $repo 'bin/aether.exe' }
if ($env:UAC_AETHER_SRC) {
    $requested = (Resolve-Path -LiteralPath $env:UAC_AETHER_SRC).Path
    if ($requested -ne (Resolve-Path -LiteralPath $source).Path) {
        throw 'The Windows POW build uses its pinned core/aether snapshot. Refresh that snapshot before building another revision.'
    }
}

$sourceFiles = (Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json).files
$entries = foreach ($name in ($sourceFiles.PSObject.Properties.Name | Sort-Object)) {
    $path = Join-Path $repo $name
    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash $name"
}
$payload = [Text.Encoding]::UTF8.GetBytes($entries -join "`n")
$sha = [Security.Cryptography.SHA256]::Create()
try {
    $sourceId = [BitConverter]::ToString($sha.ComputeHash($payload)).Replace('-', '').ToLowerInvariant()
} finally {
    $sha.Dispose()
}
$expected = "pow-config/1 $sourceId"
if (-not $Test -and (Test-Path -LiteralPath $Destination)) {
    $installed = & $Destination --pow-contract 2>$null
    if ($LASTEXITCODE -eq 0 -and $installed -eq $expected) {
        Write-Host "Aether $installed"
        return
    }
}

$priorId = $env:UAC_AETHER_SOURCE_ID
$env:UAC_AETHER_SOURCE_ID = $sourceId
$manifest = Join-Path $source 'Cargo.toml'
try {
    if ($Test) {
        & cargo test --release --locked --manifest-path $manifest --target-dir $target --lib
        if ($LASTEXITCODE -ne 0) { throw "Aether tests failed ($LASTEXITCODE)." }
    }
    & cargo build --release --locked --manifest-path $manifest --target-dir $target --bin aether
    if ($LASTEXITCODE -ne 0) { throw "Aether build failed ($LASTEXITCODE)." }
    $built = Join-Path $target 'release/aether.exe'
    $contract = & $built --pow-contract
    if ($LASTEXITCODE -ne 0 -or $contract -ne $expected) {
        throw 'Staged Aether executable failed its source and contract check.'
    }
    New-Item -ItemType Directory -Path (Split-Path -Parent $Destination) -Force | Out-Null
    Copy-Item -LiteralPath $built -Destination $Destination -Force
    Write-Host "Aether $contract"
} finally {
    $env:UAC_AETHER_SOURCE_ID = $priorId
}
