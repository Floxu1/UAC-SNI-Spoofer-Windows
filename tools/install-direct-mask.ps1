param([string]$Destination)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
if (-not $Destination) { $Destination = Join-Path $repo 'bin' }
$stage = Join-Path $repo 'build/direct-port/mask-download'
$archive = Join-Path $stage 'byedpi.zip'
$expected = '70d2c94147193cb915f9c6eb5144b8d404dacbcfa90bda2383b6b211afafa456'
$url = 'https://github.com/hufrea/byedpi/releases/download/v0.17.3/byedpi-17.3-x86_64-w64.zip'

New-Item -ItemType Directory -Path $stage -Force | Out-Null
if (-not (Test-Path -LiteralPath $archive) -or
    (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $expected) {
    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if ($curl) {
        & $curl.Source --location --fail --silent --show-error --output $archive $url
        if ($LASTEXITCODE -ne 0) { throw 'Could not download the Direct ByeDPI release.' }
    } else {
        Invoke-WebRequest -Uri $url -OutFile $archive -UseBasicParsing
    }
}
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $expected) {
    throw 'Direct ByeDPI release archive checksum mismatch.'
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead($archive)
try {
    $entry = $zip.GetEntry('ciadpi.exe')
    if ($null -eq $entry) { throw 'Direct ByeDPI archive is missing ciadpi.exe.' }
    $candidate = Join-Path $stage 'ciadpi.exe'
    [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $candidate, $true)
} finally {
    $zip.Dispose()
}
New-Item -ItemType Directory -Path $Destination -Force | Out-Null
Copy-Item -LiteralPath $candidate -Destination (Join-Path $Destination 'uac-direct-mask.exe') -Force
Write-Host 'Direct ByeDPI 0.17.3 ready'
