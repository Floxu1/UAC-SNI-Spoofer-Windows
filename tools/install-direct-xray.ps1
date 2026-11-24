param([string]$Destination)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
if (-not $Destination) { $Destination = Join-Path $repo 'bin' }
$exe = Join-Path $Destination 'uac-direct-xray.exe'
$license = Join-Path $Destination 'uac-direct-xray-LICENSE'
$archiveHash = 'c7172078fca4711bcd92a4774dcd1822544579c58816197575c47533317fd8d1'
$exeHash = '1d9674327972a21afd4c906a7a72bb0856935aa9e0227c87f34f03d11a88bddf'
$url = 'https://github.com/XTLS/Xray-core/releases/download/v26.7.28/Xray-windows-64.zip'

if ((Test-Path -LiteralPath $exe) -and (Test-Path -LiteralPath $license) -and
    (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash -eq $exeHash) {
    Write-Host 'Direct Xray 26.7.28 (5ca6f4b) ready'
    return
}

$stage = Join-Path $repo 'build/direct-port/xray-download'
New-Item -ItemType Directory -Path $stage -Force | Out-Null
$archive = Join-Path $stage 'Xray-windows-64.zip'
if (-not (Test-Path -LiteralPath $archive) -or
    (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $archiveHash) {
    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if ($curl) {
        & $curl.Source --location --fail --silent --show-error --output $archive $url
        if ($LASTEXITCODE -ne 0) { throw 'Could not download the Direct Xray release.' }
    } else {
        Invoke-WebRequest -Uri $url -OutFile $archive -UseBasicParsing
    }
}
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $archiveHash) {
    throw 'Direct Xray release archive checksum mismatch.'
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead($archive)
try {
    foreach ($name in 'xray.exe', 'LICENSE') {
        $entry = $zip.GetEntry($name)
        if ($null -eq $entry) { throw "Direct Xray archive is missing $name." }
        [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, (Join-Path $stage $name), $true)
    }
} finally {
    $zip.Dispose()
}

$candidate = Join-Path $stage 'xray.exe'
if ((Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash -ne $exeHash) {
    throw 'Direct Xray executable checksum mismatch.'
}
New-Item -ItemType Directory -Path $Destination -Force | Out-Null
Copy-Item -LiteralPath $candidate -Destination $exe -Force
Copy-Item -LiteralPath (Join-Path $stage 'LICENSE') -Destination $license -Force
Write-Host 'Direct Xray 26.7.28 (5ca6f4b) ready'
