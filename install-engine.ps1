$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$bin = Join-Path $PSScriptRoot 'bin'
New-Item -ItemType Directory -Path $bin -Force | Out-Null

function Get-RemoteFile([string]$Uri, [string]$OutFile) {
    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if ($null -ne $curl) {
        & $curl.Source --location --fail --silent --show-error --output $OutFile $Uri
        if ($LASTEXITCODE -ne 0) { throw "Download failed: $Uri" }
        return
    }
    Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing
}

$xrayVersion = '26.3.27'
$xraySha256 = 'd004c39288ce9ada487c6f398c7c545f7d749e44bdfdd59dbc9f865afba4e1ad'
$xrayExe = Join-Path $bin 'xray.exe'
$needsXray = -not (Test-Path $xrayExe)
if (-not $needsXray) {
    try {
        $installedXray = (& $xrayExe version 2>&1 | Out-String)
        $needsXray = ($LASTEXITCODE -ne 0 -or $installedXray -notmatch "Xray $([regex]::Escape($xrayVersion))")
    } catch {
        $needsXray = $true
    }
}
if ($needsXray) {
    $xrayZip = Join-Path $env:TEMP "xray-$xrayVersion-windows-64.zip"
    $xrayUrl = "https://github.com/XTLS/Xray-core/releases/download/v$xrayVersion/Xray-windows-64.zip"
    Write-Host "Downloading Xray $xrayVersion for Windows x64..."
    Get-RemoteFile $xrayUrl $xrayZip
    $actualHash = (Get-FileHash -LiteralPath $xrayZip -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $xraySha256) {
        throw "Xray archive checksum mismatch: $actualHash"
    }
    $xrayTemp = Join-Path $env:TEMP ('uac-xray-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $xrayTemp | Out-Null
    try {
        Expand-Archive -LiteralPath $xrayZip -DestinationPath $xrayTemp -Force
        foreach ($name in @('xray.exe', 'geoip.dat', 'geosite.dat', 'LICENSE')) {
            $source = Join-Path $xrayTemp $name
            if (Test-Path $source) { Copy-Item -LiteralPath $source -Destination $bin -Force }
        }
    } finally {
        Remove-Item -LiteralPath $xrayTemp -Recurse -Force
        Remove-Item -LiteralPath $xrayZip -Force -ErrorAction SilentlyContinue
    }
}

if (-not (Test-Path $xrayExe)) {
    throw 'xray.exe was not found in the downloaded archive.'
}
$verifiedXray = (& $xrayExe version 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0 -or $verifiedXray -notmatch "Xray $([regex]::Escape($xrayVersion))") {
    throw "Xray $xrayVersion runtime validation failed."
}
Write-Host $verifiedXray.Trim()

$singVersion = '1.13.14'
$singSha256 = 'f580782c6dd10f7691c66cea1d7c421813c5fbf7e305d1ee7ce0c3a40d196341'
$singExe = Join-Path $bin 'sing-box.exe'
$cronet = Join-Path $bin 'libcronet.dll'
$singLicense = Join-Path $bin 'sing-box-LICENSE'
$needsSingBox = (-not (Test-Path $singExe) -or -not (Test-Path $cronet) -or -not (Test-Path $singLicense))
if (-not $needsSingBox) {
    try {
        $installedVersion = (& $singExe version 2>&1 | Out-String)
        $needsSingBox = ($LASTEXITCODE -ne 0 -or $installedVersion -notmatch "sing-box version $([regex]::Escape($singVersion))")
    } catch {
        $needsSingBox = $true
    }
}
if ($needsSingBox) {
    $singZip = Join-Path $env:TEMP "sing-box-$singVersion-windows-amd64.zip"
    $singUrl = "https://github.com/SagerNet/sing-box/releases/download/v$singVersion/sing-box-$singVersion-windows-amd64.zip"
    Write-Host "Downloading sing-box $singVersion for Windows x64..."
    Get-RemoteFile $singUrl $singZip
    $actualHash = (Get-FileHash -LiteralPath $singZip -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $singSha256) {
        throw "sing-box archive checksum mismatch: $actualHash"
    }
    $singTemp = Join-Path $env:TEMP ('uac-sing-box-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $singTemp | Out-Null
    try {
        Expand-Archive -LiteralPath $singZip -DestinationPath $singTemp -Force
        $singFolder = Get-ChildItem -LiteralPath $singTemp -Directory | Select-Object -First 1
        if ($null -eq $singFolder) { throw 'sing-box folder was not found in the archive.' }
        Copy-Item -LiteralPath (Join-Path $singFolder.FullName 'sing-box.exe') -Destination $singExe -Force
        Copy-Item -LiteralPath (Join-Path $singFolder.FullName 'libcronet.dll') -Destination $cronet -Force
        Copy-Item -LiteralPath (Join-Path $singFolder.FullName 'LICENSE') -Destination $singLicense -Force
    } finally {
        Remove-Item -LiteralPath $singTemp -Recurse -Force
    }
}

if (-not (Test-Path $singExe) -or -not (Test-Path $cronet) -or -not (Test-Path $singLicense)) {
    throw 'sing-box runtime was not found in the downloaded archive.'
}
$verifiedVersion = (& $singExe version 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0 -or $verifiedVersion -notmatch "sing-box version $([regex]::Escape($singVersion))") {
    throw "sing-box $singVersion runtime validation failed."
}
Write-Host $verifiedVersion.Trim()

# --- uac-psiphon.exe: built from source in pow_helper/ (Go, deps pinned by go.sum) ---
$psiphonExe = Join-Path $bin 'uac-psiphon.exe'
$powHelper = Join-Path $PSScriptRoot 'pow_helper'
if (-not (Test-Path $psiphonExe) -or $env:UAC_REBUILD_POW -eq '1') {
    $go = Get-Command go -ErrorAction SilentlyContinue
    if ($null -eq $go -and (Test-Path 'C:\Program Files\Go\bin\go.exe')) { $go = Get-Command 'C:\Program Files\Go\bin\go.exe' }
    if ($null -eq $go) {
        throw 'Go was not found. uac-psiphon.exe is built from pow_helper/ and needs Go 1.26+ (https://go.dev/dl/). Install Go, reopen the shell and rerun.'
    }
    if (-not (Test-Path (Join-Path $powHelper 'go.mod'))) { throw "pow_helper/go.mod was not found at $powHelper." }
    Write-Host 'Building uac-psiphon.exe from pow_helper (go build)...'
    Push-Location $powHelper
    try {
        $env:CGO_ENABLED = '0'; $env:GOOS = 'windows'; $env:GOARCH = 'amd64'
        & $go.Source build -mod=readonly -trimpath -ldflags '-s -w' -o $psiphonExe .
        if ($LASTEXITCODE -ne 0) { throw "go build of uac-psiphon failed (exit $LASTEXITCODE)." }
    } finally {
        Pop-Location
    }
}
if (-not (Test-Path $psiphonExe)) { throw 'uac-psiphon.exe was not produced.' }
Write-Host "uac-psiphon.exe ready ($((Get-Item $psiphonExe).Length) bytes)"

# --- aether.exe: Rust crate core/aether of UAC-SNI-Spoofer-Android (no prebuilt release) ---
$aetherVersion = '1.6.0'
$aetherRepo = 'https://github.com/Floxu1/UAC-SNI-Spoofer-Android.git'
$aetherCommit = '1327c02f47539858f1fe41b3f02a4c7196620b46'
$aetherExe = Join-Path $bin 'aether.exe'
$needsAether = -not (Test-Path $aetherExe)
if (-not $needsAether) {
    try {
        $installedVersion = (& $aetherExe --version 2>&1 | Out-String)
        $needsAether = ($LASTEXITCODE -ne 0 -or $installedVersion -notmatch "aether $([regex]::Escape($aetherVersion))")
    } catch {
        $needsAether = $true
    }
}
if ($needsAether) {
    $cargo = Get-Command cargo -ErrorAction SilentlyContinue
    if ($null -eq $cargo) {
        throw "Rust/cargo was not found. aether.exe $aetherVersion is built from $aetherRepo (core/aether) and needs Rust 1.88+ (https://rustup.rs) plus cmake/NASM for boring-sys. Or place a prebuilt aether.exe $aetherVersion in bin\."
    }
    # Source: UAC_AETHER_SRC (path to core/aether), sibling checkout, or a pinned fresh clone.
    $aetherSrc = $env:UAC_AETHER_SRC
    if (-not $aetherSrc) {
        $sibling = Join-Path (Split-Path $PSScriptRoot -Parent) 'mobile-build\core\aether'
        if (Test-Path (Join-Path $sibling 'Cargo.toml')) { $aetherSrc = $sibling }
    }
    if (-not $aetherSrc) {
        $git = Get-Command git -ErrorAction SilentlyContinue
        if ($null -eq $git) { throw 'git is needed to fetch the aether source.' }
        $clone = Join-Path $env:TEMP "uac-android-$($aetherCommit.Substring(0,7))"
        if (-not (Test-Path (Join-Path $clone 'core\aether\Cargo.toml'))) {
            Write-Host "Fetching aether source ($aetherCommit)..."
            if (Test-Path $clone) { Remove-Item -LiteralPath $clone -Recurse -Force }
            & git init -q $clone
            & git -C $clone remote add origin $aetherRepo
            & git -C $clone fetch -q --depth 1 origin $aetherCommit
            if ($LASTEXITCODE -ne 0) { throw 'git fetch of the aether source failed.' }
            & git -C $clone checkout -q FETCH_HEAD
        }
        $aetherSrc = Join-Path $clone 'core\aether'
    }
    Write-Host "Building aether $aetherVersion from $aetherSrc (cargo build --release)..."
    Push-Location $aetherSrc
    try {
        & $cargo.Source build --release --locked --bin aether
        if ($LASTEXITCODE -ne 0) { throw "cargo build of aether failed (exit $LASTEXITCODE)." }
        $targetDir = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $aetherSrc 'target' }
        Copy-Item -LiteralPath (Join-Path $targetDir 'release\aether.exe') -Destination $aetherExe -Force
    } finally {
        Pop-Location
    }
}
$verifiedVersion = (& $aetherExe --version 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0 -or $verifiedVersion -notmatch "aether $([regex]::Escape($aetherVersion))") {
    throw "aether $aetherVersion runtime validation failed."
}
Write-Host $verifiedVersion.Trim()
