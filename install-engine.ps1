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
