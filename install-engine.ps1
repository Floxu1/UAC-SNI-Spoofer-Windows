$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$bin = Join-Path $PSScriptRoot 'bin'
New-Item -ItemType Directory -Path $bin -Force | Out-Null

if (-not (Test-Path (Join-Path $bin 'xray.exe'))) {
    $xrayZip = Join-Path $env:TEMP 'xray-windows-64.zip'
    $xrayUrl = 'https://github.com/XTLS/Xray-core/releases/latest/download/Xray-windows-64.zip'
    Write-Host "Downloading Xray for Windows x64..."
    Invoke-WebRequest -Uri $xrayUrl -OutFile $xrayZip -UseBasicParsing
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
    }
}

if (-not (Test-Path (Join-Path $bin 'xray.exe'))) {
    throw 'xray.exe was not found in the downloaded archive.'
}
& (Join-Path $bin 'xray.exe') version

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
    Invoke-WebRequest -Uri $singUrl -OutFile $singZip -UseBasicParsing
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
