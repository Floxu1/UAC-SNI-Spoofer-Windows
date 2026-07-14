$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$bin = Join-Path $PSScriptRoot 'bin'
New-Item -ItemType Directory -Path $bin -Force | Out-Null
$zip = Join-Path $env:TEMP 'xray-windows-64.zip'
$url = 'https://github.com/XTLS/Xray-core/releases/latest/download/Xray-windows-64.zip'
Write-Host "Downloading Xray for Windows x64..."
Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
$temp = Join-Path $env:TEMP ('uac-xray-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp | Out-Null
Expand-Archive -LiteralPath $zip -DestinationPath $temp -Force
foreach ($name in @('xray.exe', 'geoip.dat', 'geosite.dat', 'LICENSE')) {
    $source = Join-Path $temp $name
    if (Test-Path $source) { Copy-Item -LiteralPath $source -Destination $bin -Force }
}
Remove-Item -LiteralPath $temp -Recurse -Force
if (-not (Test-Path (Join-Path $bin 'xray.exe'))) { throw 'xray.exe was not found in the downloaded archive.' }
& (Join-Path $bin 'xray.exe') version
