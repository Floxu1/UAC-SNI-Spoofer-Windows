param(
    [string]$DistPath = "",
    [string]$OutputPath = ""
)

$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Set-Location $projectRoot

$version = (python -c "from uac_desktop import __version__; print(__version__)").Trim()
if (-not $version) { throw 'Could not read uac_desktop.__version__' }

if (-not $DistPath) { $DistPath = Join-Path $projectRoot 'dist\UAC-Spoofer-Desktop' }
$distFull = [IO.Path]::GetFullPath($DistPath)
if (-not (Test-Path -LiteralPath (Join-Path $distFull 'UAC-Spoofer-Desktop.exe'))) {
    throw "Built app was not found at $distFull. Run build.ps1 first."
}

if (-not $OutputPath) { $OutputPath = Join-Path $projectRoot "github_release_v$version" }
$outputFull = [IO.Path]::GetFullPath($OutputPath)
if (-not $outputFull.StartsWith($projectRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Release output must stay inside the project workspace.'
}
if (Test-Path -LiteralPath $outputFull) {
    Remove-Item -LiteralPath $outputFull -Recurse -Force
}
New-Item -ItemType Directory -Path $outputFull | Out-Null

$assetName = "UAC-Spoofer-Desktop-v$version-Windows-x64.zip"
$assetPath = Join-Path $outputFull $assetName
Compress-Archive -LiteralPath $distFull -DestinationPath $assetPath -CompressionLevel Optimal

$sourceName = "UAC-Spoofer-Desktop-v$version-Source.zip"
$sourcePath = Join-Path $outputFull $sourceName
$sourceStage = Join-Path $outputFull '_source_stage'
New-Item -ItemType Directory -Path $sourceStage | Out-Null
foreach ($name in @(
    'main.py', 'uac_desktop', 'assets', 'third_party', 'tools', 'tests',
    'README.md', 'requirements.txt', 'build.ps1', 'release.ps1',
    'install-engine.ps1', 'run.ps1', 'UAC-Spoofer-Desktop.spec'
)) {
    $sourceItem = Join-Path $projectRoot $name
    if (Test-Path -LiteralPath $sourceItem) {
        Copy-Item -LiteralPath $sourceItem -Destination $sourceStage -Recurse -Force
    }
}
Compress-Archive -Path (Join-Path $sourceStage '*') -DestinationPath $sourcePath -CompressionLevel Optimal
Remove-Item -LiteralPath $sourceStage -Recurse -Force

$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $assetPath).Hash.ToLowerInvariant()
$sourceHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $sourcePath).Hash.ToLowerInvariant()
@(
    "$hash  $assetName"
    "$sourceHash  $sourceName"
) | Set-Content -LiteralPath (Join-Path $outputFull 'SHA256SUMS.txt') -Encoding utf8

$manifest = [ordered]@{
    version = $version
    channel = 'stable'
    platform = 'windows-x64'
    asset = $assetName
    sha256 = $hash
    source_asset = $sourceName
    source_sha256 = $sourceHash
    update_source = 'GitHub Releases API'
    published_at = (Get-Date).ToUniversalTime().ToString('o')
}
$manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $outputFull 'release-manifest.json') -Encoding utf8

@"
# UAC Spoofer Desktop v$version

## فارسی
- پروفایل پرسرعت مستقل همراه اول و ایرانسل
- انتخاب Edge/SNI به‌صورت زوج تست‌شده و اپراتورمحور
- رتبه‌بندی پروفایل‌ها با تست واقعی صفحه و دانلود کوتاه
- بازیابی تراکنشی Proxy ویندوز در خروج عادی، خطا و بسته‌شدن اجباری
- اعمال واقعی App Bypass با راه‌اندازی مجدد کنترل‌شده تونل

## English
- Isolated MCI and IranCell performance profiles
- Carrier-scoped, verified Edge + SNI pairing
- Profile ranking with real page and bounded download measurements
- Transactional Windows proxy restoration, including crash watchdog recovery
- Live App Bypass apply through a controlled tunnel reload

## GitHub Release asset
Upload: $assetName

Optional source snapshot: $sourceName

SHA-256: $hash
"@ | Set-Content -LiteralPath (Join-Path $outputFull 'RELEASE_NOTES.md') -Encoding utf8

@"
# تنظیم بررسی بروزرسانی

1. در GitHub یک Release با Tag برابر v$version بسازید.
2. فایل $assetName را به همان Release پیوست کنید.
3. در برنامه به Advanced Settings > Update repository بروید.
4. آدرس ریشه مخزن را وارد کنید؛ مثال: https://github.com/OWNER/REPOSITORY

آدرس باید ریشه مخزن باشد، نه لینک فایل ZIP و نه صفحه /releases.

برای تغییر پیش‌فرض در سورس، مقدار UPDATE_REPOSITORY_URL را در
uac_desktop/app_config.py قرار دهید و برنامه را دوباره Build کنید.

Update checking reads GitHub's latest Release API. The Release must be published
(not draft), and its Windows asset name should contain Windows/x64 and end in .zip.
"@ | Set-Content -LiteralPath (Join-Path $outputFull 'GITHUB_UPDATE_SETUP.md') -Encoding utf8

Copy-Item -LiteralPath (Join-Path $projectRoot 'README.md') -Destination (Join-Path $outputFull 'SOURCE_README.md')

Write-Host "GitHub release folder: $outputFull"
Write-Host "Asset: $assetName"
Write-Host "SHA256: $hash"
