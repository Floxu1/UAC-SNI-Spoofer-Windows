# UAC Spoofer Desktop

## Language

[فارسی](README.fa.md) | **English**

---

## What it is

UAC Spoofer Desktop is a Windows network dashboard built around Xray and the Patterniha SNI-spoofing method.

It manages carrier-specific routes, scans and ranks SNI/Edge pairs, applies the Windows proxy, and restores the previous proxy state when the app exits.

The desktop profiles are tuned separately for **MCI / Hamrah Aval** and **IranCell**, so changing one carrier does not overwrite the other carrier's settings.

## Features

- Separate MCI, IranCell, and Auto carrier modes
- Xray-based local SOCKS/HTTP tunnel
- Patterniha SNI/Edge scanner with live results
- MCI TLS-record startup optimization and YouTube warmup
- Suggested-config ranking using real page and bounded download checks
- Persian and English interface with RTL/LTR handling
- App Bypass, live logs, public-IP check, and advanced tuning
- GitHub Releases update checker
- Transactional Windows proxy restore after disconnect, exit, or restart

## Portable version

1. Download `UAC-Spoofer-Desktop-v1.5.0-Windows-x64.zip` from GitHub Releases.
2. Extract the complete archive.
3. Keep the `_internal` folder beside the EXE.
4. Run `UAC-Spoofer-Desktop.exe`.
5. Accept the Windows UAC prompt.

Python is not required for the portable build.

## Run from source

Requirements:

- Windows 10/11 x64
- Python 3.11 or 3.12

```powershell
python -m pip install -r requirements.txt
powershell -ExecutionPolicy Bypass -File .\install-engine.ps1
python main.py
```

## Carrier mode

- `mci`: independent MCI / Hamrah Aval route, SNI, Edge, benchmarks, and tuning.
- `irancell`: independent IranCell route and tuning.
- `auto`: the app-managed general profile.

For the most stable result, select your current carrier manually.

## Updates

Before publishing the project on GitHub, edit:

```text
uac_desktop/app_config.py
```

Set these values:

```text
UPDATE_REPOSITORY_URL
GITHUB_RELEASES_URL
LATEST_VERSION_URL
UPDATE_CHECK_ENDPOINT
PORTABLE_DOWNLOAD_URL
```

Also check the current app version here:

```text
uac_desktop/__init__.py
```

Version variable:

```text
__version__
```

Publish a GitHub Release, for example:

```text
v1.5.0
```

Then upload the Windows x64 portable ZIP file.

Runtime release parsing is handled by:

```text
uac_desktop/update_checker.py
```

Function:

```text
check_latest_release()
```

## Credits

Special thanks to the **Patterniha** group for inventing and introducing this SNI-spoofing method.

The integrated upstream source and GPL-3.0 license are included under:

```text
third_party/patterniha_sni_spoofing/
```
