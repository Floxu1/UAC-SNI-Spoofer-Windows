# UAC SNI Spoofer Windows

## Language / زبان

[فارسی](./README.md) | **English**

---
[کانال تلگرام](https://t.me/UacSniSpoofer): `t.me/UacSniSpoofer`

---

## Overview

UAC SNI Spoofer Windows is a Windows network dashboard built around Xray and the Patterniha SNI-spoofing method.

The application manages carrier-specific routes, scans and ranks SNI and Edge pairs, applies the Windows proxy automatically, and restores the previous proxy state when the connection is stopped or the app exits.

The desktop profiles are tuned separately for **MCI / Hamrah Aval** and **IranCell**, so changing one carrier does not overwrite or break the other carrier's settings.

<img width="1438" height="922" alt="image" src="https://github.com/user-attachments/assets/5f3f0300-d1b1-45f7-9868-9eb8f1e14f71" />

## Features

- Separate MCI, IranCell, and Auto carrier modes
- Xray-based local SOCKS/HTTP tunnel
- Patterniha SNI and Edge scanner with live results
- MCI TLS startup optimization
- YouTube route warmup for faster video startup
- Suggested configuration ranking using real page checks and bounded download tests
- Persian and English interface with RTL/LTR support
- App Bypass
- Live logs
- Public IP check
- Advanced tuning for route, SNI, DNS, timeout, and fallback behavior
- GitHub Releases update checker
- Safe Windows proxy restore after disconnect, exit, or restart

## Carrier support

This application is tuned for the following carriers:

- MCI / Hamrah Aval
- IranCell

In `mci` mode, the app uses the independent MCI profile. In `irancell` mode, it uses the independent IranCell profile. For the most stable result, select your current carrier manually.

## Portable version

The portable version is prepared for users who do not want to install Python or extra dependencies.

How to run:

1. Download the following file from GitHub Releases:

```text
UAC-Spoofer-Desktop-v1.0.0-Windows-x64.zip
```

2. Extract the full ZIP archive.
3. Keep the `_internal` folder beside the executable file.
4. Run:

```text
UAC-Spoofer-Desktop.exe
```

5. Accept the Windows UAC prompt if it appears.

Python is not required for the portable build.

## Run from source

Requirements:

- Windows 10/11 x64
- Python 3.11 or 3.12

Run:

```powershell
python -m pip install -r requirements.txt
powershell -ExecutionPolicy Bypass -File .\install-engine.ps1
python main.py
```

## Carrier mode

The application includes multiple carrier modes:

- `mci`: independent MCI / Hamrah Aval route, SNI, Edge, benchmarks, and tuning
- `irancell`: independent IranCell route and tuning
- `auto`: app-managed automatic profile

For the most stable and deterministic result, select your current carrier manually.

## Update configuration

Before publishing the project on GitHub, check this file:

```text
uac_desktop/app_config.py
```

Update-related fields:

```text
UPDATE_REPOSITORY_URL
GITHUB_RELEASES_URL
LATEST_VERSION_URL
UPDATE_CHECK_ENDPOINT
PORTABLE_DOWNLOAD_URL
```

The current app version is stored here:

```text
uac_desktop/__init__.py
```

Version variable:

```text
__version__
```

After publishing the project on GitHub, create a Release, for example:

```text
v1.5.0
```

Then upload the Windows x64 portable ZIP file to that Release.

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
---
## License

This project is released under the **GNU General Public License v3.0 (GPL-3.0)**.

You may use, study, and modify the software, but if you distribute modified or derivative versions, you must comply with GPL-3.0, provide access to the source code, and keep the same license terms.

The full license text is available in [LICENSE](LICENSE).
