<div align="center">

<img src="assets/icon.png" width="112" alt="UAC SNI Spoofer icon">

# UAC SNI Spoofer — Windows

**A one-click Windows network dashboard: Xray + Patterniha SNI spoofing, and a second Psiphon-over-WARP engine.**

[![Version](https://img.shields.io/badge/version-1.1.1-2ea44f?style=flat-square)](https://github.com/Floxu1/UAC-SNI-Spoofer-Windows/releases)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11%20x64-0078D6?style=flat-square&logo=windows)](#download--quick-start)
[![License](https://img.shields.io/badge/license-GPL--3.0-blue?style=flat-square)](LICENSE)
[![Latest release](https://img.shields.io/github/v/release/Floxu1/UAC-SNI-Spoofer-Windows?style=flat-square&label=latest)](https://github.com/Floxu1/UAC-SNI-Spoofer-Windows/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/Floxu1/UAC-SNI-Spoofer-Windows/total?style=flat-square)](https://github.com/Floxu1/UAC-SNI-Spoofer-Windows/releases)

[فارسی](./README.md) · **English** · [Step-by-step guide](https://floxu1.github.io/UAC-SNI-Spoofer-Windows/) · [Telegram](https://t.me/UacSniSpoofer)

<img src="assets/readme/engine1-home.png" width="860" alt="Engine 1 home screen">

</div>

---

## Table of contents

- [Overview](#overview)
- [Features](#features)
- [Engine 1 — Xray + SNI spoofing](#engine-1--xray--sni-spoofing)
- [Engine 2 — UAC PoW (Psiphon over WARP)](#engine-2--uac-pow-psiphon-over-warp)
- [Download & quick start](#download--quick-start)
- [Build from source](#build-from-source)
- [FAQ & troubleshooting](#faq--troubleshooting)
- [What's new in 1.1.1](#whats-new-in-111)
- [Credits](#credits)
- [License](#license)

## Overview

UAC SNI Spoofer Windows wraps two complete tunnel engines in one bilingual (Persian/English, RTL/LTR) desktop app:

| | Engine 1 — `Xray` | Engine 2 — `UAC PoW` |
|---|---|---|
| Core | `Xray` + Patterniha SNI-spoofing core | `aether` (WARP / MASQUE) + `Psiphon` |
| Needs configs | Yes (built-in suggested list, your own, or SNI Maker) | No |
| Best for | MCI / IranCell lines with SNI filtering | Lines where configs keep dying |

Both engines apply the Windows proxy automatically and restore the previous proxy and network state on disconnect, exit, or after a crash.

## Features

**Connection & routing**
- Separate, isolated profiles for **MCI / Hamrah Aval**, **IranCell** and **Auto**; changing one never overwrites the other.
- Local `SOCKS`/`HTTP` tunnel, automatic **Windows Proxy** with safe restore.
- Optional system-wide **TUN mode** (`sing-box`) for TCP + UDP, verified with a real YouTube route before reporting "connected"; `ping` stays direct so CMD shows real latency.
- **Mobile Gateway** — share the connection with phones on the same LAN, no proxy/static-IP setup on the phone; live device list.
- **App Bypass** — chosen processes go direct (also translated into `sing-box` rules in TUN mode).
- **Iranian sites direct** (on by default) — Iranian domains/IPs skip the tunnel; toggle in Tuning.
- **Mux off by default** (measured to break SNI/ECH ws routes); can still be enabled in Tuning.

**Finding a working route**
- **Quick-start wizard** — detects your carrier and the line's DPI behaviour, then finds and saves working configs for you.
- **Auto mode with quality pick** — tests the top candidates in parallel and chooses by real page load + throughput, not just ping.
- **SNI Maker** — fetch a public list (Patterniha's by default), live-test every config through the real tunnel, keep the healthy ones; filter by country.
- **SNI Lab / batch tester** and carrier-aware **SNI finder** with per-edge rounds of real tunnel tests.
- **Clean IP finder** — re-tests cached good Cloudflare edges for your carrier, then samples ranges with a real TLS ClientHello.
- **ECH keys** — fetches and caches ECH configs from several resolvers in parallel (faster than per-dial lookup).
- **Gene Lab import** — import `strategies.json` into the pattern settings, with a learning multi-gene pool.

**UI & diagnostics**
- Public IP card with flag, ISP/ASN, city and time zone (fast multi-source lookup with cache).
- Active Route card (config, country, edge IP, fake SNI, Spoof/ECH), live download/upload/latency.
- Readable, grouped **Live Logs** with summary header and connect summary.
- Simple and pro **Tuning** dialogs (route, SNI, DNS, timeouts, fallback, pattern core).
- Engine switch guard (asks before disconnecting), one-time coach marks, GitHub Releases update checker.
- One-time **1.1.1 data reset** — old data is *moved* (never deleted) to `%APPDATA%\UAC Spoofer Desktop.backup-before-1.1.1-<time>` so 1.1.1 starts clean with the wizard.

## Engine 1 — Xray + SNI spoofing

Xray routes traffic through the Patterniha core, which disguises the TLS handshake with a fake SNI toward a clean Cloudflare edge.

<table>
<tr>
<td width="50%" valign="top" align="center"><img src="assets/readme/engine1-sni-maker.png" alt="SNI Maker"><br><sub>SNI Maker</sub></td>
<td width="50%" valign="top" align="center"><img src="assets/readme/engine1-sni-lab.png" alt="SNI Lab"><br><sub>SNI Lab</sub></td>
</tr>
<tr>
<td width="50%" valign="top" align="center"><img src="assets/readme/engine1-tuning.png" alt="Tuning"><br><sub>Tuning</sub></td>
<td width="50%" valign="top" align="center"><img src="assets/readme/wizard.png" alt="Quick-start wizard"><br><sub>Quick-start wizard</sub></td>
</tr>
</table>

## Engine 2 — UAC PoW (Psiphon over WARP)

No configs needed: `aether` raises a WARP leg (MASQUE / WireGuard ladder with clean-IP scanning) and `Psiphon` runs through it. Pick an exit country or leave it on Auto.

<table>
<tr>
<td colspan="2" align="center"><img src="assets/readme/engine2-home.png" alt="Engine 2 home"><br><sub>Engine 2 home</sub></td>
</tr>
<tr>
<td width="50%" valign="top" align="center"><img src="assets/readme/engine2-settings.png" alt="PoW settings"><br><sub>PoW settings</sub></td>
<td width="50%" valign="top" align="center"><img src="assets/readme/engine2-country.png" alt="Exit country"><br><sub>Exit country</sub></td>
</tr>
</table>

Options include Psiphon-over-WARP (default), HTTP/2 fragment, parallel MASQUE sessions, low-RTT IP pick and direct-Psiphon-first.

## Download & quick start

1. Download `UAC-Spoofer-Desktop-v1.1.1-Windows-x64-portable.zip` from **[Releases](https://github.com/Floxu1/UAC-SNI-Spoofer-Windows/releases/latest)** (verify with `SHA256SUMS.txt`).
2. Extract the whole ZIP; keep the `_internal` folder next to the exe.
3. Run `UAC-Spoofer-Desktop.exe` and accept the UAC prompt (admin is needed for the spoofing driver, TUN and gateway).
4. Follow the quick-start wizard, then press **Connect**.

No Python install is required. Full illustrated guide: **[floxu1.github.io/UAC-SNI-Spoofer-Windows](https://floxu1.github.io/UAC-SNI-Spoofer-Windows/)**.

## Build from source

**Requirements:** Windows 10/11 x64 · Python 3.11/3.12 · `git` · Go 1.26+ · Rust 1.88+ (`cargo`) with `cmake` and `NASM` (for `boring-sys`).

```powershell
git clone https://github.com/Floxu1/UAC-SNI-Spoofer-Windows.git
cd UAC-SNI-Spoofer-Windows
powershell -ExecutionPolicy Bypass -File .\build.ps1
# -> dist\UAC-Spoofer-Desktop\UAC-Spoofer-Desktop.exe
```

`build.ps1` installs `requirements.txt`, runs `install-engine.ps1`, then PyInstaller. `install-engine.ps1` fills `bin\` idempotently:

| File | Source |
|---|---|
| `xray.exe`, `geoip.dat`, `geosite.dat` | Xray-core `26.3.27` release, SHA-256 pinned |
| `sing-box.exe`, `libcronet.dll` | sing-box `1.13.14` release, SHA-256 pinned |
| `uac-psiphon.exe` | `go build` of `pow_helper/` (Psiphon tunnel-core, pinned by `go.sum`) |
| `aether.exe` | `cargo build` of `core/aether` from [UAC-SNI-Spoofer-Android](https://github.com/Floxu1/UAC-SNI-Spoofer-Android) at a pinned commit (or `UAC_AETHER_SRC`) |

Run from source without packaging: `python -m pip install -r requirements.txt`, `.\install-engine.ps1`, `python main.py`.

## FAQ & troubleshooting

<details><summary><b>It doesn't connect on Engine 1.</b></summary>

Run the quick-start wizard again, select your carrier manually, and try **Auto**. Use SNI Maker or Clean IP to refresh routes. If configs keep dying, try Engine 2.
</details>

<details><summary><b>Which proxy mode should I use?</b></summary>

`Windows Proxy` covers browsers and most apps. Use `TUN` for games and apps that ignore the system proxy.
</details>

<details><summary><b>Ping in CMD shows my real latency — is the tunnel off?</b></summary>

No. ICMP can't travel over SOCKS/VLESS/Trojan, so `ping` is routed direct on purpose.
</details>

<details><summary><b>My old settings disappeared after updating to 1.1.1.</b></summary>

That is the one-time 1.1.1 reset. Everything was moved to `%APPDATA%\UAC Spoofer Desktop.backup-before-1.1.1-<time>`; nothing was deleted. It never runs again.
</details>

<details><summary><b>The internet is broken after a crash.</b></summary>

Start the app once and exit: it restores the saved Windows proxy and gateway state automatically.
</details>

## What's new in 1.1.1

- Engine 2 **UAC PoW** (Psiphon over WARP) with its own settings, exit-country picker and speed options.
- Quick-start wizard, coach marks and a full illustrated guide site.
- Auto mode now picks by real quality (page load + throughput) among parallel-tested candidates.
- Iranian sites go direct by default; Mux off by default.
- Faster public-IP lookup (multi-source, cached).
- Clean IP finder, ECH key cache, SNI finder, Gene Lab import.
- One-time data reset for a clean start (old data moved to a backup folder).
- A fresh clone now builds everything (`aether`, `uac-psiphon` included) with `build.ps1`.

## Credits

- Special thanks to the **Patterniha** group for inventing and introducing this SNI-spoofing method. Upstream source and its GPL-3.0 license: `third_party/patterniha_sni_spoofing/`.
- [**Xray-core**](https://github.com/XTLS/Xray-core) — tunnel core.
- [**sing-box**](https://github.com/SagerNet/sing-box) `v1.13.14` by SagerNet — optional TUN mode; license shipped as `bin/sing-box-LICENSE`.
- [**Psiphon tunnel-core**](https://github.com/Psiphon-Labs/psiphon-tunnel-core) — inner hop of Engine 2 (`pow_helper/`).
- **aether** — WARP/MASQUE client from [UAC-SNI-Spoofer-Android](https://github.com/Floxu1/UAC-SNI-Spoofer-Android), licensed AGPL-3.0-only.

## License

Released under the **GNU General Public License v3.0** — see [LICENSE](LICENSE) and [NOTICE](NOTICE). You may use, study and modify the software; distributed modified versions must stay GPL-3.0 and provide source. Do not remove Patterniha credits from this project or derivative distributions.

<div align="center"><sub>Copyright © 2026 Floxu1</sub></div>
