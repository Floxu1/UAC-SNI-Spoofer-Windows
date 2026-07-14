from __future__ import annotations

import os
import sys
from pathlib import Path


def bundle_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
    return Path(__file__).resolve().parent.parent


ROOT = bundle_root()
ASSETS = ROOT / "assets"
BIN = ROOT / "bin"
DATA_DIR = Path(os.getenv("APPDATA", Path.home())) / "UAC Spoofer Desktop"
DATA_DIR.mkdir(parents=True, exist_ok=True)
SETTINGS_FILE = DATA_DIR / "settings.json"
PROFILES_FILE = DATA_DIR / "profiles.json"
BOOKMARKS_FILE = DATA_DIR / "sni-bookmarks.json"
SNI_RESULTS_FILE = DATA_DIR / "sni-scan-results.json"
XRAY_CONFIG = DATA_DIR / "xray-config.json"
XRAY_OWNER_FILE = DATA_DIR / "xray-owner.json"
LOG_FILE = DATA_DIR / "uac-spoofer.log"
