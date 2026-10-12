"""One-time data reset for v1.1.1.

Runs at startup before anything reads settings/profiles. Keyed to the literal
reset id ``1.1.1`` (not to "version changed"), so later versions never reset.
Old data is MOVED to a sibling folder, never deleted. Locked files are copied
and left in place; nothing here may raise.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

RESET_ID = "1.1.1"
MARKER_NAME = f".reset_{RESET_ID.replace('.', '_')}_done"


def data_dir() -> Path:
    return Path(os.getenv("APPDATA", Path.home())) / "UAC Spoofer Desktop"


def _stop_old_engines() -> None:
    """Kill engine processes started from old config/owner files before moving them."""
    if sys.platform != "win32":
        return
    try:
        from .process_win import cleanup_bin_helpers
        cleanup_bin_helpers()
    except Exception:
        pass
    try:
        from .paths import BIN
        root = str(Path(BIN).resolve()).lower()
    except Exception:
        return
    for image in ("xray.exe", "sing-box.exe"):
        try:
            out = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 f"Get-Process -Name '{image[:-4]}' -EA 0 | % {{ \"$($_.Id)|$($_.Path)\" }}"],
                capture_output=True, text=True, timeout=10,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).stdout
            for line in out.splitlines():
                pid, _, path = line.partition("|")
                if path and str(Path(path).resolve()).lower().startswith(root):
                    subprocess.run(["taskkill", "/F", "/PID", pid.strip()], capture_output=True,
                                   timeout=5, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except Exception:
            pass


def _move_entry(src: Path, dst: Path) -> None:
    try:
        shutil.move(str(src), str(dst))
        return
    except Exception:
        pass
    # Locked (e.g. log in use): copy what we can, leave the original.
    try:
        if src.is_dir():
            shutil.copytree(src, dst, dirs_exist_ok=True,
                            ignore_dangling_symlinks=True, copy_function=_safe_copy)
            shutil.rmtree(src, ignore_errors=True)
        else:
            shutil.copy2(src, dst)
            try:
                src.unlink()
            except Exception:
                pass
    except Exception:
        pass


def _safe_copy(src, dst, *, follow_symlinks=True):
    try:
        return shutil.copy2(src, dst, follow_symlinks=follow_symlinks)
    except Exception:
        return dst


def _other_instance_running() -> bool:
    if sys.platform != "win32":
        return False
    try:
        import ctypes
        handle = ctypes.windll.kernel32.OpenMutexW(0x00100000, False, "Local\\UAC-Spoofer-Desktop-v1")
        if handle:
            ctypes.windll.kernel32.CloseHandle(handle)
            return True
    except Exception:
        pass
    return False


def run(folder: Path | None = None) -> str:
    """Return 'done-before', 'fresh', 'moved:<backup path>' or 'error:<msg>'."""
    try:
        folder = Path(folder) if folder else data_dir()
        folder.mkdir(parents=True, exist_ok=True)
        marker = folder / MARKER_NAME
        if marker.exists():
            return "done-before"
        if _other_instance_running():
            return "skipped-running"  # never pull data from under a live app
        entries = [p for p in folder.iterdir() if p.name != MARKER_NAME]
        result = "fresh"
        if entries:
            _stop_old_engines()
            stamp = time.strftime("%Y%m%d-%H%M%S")
            backup = folder.parent / f"{folder.name}.backup-before-{RESET_ID}-{stamp}"
            n = 1
            while backup.exists():
                n += 1
                backup = folder.parent / f"{folder.name}.backup-before-{RESET_ID}-{stamp}-{n}"
            backup.mkdir(parents=True)
            for entry in entries:
                _move_entry(entry, backup / entry.name)
            result = f"moved:{backup}"
        marker.write_text(f"{RESET_ID} {time.strftime('%Y-%m-%d %H:%M:%S')} {result}\n", encoding="utf-8")
        return result
    except Exception as exc:  # never block startup
        return f"error:{exc}"