from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .paths import DATA_DIR


NPCAP_VERSION = "1.88"
NPCAP_URL = f"https://npcap.com/dist/npcap-{NPCAP_VERSION}.exe"
NPCAP_SHA256 = "a2f4ec1e5ea353ff67efd24b2ebf081ba44532410fae8d5e146af0310aa4f56b"
NPCAP_INSTALLER = (
    Path(os.getenv("LOCALAPPDATA", DATA_DIR))
    / "UAC Spoofer Desktop"
    / "installers"
    / f"npcap-{NPCAP_VERSION}.exe"
)
NPCAP_LOG = DATA_DIR / "npcap-bootstrap.log"
_DLL_HANDLES: list[object] = []


@dataclass(frozen=True, slots=True)
class NpcapBootstrapResult:
    available: bool
    action: str
    detail: str = ""


def _write_log(message: str) -> None:
    try:
        NPCAP_LOG.parent.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        with NPCAP_LOG.open("a", encoding="utf-8") as stream:
            stream.write(f"[{stamp}] {message}\n")
    except OSError:
        pass


def _candidate_dlls() -> tuple[Path, ...]:
    windows = Path(os.getenv("WINDIR", r"C:\Windows"))
    values = [
        windows / "System32" / "Npcap" / "wpcap.dll",
        windows / "Sysnative" / "Npcap" / "wpcap.dll",
        windows / "System32" / "wpcap.dll",
        windows / "SysWOW64" / "Npcap" / "wpcap.dll",
        windows / "SysWOW64" / "wpcap.dll",
    ]
    seen: set[str] = set()
    result: list[Path] = []
    for value in values:
        key = str(value).casefold()
        if key not in seen:
            seen.add(key)
            result.append(value)
    return tuple(result)


def activate_npcap_path() -> Path | None:
    for dll in _candidate_dlls():
        try:
            if not dll.is_file() or dll.stat().st_size <= 0:
                continue
        except OSError:
            continue
        directory = dll.parent
        if directory.name.casefold() == "npcap":
            current = os.environ.get("PATH", "")
            entries = [item for item in current.split(os.pathsep) if item]
            if str(directory).casefold() not in {item.casefold() for item in entries}:
                os.environ["PATH"] = str(directory) + os.pathsep + current
            add_directory = getattr(os, "add_dll_directory", None)
            if callable(add_directory):
                try:
                    _DLL_HANDLES.append(add_directory(str(directory)))
                except OSError:
                    pass
        return dll
    return None


def _service_running(name: str) -> bool:
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        completed = subprocess.run(
            ["sc.exe", "query", name],
            capture_output=True,
            text=True,
            check=False,
            creationflags=flags,
        )
    except OSError:
        return False
    output = f"{completed.stdout}\n{completed.stderr}"
    return completed.returncode == 0 and re.search(r":\s*4\s", output) is not None


def _ensure_driver_running() -> bool:
    for service in ("npcap", "npf"):
        if _service_running(service):
            return True
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    for service in ("npcap", "npf"):
        try:
            subprocess.run(
                ["sc.exe", "start", service],
                capture_output=True,
                text=True,
                check=False,
                creationflags=flags,
            )
        except OSError:
            continue
        for _ in range(10):
            if _service_running(service):
                return True
            time.sleep(0.1)
    return False


def npcap_available() -> bool:
    if sys.platform != "win32":
        return True
    return activate_npcap_path() is not None and _ensure_driver_running()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _valid_installer(path: Path) -> bool:
    try:
        return path.is_file() and _sha256(path).casefold() == NPCAP_SHA256
    except OSError:
        return False


def download_npcap(
    destination: Path = NPCAP_INSTALLER,
    opener: Callable[..., object] = urllib.request.urlopen,
) -> Path:
    destination = Path(destination)
    if _valid_installer(destination):
        return destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    partial = destination.with_suffix(destination.suffix + ".part")
    partial.unlink(missing_ok=True)
    request = urllib.request.Request(
        NPCAP_URL,
        headers={"User-Agent": "UAC-Spoofer-Desktop/Npcap-Bootstrap"},
    )
    try:
        with opener(request, timeout=30) as response, partial.open("wb") as stream:
            total = 0
            while True:
                block = response.read(128 * 1024)
                if not block:
                    break
                total += len(block)
                if total > 16 * 1024 * 1024:
                    raise RuntimeError("Npcap installer download exceeded the size limit")
                stream.write(block)
        if not _valid_installer(partial):
            raise RuntimeError("Npcap installer verification failed")
        os.replace(partial, destination)
        return destination
    except Exception:
        partial.unlink(missing_ok=True)
        raise


def launch_npcap_installer(installer: Path) -> int:
    completed = subprocess.run(
        [str(installer)],
        cwd=str(installer.parent),
        check=False,
    )
    return int(completed.returncode)


def ensure_npcap(
    available: Callable[[], bool] = npcap_available,
    downloader: Callable[[], Path] = download_npcap,
    launcher: Callable[[Path], int] = launch_npcap_installer,
) -> NpcapBootstrapResult:
    if available():
        return NpcapBootstrapResult(True, "ready")
    _write_log(f"Npcap {NPCAP_VERSION} is missing; downloading the official installer")
    try:
        installer = downloader()
    except Exception as exc:
        detail = f"download failed: {exc}"
        _write_log(detail)
        return NpcapBootstrapResult(False, "download-failed", detail)
    try:
        exit_code = launcher(installer)
    except Exception as exc:
        detail = f"installer launch failed: {exc}"
        _write_log(detail)
        return NpcapBootstrapResult(False, "launch-failed", detail)
    for _ in range(40):
        if available():
            _write_log(f"Npcap {NPCAP_VERSION} installed successfully")
            return NpcapBootstrapResult(True, "installed")
        time.sleep(0.25)
    detail = f"installer exited with code {exit_code}; setup was not completed"
    _write_log(detail)
    return NpcapBootstrapResult(False, "not-installed", detail)


__all__ = [
    "NPCAP_INSTALLER",
    "NPCAP_SHA256",
    "NPCAP_URL",
    "NPCAP_VERSION",
    "NpcapBootstrapResult",
    "activate_npcap_path",
    "download_npcap",
    "ensure_npcap",
    "launch_npcap_installer",
    "npcap_available",
]
