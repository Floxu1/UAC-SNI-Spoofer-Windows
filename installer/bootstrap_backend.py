"""Embedded payload and native Windows Installer execution for the setup UI."""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import winreg
from pathlib import Path
from uac_desktop.data_reset import MARKER_NAME
from uac_desktop.install_type import APP_EXE

MAGIC = b"UACMSI01"
TRAILER = struct.Struct("<8sQ32s")
KEY = r"Software\UAC\UAC Spoofer Desktop"
MSI_NAME = "UAC-Spoofer-Windows-Setup.msi"
BUSY = 10001
PAYLOAD = 10002
COMMUNICATION = 10003


def installation_defaults():
    program_files = ctypes.create_unicode_buffer(260)
    ctypes.windll.shell32.SHGetFolderPathW(None, 0x26, None, 0, program_files)
    defaults = (str(Path(program_files.value) / "UAC Spoofer Desktop"), True, True)
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, KEY, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
            def value(name, fallback):
                try:
                    return winreg.QueryValueEx(key, name)[0]
                except FileNotFoundError:
                    return fallback

            return (value("InstallFolder", defaults[0]),
                    str(value("DESKTOPShortcut", "1")) != "0", str(value("STARTMENUShortcut", "1")) != "0")
    except OSError:
        return defaults


def settings_directory() -> Path:
    return Path(os.environ["APPDATA"]) / "UAC Spoofer Desktop"


def saved_language() -> str:
    try:
        data = json.loads((settings_directory() / "settings.json").read_text(encoding="utf-8-sig"))
        if data.get("language") in ("fa", "en"):
            return data["language"]
    except (OSError, ValueError, AttributeError):
        pass
    return "fa" if ctypes.windll.kernel32.GetUserDefaultUILanguage() == 1065 else "en"


def seed_language(language: str) -> None:
    root = settings_directory()
    root.mkdir(parents=True, exist_ok=True)
    marker = root / MARKER_NAME
    if not marker.exists():
        if any(root.iterdir()):
            return
        marker.touch(exist_ok=True)
    try:
        with (root / "settings.json").open("x", encoding="utf-8") as stream:
            json.dump({"language": language}, stream)
    except FileExistsError:
        pass


def running_application() -> bool:
    kernel = ctypes.windll.kernel32
    kernel.OpenMutexW.restype = ctypes.c_void_p
    kernel.CloseHandle.argtypes = (ctypes.c_void_p,)
    handle = kernel.OpenMutexW(0x100000, False, "Local\\UAC-Spoofer-Desktop-v1")
    if not handle:
        return False
    kernel.CloseHandle(handle)
    return True


def validate_directory(value: str) -> Path:
    path = Path(value)
    if (not path.is_absolute() or path.drive.startswith("\\") or path == path.parent
            or '"' in value or any(ord(ch) < 32 for ch in value)):
        raise ValueError("invalid installation path")
    return path.resolve()


def launch_from_desktop(directory: Path) -> None:
    executable = directory / APP_EXE
    if not ctypes.windll.shell32.IsUserAnAdmin():
        os.startfile(str(executable), "open", cwd=str(directory))
        return
    # Ask the existing desktop shell to open the app if Setup itself was elevated.
    system = ctypes.create_unicode_buffer(260)
    if not ctypes.windll.kernel32.GetSystemDirectoryW(system, len(system)):
        raise OSError("Windows system directory is unavailable")
    powershell = Path(system.value) / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    command = """
$ErrorActionPreference='Stop'
$windows = (New-Object -ComObject Shell.Application).Windows()
$desktop = $windows.FindWindowSW(0, 0, 8, 0, 1)
if ($null -eq $desktop) { exit 1 }
$desktop.Document.Application.ShellExecute($env:UAC_SETUP_LAUNCH_EXE,'',$env:UAC_SETUP_LAUNCH_DIR,'open',1)
"""
    subprocess.run([str(powershell), "-NoProfile", "-NonInteractive", "-Command", command],
                   env={**os.environ, "UAC_SETUP_LAUNCH_EXE": str(executable), "UAC_SETUP_LAUNCH_DIR": str(directory)},
                   creationflags=subprocess.CREATE_NO_WINDOW, check=True, timeout=10)


def extract_payload(executable: Path, destination: Path, cancel: threading.Event) -> None:
    with executable.open("rb") as source:
        source.seek(-TRAILER.size, os.SEEK_END)
        magic, length, expected = TRAILER.unpack(source.read(TRAILER.size))
        offset = source.tell() - TRAILER.size - length
        if magic != MAGIC or not 0 < length < 2 ** 31 or offset <= 0:
            raise ValueError("invalid embedded MSI")
        source.seek(offset)
        digest = hashlib.sha256()
        with destination.open("xb") as target:
            remaining = length
            while remaining:
                if cancel.is_set():
                    raise InterruptedError
                data = source.read(min(1024 * 1024, remaining))
                if not data:
                    raise ValueError("truncated embedded MSI")
                target.write(data)
                digest.update(data)
                remaining -= len(data)
        if digest.digest() != expected:
            raise ValueError("embedded MSI checksum failed")


def _product_code(msi, package: Path) -> str:
    database, view, record = ctypes.c_uint(), ctypes.c_uint(), ctypes.c_uint()
    try:
        sql = "SELECT `Value` FROM `Property` WHERE `Property` = 'ProductCode'"
        if (msi.MsiOpenDatabaseW(str(package), None, ctypes.byref(database))
                or msi.MsiDatabaseOpenViewW(database, sql, ctypes.byref(view))
                or msi.MsiViewExecute(view, 0) or msi.MsiViewFetch(view, ctypes.byref(record))):
            raise ValueError("MSI product identity cannot be read")
        target, length = ctypes.create_unicode_buffer(64), ctypes.c_uint(64)
        if msi.MsiRecordGetStringW(record, 1, target, ctypes.byref(length)):
            raise ValueError("MSI product identity cannot be read")
        return target.value
    finally:
        for handle in (record, view, database):
            if handle.value:
                msi.MsiCloseHandle(handle)


def install_package(package: Path, directory: Path, desktop: bool, start_menu: bool, cancel, notify,
                    *, owner: int = 0) -> int:
    msi = ctypes.WinDLL("msi.dll")
    total = completed = action_ticks = 0
    reverse = False
    last_percent = -2
    cancel_returned = False
    handler_type = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_uint, ctypes.c_uint)

    @handler_type
    def callback(_context, message, record):
        nonlocal total, completed, reverse, action_ticks, last_percent, cancel_returned
        kind = message & 0xFF000000
        try:
            if kind in (0x08000000, 0x09000000, 0x0A000000) and cancel.is_set() and not cancel_returned:
                cancel_returned = True
                return 2  # IDCANCEL lets MSI roll back its own transaction.
            if kind == 0x08000000:
                value, count = ctypes.create_unicode_buffer(160), ctypes.c_uint(160)
                if msi.MsiRecordGetStringW(record, 1, value, ctypes.byref(count)) == 0:
                    notify("action", value.value)
            elif kind in (0x01000000, 0x02000000):
                notify("msi_error", msi.MsiRecordGetInteger(record, 1))
                button_type = message & 15
                # Decline retry/ignore so failed operations keep MSI's rollback semantics.
                return {1: 2, 2: 3, 3: 2, 4: 7, 5: 2, 6: 2}.get(button_type, 1)
            elif kind == 0x05000000:
                return 2
            elif kind in (0x09000000, 0x0A000000):
                get = lambda field: max(0, msi.MsiRecordGetInteger(record, field))
                if kind == 0x09000000:
                    completed += -action_ticks if reverse else action_ticks
                else:
                    mode, ticks = get(1), get(2)
                    if mode == 0:
                        total, reverse, action_ticks = ticks, bool(get(3)), 0
                        completed = total if reverse else 0
                    elif mode == 1:
                        action_ticks = ticks if get(3) else 0
                    elif mode == 2:
                        completed += -ticks if reverse else ticks
                    elif mode == 3:
                        total += ticks
                percent = min(99, max(0, completed * 100 // total)) if total else -1
                if percent != last_percent:
                    last_percent = percent
                    notify("progress", percent)
        except OSError:
            cancel.set()
            return 2
        return 1

    properties = (f'INSTALLFOLDER="{directory}" UAC_DESKTOP_SHORTCUT={int(desktop)} '
                  f'UAC_STARTMENU_SHORTCUT={int(start_menu)} REBOOT=ReallySuppress')
    if msi.MsiQueryProductStateW(_product_code(msi, package)) == 5:
        properties += " REINSTALL=ALL REINSTALLMODE=vomus"
    window = ctypes.c_void_p(owner)
    # Basic UI lets Windows Installer request elevation itself. The external
    # handler consumes progress and status, leaving consent to Windows.
    previous_level = msi.MsiSetInternalUI(3 if owner else 2, ctypes.byref(window))
    filters = sum(1 << index for index in (1, 2, 5, 8, 9, 10))
    if msi.MsiSetExternalUIRecord(callback, filters, None, None) != 0:
        return COMMUNICATION
    try:
        return int(msi.MsiInstallProductW(str(package), properties))
    finally:
        msi.MsiSetExternalUIRecord(None, 0, None, None)
        msi.MsiSetInternalUI(previous_level, ctypes.byref(window))


def start_install(directory: Path, desktop: bool, start_menu: bool, cancel, notify, *, owner: int = 0) -> int:
    if running_application():
        return BUSY
    # Windows Installer may need the original cabinet during Repair.
    cache = Path(os.environ["LOCALAPPDATA"]) / "UAC Setup Cache"
    cache.mkdir(exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix="package-", dir=cache))
    retained = False
    try:
        package = stage / MSI_NAME
        notify("action", "ExtractPayload")
        extract_payload(Path(sys.executable), package, cancel)
        if cancel.is_set():
            return 1602
        result = install_package(package, directory, desktop, start_menu, cancel, notify, owner=owner)
        if result == 0 and not (directory / APP_EXE).is_file():
            return PAYLOAD
        retained = result in (0, 3010)
        return result
    finally:
        if not retained:
            shutil.rmtree(stage, ignore_errors=True)


def silent_install() -> int:
    if not ctypes.windll.shell32.IsUserAnAdmin():
        return 740
    directory, desktop, start_menu = installation_defaults()
    try:
        return start_install(validate_directory(directory), desktop, start_menu, threading.Event(), lambda *_: None)
    except (OSError, ValueError):
        return PAYLOAD
