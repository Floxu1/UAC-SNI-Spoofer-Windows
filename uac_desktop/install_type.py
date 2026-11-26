"""Distribution identity shared by the packager, app and updater."""
from __future__ import annotations

import ctypes
import json
import struct
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from . import __version__

APP_EXE = "UAC-Spoofer-Desktop.exe"
UPDATER_EXE = "UAC-Update.exe"
PORTABLE_MARKER = "uac-package.json"
UPGRADE_CODE = "{B10E0497-D1E5-40E7-AF3F-D4DED254424A}"
APP_COMPONENT = "{8A447B31-BAFD-4E6B-9302-B07B30D772F8}"
PORTABLE_ASSET = "UAC-Spoofer-Windows-Portable.zip"
MSI_ASSET = "UAC-Spoofer-Windows-Setup.msi"
REQUIRED_RUNTIME = (
    "_internal/bin/xray.exe", "_internal/bin/geoip.dat", "_internal/bin/geosite.dat",
    "_internal/bin/sing-box.exe", "_internal/bin/libcronet.dll", "_internal/bin/aether.exe",
    "_internal/bin/keyfetch-net.ps1", "_internal/bin/uac-psiphon.exe", "_internal/bin/uac-pow-guard.exe",
    "_internal/bin/uac-direct.exe", "_internal/bin/uac-direct-xray.exe",
    "_internal/bin/uac-direct-mask.exe", "_internal/bin/uac-direct-guard.exe",
    "_internal/assets/pow_server_entries.txt",
)


class InstallType(str, Enum):
    DEVELOPMENT = "development"
    PORTABLE = "portable"
    MSI = "msi"


@dataclass(frozen=True)
class Installation:
    kind: InstallType
    executable: Path
    version: str
    architecture: str = ""


def pe_architecture(path: Path) -> str:
    with path.open("rb") as stream:
        header = stream.read(64)
        if len(header) < 64 or header[:2] != b"MZ":
            raise ValueError(f"Invalid Windows executable: {path.name}")
        stream.seek(struct.unpack_from("<I", header, 60)[0])
        signature = stream.read(6)
        if not signature.startswith(b"PE\0\0") or len(signature) != 6:
            raise ValueError(f"Invalid PE header: {path.name}")
        return {b"\x64\x86": "x64", b"\x4c\x01": "x86", b"\x64\xaa": "arm64"}.get(signature[4:], "")


def portable_metadata(version: str, architecture: str) -> dict:
    return {"schema": 1, "product": "UAC Spoofer Desktop", "kind": "portable",
            "version": version, "architecture": architecture}


def _msi_property(msi, product: str, name: str) -> str:
    output = ctypes.create_unicode_buffer(512)
    size = ctypes.c_uint(len(output))
    if msi.MsiGetProductInfoW(product, name, output, ctypes.byref(size)) != 0:
        raise OSError(f"Could not read Windows Installer property {name}")
    return output.value


def registered_msi(executable: Path) -> str | None:
    """Return the version of the MSI product that owns this exact executable."""
    msi = ctypes.WinDLL("msi.dll")
    for index in range(256):
        product = ctypes.create_unicode_buffer(39)
        status = msi.MsiEnumRelatedProductsW(UPGRADE_CODE, 0, index, product)
        if status == 259:  # ERROR_NO_MORE_ITEMS
            return None
        if status != 0:
            raise OSError(f"Could not query Windows Installer ({status})")
        path = ctypes.create_unicode_buffer(32768)
        size = ctypes.c_uint(len(path))
        state = msi.MsiGetComponentPathW(product.value, APP_COMPONENT, path, ctypes.byref(size))
        if state == 3 and Path(path.value).resolve() == executable.resolve():  # INSTALLSTATE_LOCAL
            return _msi_property(msi, product.value, "VersionString")
    raise OSError("Too many related Windows Installer products")


def detect_distribution(executable: Path, version: str) -> Installation:
    executable = executable.resolve()
    development = Installation(InstallType.DEVELOPMENT, executable, version)
    try:
        architecture = pe_architecture(executable)
        if not architecture:
            return development
        registered = registered_msi(executable)
        if registered is not None:
            if registered == version:
                return Installation(InstallType.MSI, executable, version, architecture)
            return development
        marker_path = executable.parent / PORTABLE_MARKER
        with marker_path.open("rb") as stream:
            marker = json.loads(stream.read(4096))
        if marker == portable_metadata(version, architecture) and (executable.parent / "_internal").is_dir():
            return Installation(InstallType.PORTABLE, executable, version, architecture)
    except (OSError, ValueError):
        pass
    return development


def current_installation() -> Installation:
    executable = Path(sys.executable)
    if sys.platform != "win32" or not getattr(sys, "frozen", False):
        return Installation(InstallType.DEVELOPMENT, executable, __version__)
    return detect_distribution(executable, __version__)
