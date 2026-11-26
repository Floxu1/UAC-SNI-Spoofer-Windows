"""Verified release download and out-of-process Windows update application."""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import zipfile
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from urllib.parse import unquote, urljoin, urlsplit

from .app_config import UPDATE_REPOSITORY_URL
from .install_type import (
    APP_EXE, MSI_ASSET, PORTABLE_ASSET, PORTABLE_MARKER, REQUIRED_RUNTIME, UPDATER_EXE, UPGRADE_CODE,
    Installation, InstallType, detect_distribution, pe_architecture, portable_metadata, registered_msi,
)
from .update_checker import ReleaseAsset, SemVersion, UpdateInfo, check_latest_release

_PACKAGES = {InstallType.PORTABLE: PORTABLE_ASSET, InstallType.MSI: MSI_ASSET}
_GITHUB_DOWNLOAD_HOSTS = {"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"}
_MANAGED = ("_internal", UPDATER_EXE, PORTABLE_MARKER, APP_EXE)
_REQUEST = "request.json"
_MAX_DOWNLOAD = 1024 ** 3
_MAX_EXPANDED = 2 * 1024 ** 3


class UpdateCancelled(Exception):
    pass


@dataclass(frozen=True)
class PreparedUpdate:
    stage: Path
    installation: Installation
    version: str
    size: int
    sha256: str

    @property
    def package(self) -> Path:
        return self.stage / _PACKAGES[self.installation.kind]


def select_asset(info: UpdateInfo, installation: Installation) -> ReleaseAsset:
    name = _PACKAGES.get(installation.kind)
    version = SemVersion.parse(info.latest_version)
    if (not name or installation.architecture != "x64" or not info.is_update_available or info.prerelease
            or version.prerelease or version.build or version <= SemVersion.parse(installation.version)
            or info.repo_url.casefold() != UPDATE_REPOSITORY_URL.casefold()
            or SemVersion.parse(info.tag_name) != version):
        raise ValueError("No compatible stable update is available for this installation")
    matches = [asset for asset in info.assets if asset.name == name]
    if len(matches) != 1:
        raise ValueError(f"The release has no unique {name} package")
    asset, = matches
    parsed = urlsplit(asset.url)
    repo = urlsplit(UPDATE_REPOSITORY_URL)
    expected = f"{repo.path}/releases/download/{info.tag_name}/{name}"
    if (parsed.scheme != "https" or parsed.netloc.casefold() != "github.com"
            or unquote(parsed.path).casefold() != expected.casefold() or parsed.query or parsed.fragment
            or not 0 < asset.size <= _MAX_DOWNLOAD or not re.fullmatch(r"sha256:[0-9a-fA-F]{64}", asset.digest)):
        raise ValueError("GitHub did not provide a valid size and SHA-256 digest for this package")
    return asset


def _cancel_if_requested(cancel: threading.Event) -> None:
    if cancel.is_set():
        raise UpdateCancelled


def _download(asset: ReleaseAsset, destination: Path, cancel: threading.Event, progress, get) -> None:
    partial = destination.with_suffix(".part")
    url = asset.url
    try:
        for _ in range(5):
            _cancel_if_requested(cancel)
            parsed = urlsplit(url)
            if parsed.scheme != "https" or parsed.netloc.casefold() not in _GITHUB_DOWNLOAD_HOSTS:
                raise ValueError("An update download redirected outside GitHub")
            with get(url, stream=True, timeout=(5, 15), allow_redirects=False,
                     headers={"Accept-Encoding": "identity"}) as response:
                if response.status_code in (301, 302, 303, 307, 308):
                    url = urljoin(url, response.headers["Location"])
                    continue
                response.raise_for_status()
                if response.status_code != 200:
                    raise ValueError(f"Unexpected update response: {response.status_code}")
                length = response.headers.get("Content-Length")
                if length is not None and int(length) != asset.size:
                    raise ValueError("The HTTP content length does not match the release")
                received = 0
                digest = hashlib.sha256()
                with partial.open("xb") as output:
                    for block in response.iter_content(512 * 1024):
                        _cancel_if_requested(cancel)
                        received += len(block)
                        if received > asset.size:
                            raise ValueError("The update is larger than the published package")
                        digest.update(block)
                        output.write(block)
                        progress(received, asset.size)
                if received != asset.size or digest.hexdigest() != asset.digest[7:].lower():
                    raise ValueError("The update size or SHA-256 does not match the release")
                _cancel_if_requested(cancel)
                partial.replace(destination)
                return
        raise ValueError("Too many update download redirects")
    finally:
        partial.unlink(missing_ok=True)


def _portable_members(archive: zipfile.ZipFile) -> dict[str, zipfile.ZipInfo]:
    members = {}
    expanded = 0
    for entry in archive.infolist():
        name = entry.filename.removesuffix("/")
        path = PureWindowsPath(name)
        parts = name.split("/")
        if (not name or "\\" in name or path.anchor or any(
                not part or part in (".", "..") or part.endswith((" ", "."))
                or any(character in '<>:"|?*' or ord(character) < 32 for character in part)
                or PureWindowsPath(part).is_reserved() for part in parts)
                or stat.S_ISLNK(entry.external_attr >> 16) or name.casefold() in members
                or (parts[0] != "_internal" and (len(parts) != 1 or name not in _MANAGED))):
            raise ValueError(f"Unsafe path in Portable package: {entry.filename}")
        expanded += entry.file_size
        if expanded > _MAX_EXPANDED:
            raise ValueError("Portable package exceeds the unpacked size limit")
        members[name.casefold()] = entry
    for relative in (APP_EXE, UPDATER_EXE, PORTABLE_MARKER, *REQUIRED_RUNTIME):
        entry = members.get(relative.casefold())
        if entry is None or entry.is_dir() or entry.file_size == 0:
            raise ValueError(f"Portable package is missing {relative}")
    return members


def _validate_portable(archive: zipfile.ZipFile, update: PreparedUpdate) -> None:
    members = _portable_members(archive)
    marker = members[PORTABLE_MARKER.casefold()]
    if (marker.file_size > 4096 or json.loads(archive.read(marker))
            != portable_metadata(update.version, update.installation.architecture)):
        raise ValueError("Portable package identity, version or architecture is incorrect")
    # Read the executable header without expanding its contents to disk.
    with archive.open(members[APP_EXE.casefold()]) as stream:
        header = stream.read(64)
        offset = int.from_bytes(header[60:64], "little")
        if (len(header) != 64 or not header.startswith(b"MZ") or not 64 <= offset <= 64 * 1024
                or stream.seek(offset) != offset or stream.read(6) != b"PE\0\0\x64\x86"):
            raise ValueError("Portable executable is not Windows x64")


def msi_metadata(path: Path) -> dict[str, str]:
    msi = ctypes.WinDLL("msi.dll")
    database, summary = ctypes.c_uint(), ctypes.c_uint()
    if msi.MsiOpenDatabaseW(str(path), None, ctypes.byref(database)) != 0:
        raise ValueError("The setup package is not a readable MSI database")
    handles = [database.value]
    try:
        if msi.MsiGetSummaryInformationW(database, None, 0, ctypes.byref(summary)) != 0:
            raise ValueError("MSI summary information is missing")
        handles.append(summary.value)
        output = ctypes.create_unicode_buffer(512)
        size = ctypes.c_uint(len(output))
        data_type = ctypes.c_uint()
        if msi.MsiSummaryInfoGetPropertyW(summary, 7, ctypes.byref(data_type), None, None,
                                          output, ctypes.byref(size)) != 0:
            raise ValueError("MSI architecture is missing")
        fields = {"architecture": output.value.partition(";")[0]}
        for field in ("UpgradeCode", "ProductVersion", "ProductName", "ProductCode", "ALLUSERS"):
            view, record = ctypes.c_uint(), ctypes.c_uint()
            sql = f"SELECT `Value` FROM `Property` WHERE `Property` = '{field}'"
            if msi.MsiDatabaseOpenViewW(database, sql, ctypes.byref(view)) != 0:
                raise ValueError(f"Could not query MSI field {field}")
            handles.append(view.value)
            if msi.MsiViewExecute(view, 0) != 0 or msi.MsiViewFetch(view, ctypes.byref(record)) != 0:
                raise ValueError(f"MSI field {field} is missing")
            handles.append(record.value)
            size = ctypes.c_uint(len(output))
            if msi.MsiRecordGetStringW(record, 1, output, ctypes.byref(size)) != 0:
                raise ValueError(f"Could not read MSI field {field}")
            fields[field] = output.value
        return fields
    finally:
        for handle in reversed(handles):
            msi.MsiCloseHandle(handle)


def _validate_package(update: PreparedUpdate) -> None:
    if update.installation.kind == InstallType.PORTABLE:
        with zipfile.ZipFile(update.package) as archive:
            _validate_portable(archive, update)
    else:
        fields = msi_metadata(update.package)
        if (fields["UpgradeCode"].casefold() != UPGRADE_CODE.casefold()
                or fields["ProductVersion"] != update.version or fields["architecture"].casefold() != "x64"
                or fields["ProductName"] != "UAC Spoofer Desktop" or fields["ALLUSERS"] != "1"):
            raise ValueError("MSI identity, version, architecture or installation scope is incorrect")


def _program_files() -> Path:
    path = ctypes.create_unicode_buffer(32768)
    if ctypes.windll.shell32.SHGetFolderPathW(None, 0x26, None, 0, path) != 0 or not path.value:
        raise OSError("Could not locate the protected Windows Program Files directory")
    return Path(path.value).resolve()


def prepare_update(installation: Installation, cancel: threading.Event, progress) -> PreparedUpdate:
    import requests

    info = check_latest_release(UPDATE_REPOSITORY_URL, installation.version)
    asset = select_asset(info, installation)
    _cancel_if_requested(cancel)
    stage = Path(tempfile.mkdtemp(prefix="UAC-Update-", dir=_program_files()))
    try:
        update = PreparedUpdate(stage, installation, info.latest_version, asset.size, asset.digest[7:].lower())
        _download(asset, update.package, cancel, progress, requests.get)
        _validate_package(update)
        _cancel_if_requested(cancel)
        return update
    except BaseException:
        shutil.rmtree(stage)
        raise


def discard_update(update: PreparedUpdate) -> None:
    shutil.rmtree(update.stage, ignore_errors=True)


def launch_worker(update: PreparedUpdate) -> None:
    installation = update.installation
    worker = update.stage / UPDATER_EXE
    shutil.copy2(installation.executable.with_name(UPDATER_EXE), worker)
    (update.stage / _REQUEST).write_text(json.dumps({
        "pid": os.getpid(), "exe": str(installation.executable), "kind": installation.kind.value,
        "old_version": installation.version, "version": update.version, "architecture": installation.architecture,
        "size": update.size, "sha256": update.sha256,
    }), encoding="utf-8")
    subprocess.Popen([str(worker)], cwd=update.stage, env={**os.environ, "PYINSTALLER_RESET_ENVIRONMENT": "1"},
                     creationflags=subprocess.DETACHED_PROCESS)


def _wait_for_parent(pid: int) -> None:
    kernel = ctypes.WinDLL("kernel32.dll", use_last_error=True)
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.WaitForSingleObject.argtypes = (ctypes.c_void_p, ctypes.c_uint)
    kernel.CloseHandle.argtypes = (ctypes.c_void_p,)
    handle = kernel.OpenProcess(0x100000, False, pid)
    if not handle:
        if ctypes.get_last_error() == 87:  # The parent already exited.
            return
        raise OSError("Could not wait for the running application to exit")
    try:
        if kernel.WaitForSingleObject(handle, 60_000) != 0:
            raise OSError("The running application did not exit")
    finally:
        kernel.CloseHandle(handle)


def _relaunch(executable: Path) -> None:
    subprocess.Popen([str(executable)], cwd=executable.parent,
                     env={**os.environ, "PYINSTALLER_RESET_ENVIRONMENT": "1"})


def _apply_portable(update: PreparedUpdate) -> None:
    root = update.installation.executable.parent
    # Renames are same-volume. Keep all unmanaged files in place.
    work = Path(tempfile.mkdtemp(prefix=".uac-update-", dir=root))
    incoming, backup = work / "incoming", work / "backup"
    backup.mkdir()
    moved_old, moved_new = [], []
    keep_backup = False
    try:
        with zipfile.ZipFile(update.package) as archive:
            _validate_portable(archive, update)
            archive.extractall(incoming)
        if any(not (root / name).exists() for name in _MANAGED):
            raise OSError("The Portable installation changed before the update")
        if pe_architecture(incoming / UPDATER_EXE) != update.installation.architecture:
            raise ValueError("The update worker architecture is incompatible")
        for name in _MANAGED:
            (root / name).replace(backup / name)
            moved_old.append(name)
            (incoming / name).replace(root / name)
            moved_new.append(name)
        _relaunch(update.installation.executable)
    except BaseException:
        try:
            for name in reversed(moved_new):
                (root / name).replace(incoming / name)
            for name in reversed(moved_old):
                (backup / name).replace(root / name)
        except OSError as error:
            keep_backup = True
            raise OSError(f"Portable rollback needs attention. The previous files are in {backup}") from error
        raise
    finally:
        if not keep_backup:
            shutil.rmtree(work, ignore_errors=True)


def _apply_msi(update: PreparedUpdate) -> bool:
    directory = ctypes.create_unicode_buffer(32768)
    if not ctypes.windll.kernel32.GetSystemDirectoryW(directory, len(directory)):
        raise OSError("Could not locate the Windows Installer executable")
    msiexec = Path(directory.value) / "msiexec.exe"
    result = subprocess.run([str(msiexec), "/i", str(update.package), "/passive", "/norestart",
                             f"INSTALLFOLDER={update.installation.executable.parent}",
                             "/l*v", str(update.stage / "installer.log")], check=False)
    if result.returncode in (1641, 3010):
        return False
    if result.returncode or registered_msi(update.installation.executable) != update.version:
        raise OSError(f"Windows Installer did not complete the upgrade ({result.returncode})")
    _relaunch(update.installation.executable)
    return True


def run_worker() -> int:
    stage = Path(sys.executable).resolve().parent
    # This executable is only invoked from a dedicated, protected directory.
    if stage.parent != _program_files() or not stage.name.startswith("UAC-Update-"):
        return 1
    ctypes.windll.kernel32.SetDllDirectoryW(None)
    old = None
    try:
        request = json.loads((stage / _REQUEST).read_text(encoding="utf-8"))
        _wait_for_parent(int(request["pid"]))
        old = Installation(InstallType(request["kind"]), Path(request["exe"]),
                           request["old_version"], request["architecture"])
        update = PreparedUpdate(stage, old, request["version"], request["size"], request["sha256"])
        if (old.kind not in _PACKAGES or old.architecture != "x64"
                or detect_distribution(old.executable, old.version) != old
                or SemVersion.parse(update.version) <= SemVersion.parse(old.version)):
            raise ValueError("The installation changed before the update")
        with update.package.open("rb") as stream:
            if (update.package.stat().st_size != update.size
                    or hashlib.file_digest(stream, "sha256").hexdigest() != update.sha256):
                raise ValueError("The staged update failed integrity verification")
        _validate_package(update)
        if old.kind == InstallType.PORTABLE:
            _apply_portable(update)
        elif not _apply_msi(update):
            ctypes.windll.user32.MessageBoxW(None, "Restart Windows to finish the UAC update.",
                                            "UAC Spoofer Desktop", 0x40)
        update.package.unlink(missing_ok=True)
        return 0
    except Exception as error:
        (stage / "update-error.txt").write_text(str(error), encoding="utf-8")
        ctypes.windll.user32.MessageBoxW(None, f"Update could not finish.\n{error}\n\n{stage}",
                                        "UAC Spoofer Desktop", 0x30)
        if old is not None and detect_distribution(old.executable, old.version) == old:
            try:
                _relaunch(old.executable)
            except OSError:
                pass
        return 1
