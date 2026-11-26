from __future__ import annotations

import hashlib
import json
import struct
import threading
import zipfile
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
import requests

from uac_desktop import install_type, updater
from uac_desktop.app_config import UPDATE_REPOSITORY_URL
from uac_desktop.install_type import (
    APP_EXE, MSI_ASSET, PORTABLE_ASSET, PORTABLE_MARKER, REQUIRED_RUNTIME, UPDATER_EXE,
    Installation, InstallType, portable_metadata,
)
from uac_desktop.update_checker import ReleaseAsset, UpdateInfo


def _exe(architecture=0x8664):
    header = bytearray(64)
    header[:2] = b"MZ"
    struct.pack_into("<I", header, 60, 64)
    return bytes(header) + b"PE\0\0" + struct.pack("<H", architecture)


def _asset(name, payload=b"payload"):
    return ReleaseAsset(name, f"{UPDATE_REPOSITORY_URL}/releases/download/v1.2.0/{name}",
                        len(payload), "sha256:" + hashlib.sha256(payload).hexdigest())


def _release(*assets):
    return UpdateInfo(UPDATE_REPOSITORY_URL, "1.1.2", "1.2.0", "v1.2.0", "New version",
                      UPDATE_REPOSITORY_URL + "/releases/tag/v1.2.0", "", "", False, True, assets=assets)


@pytest.mark.parametrize(("kind", "asset_name"), [(InstallType.MSI, MSI_ASSET), (InstallType.PORTABLE, PORTABLE_ASSET)])
def test_selects_only_the_matching_verified_asset(kind, asset_name):
    install = Installation(kind, Path(APP_EXE), "1.1.2", "x64")
    info = _release(_asset(PORTABLE_ASSET), _asset(MSI_ASSET))
    assert updater.select_asset(info, install).name == asset_name
    with pytest.raises(ValueError):
        updater.select_asset(replace(info, assets=tuple(asset for asset in info.assets if asset.name != asset_name)), install)
    for invalid in (replace(install, architecture="arm64"), replace(install, kind=InstallType.DEVELOPMENT)):
        with pytest.raises(ValueError):
            updater.select_asset(info, invalid)
    with pytest.raises(ValueError):
        updater.select_asset(_release(replace(_asset(asset_name), digest="")), install)
    with pytest.raises(ValueError):
        updater.select_asset(replace(info, repo_url="https://github.com/fork/UAC"), install)


def test_distribution_requires_installer_registration_or_portable_identity(tmp_path, monkeypatch):
    exe = tmp_path / APP_EXE
    exe.write_bytes(_exe())
    (tmp_path / "_internal").mkdir()
    (tmp_path / PORTABLE_MARKER).write_text(json.dumps(portable_metadata("1.1.2", "x64")))
    monkeypatch.setattr(install_type, "registered_msi", lambda path: None)
    assert install_type.detect_distribution(exe, "1.1.2").kind is InstallType.PORTABLE
    assert install_type.detect_distribution(exe, "9.9.0").kind is InstallType.DEVELOPMENT
    monkeypatch.setattr(install_type, "registered_msi", lambda path: "1.1.2")
    assert install_type.detect_distribution(exe, "1.1.2").kind is InstallType.MSI
    assert install_type.detect_distribution(exe, "9.9.0").kind is InstallType.DEVELOPMENT


class _Response:
    status_code = 200
    headers = {}

    def __init__(self, blocks):
        self.blocks = blocks

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def raise_for_status(self):
        pass

    def iter_content(self, _block_size):
        yield from self.blocks


def test_download_interrupt_and_bad_digest_leave_no_partial_file(tmp_path):
    destination = tmp_path / PORTABLE_ASSET
    asset = _asset(PORTABLE_ASSET, b"payload")
    cancel = threading.Event()

    def interrupted():
        yield b"pa"
        raise requests.ConnectionError("Disconnected")

    for blocks, error in ((interrupted(), requests.ConnectionError), ([b"pay"], ValueError),
                          ([b"corrupt"], ValueError)):
        with pytest.raises(error):
            updater._download(asset, destination, cancel, lambda *_: None, lambda *_a, **_k: _Response(blocks))
        assert not list(tmp_path.iterdir())
    updater._download(asset, destination, cancel, lambda *_: None,
                      lambda *_a, **_k: _Response([b"pay", b"load"]))
    assert destination.read_bytes() == b"payload"


def _portable_fixture(tmp_path, extra=None):
    stage = tmp_path / "stage"
    stage.mkdir()
    root = tmp_path / "portable"
    root.mkdir()
    installation = Installation(InstallType.PORTABLE, root / APP_EXE, "1.1.2", "x64")
    update = updater.PreparedUpdate(stage, installation, "1.2.0", 0, "")
    marker = portable_metadata(installation.version, "x64")
    (root / PORTABLE_MARKER).write_text(json.dumps(marker))
    (root / APP_EXE).write_bytes(_exe() + b"old")
    (root / UPDATER_EXE).write_bytes(_exe() + b"old")
    (root / "_internal").mkdir()
    (root / "_internal" / "old-runtime").write_bytes(b"old")
    (root / "settings.json").write_text("keep")
    with zipfile.ZipFile(update.package, "w") as archive:
        archive.writestr(PORTABLE_MARKER, json.dumps(portable_metadata(update.version, "x64")))
        archive.writestr(APP_EXE, _exe() + b"new")
        archive.writestr(UPDATER_EXE, _exe() + b"new")
        for name in REQUIRED_RUNTIME:
            archive.writestr(name, b"dependency")
        if extra:
            archive.writestr(extra, b"bad")
    return root, update


def test_portable_update_replaces_runtime_and_preserves_user_files(tmp_path, monkeypatch):
    root, update = _portable_fixture(tmp_path)
    relaunched = []
    monkeypatch.setattr(updater, "_relaunch", relaunched.append)
    updater._apply_portable(update)
    assert (root / APP_EXE).read_bytes().endswith(b"new")
    assert not (root / "_internal" / "old-runtime").exists()
    assert json.loads((root / PORTABLE_MARKER).read_bytes())["version"] == update.version
    assert (root / "settings.json").read_text() == "keep"
    assert relaunched == [root / APP_EXE]


@pytest.mark.parametrize("failure", ["bad-path", "locked-file", "restart-failed"])
def test_portable_failure_keeps_current_version_and_user_files(tmp_path, monkeypatch, failure):
    root, update = _portable_fixture(tmp_path, "../outside" if failure == "bad-path" else None)
    replace_path = Path.replace

    def rename(path, target):
        if failure == "locked-file" and path.parent.name == "incoming" and path.name == UPDATER_EXE:
            raise PermissionError("locked")
        return replace_path(path, target)

    def relaunch(_):
        raise OSError("launch failed")

    monkeypatch.setattr(Path, "replace", rename)
    monkeypatch.setattr(updater, "_relaunch", relaunch)
    with pytest.raises((ValueError, OSError)):
        updater._apply_portable(update)
    assert (root / APP_EXE).read_bytes().endswith(b"old")
    assert (root / UPDATER_EXE).read_bytes().endswith(b"old")
    assert (root / "_internal" / "old-runtime").read_bytes() == b"old"
    assert (root / "settings.json").read_text() == "keep"
    assert not (tmp_path / "outside").exists()


@pytest.mark.parametrize("pending", [False, True])
def test_app_hands_off_update_only_after_cleanup(monkeypatch, pending):
    import main
    from uac_desktop import process_win

    calls = []
    update = object()
    proxy = SimpleNamespace(has_pending_restore=pending)
    engine = SimpleNamespace(system_proxy=proxy, stop=lambda **_: calls.append("engine"),
                             gateway=SimpleNamespace(recover=lambda **_: calls.append("gateway") or True))
    window = SimpleNamespace(engine=engine, _prepared_update=update, _update_shutdown_ok=True,
                             _engine_busy=lambda: False, shutdown=lambda: calls.append("shutdown"))
    app = SimpleNamespace(exec=lambda: 0)
    monkeypatch.setattr(main, "WindowsProxy", SimpleNamespace(
        process_identity=lambda: {"pid": 123, "create_time": 1},
        recover_stale=lambda **_: calls.append("proxy"),
    ))
    monkeypatch.setattr(process_win, "cleanup_bin_helpers", lambda: calls.append("helpers"))
    monkeypatch.setattr(updater, "launch_worker", lambda value: calls.append(("apply", value)))
    monkeypatch.setattr(updater, "discard_update", lambda value: calls.append(("discard", value)))
    monkeypatch.setattr(main, "ctypes", SimpleNamespace(windll=SimpleNamespace(
        user32=SimpleNamespace(MessageBoxW=lambda *_: None),
    )))
    assert main.run_event_loop(app, window) == 0
    assert calls == ["shutdown", "engine", "gateway", "helpers", "proxy",
                     ("discard" if pending else "apply", update)]
