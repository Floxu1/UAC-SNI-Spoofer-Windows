import hashlib
from pathlib import Path

from uac_desktop import npcap


class DownloadResponse:
    def __init__(self, payload):
        self.payload = payload
        self.offset = 0

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self, size):
        value = self.payload[self.offset:self.offset + size]
        self.offset += len(value)
        return value


def test_ready_npcap_skips_download_and_installer():
    called = []
    result = npcap.ensure_npcap(
        available=lambda: True,
        downloader=lambda: called.append("download"),
        launcher=lambda _path: called.append("launch"),
    )

    assert result.available is True
    assert result.action == "ready"
    assert called == []


def test_windows_npcap_check_requires_dll_and_running_driver(monkeypatch):
    monkeypatch.setattr(npcap.sys, "platform", "win32")
    monkeypatch.setattr(npcap, "activate_npcap_path", lambda: Path("wpcap.dll"))
    monkeypatch.setattr(npcap, "_ensure_driver_running", lambda: False)

    assert npcap.npcap_available() is False

    monkeypatch.setattr(npcap, "_ensure_driver_running", lambda: True)
    assert npcap.npcap_available() is True


def test_missing_npcap_downloads_launches_and_rechecks(tmp_path):
    checks = iter([False, True])
    installer = tmp_path / "npcap.exe"
    installer.write_bytes(b"installer")
    launched = []

    result = npcap.ensure_npcap(
        available=lambda: next(checks),
        downloader=lambda: installer,
        launcher=lambda path: launched.append(path) or 0,
    )

    assert result.available is True
    assert result.action == "installed"
    assert launched == [installer]


def test_download_rejects_unverified_installer(tmp_path, monkeypatch):
    payload = b"not-the-official-installer"
    monkeypatch.setattr(npcap, "NPCAP_SHA256", hashlib.sha256(b"other").hexdigest())
    destination = tmp_path / "npcap.exe"

    try:
        npcap.download_npcap(
            destination,
            opener=lambda *_args, **_kwargs: DownloadResponse(payload),
        )
    except RuntimeError as exc:
        assert "verification failed" in str(exc)
    else:
        raise AssertionError("invalid installer was accepted")

    assert not destination.exists()
    assert not Path(str(destination) + ".part").exists()


def test_download_accepts_pinned_installer(tmp_path, monkeypatch):
    payload = b"verified-installer"
    monkeypatch.setattr(npcap, "NPCAP_SHA256", hashlib.sha256(payload).hexdigest())
    destination = tmp_path / "npcap.exe"

    result = npcap.download_npcap(
        destination,
        opener=lambda *_args, **_kwargs: DownloadResponse(payload),
    )

    assert result == destination
    assert destination.read_bytes() == payload
