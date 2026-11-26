import hashlib
import json
import threading

import pytest

from installer import bootstrap_backend as backend
from installer.bootstrap_strings import translate
from uac_desktop import data_reset


def test_embedded_msi_verifies_hash_before_install(tmp_path):
    bundle = tmp_path / "Setup.exe"
    package = b"sample MSI data"
    tail = backend.TRAILER.pack(backend.MAGIC, len(package), hashlib.sha256(package).digest())
    bundle.write_bytes(b"launcher" + package + tail)
    output = tmp_path / "setup.msi"
    backend.extract_payload(bundle, output, threading.Event())
    assert output.read_bytes() == package
    bundle.write_bytes(b"launcher" + b"X" + package[1:] + tail)
    with pytest.raises(ValueError, match="checksum"):
        backend.extract_payload(bundle, tmp_path / "invalid.msi", threading.Event())


def test_first_run_language_passes_storage_migration_and_keeps_existing_choice(tmp_path, monkeypatch):
    profile = tmp_path / "UAC Spoofer Desktop"
    monkeypatch.setattr(backend, "settings_directory", lambda: profile)
    backend.seed_language("fa")
    assert data_reset.run(profile) == "done-before"
    assert json.loads((profile / "settings.json").read_text())["language"] == "fa"
    backend.seed_language("en")
    assert json.loads((profile / "settings.json").read_text())["language"] == "fa"
    assert translate("fa", "launch") == "اجرای \u2066UAC Spoofer Desktop\u2069"
    assert translate("en", "launch") == "Launch UAC Spoofer Desktop"
