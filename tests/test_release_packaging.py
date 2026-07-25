from pathlib import Path

import pytest

from tools import prepare_github_release as release


def test_release_runtime_manifest_covers_tun_assets():
    assert set(release.PORTABLE_RUNTIME_FILES) == {
        Path("UAC-Spoofer-Desktop.exe"),
        Path("_internal/bin/xray.exe"),
        Path("_internal/bin/sing-box.exe"),
        Path("_internal/bin/libcronet.dll"),
        Path("_internal/bin/sing-box-LICENSE"),
    }


def test_release_cleanup_removes_stale_portable(monkeypatch, tmp_path):
    output = tmp_path / "github_release"
    stale = output / "portable" / "_internal" / "bin" / "stale.dll"
    stale.parent.mkdir(parents=True)
    stale.write_bytes(b"stale")
    (output / "old.zip").write_bytes(b"old")
    monkeypatch.setattr(release, "OUT", output)
    release.clear_output_files()
    assert list(output.iterdir()) == []


def test_release_validation_reports_missing_runtime(tmp_path):
    present = tmp_path / "sing-box.exe"
    missing = tmp_path / "libcronet.dll"
    present.write_bytes(b"exe")
    with pytest.raises(SystemExit, match="libcronet.dll"):
        release.require_file_paths(
            [present, missing],
            "Portable build is missing required files",
        )
