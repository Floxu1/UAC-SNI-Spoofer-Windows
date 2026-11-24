from pathlib import Path

import pytest

from tools import prepare_github_release as release


def test_release_runtime_manifest_covers_tun_and_pow_assets():
    assert set(release.PORTABLE_RUNTIME_FILES) == {
        Path("UAC-Spoofer-Desktop.exe"),
        Path("_internal/bin/xray.exe"),
        Path("_internal/bin/sing-box.exe"),
        Path("_internal/bin/libcronet.dll"),
        Path("_internal/bin/sing-box-LICENSE"),
        Path("_internal/bin/geoip.dat"),
        Path("_internal/bin/geosite.dat"),
        Path("_internal/bin/aether.exe"),
        Path("_internal/bin/keyfetch-net.ps1"),
        Path("_internal/bin/uac-psiphon.exe"),
        Path("_internal/bin/uac-pow-guard.exe"),
        Path("_internal/bin/uac-direct.exe"),
        Path("_internal/bin/uac-direct-xray.exe"),
        Path("_internal/licenses/direct-xray/uac-direct-xray-LICENSE"),
        Path("_internal/bin/uac-direct-mask.exe"),
        Path("_internal/bin/uac-direct-guard.exe"),
        Path("_internal/licenses/direct/SOURCE.json"),
        Path("_internal/licenses/direct/LICENSE"),
        Path("_internal/licenses/direct/BYEDPI-LICENSE"),
        Path("_internal/licenses/aether/SOURCE.json"),
        Path("_internal/licenses/aether/LICENSE"),
        Path("_internal/licenses/quiche/COPYING"),
        Path("_internal/assets/pow_server_entries.txt"),
    }


def test_release_manifest_covers_all_assistant_images():
    assert set(release.ASSISTANT_ASSET_FILES) == {
        Path("_internal/wizard guider/wizard_01_normal.png"),
        Path("_internal/wizard guider/wizard_02_thinking.png"),
        Path("_internal/wizard guider/wizard_03_waiting.png"),
        Path("_internal/wizard guider/wizard_04_happy.png"),
        Path("_internal/wizard guider/wizard_05_sad.png"),
        Path("_internal/wizard guider/wizard_06_guiding_right.png"),
        Path("_internal/wizard guider/wizard_07_confused.png"),
        Path("_internal/wizard guider/wizard_08_surprised.png"),
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
