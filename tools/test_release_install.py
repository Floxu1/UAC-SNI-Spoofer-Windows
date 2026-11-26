"""Run the real MSI lifecycle on a clean, elevated Windows test host."""
from __future__ import annotations

import argparse
import ctypes
import os
import subprocess
import tempfile
from pathlib import Path

from tools.prepare_github_release import ROOT, build_msi, sha256
from uac_desktop import __version__
from uac_desktop.install_type import APP_EXE, MSI_ASSET, REQUIRED_RUNTIME, registered_msi
from uac_desktop.updater import _program_files, msi_metadata


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wix", default="wix")
    args = parser.parse_args()
    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise SystemExit("The per-machine MSI lifecycle requires an elevated Windows test host.")
    dist = ROOT / "dist" / "UAC-Spoofer-Desktop"
    initial = ROOT / "github_release" / MSI_ASSET
    application = _program_files() / "UAC Spoofer Desktop" / APP_EXE
    if application.parent.exists() or registered_msi(application) is not None:
        raise SystemExit("Use a clean test host to preserve any existing installation.")
    system_installer = Path(os.environ["SystemRoot"]) / "System32" / "msiexec.exe"
    with tempfile.TemporaryDirectory(prefix="uac-msi-test-") as folder:
        stage = Path(folder)
        marker = stage / "AppData" / "UAC Spoofer Desktop" / "settings.json"
        marker.parent.mkdir(parents=True)
        marker.write_text('{"keep":true}', encoding="utf-8")
        os.environ["APPDATA"] = str(marker.parent.parent)
        recovery = stage / "failure.msi"
        upgrade = stage / "upgrade.msi"
        failure_source = stage / "Failure.wxs"
        source = (ROOT / "installer" / "Package.wxs").read_text(encoding="utf-8")
        failure_source.write_text(source.replace("    <MediaTemplate", (
            '    <CustomAction Id="TestFailure" Error="Intentional rollback test" />\n'
            '    <InstallExecuteSequence><Custom Action="TestFailure" After="InstallFiles" />'
            '</InstallExecuteSequence>\n    <MediaTemplate'
        )), encoding="utf-8")
        major, minor, patch = map(int, __version__.split("."))
        replacement = f"{major}.{minor}.{patch + 1}"
        build_msi(dist, recovery, args.wix, replacement, source=failure_source)
        build_msi(dist, upgrade, args.wix, replacement)

        def install(operation, package, case, allowed=(0,)):
            log = stage / f"{case}.log"
            result = subprocess.run([str(system_installer), operation, str(package), "/qn", "/norestart",
                                     "/l*v", str(log)], check=False)
            if result.returncode not in allowed:
                tail = log.read_text(encoding="utf-16", errors="replace").splitlines()[-35:] if log.exists() else []
                raise RuntimeError(f"{case}: Windows Installer returned {result.returncode}\n" + "\n".join(tail))

        installed = None
        try:
            install("/i", initial, "clean-install")
            installed = initial
            assert registered_msi(application) == __version__
            assert sha256(application) == sha256(dist / APP_EXE)
            for file in REQUIRED_RUNTIME:
                assert sha256(application.parent / file) == sha256(dist / file)
            for name, switch in (("xray.exe", "version"), ("aether.exe", "--pow-contract"),
                                 ("uac-direct.exe", "--direct-contract")):
                subprocess.run([str(application.parent / "_internal" / "bin" / name), switch],
                               check=True, timeout=15)
            target = application.parent / "_internal" / "bin" / "geosite.dat"
            target.unlink()
            install("/fa", initial, "repair")
            assert sha256(target) == sha256(dist / target.relative_to(application.parent))
            install("/i", recovery, "intentional-failure", allowed=(1603,))
            assert registered_msi(application) == __version__
            assert sha256(application) == sha256(dist / APP_EXE)
            install("/i", upgrade, "major-upgrade")
            installed = upgrade
            assert registered_msi(application) == replacement
        finally:
            if installed is not None:
                install("/x", msi_metadata(installed)["ProductCode"], "uninstall")
        assert not application.exists() and registered_msi(application) is None
        assert marker.read_text(encoding="utf-8") == '{"keep":true}'
        print("MSI clean install, repair, rollback, upgrade and uninstall passed.")


if __name__ == "__main__":
    main()
