from __future__ import annotations

import hashlib
import argparse
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import tokenize
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ""):
    sys.path.insert(0, str(ROOT))

from uac_desktop import __version__
from uac_desktop.install_type import (APP_COMPONENT, APP_EXE, MSI_ASSET, PORTABLE_ASSET, PORTABLE_MARKER,
                                      UPDATER_EXE, UPGRADE_CODE, pe_architecture,
                                      portable_metadata)

OUT = ROOT / "github_release"
STAGE = ROOT / "github_release_stage"
DIST = ROOT / "dist" / "UAC-Spoofer-Desktop"
PORTABLE = OUT / "portable"
SOURCE = OUT / "source"
PORTABLE_RUNTIME_FILES = (
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
)
ASSISTANT_ASSET_FILES = tuple(
    Path("_internal/wizard guider") / f"wizard_{index:02d}_{state}.png" for index, state in enumerate((
        "normal", "thinking", "waiting", "happy", "sad", "guiding_right", "confused", "surprised"
    ), start=1)
)
WIX_EXTENSIONS = ("WixToolset.UI.wixext", "WixToolset.Util.wixext")
WIX_VERSION = "6.0.2"
SETUP_ASSET = "UAC-Spoofer-Windows-Setup.exe"


def copy_file(source: Path, destination: Path) -> str:
    source = Path(source)
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        shutil.copy2(source, destination)
    except PermissionError:
        if not destination.is_file() or sha256(source) != sha256(destination):
            raise
    return str(destination)


def copy_item(source: Path, destination: Path, *, merge: bool = False) -> None:
    if source.is_dir():
        shutil.copytree(
            source,
            destination,
            dirs_exist_ok=merge,
            copy_function=copy_file,
            ignore=shutil.ignore_patterns(
                "__pycache__", "*.pyc", "*.pyo", "*.bak*", "_bak*", ".pytest_cache", ".ruff_cache"
            ),
        )
    else:
        copy_file(source, destination)


def clean_python_comments(path: Path) -> None:
    source = path.read_text(encoding="utf-8-sig")
    output = []
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type == tokenize.COMMENT and "patterniha" not in token.string.casefold():
            token = tokenize.TokenInfo(token.type, "", token.start, token.end, token.line)
        output.append(token)
    cleaned = tokenize.untokenize(output)
    compile(cleaned, str(path), "exec")
    path.write_text(cleaned, encoding="utf-8", newline="\n")


def clean_powershell_comments(path: Path) -> None:
    lines = path.read_text(encoding="utf-8-sig").splitlines()
    kept = []
    for line in lines:
        stripped = line.lstrip()
        if stripped.startswith("#") and "patterniha" not in stripped.casefold():
            kept.append("")
        else:
            kept.append(line)
    path.write_text("\n".join(kept).rstrip() + "\n", encoding="utf-8", newline="\n")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def zip_tree(source: Path, destination: Path) -> None:
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(source.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(source))


def reset_tree(path: Path) -> None:
    if not path.exists():
        return
    for attempt in range(20):
        try:
            shutil.rmtree(path)
            return
        except PermissionError:
            if attempt == 19:
                raise
            time.sleep(1)


def require_file_paths(paths, message: str) -> None:
    missing = [str(path) for path in paths if not path.is_file()]
    if missing:
        raise SystemExit(message + ": " + ", ".join(missing))


def clear_output_files() -> None:
    OUT.mkdir(exist_ok=True)
    for path in OUT.iterdir():
        if path.is_dir():
            reset_tree(path)
        else:
            path.unlink()


def _installer_art(directory: Path) -> None:
    from PIL import Image

    with Image.open(ROOT / "assets" / "icon.png") as source:
        icon = source.convert("RGBA")
    icon.save(directory / "UacProduct.ico", sizes=[(size, size) for size in (16, 24, 32, 48, 64, 128, 256)])
    banner = Image.new("RGB", (493, 58), "#ffffff")
    banner_logo = icon.resize((40, 40), Image.Resampling.LANCZOS)
    banner.paste(banner_logo, (437, 9), banner_logo)
    banner.save(directory / "banner.bmp")

    # WiX places Welcome, Maintenance and Finish text to the right of the 180 px artwork column.
    dialog = Image.new("RGB", (493, 312), "#ffffff")
    dialog_logo = icon.resize((72, 72), Image.Resampling.LANCZOS)
    dialog.paste(dialog_logo, (54, 28), dialog_logo)
    dialog.save(directory / "dialog.bmp")


def build_msi(dist: Path, output: Path, wix: str, version: str, *, source: Path | None = None) -> None:
    if not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version):
        raise ValueError("MSI releases require a stable MAJOR.MINOR.PATCH version")
    if any(value > limit for value, limit in zip(map(int, version.split(".")), (255, 255, 65535))):
        raise ValueError("Version exceeds Windows Installer limits")
    installed = subprocess.check_output([wix, "extension", "list", "-g"], text=True).splitlines()
    extension_args = []
    for extension in WIX_EXTENSIONS:
        reference = f"{extension}/{WIX_VERSION}"
        if not any(line.split() == [extension, WIX_VERSION] for line in installed):
            subprocess.run([wix, "extension", "add", "-g", reference], check=True)
        extension_args.extend(("-ext", reference))
    # The native CAB builder needs short source paths for the bundled Qt files.
    with tempfile.TemporaryDirectory(prefix="uw-") as temporary:
        assets = Path(temporary)
        payload = assets / "p"
        shutil.copytree(dist, payload)
        _installer_art(assets)
        license_rtf = assets / "license.rtf"
        license_text = (ROOT / "LICENSE").read_text(encoding="ascii").translate(
            str.maketrans({"\\": r"\\", "{": r"\{", "}": r"\}"}))
        license_rtf.write_text(r"{\rtf1\ansi\deff0{\fonttbl{\f0 Segoe UI;}}\fs20 " +
                               "\\par\n".join(license_text.splitlines()) + "}", encoding="ascii")
        subprocess.run([
            wix, "build", str(source or ROOT / "installer" / "Package.wxs"), str(ROOT / "installer" / "Options.wxs"),
            "-arch", "x64", "-pdbtype", "none", *extension_args,
            "-bindvariable", f"WixUILicenseRtf={license_rtf}",
            "-bindvariable", f"WixUIBannerBmp={assets / 'banner.bmp'}",
            "-bindvariable", f"WixUIDialogBmp={assets / 'dialog.bmp'}",
            "-d", f"Version={version}", "-d", f"Payload={payload}", "-d", f"BrandAssets={assets}",
            "-d", f"UpgradeCode={UPGRADE_CODE}", "-d", f"AppComponent={APP_COMPONENT}", "-o", str(output),
        ], check=True)


def build_bootstrapper(msi: Path, output: Path) -> None:
    from installer.bootstrap_backend import MAGIC, TRAILER

    with tempfile.TemporaryDirectory(prefix="uac-setup-build-") as temporary:
        work = Path(temporary)
        assets = work / "assets"
        assets.mkdir()
        _installer_art(assets)
        env = {**os.environ, "APPDATA": str(work / "qa-appdata"), "QT_QPA_PLATFORM": "offscreen"}
        subprocess.run([sys.executable, "-c", """
import sys
from pathlib import Path
from PySide6.QtWidgets import QApplication
from uac_desktop.theme import ENGINE_BRAND_PALETTES
from uac_desktop.ui import _engine_mark

app = QApplication([])
for engine, palette in ENGINE_BRAND_PALETTES.items():
    mark = _engine_mark(engine, 48, palette['accent'])
    if not mark.save(str(Path(sys.argv[1]) / f'setup-{engine}.png')):
        raise RuntimeError(f'Could not export the existing {engine} mark')
""", str(assets)], cwd=ROOT, env=env, check=True)
        data = [ROOT / "assets" / "icon.png", *assets.glob("setup-*.png")]
        fonts = [ROOT / "assets" / "fonts" / f"vazirmatn_ui_fd_{weight}.ttf"
                 for weight in ("regular", "semibold", "bold")]
        args = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--onefile", "--windowed", "--noupx",
                "--name", "UAC-Setup", "--paths", str(ROOT), "--icon", str(assets / "UacProduct.ico"),
                "--specpath", str(work), "--workpath", str(work / "work"), "--distpath", str(work / "dist")]
        for source in (*data, *fonts):
            target = "assets/fonts" if source in fonts else "assets"
            args.extend(("--add-data", f"{source};{target}"))
        args.extend(("--add-data", f"{ROOT / 'assets' / 'ui' / 'lucide-direct-check.svg'};assets/ui"))
        subprocess.run([*args, str(ROOT / "installer" / "bootstrap.py")], cwd=ROOT, check=True)
        copy_file(work / "dist" / "UAC-Setup.exe", output)
        digest = hashlib.sha256()
        with output.open("ab") as destination, msi.open("rb") as package:
            for block in iter(lambda: package.read(1024 * 1024), b""):
                destination.write(block)
                digest.update(block)
            destination.write(TRAILER.pack(MAGIC, msi.stat().st_size, digest.digest()))


def main() -> None:
    global DIST, OUT, STAGE, PORTABLE, SOURCE
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist", type=Path, default=DIST)
    parser.add_argument("--output", type=Path, default=OUT)
    parser.add_argument("--wix", default="wix")
    args = parser.parse_args()
    DIST, OUT = args.dist.resolve(), args.output.resolve()
    # Only clear the dedicated release directories, never an arbitrary supplied path.
    if (ROOT not in OUT.parents or OUT.name != "github_release"
            or OUT == DIST or OUT in DIST.parents or DIST in OUT.parents):
        raise SystemExit("Use a dedicated github_release directory outside the build payload")
    STAGE = OUT.with_name("github_release_stage").resolve()
    if ROOT not in STAGE.parents or STAGE.parent != OUT.parent:
        raise SystemExit("Release staging must stay in the workspace")
    PORTABLE, SOURCE = OUT / "portable", OUT / "source"
    require_file_paths(
        (DIST / path for path in (*PORTABLE_RUNTIME_FILES, *ASSISTANT_ASSET_FILES, UPDATER_EXE)),
        "Build is missing required files; run build.ps1 first",
    )
    if pe_architecture(DIST / APP_EXE) != "x64" or pe_architecture(DIST / UPDATER_EXE) != "x64":
        raise SystemExit("Release packaging expects a Windows x64 build")
    reset_tree(STAGE)
    stage_portable = STAGE / "portable"
    stage_source = STAGE / "source"
    copy_item(DIST, stage_portable)
    current = __version__
    (stage_portable / PORTABLE_MARKER).write_text(
        json.dumps(portable_metadata(current, "x64")) + "\n", encoding="utf-8",
    )

    for name in (
        "main.py",
        "LICENSE",
        "README.md",
        "README.en.md",
        "requirements.txt",
        "build.ps1",
        "install-engine.ps1",
        "run.ps1",
        "release.ps1",
        "UAC-Spoofer-Desktop.spec",
    ):
        copy_item(ROOT / name, stage_source / name)
    for name in ("uac_desktop", "assets", "third_party", "docs", "wizard guider", "installer"):
        copy_item(ROOT / name, stage_source / name)
    (stage_source / "tools").mkdir()
    copy_item(Path(__file__), stage_source / "tools" / Path(__file__).name)
    for path in (ROOT / "tools").glob("*.ps1"):
        copy_item(path, stage_source / "tools" / path.name)
    for name in ("update_worker.py", "pow-guard.c"):
        copy_item(ROOT / "tools" / name, stage_source / "tools" / name)
    copy_file(ROOT / "bin" / "keyfetch-net.ps1", stage_source / "bin" / "keyfetch-net.ps1")
    if (ROOT / ".git").exists():
        tracked = subprocess.check_output(["git", "ls-files", "-z", "--", "core", "pow_helper"], cwd=ROOT)
        for name in tracked.decode("utf-8").split("\0"):
            if name and (ROOT / name).is_file():
                copy_file(ROOT / name, stage_source / name)
    else:
        for name in ("core", "pow_helper"):
            copy_item(ROOT / name, stage_source / name)

    for path in stage_source.rglob("*.py"):
        if "third_party" not in path.parts:
            clean_python_comments(path)
    clean_python_comments(stage_source / "UAC-Spoofer-Desktop.spec")
    for path in stage_source.rglob("*.ps1"):
        clean_powershell_comments(path)

    copy_item(ROOT / "README.md", STAGE / "README.md")
    copy_item(ROOT / "README.en.md", STAGE / "README.en.md")
    copy_item(ROOT / "requirements.txt", STAGE / "requirements.txt")
    licenses = STAGE / "LICENSES"
    licenses.mkdir()
    copy_item(
        ROOT / "third_party" / "patterniha_sni_spoofing" / "LICENSE",
        licenses / "Patterniha-GPL-3.0.txt",
    )
    copy_item(ROOT / "bin" / "LICENSE", licenses / "Xray-LICENSE.txt")
    copy_item(
        ROOT / "bin" / "sing-box-LICENSE",
        licenses / "sing-box-LICENSE.txt",
    )

    portable_zip = STAGE / PORTABLE_ASSET
    msi = STAGE / MSI_ASSET
    setup = STAGE / SETUP_ASSET
    source_zip = STAGE / f"UAC-Spoofer-Desktop-v{current}-Source.zip"
    zip_tree(stage_portable, portable_zip)
    build_msi(DIST, msi, args.wix, current)
    build_bootstrapper(msi, setup)
    zip_tree(stage_source, source_zip)

    files = [stage_portable / APP_EXE, portable_zip, msi, setup, source_zip]
    hashes = {path.name: sha256(path) for path in files}
    (STAGE / "SHA256SUMS.txt").write_text(
        "\n".join(f"{hashes[path.name]}  {path.name}" for path in files) + "\n",
        encoding="utf-8",
    )
    manifest = {
        "version": current,
        "portable_directory": "portable",
        "portable_asset": portable_zip.name,
        "msi_asset": msi.name,
        "setup_asset": setup.name,
        "architecture": "x64",
        "packages": {kind: {"name": path.name, "size": path.stat().st_size, "sha256": hashes[path.name]}
                     for kind, path in (("portable", portable_zip), ("msi", msi))},
        "source_asset": source_zip.name,
        "update_config": "source/uac_desktop/app_config.py",
        "current_version_file": "source/uac_desktop/__init__.py",
    }
    (STAGE / "release-manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    clear_output_files()
    copy_item(stage_portable, PORTABLE)
    for path in STAGE.iterdir():
        if path.name != "portable":
            copy_item(path, OUT / path.name)

    required = [
        *(PORTABLE / path for path in (*PORTABLE_RUNTIME_FILES, *ASSISTANT_ASSET_FILES)),
        SOURCE / "main.py",
        SOURCE / "uac_desktop" / "app_config.py",
        *(SOURCE / "wizard guider" / f"wizard_{index:02d}_{state}.png" for index, state in enumerate((
            "normal", "thinking", "waiting", "happy", "sad", "guiding_right", "confused", "surprised"
        ), start=1)),
        OUT / "README.md",
        OUT / "LICENSES" / "sing-box-LICENSE.txt",
        OUT / portable_zip.name,
        OUT / msi.name,
        OUT / setup.name,
        OUT / source_zip.name,
    ]
    require_file_paths(required, "Missing release files")
    print(OUT)


if __name__ == "__main__":
    main()
