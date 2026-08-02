from __future__ import annotations

import hashlib
import io
import json
import shutil
import time
import tokenize
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
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
)
ASSISTANT_ASSET_FILES = tuple(
    Path("_internal/wizard guider") / f"wizard_{index:02d}_{state}.png" for index, state in enumerate((
        "normal", "thinking", "waiting", "happy", "sad", "guiding_right", "confused", "surprised"
    ), start=1)
)


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
                "__pycache__", "*.pyc", "*.pyo", "*.bak", ".pytest_cache", ".ruff_cache"
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


def main() -> None:
    require_file_paths(
        (DIST / path for path in (*PORTABLE_RUNTIME_FILES, *ASSISTANT_ASSET_FILES)),
        "Portable build is missing required files; run PyInstaller first",
    )
    reset_tree(STAGE)
    stage_portable = STAGE / "portable"
    stage_source = STAGE / "source"
    copy_item(DIST, stage_portable)

    for name in (
        "main.py",
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
    for name in ("uac_desktop", "assets", "third_party", "docs", "wizard guider"):
        copy_item(ROOT / name, stage_source / name)
    (stage_source / "tools").mkdir()
    copy_item(Path(__file__), stage_source / "tools" / Path(__file__).name)

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

    version = {}
    exec((stage_source / "uac_desktop" / "__init__.py").read_text(encoding="utf-8"), version)
    current = version["__version__"]
    portable_zip = STAGE / f"UAC-Spoofer-Desktop-v{current}-Windows-x64-portable.zip"
    source_zip = STAGE / f"UAC-Spoofer-Desktop-v{current}-Source.zip"
    zip_tree(stage_portable, portable_zip)
    zip_tree(stage_source, source_zip)

    files = [stage_portable / "UAC-Spoofer-Desktop.exe", portable_zip, source_zip]
    (STAGE / "SHA256SUMS.txt").write_text(
        "\n".join(f"{sha256(path)}  {path.name}" for path in files) + "\n",
        encoding="utf-8",
    )
    manifest = {
        "version": current,
        "portable_directory": "portable",
        "portable_asset": portable_zip.name,
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
        portable_zip,
        source_zip,
    ]
    require_file_paths(required, "Missing release files")
    print(OUT)


if __name__ == "__main__":
    main()
