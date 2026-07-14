from __future__ import annotations

import hashlib
import io
import json
import shutil
import tokenize
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "github_release"
DIST = ROOT / "dist" / "UAC-Spoofer-Desktop"
PORTABLE = OUT / "portable"
SOURCE = OUT / "source"


def copy_item(source: Path, destination: Path) -> None:
    if source.is_dir():
        shutil.copytree(
            source,
            destination,
            ignore=shutil.ignore_patterns(
                "__pycache__", "*.pyc", "*.pyo", "*.bak", ".pytest_cache", ".ruff_cache"
            ),
        )
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


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


def main() -> None:
    if not (DIST / "UAC-Spoofer-Desktop.exe").is_file():
        raise SystemExit("Portable build is missing; run PyInstaller first.")
    if OUT.exists():
        try:
            shutil.rmtree(OUT)
        except PermissionError:
            if any(OUT.iterdir()):
                raise
    OUT.mkdir(exist_ok=True)
    copy_item(DIST, PORTABLE)

    for name in (
        "main.py",
        "README.md",
        "requirements.txt",
        "build.ps1",
        "install-engine.ps1",
        "run.ps1",
        "release.ps1",
        "UAC-Spoofer-Desktop.spec",
    ):
        copy_item(ROOT / name, SOURCE / name)
    for name in ("uac_desktop", "assets", "third_party"):
        copy_item(ROOT / name, SOURCE / name)
    (SOURCE / "tools").mkdir()
    copy_item(Path(__file__), SOURCE / "tools" / Path(__file__).name)

    for path in SOURCE.rglob("*.py"):
        if "third_party" not in path.parts:
            clean_python_comments(path)
    clean_python_comments(SOURCE / "UAC-Spoofer-Desktop.spec")
    for path in SOURCE.rglob("*.ps1"):
        clean_powershell_comments(path)

    copy_item(ROOT / "README.md", OUT / "README.md")
    copy_item(ROOT / "requirements.txt", OUT / "requirements.txt")
    licenses = OUT / "LICENSES"
    licenses.mkdir()
    copy_item(
        ROOT / "third_party" / "patterniha_sni_spoofing" / "LICENSE",
        licenses / "Patterniha-GPL-3.0.txt",
    )
    copy_item(ROOT / "bin" / "LICENSE", licenses / "Xray-LICENSE.txt")

    version = {}
    exec((SOURCE / "uac_desktop" / "__init__.py").read_text(encoding="utf-8"), version)
    current = version["__version__"]
    portable_zip = OUT / f"UAC-Spoofer-Desktop-v{current}-Windows-x64.zip"
    source_zip = OUT / f"UAC-Spoofer-Desktop-v{current}-Source.zip"
    zip_tree(PORTABLE, portable_zip)
    zip_tree(SOURCE, source_zip)

    files = [PORTABLE / "UAC-Spoofer-Desktop.exe", portable_zip, source_zip]
    (OUT / "SHA256SUMS.txt").write_text(
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
    (OUT / "release-manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    required = [
        PORTABLE / "UAC-Spoofer-Desktop.exe",
        PORTABLE / "_internal" / "bin" / "xray.exe",
        SOURCE / "main.py",
        SOURCE / "uac_desktop" / "app_config.py",
        OUT / "README.md",
        portable_zip,
        source_zip,
    ]
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        raise SystemExit("Missing release files: " + ", ".join(missing))
    print(OUT)


if __name__ == "__main__":
    main()
