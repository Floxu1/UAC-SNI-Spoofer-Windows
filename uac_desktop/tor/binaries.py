"""Tor Expert Bundle discovery & automatic downloader for Development, Portable, and MSI installs."""
from __future__ import annotations

import argparse
import io
import json
import os
import re
import tarfile
import tempfile
import threading
from pathlib import Path
from typing import Callable
from urllib.parse import urljoin

import requests

from ..install_type import InstallType, current_installation
from ..paths import BIN, DATA_DIR

LogFn = Callable[[str], None]

_RELEASES_JSON = "https://aus1.torproject.org/torbrowser/update_3/release/downloads.json"
_DIST_INDEX = "https://dist.torproject.org/torbrowser/"
_WANTED_FILES = {
    "tor/tor.exe": "tor.exe",
    "tor/pluggable_transports/lyrebird.exe": "lyrebird.exe",
    "tor/pluggable_transports/obfs4proxy.exe": "obfs4proxy.exe",
    "tor/pluggable_transports/snowflake-client.exe": "snowflake-client.exe",
    "tor/pluggable_transports/conjure-client.exe": "conjure-client.exe",
    "tor/pluggable_transports/pt_config.json": "pt_config.json",
    "data/geoip": "geoip",
    "data/geoip6": "geoip6",
}


def runtime_tor_bin_dir() -> Path:
    return Path(DATA_DIR) / "tor" / "bin"


def tor_binary_dirs() -> tuple[Path, ...]:
    """Search bundled directory (_internal/bin/tor or bin/tor) first, then writable APPDATA/tor/bin."""
    dirs = [BIN / "tor", runtime_tor_bin_dir(), BIN]
    unique: list[Path] = []
    for d in dirs:
        if d not in unique:
            unique.append(d)
    return tuple(unique)


def _dir_writable(path: Path) -> bool:
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".uac_write_test"
        probe.write_bytes(b"ok")
        probe.unlink(missing_ok=True)
        return True
    except OSError:
        return False


def writable_tor_bin_dir() -> Path:
    """Use bin/tor for Development & writable Portable installs; use APPDATA/tor/bin for MSI."""
    install = current_installation()
    if install.kind != InstallType.MSI:
        bundled = BIN / "tor"
        if _dir_writable(bundled):
            return bundled
    target = runtime_tor_bin_dir()
    target.mkdir(parents=True, exist_ok=True)
    return target


def find_tor_asset(name: str) -> Path | None:
    for directory in tor_binary_dirs():
        candidate = directory / name
        if candidate.is_file():
            return candidate
    return None


def tor_binaries_ready() -> bool:
    return (
        find_tor_asset("tor.exe") is not None
        and (find_tor_asset("lyrebird.exe") is not None or find_tor_asset("obfs4proxy.exe") is not None)
    )


def _download_bytes(
    url: str,
    *,
    proxy: str = "",
    timeout: float = 45.0,
    cancel: threading.Event | None = None,
    log: LogFn | None = None,
) -> bytes:
    log = log or (lambda _m: None)
    proxies = {"http": proxy, "https": proxy} if proxy else None
    sess = requests.Session()
    sess.trust_env = False
    try:
        resp = sess.get(
            url,
            proxies=proxies,
            timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0 UAC-Tor/1.0"},
            allow_redirects=True,
        )
        resp.raise_for_status()
        return resp.content
    except Exception as exc:
        if proxy or (cancel is not None and cancel.is_set()):
            raise
        log(f"Tor core direct download failed ({type(exc).__name__}); retrying with DPI bypass")
    finally:
        sess.close()

    from .bridges import custom_https_request

    current = url
    for _ in range(5):
        if cancel is not None and cancel.is_set():
            raise RuntimeError("Tor binary download cancelled")
        for method in ("mutator_vec26_fastpath_oob", "mutator_vec24_rfc_4rec", "uac_disoob_byte0_ttl1", "mutator_vec01_oob_400"):
            if cancel is not None and cancel.is_set():
                raise RuntimeError("Tor binary download cancelled")
            try:
                code, hdrs, body = custom_https_request(
                    current,
                    method=method,
                    timeout=max(timeout, 60.0),
                    max_bytes=80 * 1024 * 1024,
                )
                if code in (301, 302, 303, 307, 308) and hdrs.get("location"):
                    current = urljoin(current, hdrs["location"])
                    break
                if 200 <= code < 300 and body:
                    return body
            except Exception:
                continue
        else:
            raise RuntimeError(f"Could not download {current}")
    raise RuntimeError("Too many redirects while downloading Tor Expert Bundle")


def discover_expert_bundle_url(
    *,
    proxy: str = "",
    cancel: threading.Event | None = None,
    log: LogFn | None = None,
) -> tuple[str, str]:
    try:
        raw = _download_bytes(_RELEASES_JSON, proxy=proxy, timeout=20.0, cancel=cancel, log=log)
        version = str(json.loads(raw.decode("utf-8", errors="replace")).get("version") or "").strip()
        if version:
            return version, f"{_DIST_INDEX}{version}/tor-expert-bundle-windows-x86_64-{version}.tar.gz"
    except Exception:
        pass
    html = _download_bytes(_DIST_INDEX, proxy=proxy, timeout=20.0, cancel=cancel, log=log).decode("utf-8", errors="replace")
    versions = re.findall(r'href="(\d+\.\d+(?:\.\d+)?)/"', html)
    if not versions:
        raise RuntimeError("Could not discover latest Tor Expert Bundle version")
    versions.sort(key=lambda v: tuple(int(p) for p in v.split(".")), reverse=True)
    ver = versions[0]
    return ver, f"{_DIST_INDEX}{ver}/tor-expert-bundle-windows-x86_64-{ver}.tar.gz"


def install_tor_bundle(
    destination: Path | None = None,
    *,
    proxy: str = "",
    cancel: threading.Event | None = None,
    log: LogFn | None = None,
) -> Path:
    """Download and atomically extract Tor Expert Bundle (tor.exe, lyrebird.exe, geoip, pt_config.json)."""
    log = log or (lambda _m: None)
    dest = Path(destination) if destination is not None else writable_tor_bin_dir()
    dest.mkdir(parents=True, exist_ok=True)

    version, url = discover_expert_bundle_url(proxy=proxy, cancel=cancel, log=log)
    log(f"Tor core: downloading Tor Expert Bundle {version}")
    raw = _download_bytes(url, proxy=proxy, timeout=90.0, cancel=cancel, log=log)

    extracted: list[str] = []
    with tempfile.TemporaryDirectory(prefix="tor-dl-", dir=dest) as stage_str:
        stage = Path(stage_str)
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
            for member in archive.getmembers():
                if not member.isfile():
                    continue
                norm = member.name.replace("\\", "/").lstrip("./")
                out_name = next(
                    (target for suffix, target in _WANTED_FILES.items() if norm == suffix or norm.endswith("/" + suffix)),
                    None,
                )
                if out_name is None and norm.endswith(".dll") and "/tor/" in ("/" + norm):
                    out_name = Path(norm).name
                if out_name:
                    stream = archive.extractfile(member)
                    if stream is not None:
                        (stage / out_name).write_bytes(stream.read())
                        extracted.append(out_name)

        tor_stage = stage / "tor.exe"
        if not tor_stage.is_file() or tor_stage.read_bytes()[:2] != b"MZ":
            raise RuntimeError("Downloaded archive does not contain a valid Windows tor.exe")

        for fname in extracted:
            (stage / fname).replace(dest / fname)

    log(f"Tor core: installed {version} into {dest} ({', '.join(sorted(extracted))})")
    return dest


def ensure_tor_binaries(
    *,
    proxy: str = "",
    cancel: threading.Event | None = None,
    log: LogFn | None = None,
) -> Path:
    existing = find_tor_asset("tor.exe")
    if existing is not None and (find_tor_asset("lyrebird.exe") is not None or find_tor_asset("obfs4proxy.exe") is not None):
        return existing
    dest = install_tor_bundle(proxy=proxy, cancel=cancel, log=log)
    return dest / "tor.exe"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Download Tor Expert Bundle (Windows x64) for UAC Spoofer")
    parser.add_argument("--target", default="bin/tor", help="Destination folder (default: bin/tor)")
    parser.add_argument("--proxy", default="", help="Optional HTTP/SOCKS proxy URL")
    parser.add_argument("--force", action="store_true", help="Re-download even if tor.exe already exists")
    args = parser.parse_args(argv)
    target = Path(args.target)
    if not args.force and (target / "tor.exe").is_file() and (target / "lyrebird.exe").is_file():
        print(f"[TOR] Using existing binaries in {target}")
        return 0
    install_tor_bundle(target, proxy=args.proxy, log=print)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
