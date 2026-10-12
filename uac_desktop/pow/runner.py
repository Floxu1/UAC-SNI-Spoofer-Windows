"""Subprocess runner for the aether outer leg (Windows port of AetherNative).

The same Rust core as Android, driven through its CLI instead of JNI:

- ``prepare_identity`` / ``renew_certificate`` run ``aether --prepare-only``
  (provision key/cert, print JSON, exit) — mirrors ``AetherNative.prepare``.
- ``AetherProcess`` runs ``aether`` with env vars mapped from the mobile
  ``chainOuterJson`` payload and watches TCP readiness of the chain SOCKS
  port — mirrors ``AetherNative.startProxy`` + ``awaitOuterProxy``.
- stderr (env_logger) is streamed line-by-line to the coordinator so the
  connect-steps card sees the same ``Key:`` / ``Cert:`` / ``Scanning`` /
  ``Rejected`` / ``Accepted`` lines as mobile ``lastLog()``.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable

from .config import (
    CHAIN_SOCKS_PORT,
    KEY_FETCHES,
    KEY_FETCH_TIMEOUT_S,
    chain_outer_json,
    uses_mci_firewall,
)

LogCallback = Callable[[str], None]


def find_aether_binary() -> Path | None:
    from ..paths import BIN

    candidates = [
        BIN / "aether.exe",
        Path(__file__).resolve().parent.parent.parent / "bin" / "aether.exe",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def json_to_env(payload: dict) -> dict[str, str]:
    """Map a mobile chainOuterJson payload onto aether CLI env vars."""
    env: dict[str, str] = {}
    if payload.get("config_path"):
        env["AETHER_CONFIG"] = str(payload["config_path"])
    protocol = str(payload.get("protocol", "masque")).lower()
    env["AETHER_PROTOCOL"] = {
        "wireguard": "wg",
        "gool": "gool",
    }.get(protocol, "masque")
    if payload.get("listen"):
        env["AETHER_SOCKS"] = str(payload["listen"])
    if payload.get("scan_mode"):
        env["AETHER_SCAN"] = str(payload["scan_mode"])
    ip_scan = str(payload.get("ip_scan", "")).lower()
    if ip_scan in ("v4", "v6", "both"):
        env["AETHER_IP"] = ip_scan
    if payload.get("obfuscation_profile"):
        env["AETHER_NOIZE"] = str(payload["obfuscation_profile"])
    if str(payload.get("masque_transport", "")).lower() == "h2":
        env["AETHER_MASQUE_HTTP2"] = "1"
    if payload.get("h2_fragmentation"):
        env["AETHER_MASQUE_H2_FRAGMENT"] = "1"
    api_camo = str(payload.get("api_camo", "") or "").strip().lower()
    if api_camo in KEY_FETCHES:
        env["AETHER_API_CAMO"] = api_camo
    discovery = str(payload.get("endpoint_discovery", "") or "").strip().lower()
    if discovery in ("cache", "fresh", "clean", "saved"):
        env["AETHER_DISCOVERY"] = discovery
    if payload.get("endpoint_cache_path"):
        env["AETHER_MASQUE_CACHE"] = str(payload["endpoint_cache_path"])
    for key in (
        "log_level", "perf_profile", "tls_curve_preset", "dns_servers",
        "route_block", "route_direct", "routes_file", "team",
        "access_client_id", "access_client_secret", "access_token", "access_email",
    ):
        value = payload.get(key)
        if value not in (None, ""):
            env["AETHER_" + key.upper()] = str(value)
    if payload.get("gateway"):
        env["AETHER_GATEWAY"] = "1"
    if payload.get("renew_masque"):
        env["AETHER_RENEW_CERT"] = "1"
    return env


def _prepare_args(binary: Path, payload: dict, renew: bool) -> list[str]:
    args = [str(binary), "--prepare-only"]
    if renew:
        args.append("--renew-cert")
    if payload.get("api_camo"):
        args += ["--api-camo", str(payload["api_camo"])]
    return args


def _drain_pipe(stream, sink: list[str], on_line: LogCallback | None = None) -> None:
    """Read a child pipe to EOF so the child can never block on a full pipe."""
    try:
        for line in stream:
            sink.append(line)
            if on_line is not None:
                text = line.strip()
                if text:
                    try:
                        on_line(text)
                    except Exception:
                        pass
    except Exception:
        pass


def prepare_identity(
    data_dir: Path,
    settings,
    protocol: str = "masque",
    renew: bool = False,
    timeout: float = KEY_FETCH_TIMEOUT_S,
    on_log: LogCallback | None = None,
    stop: threading.Event | None = None,
    api_camo: str | None = None,
) -> dict:
    """Provision key/cert via ``aether --prepare-only``. Returns addresses JSON.

    Both child pipes are drained on background threads while the child runs.
    (The old loop only polled and read the pipes after exit; aether's
    env_logger fills the ~4 KB Windows pipe during the key race, then blocks
    on its next write and the request hung until the timeout with no log.)
    The core's ``Key:`` / ``Cert:`` progress lines are written to
    ``aether-core.log``, not stderr, on Windows: that file is tailed live and
    forwarded to ``on_log`` the same way the outer leg does.
    """
    from .config import cert_renew_json, key_request_json

    binary = find_aether_binary()
    if binary is None:
        raise RuntimeError("aether.exe is missing from the app bin folder")
    raw = cert_renew_json(data_dir, settings) if renew else key_request_json(
        data_dir, settings, protocol
    )
    payload = json.loads(raw)
    if api_camo:
        payload["api_camo"] = api_camo
    env = dict(os.environ)
    env.update(json_to_env(payload))
    env["AETHER_PREPARE_ONLY"] = "1"
    if renew:
        env["AETHER_RENEW_CERT"] = "1"
    args = _prepare_args(binary, payload, renew)

    tail_stop = threading.Event()
    tail_thread: threading.Thread | None = None
    config_path = str(payload.get("config_path") or "")
    if on_log is not None and config_path:
        core_log = Path(config_path).parent / "aether-core.log"
        start_offset = core_log.stat().st_size if core_log.exists() else 0
        tail_thread = threading.Thread(
            target=follow_core_log,
            args=(core_log, tail_stop, on_log, start_offset),
            name="pow-prepare-core-log",
            daemon=True,
        )
        tail_thread.start()

    process = subprocess.Popen(
        args,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    out_lines: list[str] = []
    err_lines: list[str] = []
    readers = [
        threading.Thread(target=_drain_pipe, args=(process.stdout, out_lines), daemon=True,
                         name="pow-prepare-stdout"),
        threading.Thread(target=_drain_pipe, args=(process.stderr, err_lines, on_log), daemon=True,
                         name="pow-prepare-stderr"),
    ]
    for reader in readers:
        reader.start()

    def _finish(kill: bool) -> None:
        if kill and process.poll() is None:
            try:
                process.kill()
            except Exception:
                pass
        try:
            process.wait(timeout=5)
        except Exception:
            pass
        for reader in readers:
            reader.join(timeout=2)
        # Let the tail pick up the last lines the core flushed before exit.
        if tail_thread is not None:
            time.sleep(0.3)
            tail_stop.set()
            tail_thread.join(timeout=2)

    deadline = time.monotonic() + timeout
    while process.poll() is None:
        if stop is not None and stop.is_set():
            _finish(kill=True)
            raise RuntimeError("stopped")
        if time.monotonic() >= deadline:
            _finish(kill=True)
            raise RuntimeError(f"key request timed out after {int(timeout)}s")
        time.sleep(0.1)
    _finish(kill=False)
    stdout = "".join(out_lines)
    stderr = "".join(err_lines)
    if process.returncode != 0:
        tail = [line for line in stderr.strip().splitlines() if line.strip()]
        detail = tail[-1][:300] if tail else f"exit {process.returncode}"
        raise RuntimeError(f"key request failed: {detail}")
    for line in stdout.splitlines()[::-1]:
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                result = json.loads(line)
                if "ipv4" in result:
                    return result
            except ValueError:
                continue
    raise RuntimeError("key request produced no addresses")


def core_message(line: str) -> str:
    """Drop the ``HH:MM:SS  `` prefix aether writes in ``aether-core.log``."""
    text = (line or "").strip()
    if len(text) >= 10 and text[2] == ":" and text[5] == ":" and text[8:10] == "  ":
        return text[10:].strip()
    return text


def follow_core_log(
    path: Path, stop: threading.Event, callback: LogCallback, start_offset: int | None = None
) -> None:
    """Stream new ``record_log`` lines. Those never reach stderr on Windows."""
    if start_offset is not None:
        offset = start_offset
    else:
        offset = path.stat().st_size if path.exists() else 0
    pending = ""
    while not stop.is_set():
        if not path.exists():
            stop.wait(0.2)
            continue
        try:
            size = path.stat().st_size
        except OSError:
            stop.wait(0.2)
            continue
        if size < offset:
            offset = 0
        if size == offset:
            stop.wait(0.2)
            continue
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                handle.seek(offset)
                chunk = handle.read()
                offset = handle.tell()
        except OSError:
            stop.wait(0.2)
            continue
        pending += chunk
        while "\n" in pending:
            line, pending = pending.split("\n", 1)
            message = core_message(line)
            if not message:
                continue
            try:
                callback(message)
            except Exception:
                pass
    if pending.strip():
        message = core_message(pending)
        if message:
            try:
                callback(message)
            except Exception:
                pass


def tcp_accepts(port: int, host: str = "127.0.0.1", timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


class AetherProcess:
    """Owns one aether outer-leg subprocess."""

    def __init__(self, on_log: LogCallback | None = None) -> None:
        self._on_log = on_log
        self._process: subprocess.Popen | None = None
        self._reader: threading.Thread | None = None
        self._tail: threading.Thread | None = None
        self._tail_stop = threading.Event()
        self._lock = threading.Lock()

    @property
    def running(self) -> bool:
        with self._lock:
            process = self._process
        return process is not None and process.poll() is None

    def start(
        self, outer_json: str, extra_env: dict | None = None, tail_core_log: bool = True
    ) -> None:
        binary = find_aether_binary()
        if binary is None:
            raise RuntimeError("aether.exe is missing from the app bin folder")
        self.stop()
        payload = json.loads(outer_json)
        env = dict(os.environ)
        env.update(json_to_env(payload))
        env["AETHER_SCAN_ONCE"] = "1"
        if extra_env:
            env.update({str(k): str(v) for k, v in extra_env.items()})
        if env.get("AETHER_PROTOCOL") == "masque" and env.get("AETHER_MASQUE_HTTP2") != "1":
            # Mobile parity: the H3 path is QUIC; nothing extra to pass.
            pass
        args = [str(binary)]
        process = subprocess.Popen(
            args,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        try:
            from ..process_win import attach_kill_on_close_job, register_helper_pid
            register_helper_pid(process.pid)
            attach_kill_on_close_job(process)
        except Exception:
            pass
        with self._lock:
            self._process = process
        self._reader = threading.Thread(
            target=self._drain, args=(process,), name="pow-aether-log", daemon=True
        )
        self._reader.start()
        config_path = str(payload.get("config_path") or "")
        if config_path and tail_core_log:
            core_log = Path(config_path).parent / "aether-core.log"
            self._tail_stop.clear()
            self._tail = threading.Thread(
                target=follow_core_log,
                args=(core_log, self._tail_stop, self._deliver),
                name="pow-aether-core-log",
                daemon=True,
            )
            self._tail.start()

    def _deliver(self, line: str) -> None:
        callback = self._on_log
        if callback is None:
            return
        try:
            callback(line)
        except Exception:
            pass

    def _drain(self, process: subprocess.Popen) -> None:
        try:
            assert process.stderr is not None
            for line in process.stderr:
                line = line.strip()
                if not line:
                    continue
                callback = self._on_log
                if callback is not None:
                    self._deliver(line)
        except Exception:
            pass

    def wait_ready(self, port: int, budget_ms: int, stop: threading.Event) -> bool:
        deadline = time.monotonic() + budget_ms / 1000.0
        while time.monotonic() < deadline:
            if stop.is_set():
                return False
            if not self.running:
                return False
            if tcp_accepts(port):
                # Mobile grace: one accepted probe is not a ready tunnel;
                # require it twice in a row before committing.
                time.sleep(0.3)
                if self.running and tcp_accepts(port):
                    return True
            time.sleep(0.3)
        return False

    def stop(self) -> None:
        self._tail_stop.set()
        with self._lock:
            process = self._process
            self._process = None
        if process is None:
            return
        pid = getattr(process, "pid", None)
        try:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        pass
        except Exception:
            pass
        if pid:
            try:
                from ..process_win import kill_process_tree, unregister_helper_pid
                kill_process_tree(pid)
                unregister_helper_pid(pid)
            except Exception:
                pass
        reader = self._reader
        self._reader = None
        if reader is not None and reader.is_alive():
            reader.join(timeout=2)
        tail = self._tail
        self._tail = None
        if tail is not None and tail.is_alive():
            tail.join(timeout=1)
