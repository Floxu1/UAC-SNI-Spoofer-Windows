from __future__ import annotations

import json
import re
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Callable

from ..paths import BIN
from ..pow.tun_guard import KillOnCloseJob
from ..proxy_ports import listener_pid
from .store import DirectSettings, DirectStore, STARTUP_BUDGET, VerifiedProfile, write_json

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
_BUDGET_EXPIRED = "Direct carrier startup budget expired"
_SELECTED = re.compile(r"Direct IP (\S+) (?:known|range) selected(?: \d+)?$")


class CarrierError(RuntimeError):
    pass


class DirectCancelled(RuntimeError):
    pass


def ensure_active(cancel: threading.Event) -> None:
    if cancel.is_set():
        raise DirectCancelled("Direct connection cancelled")


def permits_retry(reason: str) -> bool:
    return (
        reason.startswith(("masque:", "tls:"))
        or reason in (_BUDGET_EXPIRED, "other: No usable Direct WireGuard path")
        or reason.lower().startswith("other: wireguard dataplane verify timed out")
    )


def loopback_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def check_binary(binary: Path) -> str:
    try:
        result = subprocess.run([str(binary), "--direct-contract"], capture_output=True,
                                text=True, timeout=4, creationflags=_NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CarrierError(f"Could not launch the Direct native helper: {error}") from error
    contract = result.stdout.strip()
    if result.returncode or not re.fullmatch(r"direct-config/1 [0-9a-f]{64}", contract):
        raise CarrierError("The Direct native helper has an incompatible configuration contract")
    return contract.split()[1]


def _socks_ready(port: int, pid: int) -> bool:
    if listener_pid(port) != pid:
        return False
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.25) as sock:
            sock.sendall(b"\x05\x01\x00")
            reply = sock.recv(1) + sock.recv(1)
            return reply == b"\x05\x00"
    except OSError:
        return False


class NativeAttempt:
    def __init__(self, binary: Path, directory: Path, port: int, config: dict, profile: str,
                 network: str, log: Callable[[str], None]) -> None:
        self.port = port
        self.config = config
        self.profile = profile
        self.network = network
        self.selected_peer: str | None = None
        self._log = log
        self._connected = threading.Event()
        self._failure = ""
        self._job = KillOnCloseJob()
        self._runtime = tempfile.TemporaryDirectory(prefix="carrier-", dir=directory)
        config_path = Path(self._runtime.name) / "config.json"
        try:
            write_json(config_path, config)
            self._process = subprocess.Popen(
                [str(binary), "--config", str(config_path), "--control-stdin"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace", creationflags=_NO_WINDOW,
            )
        except BaseException:
            self._job.close()
            self._runtime.cleanup()
            raise
        self._job.assign(self._process)
        self._reader = threading.Thread(target=self._read_events, name="direct-carrier-events", daemon=True)
        self._reader.start()

    def _read_events(self) -> None:
        with self._process.stdout as stream:
            for line in stream:
                line = line.strip()
                try:
                    event = json.loads(line)
                except ValueError:
                    if line:
                        self._failure = line
                        self._log(line)
                    continue
                if not isinstance(event, dict):
                    continue
                if event.get("type") == "log":
                    message = event.get("message")
                    if isinstance(message, str):
                        selected = _SELECTED.fullmatch(message)
                        if selected:
                            self.selected_peer = selected[1]
                        self._log(message)
                elif event.get("type") == "status" and event.get("status") == "connected":
                    self._connected.set()

    def running(self) -> bool:
        return self._process.poll() is None

    def wait_ready(self, cancel: threading.Event, budget: float) -> None:
        deadline = time.monotonic() + budget
        while True:
            ensure_active(cancel)
            if not self.running():
                self._reader.join(timeout=1)
                raise CarrierError(self._failure or "WireGuard over Direct did not become ready")
            if self._connected.is_set() and _socks_ready(self.port, self._process.pid) and self.running():
                ensure_active(cancel)
                return
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CarrierError(_BUDGET_EXPIRED)
            cancel.wait(min(0.2, remaining))

    def close(self) -> None:
        try:
            self._process.stdin.close()
            try:
                self._process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait(timeout=2)
        finally:
            self._job.close()
            self._reader.join(timeout=2)
            self._runtime.cleanup()


class DirectCarrier:
    def __init__(self, store: DirectStore, pow_identity: Path, network: Callable[[], str],
                 log: Callable[[str], None], binary: Path = BIN / "uac-direct.exe") -> None:
        self._store = store
        self._directory = store.directory / "wireguard"
        self._pow_identity = pow_identity
        self._network = network
        self._log = log
        self._binary = binary

    def start(self, settings: DirectSettings, cancel: threading.Event,
              excluded_ip: str | None = None) -> NativeAttempt:
        ensure_active(cancel)
        source_id = check_binary(self._binary)
        self._log(f"Direct native source {source_id}")
        if excluded_ip is not None:
            remembered = self._remembered(settings, cancel, excluded_ip)
            return remembered or self._attempt(settings, cancel, excluded_ip=excluded_ip)
        try:
            return self._attempt(settings, cancel)
        except CarrierError as error:
            ensure_active(cancel)
            if not permits_retry(str(error)):
                raise
            remembered = self._remembered(settings, cancel, None)
            if remembered:
                return remembered
            if settings.adaptive_client_hello or settings.fragment_enabled:
                return self._attempt(settings, cancel, compatibility=True)
            raise

    def _remembered(self, settings: DirectSettings, cancel: threading.Event,
                    excluded_ip: str | None) -> NativeAttempt | None:
        ensure_active(cancel)
        profile = self._store.find_profile(self._network(), excluded_ip)
        if not profile:
            self._log("Direct fallback: no verified H2 profile for this network")
            return None
        try:
            return self._attempt(settings, cancel, remembered=profile, excluded_ip=excluded_ip)
        except CarrierError as error:
            self._log(f"Direct fallback: verified {profile.source} H2 route failed: {error}")
            return None

    def _attempt(self, settings: DirectSettings, cancel: threading.Event, *,
                 excluded_ip: str | None = None, compatibility: bool = False,
                 remembered: VerifiedProfile | None = None) -> NativeAttempt:
        ensure_active(cancel)
        network = self._network()
        self._directory.mkdir(parents=True, exist_ok=True)
        carrier = self._directory / "carrier.toml"
        profile = "alternate_carrier" if excluded_ip else "primary"
        config_path = carrier
        config: dict = {}
        budget = STARTUP_BUDGET[settings.scan_mode]
        fragmentation = settings.adaptive_client_hello or settings.fragment_enabled
        if remembered:
            profile = f"verified_{remembered.source}_h2"
            budget = 25
            if network != remembered.network:
                raise CarrierError("Network changed before trying verified H2 route")
            if remembered.source == "pow":
                try:
                    changed = self._pow_identity.stat().st_mtime
                    if not self._pow_identity.is_file() or not 0 < changed <= remembered.verified_at:
                        raise ValueError
                except (OSError, ValueError) as error:
                    raise CarrierError("Verified H2 identity is missing or was changed since the last successful connection") from error
                config["masque_config_path"] = str(self._pow_identity)
            config.update(remembered.options)
            config["forced_peer"] = remembered.peer
            fragmentation = remembered.options.get("h2_fragmentation") is True
        elif compatibility:
            profile = "compatibility"
            budget = 25
            fragmentation = False
            config_path = self._directory / "h2-startup-fallback" / "carrier.toml"
            config["masque_config_path"] = str(carrier)
            hint = self._store.compatibility_hint(network)
            write_json(config_path.with_name("uac-pow-clean-h2.json"), {"peers": [hint] if hint else []})
        port = loopback_port()
        config.update({
            "config_path": str(config_path), "wireguard_config_path": str(self._directory / "wireguard.toml"),
            "protocol": "masque", "masque_transport": "h2", "scan_mode": settings.scan_mode,
            "listen": f"127.0.0.1:{port}", "endpoint_cache_path": str(self._pow_identity),
            "h2_fragmentation": fragmentation, "api_camo": "auto", "log_level": "info",
        })
        if excluded_ip:
            config["direct_retry_skip_ip"] = excluded_ip
        self._log(f"Direct native startup: profile={profile} scan={settings.scan_mode} "
                  f"h2_fragmentation={fragmentation} budget_ms={budget * 1000}")
        started_at = time.monotonic()
        try:
            attempt = NativeAttempt(self._binary, self._directory, port, config, profile, network, self._log)
        except OSError as error:
            raise CarrierError(f"Could not start Direct native helper: {error}") from error
        try:
            attempt.wait_ready(cancel, max(0, budget - (time.monotonic() - started_at)))
        except BaseException:
            attempt.close()
            raise
        self._log(f"Direct native ready: profile={profile} peer={attempt.selected_peer or 'unknown'}")
        return attempt

    def remember_verified(self, attempt: NativeAttempt) -> None:
        if not attempt.selected_peer or not attempt.network or self._network() != attempt.network:
            return
        if attempt.profile != "verified_pow_h2":
            self._store.save_verified("direct", attempt.network, attempt.selected_peer, attempt.config)
        if attempt.profile == "compatibility":
            self._store.save_compatibility_hint(attempt.network, attempt.selected_peer)
