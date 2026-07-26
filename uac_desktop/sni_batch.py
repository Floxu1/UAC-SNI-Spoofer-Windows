from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import os
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import requests

from .engine import Engine, build_xray_config
from .models import ProxyProfile, Tuning, parse_outbound
from .paths import BIN, DATA_DIR
from .pattern_core.core import PatternSniCore
from .sni_maker import ISO2_CODES
from .verified_configs import COUNTRIES, VERIFIED_SPOOF_EDGE


@dataclass(slots=True)
class LiveConfigResult:
    profile: ProxyProfile
    ok: bool = False
    ping_ms: float = 0.0
    country_code: str = ""
    country: str = ""
    exit_ip: str = ""
    source: str = ""
    error: str = ""


class _CancelSignal:
    def __init__(self, *events):
        self._events = events

    def is_set(self) -> bool:
        return any(event.is_set() for event in self._events)


def _reserve_local_ports(count: int) -> list[tuple[int, socket.socket]]:
    reservations = []
    try:
        for _index in range(max(1, int(count))):
            holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            holder.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            holder.bind(("127.0.0.1", 0))
            reservations.append((int(holder.getsockname()[1]), holder))
        return reservations
    except Exception:
        for _port, holder in reservations:
            holder.close()
        raise


def build_batch_xray_config(
        profiles: list[ProxyProfile], proxy_ports: list[int],
        relay_port: int | None | list[int | None], tuning: Tuning) -> dict:
    relay_ports = (
        [None if value is None else int(value) for value in relay_port]
        if isinstance(relay_port, (list, tuple))
        else [
            None if relay_port is None else int(relay_port)
        ] * len(profiles)
    )
    if len(relay_ports) != len(profiles):
        raise ValueError("Relay port count does not match profile count")
    inbounds = []
    outbounds = []
    rules = []
    for index, (profile, proxy_port, target_relay) in enumerate(
            zip(profiles, proxy_ports, relay_ports)):
        inbound_tag = f"maker-in-{index}"
        outbound_tag = f"maker-out-{index}"
        inbounds.append({
            "listen": "127.0.0.1",
            "port": int(proxy_port),
            "protocol": "http",
            "tag": inbound_tag,
            "settings": {"allowTransparent": False},
        })
        config = build_xray_config(
            profile, tuning=tuning,
            upstream_address=(
                "127.0.0.1" if target_relay is not None else None
            ),
        )
        outbound = config["outbounds"][0]
        outbound["tag"] = outbound_tag
        endpoints = (outbound["settings"].get("servers")
                     or outbound["settings"].get("vnext") or [])
        if not endpoints:
            raise ValueError(f"Missing outbound endpoint for {profile.name}")
        if target_relay is not None:
            endpoints[0]["address"] = "127.0.0.1"
            endpoints[0]["port"] = int(target_relay)
        outbounds.append(outbound)
        rules.append({
            "type": "field",
            "inboundTag": [inbound_tag],
            "outboundTag": outbound_tag,
        })
    outbounds.extend([
        {"tag": "direct", "protocol": "freedom"},
        {"tag": "block", "protocol": "blackhole"},
    ])
    return {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"domainStrategy": "AsIs", "rules": rules},
    }


def _valid_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(str(value or "").strip()))
    except ValueError:
        return ""


def _country_name(code: str, fallback: str = "") -> str:
    normalized = str(code or "").upper()
    return str(fallback or COUNTRIES.get(normalized, ("", normalized, normalized))[1] or normalized)


def _location_from_response(source: str, response):
    if not response.ok:
        raise ValueError(f"HTTP {response.status_code}")
    if source == "cloudflare-trace":
        values = {}
        for line in response.text.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip()
        code = str(values.get("loc", "") or "").upper()
        exit_ip = _valid_ip(values.get("ip", ""))
        country = _country_name(code)
    else:
        value = response.json()
        if source == "ipwho.is" and not value.get("success", True):
            raise ValueError(str(value.get("message", "") or "location lookup failed"))
        code = str(
            value.get("country_code", "")
            if source == "ipwho.is"
            else value.get("country", "")
        ).upper()
        exit_ip = _valid_ip(value.get("ip", ""))
        country = _country_name(
            code,
            str(value.get("country", "") or "")
            if source == "ipwho.is" else "",
        )
    if code not in ISO2_CODES or not exit_ip:
        raise ValueError("missing exit location")
    return code, exit_ip, country


def _probe_proxy(
        profile: ProxyProfile, port: int, timeout: float,
        cancel: threading.Event) -> LiveConfigResult:
    result = LiveConfigResult(profile=profile)
    proxies = {
        "http": f"http://127.0.0.1:{port}",
        "https": f"http://127.0.0.1:{port}",
    }
    session = requests.Session()
    session.trust_env = False
    headers = {
        "User-Agent": "UAC-Spoofer-Desktop/SNI-Maker",
        "Cache-Control": "no-cache",
    }
    errors = []
    endpoints = (
        ("cloudflare-trace", "https://www.cloudflare.com/cdn-cgi/trace"),
        ("ipwho.is", "https://ipwho.is/"),
        ("api.country.is", "https://api.country.is/"),
    )
    deadline = time.monotonic() + max(1.0, float(timeout))
    try:
        for sample, (source, url) in enumerate(endpoints):
            if cancel.is_set():
                result.error = "cancelled"
                return result
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            request_budget = max(
                0.5,
                min(remaining, max(2.0, float(timeout) / 2)),
            )
            try:
                response = session.get(
                    url,
                    proxies=proxies,
                    timeout=(min(2.0, request_budget), request_budget),
                    headers=headers,
                    params={"uac_probe": sample} if source == "cloudflare-trace" else None,
                )
                elapsed = max(1.0, response.elapsed.total_seconds() * 1000)
                code, exit_ip, country = _location_from_response(source, response)
                result.ok = True
                result.ping_ms = elapsed
                result.country_code = code
                result.country = country or _country_name(code)
                result.exit_ip = exit_ip
                result.source = source
                return result
            except (
                    OSError, ValueError, TypeError, AttributeError,
                    requests.RequestException) as exc:
                errors.append(f"{source}: {exc}")
        result.error = errors[-1] if errors else "live route test failed"
        return result
    finally:
        session.close()


class SniBatchTester:
    def __init__(self, log: Callable[[str], None] | None = None):
        self.log = log or (lambda _message: None)
        self._process = None
        self._job_handle = None
        self._patterns: list[PatternSniCore] = []
        self._config_path: Path | None = None
        self._lock = threading.Lock()
        self._stop_event = threading.Event()

    def _xray_binary(self) -> Path:
        binary = BIN / ("xray.exe" if os.name == "nt" else "xray")
        if not binary.exists():
            raise FileNotFoundError(f"Xray binary not found: {binary}")
        return binary

    def _drain_output(self, process) -> None:
        stream = getattr(process, "stdout", None)
        if stream is None:
            return
        for line in iter(stream.readline, ""):
            text = line.strip()
            if text:
                self.log(f"SNI MAKER XRAY {text}")

    def _start_xray(self, config_path: Path, cancel=None):
        command = [
            str(self._xray_binary()), "run", "-config", str(config_path)
        ]
        with self._lock:
            if cancel is not None and cancel.is_set():
                return None
            if os.name == "nt":
                self._job_handle = Engine._create_tun_job()
                process = Engine._spawn_tun_in_job(
                    self._job_handle, command, config_path.parent
                )
                Engine._resume_tun_process(process)
            else:
                process = subprocess.Popen(
                    command, cwd=str(config_path.parent),
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, encoding="utf-8", errors="replace",
                )
            self._process = process
        threading.Thread(
            target=self._drain_output, args=(process,),
            name="sni-maker-xray-log", daemon=True,
        ).start()
        return process

    @staticmethod
    def _wait_ready(process, ports: list[int], timeout: float = 5.0) -> None:
        selected = list(dict.fromkeys([
            ports[0], ports[len(ports) // 2], ports[-1]
        ]))
        pending = set(selected)
        deadline = time.monotonic() + timeout
        while pending and time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(f"SNI Maker Xray exited ({process.returncode})")
            for port in tuple(pending):
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.08):
                        pending.remove(port)
                except OSError:
                    pass
            if pending:
                time.sleep(0.04)
        if pending:
            raise RuntimeError("SNI Maker Xray listener startup timed out")

    def run(
            self, profiles: list[ProxyProfile], tuning: Tuning,
            cancel: threading.Event, workers: int = 64,
            timeout: float = 8.0,
            strategy: str | None = None,
            progress: Callable[[list[LiveConfigResult], int, int], None] | None = None
            ) -> list[LiveConfigResult]:
        supported = [
            profile for profile in profiles
            if profile.protocol in {"vless", "trojan", "vmess"}
            and profile.source_uri
        ]
        if not supported:
            return []
        workers = max(1, min(64, int(workers)))
        self._stop_event.clear()
        stop_signal = _CancelSignal(cancel, self._stop_event)
        if stop_signal.is_set():
            return []
        remote_ports = [int(profile.port or 443) for profile in supported]
        if any(port < 1 or port > 65535 for port in remote_ports):
            raise ValueError("SNI Maker profile has an invalid remote port")
        direct_routes = [
            (
                profile.route_mode == "reality-direct"
                or parse_outbound(profile)["security"] == "reality"
            )
            for profile in supported
        ]
        unique_remote_ports = list(dict.fromkeys(
            remote_port
            for remote_port, direct in zip(remote_ports, direct_routes)
            if not direct
        ))
        reservations = _reserve_local_ports(
            len(supported) + len(unique_remote_ports)
        )
        relay_reservations = reservations[:len(unique_remote_ports)]
        proxy_reservations = reservations[len(unique_remote_ports):]
        proxy_ports = [port for port, _holder in proxy_reservations]
        relay_by_remote_port = {
            remote_port: relay_port
            for remote_port, (relay_port, _holder) in zip(
                unique_remote_ports, relay_reservations
            )
        }
        profile_relay_ports = [
            None if direct else relay_by_remote_port[remote_port]
            for remote_port, direct in zip(remote_ports, direct_routes)
        ]
        probe_tuning = Tuning.from_dict(tuning.to_dict())
        probe_tuning.pattern_max_sessions = workers
        probe_tuning.xray_mux_enabled = False
        probe_tuning.log_level = "minimal"
        selected_strategy = str(
            strategy or (
                "tls_sni_records"
                if probe_tuning.carrier_mode == "mci"
                else "wrong_seq"
            )
        ).strip().lower()
        if selected_strategy not in {"wrong_seq", "tls_sni_records"}:
            selected_strategy = (
                "tls_sni_records"
                if probe_tuning.carrier_mode == "mci"
                else "wrong_seq"
            )
        self.log(
            f"SNI MAKER strategy={selected_strategy} "
            f"carrier={probe_tuning.carrier_mode} workers={workers}"
        )
        config = build_batch_xray_config(
            supported, proxy_ports, profile_relay_ports, probe_tuning
        )
        config_path = DATA_DIR / f"sni-maker-batch-{os.getpid()}.json"
        results = []
        batch = []
        done = 0
        try:
            with self._lock:
                self._config_path = config_path
                config_path.write_text(
                    json.dumps(config, ensure_ascii=False), encoding="utf-8"
                )
            for remote_port, (relay_port, relay_holder) in zip(
                    unique_remote_ports, relay_reservations):
                if stop_signal.is_set():
                    return []
                relay_holder.close()
                controller = ProxyProfile(
                    name=f"SNI Maker relay {remote_port}",
                    address=VERIFIED_SPOOF_EDGE,
                    fallback_address="",
                    port=remote_port,
                    config_port=relay_port,
                )
                pattern = PatternSniCore(self.log)
                with self._lock:
                    if stop_signal.is_set():
                        pattern.stop()
                        return []
                    self._patterns.append(pattern)
                    pattern.start(controller, probe_tuning, selected_strategy)
            if stop_signal.is_set():
                return []
            for _port, holder in proxy_reservations:
                holder.close()
            process = self._start_xray(config_path, stop_signal)
            if process is None:
                return []
            try:
                self._wait_ready(process, proxy_ports)
            except Exception:
                if stop_signal.is_set():
                    return []
                raise
            if stop_signal.is_set():
                return []
            with concurrent.futures.ThreadPoolExecutor(
                    max_workers=workers, thread_name_prefix="sni-maker") as pool:
                futures = {
                    pool.submit(
                        _probe_proxy, profile, port, timeout, stop_signal
                    ): profile
                    for profile, port in zip(supported, proxy_ports)
                }
                last_emit = time.monotonic()
                for future in concurrent.futures.as_completed(futures):
                    if stop_signal.is_set():
                        for pending in futures:
                            pending.cancel()
                    try:
                        result = future.result()
                    except Exception as exc:
                        result = LiveConfigResult(
                            profile=futures[future], error=str(exc)
                        )
                    results.append(result)
                    batch.append(result)
                    done += 1
                    now = time.monotonic()
                    if progress and (
                            len(batch) >= 20 or now - last_emit >= 0.08
                            or done == len(supported)):
                        progress(list(batch), done, len(supported))
                        batch.clear()
                        last_emit = now
            return sorted(
                results,
                key=lambda item: (
                    not item.ok,
                    item.country_code,
                    item.ping_ms if item.ok else float("inf"),
                    item.profile.name.lower(),
                ),
            )
        finally:
            for _port, holder in reservations:
                try:
                    holder.close()
                except OSError:
                    pass
            self.stop()
            try:
                config_path.unlink(missing_ok=True)
            except OSError:
                pass

    def stop(self) -> None:
        self._stop_event.set()
        with self._lock:
            process, self._process = self._process, None
            if process is not None and process.poll() is None:
                try:
                    process.terminate()
                    process.wait(timeout=1.5)
                except Exception:
                    try:
                        process.kill()
                    except Exception:
                        pass
            if self._job_handle:
                try:
                    Engine._close_tun_job(self._job_handle)
                except Exception:
                    pass
                self._job_handle = None
            patterns, self._patterns = self._patterns, []
            for pattern in patterns:
                try:
                    pattern.stop()
                except Exception:
                    pass
            if self._config_path is not None:
                try:
                    self._config_path.unlink(missing_ok=True)
                except OSError:
                    pass
                self._config_path = None
