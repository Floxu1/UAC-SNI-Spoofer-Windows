"""Windows Proxy and sing-box TUN adapters for UAC Tor (sing-box 1.13+ clean schema)."""
from __future__ import annotations

import ctypes
import json
import socket
import subprocess
import sys
import threading
import time
from dataclasses import replace
from pathlib import Path
from typing import Callable, Sequence

from ..application_settings import ConnectionPreferences, direct_domains, direct_ips
from ..engine import build_singbox_tun_config
from ..paths import BIN
from ..pow.routing import add_tun_proxy_listener, apply_rules, iran_domains
from ..pow.tun_guard import KillOnCloseJob, effective_mtu
from ..proxy_ports import listener_pid
from .store import TorSettings

TOR_HELPERS = (
    "tor.exe",
    "lyrebird.exe",
    "snowflake-client.exe",
    "conjure-client.exe",
    Path(sys.executable).name,
)
TOR_TUN_INTERFACE = "UAC-Spoofer Tor"
TOR_TUN_IPV4 = "172.21.0.1"
TOR_TUN_IPV6 = "fdfe:dcba:9878::1"
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


class TorOutputError(RuntimeError):
    pass


def is_admin() -> bool:
    if sys.platform != "win32":
        return True
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def require_admin() -> None:
    if not is_admin():
        raise TorOutputError("Tor VPN (TUN) mode requires Administrator access")


def _routes_through_tor_tun() -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("1.1.1.1", 443))
            return sock.getsockname()[0] == TOR_TUN_IPV4
    except OSError:
        return False


def build_tor_mixed_proxy_config(
    settings: TorSettings,
    *,
    listen_port: int,
    socks_port: int,
    processes: Sequence[str],
) -> dict:
    """Clean HTTP/SOCKS5 proxy config for Tor:
    - Proxied HTTPS domains pass directly to Tor SocksPort (socks5h) without touching Tor DNSPort.
    - Only the 'direct' outbound (Iranian / bypassed sites) uses local DNS.
    - Rejects UDP/QUIC immediately so browsers use TCP HTTPS cleanly.
    """
    protected = {name.lower() for name in (*TOR_HELPERS, "sing-box.exe")}
    selected = list(dict.fromkeys(
        Path(p).name for p in processes if Path(p).name.lower() not in protected
    ))

    rules: list[dict] = [
        {"network": "udp", "action": "reject"},
        {"ip_cidr": ["10.192.0.0/10"], "action": "route", "outbound": "proxy"},
        {
            "ip_cidr": ["127.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12", "::1/128"],
            "action": "route",
            "outbound": "direct",
        },
    ]

    if settings.routing_mode == "bypass" and selected:
        rules.append({"process_name": selected, "action": "route", "outbound": "direct"})
    elif settings.routing_mode == "only":
        rules.append({"process_path": [sys.executable], "action": "route", "outbound": "proxy"})
        if selected:
            rules.append({"process_name": selected, "invert": True, "action": "route", "outbound": "direct"})
        else:
            rules.append({"action": "route", "outbound": "direct"})

    if settings.iran_direct:
        rules.append({"domain_suffix": iran_domains(BIN / "geosite.dat"), "action": "route", "outbound": "direct"})
    if domains := direct_domains(settings.domains_direct):
        rules.append({"domain_suffix": list(domains), "action": "route", "outbound": "direct"})
    if addresses := direct_ips(settings.ips_direct):
        rules.append({"ip_cidr": list(addresses), "action": "route", "outbound": "direct"})

    return {
        "log": {"level": "warn"},
        "dns": {
            "servers": [{"type": "local", "tag": "local-dns"}],
            "final": "local-dns",
            "strategy": "ipv4_only",
        },
        "inbounds": [{
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": int(listen_port),
        }],
        "outbounds": [
            {
                "type": "socks",
                "tag": "proxy",
                "server": "127.0.0.1",
                "server_port": int(socks_port),
                "version": "5",
                "network": "tcp",
            },
            {
                "type": "direct",
                "tag": "direct",
                "domain_resolver": "local-dns",
            },
        ],
        "route": {
            "rules": rules,
            "final": "proxy",
        },
    }


def build_tor_tun_config(
    settings: TorSettings,
    *,
    socks_port: int,
    dns_port: int,
    mtu: int,
    stack: str,
    processes: Sequence[str],
    privacy: ConnectionPreferences | None = None,
    proxy_port: int = 0,
) -> dict:
    cfg = build_singbox_tun_config(socks_port=socks_port, helper_processes=TOR_HELPERS)
    cfg["inbounds"][0].update(
        interface_name=TOR_TUN_INTERFACE,
        mtu=mtu,
        stack=stack,
        strict_route=True,
        address=[f"{TOR_TUN_IPV4}/30", f"{TOR_TUN_IPV6}/126"],
    )
    cfg["dns"]["servers"] = [{
        "type": "udp",
        "tag": "remote-dns",
        "server": "127.0.0.1",
        "server_port": int(dns_port),
    }]
    cfg["dns"]["final"] = "remote-dns"
    cfg["dns"]["strategy"] = "ipv4_only"

    rules = cfg["route"]["rules"]
    rules.insert(0, {"ip_cidr": ["10.192.0.0/10"], "action": "route", "outbound": "proxy"})

    protected = {name.lower() for name in (*TOR_HELPERS, "sing-box.exe")}
    selected = list(dict.fromkeys(
        Path(p).name for p in processes if Path(p).name.lower() not in protected
    ))
    if settings.routing_mode == "bypass" and selected:
        rules.insert(3, {"process_name": selected, "action": "route", "outbound": "direct"})

    effective = privacy.for_tor(settings) if privacy is not None else settings
    # Tor transports IPv4 TCP only; ensure IPv6 & QUIC are blocked cleanly via shared apply_rules
    effective = replace(effective, ipv6_block=True, quic_block=True)
    apply_rules(cfg, effective, selected, BIN / "geosite.dat", tun=True, warp_only=False)

    if proxy_port:
        add_tun_proxy_listener(
            cfg,
            int(proxy_port),
            dns_sinkhole=bool(effective.dns_sinkhole),
            ipv6_block=True,
        )
    return cfg


class SingBoxRunner:
    def __init__(self, command: Sequence[str], cwd: Path, log: Callable[[str], None]) -> None:
        self._job = KillOnCloseJob()
        self.last_line = ""
        self._process = subprocess.Popen(
            list(command),
            cwd=str(cwd),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=_NO_WINDOW,
        )
        self._job.assign(self._process)

        def pump() -> None:
            if self._process.stdout is None:
                return
            with self._process.stdout as s:
                for line in s:
                    text = line.strip()
                    if text:
                        self.last_line = text
                        log(f"Tor sing-box: {text[-220:]}")

        self._reader = threading.Thread(target=pump, name="tor-singbox-log", daemon=True)
        self._reader.start()

    @property
    def pid(self) -> int:
        return int(self._process.pid)

    def running(self) -> bool:
        return self._process.poll() is None

    def close(self) -> None:
        try:
            if self.running():
                self._process.terminate()
                try:
                    self._process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self._process.kill()
                    self._process.wait(timeout=2)
        finally:
            self._job.close()
            self._reader.join(timeout=2)


def start_tor_mixed_proxy(
    directory: Path,
    settings: TorSettings,
    *,
    listen_port: int,
    socks_port: int,
    processes: Sequence[str],
    cancel: threading.Event,
    log: Callable[[str], None],
) -> SingBoxRunner:
    binary = BIN / "sing-box.exe"
    if not binary.is_file():
        raise TorOutputError("sing-box.exe is missing from bin/")
    cfg = build_tor_mixed_proxy_config(
        settings,
        listen_port=int(listen_port),
        socks_port=int(socks_port),
        processes=processes,
    )
    path = directory / "tor-mixed-proxy.json"
    path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")
    runner = SingBoxRunner([str(binary), "run", "-c", str(path)], directory, log)
    deadline = time.monotonic() + 5.0
    while runner.running() and time.monotonic() < deadline and not cancel.is_set():
        if listener_pid(listen_port) == runner.pid:
            return runner
        cancel.wait(0.1)
    runner.close()
    raise TorOutputError(runner.last_line or f"Tor mixed proxy did not listen on 127.0.0.1:{listen_port}")


def start_tor_tun(
    directory: Path,
    settings: TorSettings,
    *,
    socks_port: int,
    dns_port: int,
    processes: Sequence[str],
    uplink_mtu: int,
    cancel: threading.Event,
    log: Callable[[str], None],
    privacy: ConnectionPreferences | None = None,
    proxy_port: int = 0,
) -> SingBoxRunner:
    require_admin()
    binary = BIN / "sing-box.exe"
    if not binary.is_file():
        raise TorOutputError("sing-box.exe is missing from bin/")
    size = effective_mtu(1400, uplink_mtu)
    path = directory / "tor-tun.json"
    last_error = ""
    for kind, mtu in (("mixed", size), ("gvisor", min(size, 1280)), ("system", min(size, 1280))):
        if cancel.is_set():
            raise TorOutputError("cancelled")
        cfg = build_tor_tun_config(
            settings,
            socks_port=socks_port,
            dns_port=dns_port,
            mtu=mtu,
            stack=kind,
            processes=processes,
            privacy=privacy,
            proxy_port=proxy_port,
        )
        path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")
        runner = SingBoxRunner([str(binary), "run", "-c", str(path)], directory, log)
        ok = False
        try:
            deadline = time.monotonic() + 8.0
            while runner.running() and time.monotonic() < deadline and not cancel.is_set():
                if _routes_through_tor_tun():
                    ok = True
                    return runner
                cancel.wait(0.2)
            last_error = runner.last_line or "Tor TUN startup timed out"
            log(f"Tor TUN {kind}/{mtu} failed: {last_error}")
        finally:
            if not ok:
                runner.close()
    raise TorOutputError(f"Tor TUN could not start: {last_error}")
