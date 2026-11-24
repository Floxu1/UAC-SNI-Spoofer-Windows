"""Expose the verified POW exit only on a private IPv4 interface."""

from __future__ import annotations

import ipaddress
import json
import subprocess
import time

from .routing import PRIVATE_NETWORKS
from .runner import tcp_accepts


def endpoint() -> tuple[str, str]:
    script = (
        "$profiles = Get-NetConnectionProfile | Where-Object NetworkCategory -eq Private; "
        "$routes = Get-NetRoute -DestinationPrefix 0.0.0.0/0 -ErrorAction SilentlyContinue; "
        "$route = $routes | Where-Object { $_.InterfaceIndex -in $profiles.InterfaceIndex "
        "-and $_.InterfaceAlias -notlike 'UAC-Spoofer*' } | "
        "Sort-Object { $_.RouteMetric + $_.InterfaceMetric } | Select-Object -First 1; "
        "if ($route) { $ip = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $route.InterfaceIndex | "
        "Where-Object AddressState -eq Preferred | Select-Object -First 1; "
        "if ($ip) { '{0}/{1}' -f $ip.IPAddress,$ip.PrefixLength } }"
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, timeout=8, creationflags=subprocess.CREATE_NO_WINDOW,
    )
    try:
        interface = ipaddress.IPv4Interface(result.stdout.strip())
    except ValueError as exc:
        raise RuntimeError("No IPv4 address on an active private network") from exc
    if not any(interface.network.subnet_of(ipaddress.ip_network(net)) for net in PRIVATE_NETWORKS):
        raise RuntimeError("LAN share requires a private IPv4 subnet")
    return str(interface.ip), str(interface.network)


def config_for(address: str, subnet: str, port: int, socks_port: int, mode: str) -> dict:
    return {
        "log": {"level": "warn"},
        "inbounds": [{
            "type": "http" if mode == "ps5" else "socks",
            "tag": "lan-in", "listen": address, "listen_port": port,
        }],
        "outbounds": [{
            "type": "socks", "tag": "pow", "server": "127.0.0.1", "server_port": socks_port,
        }],
        "route": {
            "rules": [{"source_ip_cidr": [subnet], "invert": True, "action": "reject"}],
            "final": "pow",
        },
    }


def start(data_dir, settings, exit_port: int, stop):
    from ..paths import BIN
    from ..process_win import attach_kill_on_close_job, register_helper_pid

    address, subnet = endpoint()
    port = settings.lan_share_port
    path = data_dir / "pow-lan-share.json"
    path.write_text(json.dumps(config_for(address, subnet, port, exit_port, settings.lan_share_mode)),
                    encoding="utf-8")
    binary = BIN / "sing-box.exe"
    process = subprocess.Popen([str(binary), "run", "-c", str(path)], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        register_helper_pid(process.pid)
        attach_kill_on_close_job(process)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and not stop.is_set() and process.poll() is None:
            if tcp_accepts(port, address, timeout=0.3) and not stop.wait(0.1) and process.poll() is None:
                return process, f"{address}:{port}"
            stop.wait(0.1)
        raise RuntimeError(f"LAN share could not listen on {address}:{port}")
    except BaseException:
        close(process)
        raise


def close(process) -> None:
    from ..process_win import unregister_helper_pid

    try:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
    finally:
        unregister_helper_pid(process.pid)
