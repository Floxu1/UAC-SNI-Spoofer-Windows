from __future__ import annotations

import ctypes
import json
import os
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Sequence
from contextlib import ExitStack
from pathlib import Path

from ..engine import WindowsProxy, build_singbox_tun_config
from ..paths import BIN
from ..pow.tun_guard import KillOnCloseJob, effective_mtu
from ..proxy_ports import listener_pid
from .carrier import ensure_active, loopback_port
from .probe import ProbeResult, recv_exact, trace, verify_dns, verify_https
from .store import DirectSettings, write_json

DIRECT_XRAY = BIN / "uac-direct-xray.exe"
DIRECT_MASK = BIN / "uac-direct-mask.exe"
DIRECT_NATIVE = BIN / "uac-direct.exe"
TUN_INTERFACE = "UAC-Spoofer Direct"
TUN_IPV4 = "172.20.0.1"
TUN_IPV6 = "fdfe:dcba:9877::1"
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
_MASKS = {"oob": ("--oob", "0"), "record-sni": ("--tlsrec", "2+s")}


class OutputError(RuntimeError):
    pass


class OwnedHelper:
    def __init__(self, command: Sequence[str | Path], directory: Path, tag: str,
                 log: Callable[[str], None], env: dict | None = None) -> None:
        self._job = KillOnCloseJob()
        self.last_line = ""
        try:
            self.process = subprocess.Popen(
                [str(part) for part in command], cwd=directory, env=env,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                encoding="utf-8", errors="replace", text=True, creationflags=_NO_WINDOW,
            )
        except OSError as error:
            self._job.close()
            raise OutputError(f"Could not start {tag}: {error}") from error
        self._job.assign(self.process)

        def read() -> None:
            with self.process.stdout as stream:
                for line in stream:
                    self.last_line = line.rstrip()
                    log(f"Direct {tag}: {self.last_line}")

        self._reader = threading.Thread(target=read, name=f"direct-{tag}-log", daemon=True)
        self._reader.start()

    def running(self) -> bool:
        return self.process.poll() is None

    def wait_listener(self, port: int, cancel: threading.Event, *, socks: bool, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        while self.running():
            ensure_active(cancel)
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.08) as sock:
                    if socks:
                        sock.sendall(b"\x05\x01\x00")
                        if recv_exact(sock, 2) != b"\x05\x00":
                            raise OSError("SOCKS authentication rejected")
                if listener_pid(port) == self.process.pid and self.running():
                    return
            except OSError:
                pass
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            cancel.wait(min(0.02, remaining))
        if not self.running():
            self._reader.join(timeout=1)
        raise OutputError(self.last_line or f"Direct helper did not listen on localhost:{port}")

    def close(self) -> None:
        try:
            if self.running():
                self.process.terminate()
                try:
                    self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=2)
        finally:
            self._job.close()
            self._reader.join(timeout=2)


def start_masks(directory: Path, ipv6: bool, stack: ExitStack, cancel: threading.Event,
                log: Callable[[str], None]) -> dict[str, int]:
    ports = {}
    for name, options in _MASKS.items():
        ensure_active(cancel)
        port = loopback_port()
        with ExitStack() as attempt:
            try:
                args = [DIRECT_MASK, "--ip", "127.0.0.1", "--port", str(port), "--no-udp", "--no-domain"]
                if not ipv6:
                    args.append("--no-ipv6")
                helper = OwnedHelper([*args, *options], directory, name, log)
                attempt.callback(helper.close)
                helper.wait_listener(port, cancel, socks=True, timeout=0.4)
            except OutputError as error:
                log(f"Direct {name} unavailable: {error}")
                continue
            ports[name] = port
            stack.enter_context(attempt.pop_all())
    return ports


def start_xray(directory: Path, config: dict, socks_port: int, http_port: int,
               cancel: threading.Event, log: Callable[[str], None]) -> OwnedHelper:
    path = directory / "xray.json"
    write_json(path, config)
    runner = OwnedHelper([DIRECT_XRAY, "run", "-config", path], directory, "Xray", log,
                         {**os.environ, "XRAY_LOCATION_ASSET": str(BIN)})
    try:
        runner.wait_listener(socks_port, cancel, socks=True, timeout=8)
        if http_port:
            runner.wait_listener(http_port, cancel, socks=False, timeout=3)
        return runner
    except BaseException:
        runner.close()
        raise


def xray_traffic(port: int) -> tuple[int, int] | None:
    try:
        output = subprocess.run(
            [str(DIRECT_XRAY), "api", "statsquery", f"--server=127.0.0.1:{port}", "-pattern", "inbound>>>"],
            capture_output=True, text=True, encoding="utf-8", timeout=2, creationflags=_NO_WINDOW,
        )
        if output.returncode:
            return None
        upload = download = 0
        for item in json.loads(output.stdout).get("stat", []):
            name, value = item.get("name", ""), int(item.get("value", 0))
            if name.endswith(">>>uplink"):
                upload += value
            elif name.endswith(">>>downlink"):
                download += value
        return upload, download
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None


def build_tun_config(settings: DirectSettings, socks_port: int, dns_server: str,
                     mtu: int, routing_mode: str, processes: Sequence[str], stack: str) -> dict:
    helper_names = [DIRECT_XRAY.name, DIRECT_MASK.name, DIRECT_NATIVE.name, "uac-psiphon.exe"]
    cfg = build_singbox_tun_config(socks_port=socks_port, helper_processes=helper_names)
    cfg["inbounds"][0].update(interface_name=TUN_INTERFACE, mtu=mtu, stack=stack, strict_route=True,
                              address=[f"{TUN_IPV4}/30", f"{TUN_IPV6}/126"])
    cfg["dns"]["servers"][0]["server"] = dns_server
    cfg["dns"]["strategy"] = "prefer_ipv4" if settings.ipv6 else "ipv4_only"
    rules = cfg["route"]["rules"]
    # The selected app routing policy applies before DNS hijack, like VpnService app exclusions.
    split = []
    protected = {name.lower() for name in [*helper_names, "sing-box.exe", Path(sys.executable).name]}
    names = list(dict.fromkeys(Path(process).name for process in processes if Path(process).name.lower() not in protected))
    if routing_mode == "bypass" and names:
        split.append({"process_name": names, "action": "route", "outbound": "direct"})
    elif routing_mode == "only":
        allowed = [*names, Path(sys.executable).name]
        split.append({"process_name": allowed, "invert": True, "action": "route", "outbound": "direct"})
    rules[2:2] = split
    if not settings.ipv6:
        rules.append({"ip_version": 6, "action": "reject"})
    if settings.block_quic:
        rules.append({"network": "udp", "port": 443, "action": "reject"})
    return cfg


def require_admin() -> None:
    if sys.platform != "win32" or not ctypes.windll.shell32.IsUserAnAdmin():
        raise OutputError("Direct VPN requires Administrator access")


def _routes_through_tun() -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("1.1.1.1", 443))
            return sock.getsockname()[0] == TUN_IPV4
    except OSError:
        return False


def verify_tun(socks_port: int, dns_server: str, chained: bool, cancel: threading.Event) -> ProbeResult:
    ensure_active(cancel)
    if not _routes_through_tun():
        return ProbeResult(False, "Windows selected a route outside the Direct TUN")
    dns = verify_dns(0, dns_server)
    ensure_active(cancel)
    if not dns.ok:
        return dns
    https = verify_https("https://www.cloudflare.com/cdn-cgi/trace", 0)
    ensure_active(cancel)
    if not https.ok or not chained:
        return https
    try:
        routed, reference = trace(0).get("ip"), trace(socks_port).get("ip")
        if not routed or routed != reference:
            return ProbeResult(False, "Windows TUN traffic did not use the Direct SOCKS exit")
    except OSError as error:
        return ProbeResult(False, f"Direct TUN exit could not be verified: {error}")
    return ProbeResult(True, f"TUN DNS and HTTPS verified: {dns.detail}")


def start_tun(directory: Path, settings: DirectSettings, socks_port: int, dns_server: str,
              routing_mode: str, processes: Sequence[str], mtu: int, uplink_mtu: int,
              cancel: threading.Event, log: Callable[[str], None], allow_tunnel: Callable[[bool], None]) -> OwnedHelper:
    require_admin()
    size = effective_mtu(mtu, uplink_mtu)
    binary = BIN / "sing-box.exe"
    path = directory / "tun.json"
    last_error = ""
    for kind, mtu in (("mixed", size), ("gvisor", min(size, 1280)), ("system", min(size, 1280))):
        ensure_active(cancel)
        config = build_tun_config(settings, socks_port, dns_server, mtu, routing_mode, processes, kind)
        write_json(path, config)
        runner = OwnedHelper([binary, "run", "-c", path], directory, "TUN", log)
        established = False
        try:
            deadline = time.monotonic() + 8
            while runner.running() and time.monotonic() < deadline:
                ensure_active(cancel)
                if _routes_through_tun():
                    allow_tunnel(True)
                    established = True
                    return runner
                cancel.wait(0.2)
            if not runner.running():
                runner._reader.join(timeout=1)
            last_error = runner.last_line or "Direct TUN route startup timed out"
            log(f"Direct TUN {kind}/{mtu} failed: {last_error}")
        finally:
            if not established:
                runner.close()
    raise OutputError(f"Direct VPN could not establish a TUN route: {last_error}")


def activate_os_proxy(vpn: bool, socks_port: int, http_port: int,
                      log: Callable[[str], None]) -> WindowsProxy:
    proxy = WindowsProxy(log)
    if vpn:
        proxy.suspend_for_tun(socks_port=socks_port, http_port=http_port)
    else:
        proxy.enable(socks_port=socks_port, http_port=http_port)
    return proxy
