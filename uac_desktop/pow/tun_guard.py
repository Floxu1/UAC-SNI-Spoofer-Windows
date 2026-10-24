"""Engine 2 (PoW) system-tunnel hardening.

Everything here is engine-2 only so engine 1's TUN is untouched:

* ``harden_config``   - sniffing, DNS through the tunnel, IPv6 fast-reject,
                        strict route, chosen stack/MTU.
* ``KillOnCloseJob``  - sing-box dies with the app (crash => routes removed,
                        internet comes back by itself).
* ``kill_stale``      - remove a sing-box left from a previous crashed run
                        that still owns our adapter.
* ``verify_tun``      - real checks outside the Windows proxy (DNS, HTTPS,
                        exit IP == tunnel exit).
* ``SiteLog``         - one clean log line per site (+ errors).
"""
from __future__ import annotations

import copy
import ctypes
import re
import socket
import subprocess
import threading
import time
from typing import Callable

#: (stack, mtu) tried in order; later entries are the repair attempts.
TUN_ATTEMPTS: tuple[tuple[str, int], ...] = (
    ("mixed", 1400),
    ("gvisor", 1280),
    ("system", 1280),
)

PROBE_URLS = (
    "https://www.gstatic.com/generate_204",
    "https://www.youtube.com/generate_204",
)
TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"


def harden_config(config: dict, stack: str = "mixed", mtu: int = 1400) -> dict:
    cfg = copy.deepcopy(config)
    cfg["log"] = {"level": "debug", "timestamp": False, "disabled": False}  # sniffed domains are DEBUG lines
    inbound = cfg["inbounds"][0]
    inbound["stack"] = stack
    inbound["mtu"] = int(mtu)
    inbound["strict_route"] = True
    route = cfg.setdefault("route", {})
    rules = list(route.get("rules", []))
    # Sniff first: real domains for logs and DNS detection on any port.
    head = [
        {"action": "sniff", "timeout": "300ms"},
        {"protocol": "dns", "action": "hijack-dns"},
    ]
    rules = [r for r in rules if r.get("action") != "sniff"]
    # IPv6: DNS hands out IPv4 only, but literal v6 (apps, happy eyeballs)
    # must fail fast instead of leaking around the tunnel or hanging.
    v6 = {"ip_version": 6, "action": "reject", "method": "default"}
    # keep process/helper direct rules (loop protection) ahead of v6 reject
    insert_at = 0
    for i, rule in enumerate(rules):
        if "process_name" in rule:
            insert_at = i + 1
    rules.insert(insert_at, v6)
    route["rules"] = head + rules
    route["auto_detect_interface"] = True
    route["final"] = "proxy"
    dns = cfg.setdefault("dns", {})
    servers = dns.setdefault("servers", [])
    if not any(srv.get("tag") == "local-dns" for srv in servers):
        servers.append({"type": "local", "tag": "local-dns"})
    route["default_domain_resolver"] = "local-dns"
    dns["strategy"] = "ipv4_only"
    dns["final"] = "remote-dns"
    return cfg


# -- crash safety -------------------------------------------------------------
class KillOnCloseJob:
    """Windows job object: when our process dies, sing-box dies too."""

    def __init__(self) -> None:
        self.handle = None
        try:
            from ..engine import UACSpooferEngine as _E  # type: ignore
            maker = getattr(_E, "_create_tun_job")
        except Exception:
            maker = None
        if maker is None:
            try:
                from .. import engine as _eng
                for obj in vars(_eng).values():
                    if isinstance(obj, type) and hasattr(obj, "_create_tun_job"):
                        maker = getattr(obj, "_create_tun_job")
                        break
            except Exception:
                maker = None
        if maker is not None:
            try:
                self.handle = maker()
            except Exception:
                self.handle = None

    def assign(self, process: subprocess.Popen) -> bool:
        if not self.handle:
            return False
        try:
            k32 = ctypes.windll.kernel32
            k32.AssignProcessToJobObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
            k32.AssignProcessToJobObject.restype = ctypes.c_int
            return bool(k32.AssignProcessToJobObject(
                ctypes.c_void_p(self.handle), ctypes.c_void_p(int(process._handle))))
        except Exception:
            return False

    def close(self) -> None:
        handle, self.handle = self.handle, None
        if handle:
            try:
                ctypes.windll.kernel32.CloseHandle(ctypes.c_void_p(handle))
            except Exception:
                pass


def kill_stale(config_path: str, log: Callable[[str], None]) -> int:
    """Kill sing-box processes still running OUR engine-2 TUN config."""
    needle = str(config_path).replace("'", "''")
    script = (
        "Get-CimInstance Win32_Process -Filter \"Name='sing-box.exe'\" | "
        f"Where-Object {{ $_.CommandLine -and $_.CommandLine.Contains('{needle}') }} | "
        "ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue; $_.ProcessId }"
    )
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=15,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        ).stdout
    except Exception:
        return 0
    killed = [line for line in out.split() if line.strip().isdigit()]
    if killed:
        log(f"TUN cleanup: removed {len(killed)} leftover sing-box from a previous run")
        time.sleep(1.0)
    return len(killed)


# -- verification -------------------------------------------------------------
def _session():
    import requests

    s = requests.Session()
    s.trust_env = False  # never the Windows proxy: TUN only
    return s


def _trace(session, proxies=None, timeout=8.0) -> dict:
    r = session.get(TRACE_URL, timeout=timeout, proxies=proxies,
                    headers={"Connection": "close"})
    out = {}
    for line in r.text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def verify_tun(socks_port: int, timeout: float = 8.0) -> tuple[bool, str, dict]:
    """(ok, reason, facts). Runs with the system proxy ignored."""
    facts: dict = {}
    try:
        started = time.perf_counter()
        socket.getaddrinfo("www.youtube.com", 443, socket.AF_INET)
        facts["dns_ms"] = int((time.perf_counter() - started) * 1000)
    except OSError as exc:
        return False, f"dns: {type(exc).__name__}", facts
    session = _session()
    try:
        for url in PROBE_URLS:
            started = time.perf_counter()
            try:
                r = session.get(url, timeout=timeout, headers={"Connection": "close"})
            except Exception as exc:
                return False, f"https {url.split('/')[2]}: {type(exc).__name__}", facts
            if r.status_code >= 500:
                return False, f"https {url.split('/')[2]}: HTTP {r.status_code}", facts
            facts.setdefault("https_ms", int((time.perf_counter() - started) * 1000))
        try:
            tun = _trace(session, timeout=timeout)
        except Exception as exc:
            return False, f"exit ip: {type(exc).__name__}", facts
        facts["ip"], facts["loc"] = tun.get("ip", ""), tun.get("loc", "")
        try:
            proxies = {"https": f"socks5h://127.0.0.1:{socks_port}"}
            ref = _trace(session, proxies=proxies, timeout=timeout)
            facts["tunnel_ip"] = ref.get("ip", "")
        except Exception:
            facts["tunnel_ip"] = ""
        if facts["tunnel_ip"]:
            if facts["ip"] != facts["tunnel_ip"]:
                return False, f"traffic bypasses tunnel ({facts['ip']} != {facts['tunnel_ip']})", facts
        elif facts["loc"] == "IR":
            return False, "exit ip is Iranian (traffic bypasses tunnel)", facts
        return True, "", facts
    finally:
        session.close()


def quick_health(timeout: float = 6.0) -> bool:
    session = _session()
    try:
        r = session.get(PROBE_URLS[0], timeout=timeout, headers={"Connection": "close"})
        return r.status_code < 500
    except Exception:
        return False
    finally:
        session.close()


# -- per-site log -------------------------------------------------------------
_ID = r"\[(\d+) ([\d.]+(?:ms|s))\]"
_SNIFF = re.compile(_ID + r" .*sniffed .*?domain: ([^\s,]+)")
_OUT = re.compile(_ID + r" outbound/(\w+)\[([\w-]+)\]: outbound connection to (\S+?):(\d+)")
_ERR = re.compile(r"ERROR .*?" + _ID + r" connection: open connection to (\S+?):(\d+) using \S+: (.+)$")
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_IP = re.compile(r"^[\d.]+$|^\[?[0-9a-f:]+\]?$", re.I)


def _short_error(text: str) -> str:
    t = text.lower()
    for key, label in (("nxdomain", "DNS not found"), ("timeout", "timeout"),
                       ("i/o timeout", "timeout"), ("refused", "refused"),
                       ("reset", "reset"), ("reject", "blocked")):
        if key in t:
            return label
    return text.strip()[:60]


class SiteLog:
    """Reads sing-box stderr; emits one line per new site and one per error burst."""

    MAX_SITES = 300

    def __init__(self, stream, log: Callable[[str], None], show_direct: bool = False) -> None:
        # Direct lines are mostly our own cores (Psiphon fronting decoys);
        # only shown when the user has App Bypass entries.
        self._show_direct = show_direct
        self._stream = stream
        self._log = log
        self._domains: dict[str, str] = {}
        self._seen: set[str] = set()
        self._errors: dict[str, float] = {}
        self.thread = threading.Thread(target=self._run, name="pow-tun-sites", daemon=True)
        self.thread.start()

    def _run(self) -> None:
        try:
            for raw in iter(self._stream.readline, ""):
                try:
                    self._line(_ANSI.sub("", raw).rstrip())
                except Exception:
                    pass
        except Exception:
            pass

    def _line(self, line: str) -> None:
        m = _SNIFF.search(line)
        if m:
            self._domains[m.group(1)] = m.group(3).rstrip(".")
            if len(self._domains) > 2000:
                self._domains.clear()
            return
        m = _OUT.search(line)
        if m:
            cid, elapsed, kind, tag, host, port = m.groups()
            host = self._domains.get(cid, host)
            if _IP.match(host) or port == "53":
                return
            key = host.lower()
            if key in self._seen or len(self._seen) >= self.MAX_SITES:
                return
            self._seen.add(key)
            route = "direct" if tag in ("direct", "local-direct") else "tunnel"
            if route == "direct" and not self._show_direct:
                return
            self._log(f"Site {host} via {route} ({elapsed})")
            return
        m = _ERR.search(line)
        if m:
            cid, elapsed, host, port, err = m.groups()
            host = self._domains.get(cid, host)
            if _IP.match(host) and port == "53":
                return
            now = time.monotonic()
            if now - self._errors.get(host, 0) < 60:
                return
            self._errors[host] = now
            self._log(f"Site {host} failed: {_short_error(err)} ({elapsed})")


def other_vpn() -> str:
    """Name of another VPN adapter that is up (its firewall/kill-switch can block our TUN)."""
    script = (
        "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.Name -ne 'UAC-Spoofer' -and "
        "($_.InterfaceDescription + ' ' + $_.Name) -match 'OpenVPN|WireGuard|Windscribe|TAP-|Wintun|WARP|Cisco|Proton|Nord|Hiddify|v2ray|Clash' } | "
        "Select-Object -First 1 -ExpandProperty Name"
    )
    try:
        return subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=10,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        ).stdout.strip()
    except Exception:
        return ""
