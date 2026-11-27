"""torrc builder with Portable/MSI binary discovery, strict exit country, and PT proxy."""
from __future__ import annotations

import ctypes
import os
from pathlib import Path
from urllib.parse import urlsplit

from .binaries import find_tor_asset
from .bridges import bridge_transport, normalize_bridge_line
from .store import TorSettings, normalize_country_list


def find_tor_binary() -> Path | None:
    return find_tor_asset("tor.exe")


def find_pt_binary(name: str) -> Path | None:
    return find_tor_asset(name)


def find_geoip_files() -> tuple[Path | None, Path | None]:
    return find_tor_asset("geoip"), find_tor_asset("geoip6")


def _win_abs_path(path: Path) -> str:
    return str(path.resolve())


def _win_exec_path(path: Path) -> str:
    resolved = str(path.resolve())
    if os.name == "nt" and " " in resolved:
        buf = ctypes.create_unicode_buffer(32768)
        if ctypes.windll.kernel32.GetShortPathNameW(resolved, buf, len(buf)) and buf.value:
            return buf.value
        escaped = resolved.replace("\\", "\\\\")
        return f'"{escaped}"'
    return resolved


def _braced_countries(csv_text: str, *, skip: str = "") -> str:
    skip_l = str(skip or "").strip().lower()
    items = [
        tok.strip() for tok in normalize_country_list(csv_text).split(",")
        if tok.strip() and tok.strip() != skip_l
    ]
    return ",".join(f"{{{cc}}}" for cc in items)


def _upstream_proxy_directives(proxy_url: str) -> list[str]:
    raw = str(proxy_url or "").strip()
    if not raw:
        return []
    if "://" not in raw:
        raw = "socks5://" + raw
    parsed = urlsplit(raw)
    if not parsed.hostname or not parsed.port:
        return []
    addr = f"{parsed.hostname}:{parsed.port}"
    scheme = parsed.scheme.lower()
    out: list[str] = []
    if scheme in ("socks5", "socks5h", "socks"):
        out.append(f"Socks5Proxy {addr}")
        if parsed.username:
            out.append(f"Socks5ProxyUsername {parsed.username}")
        if parsed.password:
            out.append(f"Socks5ProxyPassword {parsed.password}")
    elif scheme in ("http", "https"):
        out.append(f"HTTPSProxy {addr}")
        if parsed.username:
            out.append(f"HTTPSProxyAuthenticator {parsed.username}:{parsed.password or ''}")
    return out


def build_torrc(
    settings: TorSettings,
    *,
    data_dir: Path,
    cookie_path: Path,
    socks_port: int,
    http_port: int,
    control_port: int,
    dns_port: int,
    bridges: list[str],
    transport_mode: str,
    pt_proxy_port: int = 0,
) -> str:
    socks_flags = " IsolateDestAddr IsolateDestPort" if settings.isolate_streams else ""
    lines = [
        f"DataDirectory {_win_abs_path(data_dir)}",
        f"SocksPort 127.0.0.1:{int(socks_port)}{socks_flags}",
        f"HTTPTunnelPort 127.0.0.1:{int(http_port)}",
        f"ControlPort 127.0.0.1:{int(control_port)}",
        f"DNSPort 127.0.0.1:{int(dns_port)}",
        "AutomapHostsOnResolve 1",
        "VirtualAddrNetworkIPv4 10.192.0.0/10",
        "CookieAuthentication 1",
        f"CookieAuthFile {_win_abs_path(cookie_path)}",
        f"MaxCircuitDirtiness {int(settings.max_circuit_dirtiness)}",
        f"ClientUseIPv6 {1 if settings.use_ipv6 else 0}",
        "AvoidDiskWrites 1",
        "ClientOnly 1",
        "Log notice stdout",
    ]
    geoip, geoip6 = find_geoip_files()
    if geoip is not None:
        lines.append(f"GeoIPFile {_win_abs_path(geoip)}")
    if geoip6 is not None:
        lines.append(f"GeoIPv6File {_win_abs_path(geoip6)}")

    clean_bridges = [b for raw in bridges if (b := normalize_bridge_line(raw))]
    use_bridges = transport_mode != "direct" and bool(clean_bridges)

    chosen_exit = settings.exit_country_code.strip().lower()
    if chosen_exit:
        lines.append(f"ExitNodes {{{chosen_exit}}}")
        lines.append("StrictNodes 1")

    entry = _braced_countries(settings.entry_nodes)
    if entry and not use_bridges:
        lines.append(f"EntryNodes {entry}")

    excl = _braced_countries(settings.exclude_nodes, skip=chosen_exit)
    if excl and not use_bridges:
        lines.append(f"ExcludeNodes {excl}")

    excl_exit = _braced_countries(settings.exclude_exit_nodes, skip=chosen_exit)
    if excl_exit:
        lines.append(f"ExcludeExitNodes {excl_exit}")

    if settings.reachable_80_443_only:
        lines.append("FascistFirewall 1")
        lines.append("ReachableAddresses *:80,*:443")

    if settings.upstream_proxy:
        lines.extend(_upstream_proxy_directives(settings.upstream_proxy))
    elif pt_proxy_port > 0:
        lines.append(f"Socks5Proxy 127.0.0.1:{int(pt_proxy_port)}")

    if use_bridges and clean_bridges:
        lines.append("UseBridges 1")
        needed_pts = {bridge_transport(b) for b in clean_bridges}
        lyrebird = find_pt_binary("lyrebird.exe") or find_pt_binary("obfs4proxy.exe")
        snowflake = find_pt_binary("snowflake-client.exe") or lyrebird
        conjure = find_pt_binary("conjure-client.exe")
        if needed_pts & {"obfs4", "webtunnel", "meek_lite", "scramblesuit"}:
            if lyrebird is None:
                raise RuntimeError("lyrebird.exe is missing (required for WebTunnel/obfs4)")
            lines.append(f"ClientTransportPlugin obfs4,webtunnel,meek_lite exec {_win_exec_path(lyrebird)}")
        if "snowflake" in needed_pts:
            if snowflake is None:
                raise RuntimeError("snowflake-client.exe is missing (required for Snowflake)")
            lines.append(f"ClientTransportPlugin snowflake exec {_win_exec_path(snowflake)}")
        if "conjure" in needed_pts and conjure is not None:
            lines.append(f"ClientTransportPlugin conjure exec {_win_exec_path(conjure)}")
        for bridge in clean_bridges[:24]:
            lines.append(f"Bridge {bridge}")

    return "\n".join(lines) + "\n"
