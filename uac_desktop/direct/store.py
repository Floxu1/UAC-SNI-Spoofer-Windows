from __future__ import annotations

import ipaddress
import json
import re
import tempfile
import time
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from urllib.parse import urlsplit

from ..pow.regions import normalize_region
from .resolvers import BUILTIN_RESOLVERS, parse_resolver, resolver_catalog

STARTUP_BUDGET = {"turbo": 75, "balanced": 90, "thorough": 105}
DEFAULT_UNFILTERED_DNS = "https://1.1.1.1/dns-query"
H2_OPTIONS = (
    "h2_fragmentation", "h2_fingerprint", "tls_curve_preset",
    "h2_large_windows", "h2_socket_tuning", "perf_profile",
)


def _fragment_list(value: str, default: str) -> str:
    parts = list(filter(None, re.split(r"[, ;]+", value.strip())))
    if parts and all(re.fullmatch(r"[0-9]{1,5}(?:-[0-9]{1,5})?", part) for part in parts):
        return ",".join(parts)
    return default


def _dns(value: str) -> str:
    value = value.strip()
    if value == "https://cloudflare-dns.com/dns-query":
        return DEFAULT_UNFILTERED_DNS
    if value.startswith(("https://", "tcp://")):
        try:
            address = urlsplit(value)
            if address.hostname and address.username is None and address.password is None and not address.fragment:
                return value
        except ValueError:
            pass
        return DEFAULT_UNFILTERED_DNS
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return DEFAULT_UNFILTERED_DNS


@dataclass(frozen=True)
class DirectSettings:
    wireguard_over_direct: bool = True
    scan_mode: str = "balanced"
    auto_select_dns: bool = True
    exit_country_code: str = ""
    fragment_enabled: bool = False
    variant: str = "A"
    hello_lengths: str = "6,98,1"
    hello_delays: str = "0"
    hello_max_split: int = 0
    second_stage_enabled: bool = True
    second_lengths: str = "114,1"
    second_delays: str = "1"
    second_max_split: int = 11
    tcp_fragment_enabled: bool = False
    tcp_lengths: str = "1"
    tcp_delays: str = "1"
    tcp_max_split: int = 201
    udp_noise: bool = False
    block_quic: bool = True
    ipv6: bool = False
    iran_direct: bool = True
    unfiltered_dns: str = DEFAULT_UNFILTERED_DNS
    domestic_dns: str = "localhost"
    pinned_dns: str = ""
    custom_dns: tuple[str, ...] = ()
    connection_mode: str = "vpn"
    kill_switch: bool = False
    routing_mode: str = "all"
    domains_direct: str = ""
    ips_direct: str = ""

    @property
    def adaptive_client_hello(self) -> bool:
        return True

    @classmethod
    def from_dict(cls, raw: dict) -> DirectSettings:
        defaults = cls()
        values = {}
        for field in fields(cls):
            name = field.name
            default = getattr(defaults, name)
            value = raw.get(name, default)
            if type(value) is not type(default):
                value = default
            if name.endswith(("_lengths", "_delays")):
                value = _fragment_list(value, default)
            elif name.endswith("_max_split"):
                value = min(1000, max(0, value))
            values[name] = value
        raw_scan_mode = raw.get("scan_mode")
        if not isinstance(raw_scan_mode, str) or raw_scan_mode not in STARTUP_BUDGET:
            values["scan_mode"] = "thorough" if raw.get("scan_ranges_by_latency") is True else defaults.scan_mode
        if values["connection_mode"] not in ("vpn", "proxy"):
            values["connection_mode"] = defaults.connection_mode
        if values["routing_mode"] not in ("all", "bypass", "only"):
            values["routing_mode"] = defaults.routing_mode
        values["exit_country_code"] = normalize_region(values["exit_country_code"])
        values["variant"] = "B" if values["variant"] == "B" else "A"
        values["hello_lengths"] = ",".join(
            part if int(part.split("-", 1)[0]) else "1"
            for part in values["hello_lengths"].split(",")
        )
        values["unfiltered_dns"] = _dns(values["unfiltered_dns"])
        values["domestic_dns"] = values["domestic_dns"].strip() or defaults.domestic_dns
        addresses = raw.get("custom_dns")
        if isinstance(addresses, (list, tuple)):
            values["custom_dns"] = tuple(resolver.url for resolver in resolver_catalog(addresses)[len(BUILTIN_RESOLVERS):])
        try:
            values["pinned_dns"] = parse_resolver(values["pinned_dns"]).url
        except ValueError:
            values["pinned_dns"] = ""
        return cls(**values)


def read_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False, mode="w", encoding="utf-8") as file:
        pending = Path(file.name)
        try:
            json.dump(value, file, ensure_ascii=False, indent=2)
            file.close()
            pending.replace(path)
        finally:
            file.close()
            pending.unlink(missing_ok=True)


def ipv4_h2_peer(value: str) -> str | None:
    host, _, port = value.partition(":")
    if not re.fullmatch(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}", host) or port not in ("", "443", "1701"):
        return None
    octets = [int(part) for part in host.split(".")]
    if max(octets) > 255:
        return None
    return ".".join(map(str, octets)) + ":443"


@dataclass(frozen=True)
class VerifiedProfile:
    source: str
    peer: str
    options: dict
    network: str
    verified_at: float


class DirectStore:
    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.settings_path = directory / "settings.json"

    def saved_settings(self) -> dict:
        return read_json(self.settings_path)

    def settings(self) -> DirectSettings:
        return DirectSettings.from_dict(self.saved_settings())

    def save_settings(self, value: DirectSettings, *, exclude=()) -> DirectSettings:
        validated = DirectSettings.from_dict(asdict(value))
        fields = {name: value for name, value in asdict(validated).items() if name not in exclude}
        write_json(self.settings_path, {**self.saved_settings(), **fields})
        return validated

    def export_settings(self, path: Path, *, exclude=()) -> None:
        settings = {name: value for name, value in asdict(self.settings()).items() if name not in exclude}
        write_json(path, {"format": "uac-direct-settings", "version": 1, "settings": settings})

    def import_settings(self, path: Path, *, exclude=()) -> DirectSettings:
        backup = read_json(path)
        value = backup.get("settings")
        if backup.get("format") != "uac-direct-settings" or backup.get("version") != 1 or not isinstance(value, dict):
            raise ValueError("The file is not a supported UAC Direct settings backup")
        settings = DirectSettings.from_dict(value)
        return self.save_settings(settings, exclude=exclude)

    def _profile_path(self, source: str) -> Path:
        return self.directory / f"verified-{source}-h2.json"

    def find_profile(self, network: str, excluded_ip: str | None = None) -> VerifiedProfile | None:
        if not network:
            return None
        now = time.time()
        for source in ("direct", "pow"):
            value = read_json(self._profile_path(source))
            verified = value.get("verified_at")
            raw_peer = value.get("peer")
            options = value.get("options")
            if value.get("network") != network or not isinstance(verified, (int, float)):
                continue
            if not 0 <= now - verified <= 86400 or not isinstance(raw_peer, str) or not isinstance(options, dict):
                continue
            peer = ipv4_h2_peer(raw_peer)
            if peer and peer.partition(":")[0] != excluded_ip:
                return VerifiedProfile(source, peer, {key: options[key] for key in H2_OPTIONS if key in options}, network, verified)
        return None

    def save_verified(self, source: str, network: str, peer: str, config: dict) -> None:
        peer = ipv4_h2_peer(peer)
        if source in ("direct", "pow") and network and peer and config.get("masque_transport") == "h2":
            write_json(self._profile_path(source), {
                "network": network, "peer": peer, "verified_at": time.time(),
                "options": {key: config[key] for key in H2_OPTIONS if key in config},
            })

    def compatibility_hint(self, network: str) -> str | None:
        value = read_json(self.directory / "compatibility.json")
        peer = value.get("peer")
        if network and network == value.get("network") and isinstance(peer, str):
            return ipv4_h2_peer(peer)
        return None

    def save_compatibility_hint(self, network: str, peer: str) -> None:
        peer = ipv4_h2_peer(peer)
        if network and peer:
            write_json(self.directory / "compatibility.json", {"network": network, "peer": peer})
