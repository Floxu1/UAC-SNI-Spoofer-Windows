from __future__ import annotations

import dataclasses
import re
import urllib.parse
import uuid
from dataclasses import dataclass, field

from .verified_configs import (COUNTRIES, VERIFIED_SPOOF_CONFIGS,
                               VERIFIED_SPOOF_EDGE, VERIFIED_SPOOF_FAKE_SNI,
                               ROTATING_SPOOF_SEQUENCES)


DEFAULT_ADDRESS = "104.18.8.83"
DEFAULT_FALLBACK = "104.18.9.83"
DEFAULT_SNI = "www.speedtest.net"
MCI_PROTECTED_PRIMARY_EDGE = "104.18.1.1"
MCI_PROTECTED_FALLBACK_EDGE_LIST = (
    "172.66.0.1",
)
MCI_PROTECTED_FALLBACK_EDGES = ",".join(MCI_PROTECTED_FALLBACK_EDGE_LIST)
MCI_PROTECTED_FAKE_SNI = "www.speedtest.net"
MCI_PROTECTED_FAKE_REPEAT = 1
MCI_PROTECTED_INJECT_DELAY_MS = 0
MCI_PROTECTED_ROUTE_STRATEGY = "plain"
MCI_PROTECTED_ROUTE_PLANS = tuple(
    (MCI_PROTECTED_ROUTE_STRATEGY, edge)
    for edge in (
        MCI_PROTECTED_PRIMARY_EDGE,
        *MCI_PROTECTED_FALLBACK_EDGE_LIST,
    )
)



SPOOF_META_RE = re.compile(r"^SPOOF-(\d+)-([A-Z]{2})(?:-(\d+)ms)?$", re.I)

BUILTIN_CONFIGS = """trojan://humanity@127.0.0.1:40443?path=%2Fassignment&security=tls&insecure=0&host=www.calmlunch.com&type=ws&allowInsecure=0&sni=www.calmlunch.com#uacSpoofer%201
trojan://humanity@127.0.0.1:40443?path=%2Fassignment&security=tls&insecure=0&host=www.ignitelimit.com&type=ws&allowInsecure=0&sni=www.ignitelimit.com#uacSpoofer%202
trojan://humanity@127.0.0.1:40443?path=assignment&security=tls&insecure=0&type=ws&allowInsecure=0&sni=www.ignitelimit.com#uacSpoofer%203
trojan://humanity@127.0.0.1:40443?path=%2Fassignment%3FTELEGRAM--KANAL--JKVPN--JKVPN--JKVPN--JKVPN--JKVPN--JKVPN&security=tls&insecure=0&fp=chrome&type=ws&allowInsecure=0&sni=www.gossipglove.com#uacSpoofer%204
trojan://humanity@127.0.0.1:40443?path=%2F%2Fassignment&security=tls&insecure=0&host=www.multiplydose.com&type=ws&allowInsecure=0&sni=www.multiplydose.com#uacSpoofer%205
vless://30980fc4-8789-42df-80d1-0c8e5cd26881@127.0.0.1:40443?path=%2Fvpnhu&security=tls&encryption=none&insecure=1&host=cdn.veilvpn.fans&fp=chrome&type=httpupgrade&allowInsecure=1&sni=cdn.veilvpn.fans#uacSpoofer%206"""


@dataclass
class ProxyProfile:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = "New V2Ray config"
    address: str = DEFAULT_ADDRESS
    fallback_address: str = DEFAULT_FALLBACK
    port: int = 443
    sni: str = DEFAULT_SNI
    method: str = "combined"
    source_uri: str = ""
    protocol: str = "vless"
    config_host: str = "127.0.0.1"
    config_port: int = 40443
    last_ping_ok: bool = False
    last_ping_ms: float = 0.0
    origin: str = "user"
    country_code: str = ""
    country_latency_ms: int = 0
    verified_spoof: bool = False
    spoof_fake_sni: str = ""
    rotating_exit: bool = False
    observed_exit_ip: str = ""
    observed_country_code: str = ""
    observed_country_name: str = ""
    country_verified_at: float = 0.0
    country_source: str = ""
    route_mode: str = "sni"
    verified_route: bool = False

    @property
    def target_label(self) -> str:
        ping = f"{self.last_ping_ms:.0f} ms" if self.last_ping_ok else "not tested"
        return f"{self.address}:{self.port} / {self.sni}  •  {ping}"

    @property
    def country_flag(self) -> str:
        return COUNTRIES.get(self.country_code.upper(), ("🌐", "", ""))[0]

    @property
    def route_is_verified(self) -> bool:
        return bool(self.verified_spoof or self.verified_route)

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, raw: dict) -> "ProxyProfile":
        valid = {f.name for f in dataclasses.fields(cls)}
        aliases = {"fallbackAddress": "fallback_address", "sourceUri": "source_uri",
                   "configHost": "config_host", "configPort": "config_port",
                   "lastPingOk": "last_ping_ok", "lastPingMs": "last_ping_ms"}
        clean = {aliases.get(k, k): v for k, v in raw.items() if aliases.get(k, k) in valid}
        if "route_mode" not in clean:
            try:
                query = {
                    str(key).lower(): str(value)
                    for key, value in urllib.parse.parse_qsl(
                        urllib.parse.urlsplit(
                            str(clean.get("source_uri", "") or "")
                        ).query,
                        keep_blank_values=True,
                    )
                }
                if query.get("security", "").lower() == "reality":
                    clean["route_mode"] = "reality-direct"
            except (TypeError, ValueError):
                pass
        return cls(**clean)


@dataclass
class Tuning:
    mode: str = "balanced"
    carrier_mode: str = "auto"
    fake_probe_enabled: bool = True
    fake_probe_count: int = 1
    fake_probe_delay_ms: int = 5
    multi_fragment_size: int = 5
    sni_split_delay_ms: int = 5
    tls_record_delay_ms: int = 5
    multi_delay_ms: int = 3
    half_delay_ms: int = 5
    route_probe_timeout_ms: int = 8000
    initial_race_enabled: bool = True
    strategy_cache_enabled: bool = True
    strategy_cache_ttl_ms: int = 600000
    startup_boost: str = "fast"
    warm_tcp_pool_enabled: bool = True
    warm_tcp_pool_size: int = 2



    xray_mux_enabled: bool = True
    xray_mux_concurrency: int = 8

    background_quality_probe_enabled: bool = False
    background_quality_probe_delay_s: int = 30
    log_level: str = "normal"

    pattern_quality_preset: str = "upload"
    pattern_connect_ip: str = "104.18.32.47"
    pattern_fallback_ips: str = "172.64.155.209"
    pattern_use_profile_edges: bool = False
    pattern_fake_sni: str = "chatgpt.com"
    pattern_fake_repeat: int = 1
    pattern_inject_delay_ms: int = 1
    pattern_ack_timeout_ms: int = 3000
    pattern_connect_timeout_ms: int = 2500
    pattern_relay_buffer_kb: int = 512
    pattern_socket_buffer_kb: int = 4096
    pattern_max_sessions: int = 12
    pattern_edge_failure_cooldown_s: int = 8
    pattern_keepalive_idle_s: int = 11
    pattern_keepalive_interval_s: int = 3
    pattern_keepalive_count: int = 3
    pattern_upload_optimized: bool = True

    @classmethod
    def preset(cls, mode: str) -> "Tuning":
        normalized = (mode or "balanced").strip().lower()
        if normalized in {"maximum", "upload"}:
            return cls(mode=mode, fake_probe_enabled=False, fake_probe_count=0,
                       fake_probe_delay_ms=0, route_probe_timeout_ms=1500,
                       initial_race_enabled=False, warm_tcp_pool_enabled=False,
                       xray_mux_enabled=True, xray_mux_concurrency=8,
                       background_quality_probe_enabled=False, log_level="minimal",
                       pattern_quality_preset="maximum", pattern_inject_delay_ms=0,
                       pattern_ack_timeout_ms=2200, pattern_connect_timeout_ms=1800,
                       pattern_relay_buffer_kb=512, pattern_socket_buffer_kb=4096,
                       pattern_max_sessions=12, pattern_edge_failure_cooldown_s=8,
                       pattern_keepalive_idle_s=10, pattern_keepalive_interval_s=2,
                       pattern_keepalive_count=4, pattern_upload_optimized=True)
        if normalized == "streaming":
            return cls(mode=mode, fake_probe_enabled=False, fake_probe_count=0,
                       initial_race_enabled=False, warm_tcp_pool_enabled=False,
                       xray_mux_enabled=False, xray_mux_concurrency=4,
                       background_quality_probe_enabled=False, log_level="minimal",
                       pattern_quality_preset="streaming", pattern_inject_delay_ms=0,
                       pattern_ack_timeout_ms=2500, pattern_connect_timeout_ms=2000,
                       pattern_relay_buffer_kb=1024, pattern_socket_buffer_kb=4096,
                       pattern_max_sessions=10, pattern_edge_failure_cooldown_s=8,
                       pattern_keepalive_idle_s=10, pattern_keepalive_interval_s=2,
                       pattern_keepalive_count=4, pattern_upload_optimized=True)
        if normalized in {"fast", "low_latency"}:
            return cls(mode="fast", fake_probe_enabled=False, fake_probe_count=0,
                       fake_probe_delay_ms=0, multi_fragment_size=256,
                       sni_split_delay_ms=0, tls_record_delay_ms=0, multi_delay_ms=0,
                       half_delay_ms=0, route_probe_timeout_ms=1200,
                       initial_race_enabled=False, warm_tcp_pool_enabled=False,
                       warm_tcp_pool_size=2, xray_mux_enabled=True, xray_mux_concurrency=8,
                       background_quality_probe_enabled=False, log_level="minimal",
                       pattern_quality_preset="low_latency", pattern_inject_delay_ms=0,
                       pattern_ack_timeout_ms=1600, pattern_connect_timeout_ms=1600,
                       pattern_relay_buffer_kb=128, pattern_socket_buffer_kb=1024,
                       pattern_max_sessions=10, pattern_edge_failure_cooldown_s=6,
                       pattern_keepalive_idle_s=9, pattern_keepalive_interval_s=2,
                       pattern_keepalive_count=3, pattern_upload_optimized=True)
        if normalized in {"compatibility", "stealth"}:
            return cls(mode=mode, fake_probe_count=2, fake_probe_delay_ms=75,
                       multi_fragment_size=5, sni_split_delay_ms=60, tls_record_delay_ms=50,
                       multi_delay_ms=15, half_delay_ms=50, route_probe_timeout_ms=8000,
                       initial_race_enabled=False, warm_tcp_pool_enabled=False,
                       warm_tcp_pool_size=1, xray_mux_enabled=False, xray_mux_concurrency=4,
                       background_quality_probe_enabled=False, log_level="normal",
                       pattern_quality_preset="compatibility", pattern_inject_delay_ms=2,
                       pattern_ack_timeout_ms=8000, pattern_connect_timeout_ms=5000,
                       pattern_relay_buffer_kb=256, pattern_socket_buffer_kb=512,
                       pattern_max_sessions=4, pattern_edge_failure_cooldown_s=12,
                       pattern_keepalive_idle_s=15, pattern_keepalive_interval_s=5,
                       pattern_keepalive_count=3, pattern_upload_optimized=False)
        return cls(mode="balanced")

    @classmethod
    def carrier_preset(cls, carrier: str) -> "Tuning":
        """Return an isolated, modem-safe baseline for one mobile carrier."""
        normalized = (carrier or "auto").strip().lower()
        if normalized == "mci":
            tuning = cls.preset("compatibility")
            tuning.carrier_mode = "mci"
            tuning.xray_mux_enabled = False
            tuning.xray_mux_concurrency = 4
            tuning.pattern_connect_ip = MCI_PROTECTED_PRIMARY_EDGE
            tuning.pattern_fallback_ips = MCI_PROTECTED_FALLBACK_EDGES
            tuning.pattern_fake_sni = MCI_PROTECTED_FAKE_SNI
            tuning.pattern_quality_preset = "compatibility"
            tuning.pattern_inject_delay_ms = 2
            tuning.pattern_ack_timeout_ms = 8000
            tuning.pattern_connect_timeout_ms = 5000
            tuning.pattern_relay_buffer_kb = 256
            tuning.pattern_socket_buffer_kb = 512
            tuning.pattern_max_sessions = 4
            tuning.pattern_edge_failure_cooldown_s = 12
            tuning.pattern_keepalive_idle_s = 15
            tuning.pattern_keepalive_interval_s = 5
            tuning.pattern_keepalive_count = 3
            tuning.pattern_upload_optimized = False
            tuning.background_quality_probe_enabled = False
            tuning.log_level = "normal"
            return tuning
        if normalized == "irancell":
            tuning = cls.preset("maximum")
            tuning.carrier_mode = "irancell"
            tuning.pattern_connect_ip = "104.19.229.21"
            tuning.pattern_fallback_ips = "104.19.230.21"
            tuning.pattern_fake_sni = "chatgpt.com"
            tuning.xray_mux_enabled = True
            tuning.xray_mux_concurrency = 8
            tuning.pattern_max_sessions = 12
            return tuning
        tuning = cls.preset("balanced")
        tuning.carrier_mode = "auto"
        return tuning

    @classmethod
    def enforce_carrier(cls, value: "Tuning", carrier: str | None = None) -> "Tuning":
        candidate = cls.from_dict(value.to_dict())
        normalized = (carrier or candidate.carrier_mode or "auto").strip().lower()
        if normalized not in {"auto", "mci", "irancell"}:
            normalized = "auto"
        candidate.carrier_mode = normalized
        if normalized != "mci":
            return candidate
        protected = cls.carrier_preset("mci")
        log_level = str(candidate.log_level or "minimal").strip().lower()
        protected.log_level = log_level if log_level in {"minimal", "normal"} else "minimal"
        return protected

    def is_legacy_mci_compatibility(self) -> bool:
        """Match only the persisted low-throughput MCI compatibility shape.

        Route identity is deliberately excluded: the primary edge, fallback
        list, Fake SNI and profile-edge preference are user measurements that
        must survive a preset migration.
        """
        if self.carrier_mode != "mci":
            return False
        legacy = type(self).carrier_preset("mci")
        compatibility = type(self).preset("compatibility")
        compatibility_fields = (
            "mode",
            "xray_mux_enabled",
            "xray_mux_concurrency",
            "background_quality_probe_enabled",
            "background_quality_probe_delay_s",
            "log_level",
            "pattern_quality_preset",
            "pattern_inject_delay_ms",
            "pattern_ack_timeout_ms",
            "pattern_connect_timeout_ms",
            "pattern_relay_buffer_kb",
            "pattern_socket_buffer_kb",
            "pattern_max_sessions",
            "pattern_edge_failure_cooldown_s",
            "pattern_keepalive_idle_s",
            "pattern_keepalive_interval_s",
            "pattern_keepalive_count",
            "pattern_upload_optimized",
        )
        for name in compatibility_fields:
            setattr(legacy, name, getattr(compatibility, name))

        route_fields = {
            "pattern_connect_ip",
            "pattern_fallback_ips",
            "pattern_use_profile_edges",
            "pattern_fake_sni",
        }
        return all(getattr(self, field.name) == getattr(legacy, field.name)
                   for field in dataclasses.fields(type(self))
                   if field.name not in route_fields)

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, raw: dict) -> "Tuning":
        valid = {f.name for f in dataclasses.fields(cls)}
        return cls(**{k: v for k, v in raw.items() if k in valid})


def parse_uri(uri: str, suggested: bool = False) -> ProxyProfile | None:
    try:
        raw = uri.strip().rstrip("\"'.,;)")
        parsed = urllib.parse.urlsplit(raw)
        protocol = parsed.scheme.lower()
        if protocol not in {"vless", "trojan", "vmess"} or not parsed.hostname:
            return None
        query = {
            str(key).lower(): str(value)
            for key, value in urllib.parse.parse_qsl(
                parsed.query, keep_blank_values=True
            )
        }
        sni = next((
            query.get(key, "") for key in (
                "sni", "servername", "host", "authority"
            ) if query.get(key)
        ), parsed.hostname)
        fragment = urllib.parse.unquote(parsed.fragment)
        name = fragment or f"{protocol.upper()} {parsed.hostname}"
        profile = ProxyProfile(name=name, source_uri=raw, protocol=protocol,
                               config_host=parsed.hostname, config_port=parsed.port or 443,
                               origin="builtin" if suggested else "user", sni=sni,
                               route_mode=(
                                   "reality-direct"
                                   if query.get("security", "").lower() == "reality"
                                   else "sni"
                               ))
        match = SPOOF_META_RE.fullmatch(fragment)
        if match:
            sequence, country_code, latency_ms = match.groups()
            country_code = country_code.upper()
            _flag, english_name, _persian_name = COUNTRIES.get(
                country_code, ("🌐", country_code, country_code)
            )
            profile.id = str(uuid.uuid5(uuid.NAMESPACE_URL, raw))
            profile.name = f"{english_name} · Spoof {int(sequence):03d}"
            profile.address = VERIFIED_SPOOF_EDGE
            profile.fallback_address = ""
            profile.origin = "verified"
            profile.country_code = country_code
            profile.country_latency_ms = 0
            profile.verified_spoof = True
            profile.spoof_fake_sni = VERIFIED_SPOOF_FAKE_SNI
            profile.rotating_exit = int(sequence) in ROTATING_SPOOF_SEQUENCES
            if profile.rotating_exit:
                profile.country_code = "XX"
                profile.name = f"Dynamic exit · Spoof {int(sequence):03d}"
        return profile
    except Exception:
        return None


URI_RE = re.compile(r"(?:vless|trojan|vmess)://[^\s]+", re.I)


def parse_many(text: str, suggested: bool = False) -> list[ProxyProfile]:
    return [p for p in (parse_uri(m.group(0), suggested) for m in URI_RE.finditer(text or "")) if p]


def default_profiles() -> list[ProxyProfile]:
    legacy_profiles = parse_many(BUILTIN_CONFIGS, suggested=True)
    for index, profile in enumerate(legacy_profiles, 1):
        profile.name = f"uacSpoofer {index}"
        profile.id = str(uuid.uuid5(uuid.NAMESPACE_URL, profile.source_uri))
    return legacy_profiles


def verified_profiles() -> list[ProxyProfile]:
    """Return the versioned, country-labelled profiles bundled with the app."""
    return parse_many(VERIFIED_SPOOF_CONFIGS, suggested=True)


def parse_outbound(profile: ProxyProfile) -> dict:
    parsed = urllib.parse.urlsplit(profile.source_uri)
    query = {
        str(key).lower(): str(value)
        for key, value in urllib.parse.parse_qsl(
            parsed.query, keep_blank_values=True
        )
    }
    host = parsed.hostname or profile.config_host
    sni = next((
        query.get(key, "") for key in (
            "sni", "servername", "host", "authority"
        ) if query.get(key)
    ), host)
    host_header = query.get("host") or query.get("authority") or sni or profile.sni
    path = query.get("path") or "/"
    if not path.startswith("/"):
        path = "/" + path
    security = (query.get("security") or "tls").strip().lower()
    network = (
        query.get("type") or query.get("network")
        or ("raw" if security == "reality" else "ws")
    ).strip().lower()
    if network == "tcp":
        network = "raw"
    try:
        alter_id = max(0, int(query.get("aid") or query.get("alterid") or 0))
    except (TypeError, ValueError):
        alter_id = 0
    alpn = [
        value.strip()
        for value in (query.get("alpn") or "").split(",")
        if value.strip()
    ]
    insecure = str(
        query.get("allowinsecure") or query.get("insecure") or ""
    ).strip().lower() in {"1", "true", "yes", "on"}
    return {
        "protocol": parsed.scheme.lower(), "user": urllib.parse.unquote(parsed.username or ""),
        "host": host, "port": parsed.port or 443, "sni": sni, "host_header": host_header,
        "path": path, "network": network, "fingerprint": query.get("fp") or query.get("fingerprint") or "",
        "pinned": query.get("pinnedpeercertsha256") or query.get("pcs") or "",
        "verify_name": query.get("verifypeercertbyname") or query.get("vcn") or "",
        "alter_id": alter_id,
        "user_security": query.get("scy") or query.get("cipher") or "auto",
        "security": security,
        "flow": query.get("flow") or "",
        "encryption": query.get("encryption") or "none",
        "reality_public_key": (
            query.get("pbk") or query.get("publickey")
            or query.get("password") or ""
        ),
        "reality_short_id": query.get("sid") or query.get("shortid") or "",
        "reality_spider_x": query.get("spx") or query.get("spiderx") or "",
        "service_name": query.get("servicename") or "",
        "authority": query.get("authority") or "",
        "mode": query.get("mode") or "",
        "extra": query.get("extra") or "",
        "header_type": query.get("headertype") or "none",
        "alpn": alpn,
        "insecure": insecure,
    }
