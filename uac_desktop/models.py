from __future__ import annotations

import dataclasses
import re
import urllib.parse
import uuid
from dataclasses import dataclass, field


DEFAULT_ADDRESS = "104.18.8.83"
DEFAULT_FALLBACK = "104.18.9.83"
DEFAULT_SNI = "www.speedtest.net"

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

    @property
    def target_label(self) -> str:
        ping = f"{self.last_ping_ms:.0f} ms" if self.last_ping_ok else "not tested"
        return f"{self.address}:{self.port} / {self.sni}  •  {ping}"

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, raw: dict) -> "ProxyProfile":
        valid = {f.name for f in dataclasses.fields(cls)}
        aliases = {"fallbackAddress": "fallback_address", "sourceUri": "source_uri",
                   "configHost": "config_host", "configPort": "config_port",
                   "lastPingOk": "last_ping_ok", "lastPingMs": "last_ping_ms"}
        clean = {aliases.get(k, k): v for k, v in raw.items() if aliases.get(k, k) in valid}
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
    # patterniha/SNI-Spoofing wrong-sequence core quality controls.
    pattern_quality_preset: str = "upload"
    pattern_connect_ip: str = "188.114.98.0"
    pattern_fallback_ips: str = "188.114.99.0,104.18.8.83,104.18.9.83"
    pattern_use_profile_edges: bool = False
    pattern_fake_sni: str = "auth.vercel.com"
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
            tuning = cls.preset("maximum")
            tuning.carrier_mode = "mci"
            
            
            
            
            tuning.xray_mux_enabled = False
            tuning.xray_mux_concurrency = 4
            tuning.pattern_connect_ip = "188.114.98.0"
            tuning.pattern_fallback_ips = "188.114.99.0"
            tuning.pattern_fake_sni = "chatgpt.com"
            tuning.pattern_quality_preset = "maximum"
            tuning.pattern_inject_delay_ms = 0
            tuning.pattern_ack_timeout_ms = 3000
            tuning.pattern_connect_timeout_ms = 2000
            tuning.pattern_relay_buffer_kb = 512
            tuning.pattern_socket_buffer_kb = 4096
            tuning.pattern_max_sessions = 10
            tuning.pattern_edge_failure_cooldown_s = 8
            tuning.pattern_keepalive_idle_s = 10
            tuning.pattern_keepalive_interval_s = 2
            tuning.pattern_keepalive_count = 4
            tuning.pattern_upload_optimized = True
            tuning.background_quality_probe_enabled = False
            tuning.log_level = "minimal"
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
        if protocol not in {"vless", "trojan"} or not parsed.hostname:
            return None
        query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
        sni = next((query.get(k, "") for k in ("sni", "servername", "serverName", "host", "authority") if query.get(k)), parsed.hostname)
        name = urllib.parse.unquote(parsed.fragment) or f"{protocol.upper()} {parsed.hostname}"
        return ProxyProfile(name=name, source_uri=raw, protocol=protocol,
                            config_host=parsed.hostname, config_port=parsed.port or 443,
                            origin="builtin" if suggested else "user", sni=DEFAULT_SNI)
    except Exception:
        return None


URI_RE = re.compile(r"(?:vless|trojan)://[^\s]+", re.I)


def parse_many(text: str, suggested: bool = False) -> list[ProxyProfile]:
    return [p for p in (parse_uri(m.group(0), suggested) for m in URI_RE.finditer(text or "")) if p]


def default_profiles() -> list[ProxyProfile]:
    profiles = parse_many(BUILTIN_CONFIGS, suggested=True)
    for index, profile in enumerate(profiles, 1):
        profile.name = f"uacSpoofer {index}"
    return profiles


def parse_outbound(profile: ProxyProfile) -> dict:
    parsed = urllib.parse.urlsplit(profile.source_uri)
    query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    host = parsed.hostname or profile.config_host
    sni = next((query.get(k, "") for k in ("sni", "serverName", "servername", "host", "authority") if query.get(k)), host)
    host_header = query.get("host") or query.get("authority") or sni or profile.sni
    path = query.get("path") or "/"
    if not path.startswith("/"):
        path = "/" + path
    network = (query.get("type") or "ws").lower()
    if network not in {"ws", "httpupgrade"}:
        network = "ws"
    return {
        "protocol": parsed.scheme.lower(), "user": urllib.parse.unquote(parsed.username or ""),
        "host": host, "port": parsed.port or 443, "sni": sni, "host_header": host_header,
        "path": path, "network": network, "fingerprint": query.get("fp") or query.get("fingerprint") or "",
        "pinned": query.get("pinnedPeerCertSha256") or query.get("pcs") or "",
        "verify_name": query.get("verifyPeerCertByName") or query.get("vcn") or "",
    }
