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
# Updated MCI DPI reads a single ClientHello. Try the Patterniha hybrid first
# (allowed Fake SNI plus a 5-byte TLS split), then the other MCI-only methods
# and edges. IranCell does not use this list.
MCI_PROTECTED_ROUTE_STRATEGY = "full5"
MCI_PROTECTED_ROUTE_PLANS = (
    ("full5", MCI_PROTECTED_PRIMARY_EDGE),
    ("wrong_seq", MCI_PROTECTED_PRIMARY_EDGE),
    ("tls_sni_records", MCI_PROTECTED_PRIMARY_EDGE),
    ("full5", MCI_PROTECTED_FALLBACK_EDGE_LIST[0]),
    ("tls_sni_records", MCI_PROTECTED_FALLBACK_EDGE_LIST[0]),
    ("plain", MCI_PROTECTED_PRIMARY_EDGE),
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
    # SNI finder tags (carrier, network, edge, fake_sni, method, tested_at,
    # score, fail_streak, demoted). Empty for every other profile.
    maker_meta: dict = field(default_factory=dict)

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
                elif query.get("ech") or query.get("echcl"):
                    clean["route_mode"] = "ech-direct"
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



    xray_mux_enabled: bool = False
    xray_mux_concurrency: int = 8
    # Iranian sites (geosite:category-ir, .ir, geoip:ir, private) bypass the tunnel.
    iran_direct: bool = True

    background_quality_probe_enabled: bool = False
    background_quality_probe_delay_s: int = 30
    log_level: str = "normal"

    pattern_quality_preset: str = "upload"
    pattern_connect_ip: str = "104.18.32.47"
    pattern_fallback_ips: str = "172.64.155.209"
    pattern_use_profile_edges: bool = False
    # Runtime-only: comma list of a Gene Lab strategy's own working edges,
    # tried before the normal edge list. Never persisted (Storage clears it).
    pattern_gene_edges: str = ""
    # Runtime-only: clean edge IPs found by the auto clean-IP finder (never persisted).
    pattern_clean_edges: str = ""
    # Runtime-only: IP chosen with "Use this IP" (Full scan); tried before everything.
    pattern_session_edge: str = ""
    # JSON list of Gene Lab primitive ops (empty = unused)
    pattern_gene_ops: str = ""
    pattern_fake_sni: str = "chatgpt.com"
    pattern_fake_repeat: int = 1
    pattern_decoy_ttl: int = 0
    pattern_ech_fragment: str = "none"
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


UAC_LINK_FIELDS = {
    "address": "uacEdge",
    "fallback_address": "uacFallback",
    "port": "uacPort",
    "method": "uacMethod",
    "spoof_fake_sni": "uacFakeSni",
}
UAC_ROUTE_METHODS = ("combined", "fragment", "half", "multi", "sni_split", "full5", "tls_sni_records")


def parse_uri(uri: str, suggested: bool = False, *, trim_prose: bool = True) -> ProxyProfile | None:
    try:
        raw = uri.strip()
        if trim_prose:
            raw = raw.rstrip("\"'.,;)")
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
                                   else "ech-direct"
                                   if (query.get("ech") or query.get("echcl") or query.get("echconfiglist"))
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
        for field_name, key in UAC_LINK_FIELDS.items():
            value = query.get(key.lower())
            if value is None:
                continue
            if field_name == "port":
                if not value.isascii() or not value.isdecimal() or not 1 <= int(value) <= 65535:
                    return None
                value = int(value)
            elif field_name == "method" and value not in UAC_ROUTE_METHODS:
                return None
            setattr(profile, field_name, value)
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

    def query_value(field):
        return next((query[key.lower()] for key in _EDITABLE_QUERY[field] if query.get(key.lower())), "")

    host = parsed.hostname or profile.config_host
    sni = query_value("sni") or query_value("host_header") or query_value("authority") or host
    host_header = query_value("host_header") or query_value("authority") or sni or profile.sni
    path = query_value("path") or "/"
    if not path.startswith("/"):
        path = "/" + path
    security = (query_value("security") or "tls").strip().lower()
    network = (
        query_value("network")
        or ("raw" if security == "reality" else "ws")
    ).strip().lower()
    if network == "tcp":
        network = "raw"
    try:
        alter_id = max(0, int(query_value("alter_id") or 0))
    except (TypeError, ValueError):
        alter_id = 0
    alpn = [
        value.strip()
        for value in query_value("alpn").split(",")
        if value.strip()
    ]
    insecure = str(
        query.get("allowinsecure") or query.get("insecure") or ""
    ).strip().lower() in {"1", "true", "yes", "on"}
    return {
        "protocol": parsed.scheme.lower(), "user": urllib.parse.unquote(parsed.username or ""),
        "host": host, "port": parsed.port or 443, "sni": sni, "host_header": host_header,
        "path": path, "network": network, "fingerprint": query_value("fingerprint"),
        "pinned": query_value("pinned"),
        "verify_name": query_value("verify_name"),
        "alter_id": alter_id,
        "user_security": query_value("user_security") or "auto",
        "security": security,
        "flow": query_value("flow"),
        "encryption": query_value("encryption") or "none",
        "reality_public_key": query_value("reality_public_key"),
        "reality_short_id": query_value("reality_short_id"),
        "reality_spider_x": query_value("reality_spider_x"),
        "service_name": query_value("service_name"),
        "authority": query_value("authority"),
        "mode": query_value("mode"),
        "extra": query_value("extra"),
        "header_type": query_value("header_type") or "none",
        "alpn": alpn,
        "insecure": insecure,
        "ech": query_value("ech"),
    }


DIRECT_ROUTE_MODES = ("reality-direct", "ech-direct")


_EDITABLE_QUERY = {
    "network": ("type", "network"),
    "host_header": ("host",),
    "path": ("path",),
    "security": ("security",),
    "sni": ("sni", "servername"),
    "fingerprint": ("fp", "fingerprint"),
    "alpn": ("alpn",),
    "flow": ("flow",),
    "encryption": ("encryption",),
    "alter_id": ("aid", "alterId"),
    "user_security": ("scy", "cipher"),
    "service_name": ("serviceName",),
    "authority": ("authority",),
    "mode": ("mode",),
    "extra": ("extra",),
    "header_type": ("headerType",),
    "reality_public_key": ("pbk", "publicKey", "password"),
    "reality_short_id": ("sid", "shortId"),
    "reality_spider_x": ("spx", "spiderX"),
    "ech": ("ech", "echcl", "echconfiglist"),
    "pinned": ("pinnedPeerCertSha256", "pcs"),
    "verify_name": ("verifyPeerCertByName", "vcn"),
    **{f"uac_{field_name}": (key,) for field_name, key in UAC_LINK_FIELDS.items()},
}


def edit_profile_uri(uri: str, changes: dict) -> str:
    """Rewrite edited fields and preserve all other URI components verbatim."""
    if not changes:
        return uri
    parts = urllib.parse.urlsplit(uri)
    netloc = parts.netloc
    if changes.keys() & {"user", "host", "port"}:
        raw_user, at, server = netloc.rpartition("@")
        if not at:
            server = netloc
        if "user" in changes:
            raw_user = urllib.parse.quote(changes["user"], safe="")
        if changes.keys() & {"host", "port"}:
            if server.startswith("["):
                end = server.index("]") + 1
                raw_host, raw_port = server[:end], server[end:].removeprefix(":")
            else:
                raw_host, _, raw_port = server.partition(":")
            if "host" in changes:
                raw_host = changes["host"].removeprefix("[").removesuffix("]")
                if ":" in raw_host:
                    raw_host = f"[{raw_host}]"
            raw_port = str(changes.get("port", raw_port))
            server = raw_host + (f":{raw_port}" if raw_port else "")
        netloc = (raw_user + "@" if raw_user or at else "") + server

    query = parts.query.split("&") if parts.query else []
    for field_name, value in changes.items():
        aliases = _EDITABLE_QUERY.get(field_name)
        if not aliases:
            continue
        keys = [urllib.parse.unquote_plus(entry.partition("=")[0]).lower() for entry in query]
        matching = [[i for i, key in enumerate(keys) if key == alias.lower()] for alias in aliases]
        # Clearing an alias group must also clear any lower-priority alternatives.
        if not value and not field_name.startswith("uac_"):
            removed = {index for indexes in matching for index in indexes}
            query = [entry for index, entry in enumerate(query) if index not in removed]
            continue
        indexes = next((indices for indices in matching if indices and query[indices[-1]].partition("=")[2]),
                       matching[0])
        encoded = urllib.parse.quote(str(value), safe="")
        if indexes:
            index = indexes[-1]
            query[index] = f"{query[index].partition('=')[0]}={encoded}"
        else:
            query.append(f"{aliases[0]}={encoded}")
    fragment = urllib.parse.quote(changes["name"], safe="") if "name" in changes else parts.fragment
    protocol = changes.get("protocol", parts.scheme)
    return f"{protocol}://{netloc}{parts.path}" + (f"?{'&'.join(query)}" if query else "") + (
        f"#{fragment}" if fragment else ""
    )


def uri_has_ech(uri) -> bool:
    try:
        query = {
            str(key).lower(): str(value)
            for key, value in urllib.parse.parse_qsl(
                urllib.parse.urlsplit(str(uri or "")).query, keep_blank_values=True)
        }
    except (TypeError, ValueError):
        return False
    return bool(query.get("ech") or query.get("echcl") or query.get("echconfiglist"))


def is_ech_route(profile) -> bool:
    return (str(getattr(profile, "route_mode", "") or "") == "ech-direct"
            or (str(getattr(profile, "route_mode", "") or "") != "reality-direct"
                and uri_has_ech(getattr(profile, "source_uri", ""))))


def is_direct_route(profile) -> bool:
    """Reality and ECH configs dial the server directly (no fake-SNI spoof)."""
    return (str(getattr(profile, "route_mode", "") or "") in DIRECT_ROUTE_MODES
            or is_ech_route(profile))


def route_label(profile) -> str:
    if str(getattr(profile, "route_mode", "") or "") == "reality-direct":
        return "Reality"
    return "ECH" if is_ech_route(profile) else "SNI"
