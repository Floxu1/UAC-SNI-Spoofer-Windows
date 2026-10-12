"""UAC PoW engine configuration — Windows port of the mobile engine-3 config.

Mirrors ``PowCoreConfig`` + ``PowEngineSettings`` + the Psiphon strategy config
(``PowPsiphonProtocols.buildConfig``) from the Android app, so the Windows
engine dials exactly the same way: same recipes, same firewall plans, same
scan budgets, same Psiphon strategies.

Desktop differences (deliberate, documented):
- There is no SIM/carrier on Windows, so ``firewall=auto`` selects the
  Hamrah Aval (MCI) plan — the strict one. Same rule as mobile ("default must
  connect on Hamrah Aval").
- Ports avoid the Xray desktop pair (20808/20809): the aether outer leg
  listens on 1820 (same as mobile ``CHAIN_SOCKS_PORT``) and the Psiphon inner
  hop on 1821.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from pathlib import Path

# ---------------------------------------------------------------------------
# Ports
# ---------------------------------------------------------------------------

#: Outer WARP/MASQUE leg (aether) SOCKS listen port. Same as mobile.
CHAIN_SOCKS_PORT = 1820
#: Psiphon inner-hop SOCKS listen port.
PSIPHON_SOCKS_PORT = 1821
#: Legacy/default aether listen port (unused in chain mode).
AETHER_SOCKS_PORT = 1819

# ---------------------------------------------------------------------------
# Modes / recipes / fetches (ids match mobile exactly)
# ---------------------------------------------------------------------------

OUTER_AUTO = "auto"
DISCOVERY_CACHE = "cache"
DISCOVERY_FRESH = "fresh"

SCAN_TURBO = "turbo"
SCAN_BALANCED = "balanced"
SCAN_THOROUGH = "thorough"
SCAN_MODES = (SCAN_TURBO, SCAN_BALANCED, SCAN_THOROUGH)

#: MASQUE first: MCI advanced filtering drops UDP before the handshake.
OUTER_LADDER = ["masque", "gool", "wireguard"]
MCI_LADDER = ["wireguard", "gool", "masque"]

FIREWALL_AUTO = "auto"
FIREWALL_IRANCELL = "irancell"
FIREWALL_MCI = "mci"
FIREWALLS = (FIREWALL_AUTO, FIREWALL_IRANCELL, FIREWALL_MCI)

RECIPE_AUTO = "auto"
RECIPE_WARP_V6 = "warp-v6"
RECIPE_WARP_ANY = "warp-any"
RECIPE_WOW_V6 = "wow-v6"
RECIPE_WOW_ANY = "wow-any"
RECIPE_MASQUE_H2 = "masque-h2"
RECIPE_MASQUE_H3 = "masque-h3"
RECIPE_MASQUE_H2_SPLIT = "masque-h2-split"
RECIPE_MASQUE_H2_SAVED = "masque-h2-saved"
RECIPES = (
    RECIPE_AUTO,
    RECIPE_WARP_V6,
    RECIPE_WARP_ANY,
    RECIPE_WOW_V6,
    RECIPE_WOW_ANY,
    RECIPE_MASQUE_H2,
    RECIPE_MASQUE_H3,
    RECIPE_MASQUE_H2_SPLIT,
    RECIPE_MASQUE_H2_SAVED,
)

KEY_AUTO = "auto"
KEY_ECH = "ech"
KEY_FRAGMENT = "fragment"
KEY_EXTERNAL = "external"
KEY_FETCHES = (KEY_AUTO, KEY_ECH, KEY_FRAGMENT, KEY_EXTERNAL)
#: Mobile default: race ECH, split ClientHello and the current network; the
#: first TLS session that is ready claims the single register/enroll send.
DEFAULT_KEY_FETCH = KEY_AUTO
#: When the race fails, one more try on the route that works on Hamrah Aval.
KEY_FETCH_FALLBACK = KEY_ECH
#: Wall-clock budgets for ``aether --prepare-only`` (register + enroll). The
#: core's own per-call timeouts are 6s connect / 8s TLS / 15s exchange.
KEY_FETCH_TIMEOUT_S = 90
KEY_FETCH_RETRY_TIMEOUT_S = 60

OBFUSCATION_PROFILES = ("off", "light", "balanced", "aggressive")

# ---------------------------------------------------------------------------
# Psiphon strategies (mirrors PowPsiphonProtocols)
# ---------------------------------------------------------------------------

FRONTED = [
    "FRONTED-MEEK-OSSH",
    "FRONTED-MEEK-HTTP-OSSH",
    "FRONTED-MEEK-QUIC-OSSH",
]
DIRECT = [
    "TLS-OSSH",
    "OSSH",
    "SSH",
    "SHADOWSOCKS-OSSH",
    "UNFRONTED-MEEK-HTTPS-OSSH",
    "UNFRONTED-MEEK-OSSH",
    "QUIC-OSSH",
    "CONJURE-OSSH",
]
FAST_DIRECT = ["TLS-OSSH", "OSSH", "SSH", "SHADOWSOCKS-OSSH"]
CHAINABLE = [
    "FRONTED-MEEK-OSSH",
    "FRONTED-MEEK-HTTP-OSSH",
    "TLS-OSSH",
    "UNFRONTED-MEEK-HTTPS-OSSH",
    "UNFRONTED-MEEK-OSSH",
    "SHADOWSOCKS-OSSH",
    "OSSH",
    "SSH",
]
ALTERNATE_DNS = ["208.67.222.222:5353", "9.9.9.9:9953", "208.67.220.220:5353"]
REGION_PHASE_TIMEOUT_SECONDS = 25
#: Automatic exit: a short first try in a nearby country, then any country.
NEARBY_PHASE_TIMEOUT_SECONDS = 12
#: Behind WARP the light protocols get a short first window before meek.
CHAINED_LIGHT_TIMEOUT_SECONDS = 20
#: Head start for the last server that worked (Psiphon default is 1s).
SERVER_AFFINITY_GRACE_MS = 1_500
#: Countries close to Iran and to the usual WARP exits, nearest first.
NEARBY = [
    "DE", "NL", "AT", "PL", "CH", "SE", "FR", "GB", "CZ", "DK",
    "BE", "IT", "RS", "RO", "LT", "FI", "NO", "IE", "ES",
]

SERVER_ENTRY_SIGNATURE_PUBLIC_KEY = (
    "sHuUVTWaRyh5pZwy4UguSgkwmBe0EHtJJkoF5WrxmvA="
)
REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY = (
    "MIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEAt7Ls+/39r+T6zNW7GiVpJfzq/xvL9SBH5rIFnk0R"
    "XYEYavax3WS6HOD35eTAqn8AniOwiH+DOkvgSKF2caqk/y1dfq47Pdymtwzp9ikpB1C5OfAysXzBiwVJlCd"
    "ajBKvBZDerV1cMvRzCKvKwRmvDmHgphQQ7WfXIGbRbmmk6opMBh3roE42KcotLFtqp0RRwLtcBRNtCdsrVs"
    "jiI1Lqz/lH+T61sGjSjQ3CHMuZYSQJZo/KrvzgQXpkaCTdbObxHqb6/+i1qaVOfEsvjoiyzTxJADvSytVt"
    "cjijhPEV6XskJVHE1Zgl+7rATr/pDQkw6DPCNBS1+Y6fy7GstZALQXwEDN/qhQI9kWkHijT8ns+i1vGg00"
    "Mk/6J75arLhqcodWsdeG/M/moWgqQAnlZAGVtJI1OgeF5fsPpXu4kctOfuZlGjVZXQNW34aOzm8r8S0eV"
    "ZitPlbhcPiR4gT/aSMz/wd8lZlzZYsje/Jr8u/YtlwjjreZrGRmG8KMOzukV3lLmMppXFMvl4bxv6YFEmI"
    "uTsOhbLTwFgh7KYNjodLj/LsqRVfwz31PgWQFTEPICV7GCvgVlPRxnofqKSjgTWI4mxDhBpVcATvaoBl1"
    "L/6WLbFvBsoAUBItWwctO2xalKxF5szhGm8lccoc5MZr8kfE0uxMgsxz4er68iCID+rsCAQM="
)
EXCHANGE_OBFUSCATION_KEY = "DpXzloJk1Hw6aSzmKKky0xcahsEHubch81Mi6K0XMlU="


@dataclass(frozen=True)
class PsiphonStrategy:
    name: str
    label: str
    timeout_seconds: int
    preferred_protocols: list[str]


STRATEGY_A = PsiphonStrategy(
    name="A", label="domain-fronted (CDN)", timeout_seconds=40,
    preferred_protocols=list(FRONTED),
)
STRATEGY_F = PsiphonStrategy(
    name="F", label="direct through WARP", timeout_seconds=28,
    preferred_protocols=list(FAST_DIRECT),
)
#: Ladder order matches mobile ``PowPsiphonProtocols.LADDER``.
STRATEGY_LADDER = (STRATEGY_A, STRATEGY_F)


def strategy_ladder(direct: bool) -> list[PsiphonStrategy]:
    """Strategy order for this leg (mirrors mobile ``PowPsiphonProtocols.ladder``).

    Direct Psiphon keeps the original order (fronted meek first). Behind WARP
    the light TLS-OSSH/OSSH/SSH/SS set goes first with a shorter timeout and
    fronted meek is the fallback.
    """
    if direct:
        return list(STRATEGY_LADDER)
    light = replace(STRATEGY_F, timeout_seconds=CHAINED_LIGHT_TIMEOUT_SECONDS)
    return [light, STRATEGY_A]


def strategy_signature(direct: bool | None = None) -> str:
    ladder = STRATEGY_LADDER if direct is None else strategy_ladder(direct)
    return ",".join(strategy.name for strategy in ladder)


def rtt_key(direct: bool, strategy_name: str) -> str:
    """RTTs are kept per leg: ``c`` behind WARP, ``d`` direct (same as mobile)."""
    return ("d" if direct else "c") + strategy_name


def start_index(
    ladder: list[PsiphonStrategy], remembered: int | None, rtt_by_name: dict[str, int]
) -> int:
    """First strategy to try: lowest saved RTT when two or more strategies were
    measured on this network, else the remembered winner, else the head."""
    measured = [i for i, s in enumerate(ladder) if int(rtt_by_name.get(s.name, 0) or 0) > 0]
    if len(measured) >= 2:
        return min(measured, key=lambda i: int(rtt_by_name[ladder[i].name]))
    if remembered is not None and 0 <= remembered < len(ladder):
        return remembered
    return 0


def auto_bias_region(
    remembered: str | None, available: list[str] | tuple[str, ...], remembered_only: bool = False
) -> str | None:
    """Country for the short head-start attempt when the exit is Automatic.

    A nearby country that worked on this network wins; otherwise the first
    nearby country Psiphon has advertised; otherwise Germany. None when
    Psiphon told us its regions and none of them is nearby.
    """
    live = {str(code).strip().upper() for code in available or () if len(str(code).strip()) == 2}

    def usable(code: str) -> bool:
        return not live or code in live

    last = (remembered or "").strip().upper()
    if last in NEARBY and usable(last):
        return last
    if remembered_only:
        return None
    for code in NEARBY:
        if usable(code):
            return code
    return None


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


@dataclass
class PowSettings:
    exit_country_code: str = ""
    outer_transport: str = OUTER_AUTO
    obfuscation_profile: str = "balanced"
    h2_fragmentation: bool = True
    scan_mode: str = SCAN_BALANCED
    optimized_mode: bool = True
    firewall_profile: str = FIREWALL_AUTO
    link_recipe: str = RECIPE_AUTO
    chain_psiphon: bool = True
    key_fetch: str = DEFAULT_KEY_FETCH
    # Speed options (Settings > Speed). All off = the connect is unchanged.
    parallel_masque: bool = False
    irancell_h3: bool = False
    direct_psiphon_first: bool = False
    lowest_rtt_ip: bool = False

    def validated(self) -> "PowSettings":
        from .regions import normalize_region

        country = normalize_region(self.exit_country_code)
        transport = (self.outer_transport or "").strip().lower() or OUTER_AUTO
        obfuscation = (self.obfuscation_profile or "").strip().lower() or "balanced"
        firewall = (self.firewall_profile or "").strip().lower()
        recipe = (self.link_recipe or "").strip().lower()
        fetch = (self.key_fetch or "").strip().lower()
        return PowSettings(
            exit_country_code=country,
            outer_transport=transport if (transport == OUTER_AUTO or transport in OUTER_LADDER) else OUTER_AUTO,
            obfuscation_profile=obfuscation if obfuscation in OBFUSCATION_PROFILES else "balanced",
            h2_fragmentation=bool(self.h2_fragmentation),
            scan_mode=normalize_scan_mode(self.scan_mode),
            optimized_mode=bool(self.optimized_mode),
            firewall_profile=firewall if firewall in FIREWALLS else FIREWALL_AUTO,
            link_recipe=recipe if recipe in RECIPES else RECIPE_AUTO,
            chain_psiphon=bool(self.chain_psiphon),
            key_fetch=fetch if fetch in KEY_FETCHES else DEFAULT_KEY_FETCH,
            parallel_masque=bool(self.parallel_masque),
            irancell_h3=bool(self.irancell_h3),
            direct_psiphon_first=bool(self.direct_psiphon_first),
            lowest_rtt_ip=bool(self.lowest_rtt_ip),
        )


DEFAULT_SETTINGS = PowSettings()

#: Class-level alias mirroring mobile ``PowEngineSettings.DEFAULT``.
PowSettings.DEFAULT = DEFAULT_SETTINGS  # type: ignore[attr-defined]


def normalize_scan_mode(raw: str | None) -> str:
    value = (raw or "").strip().lower()
    if value in ("fast", SCAN_TURBO):
        return SCAN_TURBO
    if value in ("deep", SCAN_THOROUGH):
        return SCAN_THOROUGH
    if value == SCAN_BALANCED:
        return SCAN_BALANCED
    return SCAN_BALANCED


def uses_mci_firewall(settings: PowSettings) -> bool:
    if settings.firewall_profile == FIREWALL_MCI:
        return True
    if settings.firewall_profile == FIREWALL_IRANCELL:
        return False
    # No SIM on desktop: the strict (MCI) plan is the default.
    return True


@dataclass(frozen=True)
class OuterPlan:
    protocols: list[str]
    ip_mode: str
    masque_transport: str
    fragment: bool
    fixed_order: bool
    summary: str

    def ip_for(self, protocol: str) -> str:
        if self.ip_mode == "v6-warp":
            return "v6" if protocol in ("wireguard", "gool") else "v4"
        if self.ip_mode in ("v6", "v4", "both"):
            return self.ip_mode
        return "v4"


def outer_plan(settings: PowSettings, mci: bool) -> OuterPlan:
    recipe = settings.validated().link_recipe
    if recipe == RECIPE_WARP_V6:
        return OuterPlan(["wireguard"], "v6", "h3", False, True, "WARP IPv6")
    if recipe == RECIPE_WARP_ANY:
        return OuterPlan(["wireguard"], "both", "h3", False, True, "WARP any IP")
    if recipe == RECIPE_WOW_V6:
        return OuterPlan(["gool"], "v6", "h3", False, True, "WARP-in-WARP IPv6")
    if recipe == RECIPE_WOW_ANY:
        return OuterPlan(["gool"], "both", "h3", False, True, "WARP-in-WARP any IP")
    if recipe == RECIPE_MASQUE_H2:
        return OuterPlan(["masque"], "both", "h2", False, True, "MASQUE HTTP/2")
    if recipe == RECIPE_MASQUE_H3:
        return OuterPlan(["masque"], "v4", "h3", False, True, "MASQUE HTTP/3")
    if recipe == RECIPE_MASQUE_H2_SPLIT:
        return OuterPlan(["masque"], "v4", "h2", True, True, "MASQUE HTTP/2 split hello")
    if recipe == RECIPE_MASQUE_H2_SAVED:
        return OuterPlan(["masque"], "both", "h2", False, True, "MASQUE HTTP/2 saved IPs")
    if mci:
        # Same dial that connected on an MCI modem: HTTP/2, full ClientHello,
        # v4 and v6.
        return OuterPlan(["masque"], "both", "h2", False, True, "MASQUE HTTP/2")
    return OuterPlan(list(OUTER_LADDER), "v4", "h3", False, False, "Irancell ladder")


def candidates(settings: PowSettings, mci: bool = False) -> list[str]:
    mode = settings.outer_transport
    ladder = MCI_LADDER if mci else OUTER_LADDER
    if not mode or mode == OUTER_AUTO:
        return list(ladder)
    if mode in ladder or mode in OUTER_LADDER:
        return [mode]
    return list(ladder)


def key_protocols(recipe: str) -> list[str]:
    if recipe in (RECIPE_WOW_V6, RECIPE_WOW_ANY):
        return ["wireguard", "gool"]
    if recipe in (RECIPE_MASQUE_H2, RECIPE_MASQUE_H3, RECIPE_MASQUE_H2_SPLIT, RECIPE_MASQUE_H2_SAVED):
        return ["masque"]
    if recipe in (RECIPE_WARP_V6, RECIPE_WARP_ANY):
        return ["wireguard"]
    return ["wireguard", "gool", "masque"]


def outer_label(protocol: str) -> str:
    return {"masque": "MASQUE", "wireguard": "WireGuard", "gool": "WoW"}.get(
        protocol, protocol.upper()
    )


def outer_budget_ms(protocol: str, retune: bool = False, scan_mode: str = SCAN_BALANCED) -> int:
    if retune:
        return {"masque": 14_000, "wireguard": 11_000}.get(protocol, 16_000)
    scan = normalize_scan_mode(scan_mode)
    if scan == SCAN_TURBO:
        masque, wireguard, gool = 90_000, 24_000, 34_000
    elif scan == SCAN_THOROUGH:
        masque, wireguard, gool = 180_000, 55_000, 70_000
    else:
        masque, wireguard, gool = 120_000, 36_000, 48_000
    return {"masque": masque, "wireguard": wireguard}.get(protocol, gool)


# ---------------------------------------------------------------------------
# JSON builders (mirror chainOuterJson / keyRequestJson / certRenewJson)
# ---------------------------------------------------------------------------


def identity_path(data_dir: Path) -> Path:
    return Path(data_dir) / "uac-pow.toml"


def masque_cache_path(data_dir: Path) -> Path:
    return Path(data_dir) / "uac-pow-masque-cache.json"


def lastconn_path(data_dir: Path) -> Path:
    return Path(data_dir) / "uac-pow-lastconn.toml"


def clean_h2_path(data_dir: Path) -> Path:
    return Path(data_dir) / "uac-pow-clean-h2.json"


def chain_outer_json(
    data_dir: Path,
    protocol: str,
    settings: PowSettings,
    discovery: str = DISCOVERY_CACHE,
    scan_mode: str = SCAN_BALANCED,
    mci: bool = False,
    masque_transport: str | None = None,
) -> str:
    settings = settings.validated()
    plan = outer_plan(settings, mci)
    payload = {
        "config_path": str(identity_path(data_dir)),
        "protocol": protocol,
        "listen": f"127.0.0.1:{CHAIN_SOCKS_PORT}",
        "scan_mode": normalize_scan_mode(scan_mode),
        "ip_scan": plan.ip_for(protocol),
        "endpoint_cache_path": str(masque_cache_path(data_dir)),
        "endpoint_discovery": "clean" if settings.link_recipe == RECIPE_MASQUE_H2_SAVED else discovery,
        "masque_transport": (masque_transport or plan.masque_transport) if protocol == "masque" else "h3",
        "obfuscation_profile": settings.obfuscation_profile,
        "retry_obfuscation_profiles": True,
        "tls_curve_preset": "chrome",
        "wireguard_data_check": True,
        "log_level": "info",
        "perf_profile": "high",
        "h2_fragmentation": bool(plan.fragment and protocol == "masque"),
        "api_camo": settings.key_fetch,
        "gateway": False,
    }
    return json.dumps(payload)


def key_request_json(data_dir: Path, settings: PowSettings, protocol: str) -> str:
    payload = json.loads(
        chain_outer_json(data_dir, protocol, settings, mci=uses_mci_firewall(settings))
    )
    payload["protocol"] = protocol
    # Mobile parity (PowCoreConfig.keyRequestJson): the user's key-fetch
    # setting, "auto" by default = the ECH / split-hello / direct race.
    payload["api_camo"] = settings.validated().key_fetch
    return json.dumps(payload)


def cert_renew_json(data_dir: Path, settings: PowSettings) -> str:
    payload = json.loads(key_request_json(data_dir, settings, "masque"))
    payload["renew_masque"] = True
    return json.dumps(payload)


# ---------------------------------------------------------------------------
# Psiphon config builder (mirrors PowPsiphonProtocols.buildConfig)
# ---------------------------------------------------------------------------


def psiphon_config(
    socks_port: int,
    data_directory: str,
    preferred_region: str | None,
    strategy: PsiphonStrategy,
    optimized_mode: bool = True,
    direct: bool = False,
    server_entries_path: str = "",
    region_bias: bool = False,
    upstream_port: int = CHAIN_SOCKS_PORT,
) -> str:
    from .regions import egress_region as _egress_region

    config: dict = {
        "PropagationChannelId": "FFFFFFFFFFFFFFFF",
        "SponsorId": "1111111111111111",
        "EgressRegion": "",
        "EstablishTunnelTimeoutSeconds": strategy.timeout_seconds,
        "DataDirectory": data_directory,
        "ClientVersion": "1",
        "TunnelProtocol": "",
        "RemoteServerListURL": "",
        "LocalSocksProxyPort": socks_port,
        "RemoteServerListSignaturePublicKey": REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY,
        "ServerEntrySignaturePublicKey": SERVER_ENTRY_SIGNATURE_PUBLIC_KEY,
        "ExchangeObfuscationKey": EXCHANGE_OBFUSCATION_KEY,
        "EmitBytesTransferred": True,
        "DeviceRegion": "IR",
        "ConnectionWorkerPoolSize": 12 if optimized_mode else 16,
        "EmitDiagnosticNotices": True,
        "DNSResolverPreferredAlternateServers": list(ALTERNATE_DNS),
        "DNSResolverPreferAlternateServerProbability": 1.0 if optimized_mode else 0.35,
        "DNSResolverAttemptsPerPreferredServer": 2 if optimized_mode else 1,
        "InproxyEnabled": False,
        "InproxyAllowClient": False,
        "EstablishTunnelServerAffinityGracePeriodMilliseconds": SERVER_AFFINITY_GRACE_MS,
    }
    if not direct:
        config["UpstreamProxyURL"] = f"socks5://127.0.0.1:{upstream_port}"
    if strategy.name == "A":
        config["InitialLimitTunnelProtocols"] = list(FRONTED)
        config["InitialLimitTunnelProtocolsCandidateCount"] = 24
        config["LimitTunnelProtocols"] = list(FRONTED)
        config["ConnectionWorkerPoolSize"] = 12
        config["NetworkLatencyMultiplier"] = 1.5
    else:
        config["InitialLimitTunnelProtocols"] = list(FAST_DIRECT)
        config["InitialLimitTunnelProtocolsCandidateCount"] = 16
        config["ConnectionWorkerPoolSize"] = 16
        config["NetworkLatencyMultiplier"] = 1.0
    config["EstablishTunnelTimeoutSeconds"] = strategy.timeout_seconds
    if preferred_region:
        region = _egress_region(preferred_region)
        if region:
            config["EgressRegion"] = region
            if region_bias:
                # Nearby-country head start for Automatic: keep the
                # strategy's protocol preference, give it a short window.
                config["EstablishTunnelTimeoutSeconds"] = NEARBY_PHASE_TIMEOUT_SECONDS
            else:
                config["EstablishTunnelTimeoutSeconds"] = REGION_PHASE_TIMEOUT_SECONDS
                config.pop("InitialLimitTunnelProtocols", None)
                config.pop("InitialLimitTunnelProtocolsCandidateCount", None)
                config.pop("LimitTunnelProtocols", None)
    if direct:
        meek_only = all(p.startswith("FRONTED-") for p in strategy.preferred_protocols)
        if meek_only:
            protocols = ["FRONTED-MEEK-OSSH", "FRONTED-MEEK-HTTP-OSSH"]
        else:
            protocols = ["TLS-OSSH", "SHADOWSOCKS-OSSH"]
        config["LimitTunnelProtocols"] = protocols
        config["InitialLimitTunnelProtocols"] = protocols
        config["InitialLimitTunnelProtocolsCandidateCount"] = 16 if meek_only else 8
        config["EstablishTunnelTimeoutSeconds"] = 90 if meek_only else 35
        config["ConnectionWorkerPoolSize"] = 8 if meek_only else 6
        config["DNSResolverPreferAlternateServerProbability"] = 0
        config.pop("DNSResolverPreferredAlternateServers", None)
        if meek_only:
            config["MeekTransformedHostName"] = "cdnjs.cloudflare.com"
            config["MeekSNIServerName"] = "cdnjs.cloudflare.com"
    else:
        config["LimitTunnelProtocols"] = list(CHAINABLE)
    preference = config.get("InitialLimitTunnelProtocols")
    if preference is not None:
        chainable = [p for p in preference if p in CHAINABLE]
        if not chainable:
            config.pop("InitialLimitTunnelProtocols", None)
            config.pop("InitialLimitTunnelProtocolsCandidateCount", None)
        else:
            config["InitialLimitTunnelProtocols"] = chainable
    # NOTE: server entries travel as the helper's -serverList file flag, not
    # inside this JSON. Unknown keys must not reach LoadConfig.
    _ = server_entries_path
    return json.dumps(config)


# ---------------------------------------------------------------------------
# Last-connect description (mirrors PowLastConnect.describe)
# ---------------------------------------------------------------------------


@dataclass
class LastConnect:
    protocol: str = ""
    transport: str = ""
    ip: str = ""
    peer: str = ""
    through_psiphon: bool = True

    def describe(self) -> str:
        if not self.protocol:
            return ""
        if self.protocol == "psiphon":
            return "Psiphon"
        name = {"wireguard": "WireGuard", "gool": "WARP-in-WARP", "masque": "MASQUE"}.get(
            self.protocol, self.protocol
        )
        transport_label = {"h2": "HTTP/2", "h3": "HTTP/3"}.get(self.transport, "")
        host = self.peer.split("%")[0].split("]")[0]
        if self.ip == "v6" or self.peer.startswith("[") or host.count(":") > 1:
            ip_label = "IPv6"
        elif self.ip == "v4" or host.count(".") == 3:
            ip_label = "IPv4"
        else:
            ip_label = ""
        head = " · ".join(
            part for part in (name, transport_label, ip_label, self.peer) if part
        )
        return head + (" · Psiphon" if self.through_psiphon else " · WARP")


# ---------------------------------------------------------------------------
# UI choice lists (Fa/En labels mirror the mobile panel)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Choice:
    id: str
    fa: str
    en: str


FIREWALL_CHOICES = (
    Choice(FIREWALL_AUTO, "خودکار", "Automatic"),
    Choice(FIREWALL_IRANCELL, "ایرانسل", "Irancell"),
    Choice(FIREWALL_MCI, "همراه اول", "Hamrah Aval"),
)
RECIPE_CHOICES = (
    Choice(RECIPE_AUTO, "خودکار", "Automatic"),
    Choice(RECIPE_WARP_V6, "WireGuard · IPv6", "WireGuard · IPv6"),
    Choice(RECIPE_WARP_ANY, "WireGuard · IPv4 + IPv6", "WireGuard · IPv4 + IPv6"),
    Choice(RECIPE_WOW_V6, "WARP-in-WARP · IPv6", "WARP-in-WARP · IPv6"),
    Choice(RECIPE_WOW_ANY, "WARP-in-WARP · IPv4 + IPv6", "WARP-in-WARP · IPv4 + IPv6"),
    Choice(RECIPE_MASQUE_H2, "MASQUE · HTTP/2", "MASQUE · HTTP/2"),
    Choice(RECIPE_MASQUE_H2_SAVED, "MASQUE · HTTP/2 · saved", "MASQUE · HTTP/2 · saved"),
    Choice(RECIPE_MASQUE_H3, "MASQUE · HTTP/3", "MASQUE · HTTP/3"),
    Choice(RECIPE_MASQUE_H2_SPLIT, "MASQUE · HTTP/2 · split", "MASQUE · HTTP/2 · split"),
)
SCAN_CHOICES = (
    Choice(SCAN_TURBO, "سریع", "Fast"),
    Choice(SCAN_BALANCED, "بالانس", "Balanced"),
    Choice(SCAN_THOROUGH, "عمیق", "Deep"),
)
EXIT_CHOICES = (
    Choice("chain", "وارپ، بعد سایفون", "WARP, then Psiphon"),
    Choice("warp", "فقط وارپ", "WARP only"),
)
FETCH_CHOICES = (
    Choice(KEY_AUTO, "خودکار (مسابقه)", "Automatic (race)"),
    Choice(KEY_ECH, "ECH", "ECH"),
    Choice(KEY_FRAGMENT, "قطع سلام", "Split hello"),
    Choice(KEY_EXTERNAL, "شبکه فعلی", "Current network"),
)

RECIPE_HINTS_FA = {
    RECIPE_WARP_V6: "WireGuard فقط IPv6. اگر IPv6 نباشد زود رد می‌شود.",
    RECIPE_WARP_ANY: "WireGuard روی IPv4 و IPv6.",
    RECIPE_WOW_V6: "WARP-in-WARP فقط IPv6.",
    RECIPE_WOW_ANY: "WARP-in-WARP روی IPv4 و IPv6.",
    RECIPE_MASQUE_H2: "اول آی‌پی‌های تمیز ذخیره‌شده، بعد اسکن HTTP/2. آی‌پی جدید به لیست اضافه می‌شود.",
    RECIPE_MASQUE_H2_SAVED: "فقط آی‌پی‌های تمیز ذخیره‌شده. اسکن نمی‌شود.",
    RECIPE_MASQUE_H3: "MASQUE HTTP/3 روی IPv4.",
    RECIPE_MASQUE_H2_SPLIT: "MASQUE HTTP/2 با سلام قطع‌شده.",
    RECIPE_AUTO: "ایرانسل: MASQUE HTTP/3 بعد WARP. همراه اول: MASQUE HTTP/2، اول آی‌پی تمیز.",
}


# ---------------------------------------------------------------------------
# Speed options (all off by default)
# ---------------------------------------------------------------------------

#: Irancell HTTP/3: short H3 window before the HTTP/2 fallback.
IRANCELL_H3_BUDGET_MS = 25_000
#: Direct Psiphon fast mode: one short direct try before WARP.
DIRECT_FAST_BUDGET_S = 15
#: Parallel MASQUE: extra sessions get this long to come up.
PARALLEL_EXTRA_BUDGET_MS = 25_000
#: Parallel MASQUE on a network with one known address: the extra session's own scan.
PARALLEL_DISCOVERY_BUDGET_MS = 120_000
