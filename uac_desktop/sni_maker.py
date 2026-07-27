from __future__ import annotations

import base64
import concurrent.futures
import binascii
import ipaddress
import re
import threading
import time
import urllib.parse
import uuid
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field, replace
from pathlib import Path

import requests

from .models import ProxyProfile, parse_many
from .network import GeoLocation, profile_ping
from .verified_configs import COUNTRIES, VERIFIED_SPOOF_EDGE, VERIFIED_SPOOF_FAKE_SNI


DEFAULT_REPOSITORY_URL = "https://mifa.world/vless"
SUPPORTED_PROTOCOLS = frozenset({"vless", "trojan"})
KNOWN_UNSUPPORTED_PROTOCOLS = frozenset(
    {"ss", "ssr", "hysteria", "hysteria2", "hy2", "tuic", "wireguard"}
)
ISO2_CODES = frozenset(
    """
    AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ
    BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ
    CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ
    DE DJ DK DM DO DZ
    EC EE EG EH ER ES ET
    FI FJ FK FM FO FR
    GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY
    HK HM HN HR HT HU
    ID IE IL IM IN IO IQ IR IS IT
    JE JM JO JP
    KE KG KH KI KM KN KP KR KW KY KZ
    LA LB LC LI LK LR LS LT LU LV LY
    MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ
    NA NC NE NF NG NI NL NO NP NR NU NZ
    OM
    PA PE PF PG PH PK PL PM PN PR PS PT PW PY
    QA
    RE RO RS RU RW
    SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ
    TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ
    UA UG UM US UY UZ
    VA VC VE VG VI VN VU
    WF WS
    YE YT
    ZA ZM ZW
    XK
    """.split()
)
LOCAL_SNI_HOST = "127.0.0.1"
LOCAL_SNI_PORT = 40443
MAX_SOURCE_BYTES = 10 * 1024 * 1024
URI_TOKEN_RE = re.compile(r"(?i)([a-z][a-z0-9+.-]*)://[^\s]+")
SUPPORTED_URI_TOKEN_RE = re.compile(r"(?i)(?:vless|trojan)://[^\s]+")
BASE64_TOKEN_RE = re.compile(r"^[A-Za-z0-9+/_-]+={0,2}$")


@dataclass(frozen=True)
class DecodedConfigPayload:
    text: str
    input_format: str = "none"
    config_count: int = 0


def decode_config_payload(value: str | bytes | bytearray) -> DecodedConfigPayload:
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value).decode("utf-8-sig", errors="replace")
    else:
        raw = str(value or "")
    raw = raw.lstrip("\ufeff")
    direct_count = len(SUPPORTED_URI_TOKEN_RE.findall(raw))
    if direct_count:
        return DecodedConfigPayload(raw, "direct", direct_count)
    compact = "".join(raw.split())
    if (
            len(compact) < 8
            or len(compact) % 4 == 1
            or BASE64_TOKEN_RE.fullmatch(compact) is None):
        return DecodedConfigPayload(raw)
    padded = compact + "=" * ((-len(compact)) % 4)
    try:
        decoded_bytes = base64.b64decode(
            padded.encode("ascii"), altchars=b"-_", validate=True
        )
        decoded = decoded_bytes.decode("utf-8-sig")
    except (UnicodeError, ValueError, binascii.Error):
        return DecodedConfigPayload(raw)
    decoded_count = len(SUPPORTED_URI_TOKEN_RE.findall(decoded))
    if not decoded_count:
        return DecodedConfigPayload(raw)
    return DecodedConfigPayload(decoded, "base64", decoded_count)


@dataclass
class SniImportResult:
    profiles: list[ProxyProfile] = field(default_factory=list)
    source: str = ""
    parsed_count: int = 0
    duplicate_count: int = 0
    invalid_count: int = 0
    unsupported_count: int = 0
    unsupported_by_protocol: dict[str, int] = field(default_factory=dict)
    unsupported_uris: list[str] = field(default_factory=list)
    etag: str = ""
    not_modified: bool = False
    input_format: str = "none"
    detected_count: int = 0

    @property
    def added_count(self) -> int:
        return len(self.profiles)


@dataclass(frozen=True)
class SniConversionResult:
    source_profile: ProxyProfile
    profile: ProxyProfile | None
    status: str
    error: str = ""

    @property
    def success(self) -> bool:
        return self.profile is not None

    @property
    def already_sni(self) -> bool:
        return self.status == "already_sni"

    @property
    def direct(self) -> bool:
        return self.status == "direct"


@dataclass
class SniConversionBatch:
    results: list[SniConversionResult] = field(default_factory=list)
    total: int = 0
    cancelled: bool = False

    @property
    def profiles(self) -> list[ProxyProfile]:
        return [result.profile for result in self.results if result.profile is not None]

    @property
    def converted_count(self) -> int:
        return sum(result.status == "converted" for result in self.results)

    @property
    def already_sni_count(self) -> int:
        return sum(result.status == "already_sni" for result in self.results)

    @property
    def direct_count(self) -> int:
        return sum(result.status == "direct" for result in self.results)

    @property
    def incompatible_count(self) -> int:
        return sum(result.status == "incompatible" for result in self.results)


@dataclass(frozen=True)
class SniProbeResult:
    success: bool
    ping_ms: float = 0.0
    location: GeoLocation | None = None
    stage: str = "preflight"
    route_verified: bool = False
    error: str = ""


@dataclass
class SniTestResult:
    profile: ProxyProfile
    success: bool
    ping_ms: float
    status: str
    stage: str
    route_verified: bool = False
    country_code: str = ""
    country_name: str = ""
    city: str = ""
    exit_ip: str = ""
    geo_source: str = ""
    country_verified_at: float = 0.0
    geo_confidence: str = ""
    country_hint: str = ""
    error: str = ""

    @property
    def country_flag(self) -> str:
        return country_flag(self.country_code)


@dataclass
class SniTestBatch:
    results: list[SniTestResult] = field(default_factory=list)
    total: int = 0
    cancelled: bool = False

    @property
    def tested_count(self) -> int:
        return len(self.results)

    @property
    def successful(self) -> list[SniTestResult]:
        return [result for result in self.results if result.success]

    @property
    def healthy(self) -> list[SniTestResult]:
        return [
            result for result in self.results
            if result.success and result.route_verified
        ]

    @property
    def healthy_by_country(self) -> dict[str, list[SniTestResult]]:
        return group_healthy_by_country(self.results)


ProbeFn = Callable[
    [ProxyProfile, float, Callable[[], bool]],
    SniProbeResult,
]
ProgressFn = Callable[[int, int, SniTestResult], None]


def _cancelled(value) -> bool:
    if value is None:
        return False
    if callable(value):
        return bool(value())
    is_set = getattr(value, "is_set", None)
    if callable(is_set):
        return bool(is_set())
    return bool(value)


def _normalized_country_code(value: str) -> str:
    code = str(value or "").strip().upper()
    return code if len(code) == 2 and code.isalpha() else ""


def country_flag(country_code: str) -> str:
    code = _normalized_country_code(country_code)
    if not code:
        return "🌐"
    return "".join(chr(127397 + ord(character)) for character in code)


def country_name(country_code: str, supplied: str = "") -> str:
    if str(supplied or "").strip():
        return str(supplied).strip()
    code = _normalized_country_code(country_code)
    if not code:
        return ""
    known = COUNTRIES.get(code)
    return str(known[1]) if known else code


def normalize_repository_url(url: str) -> str:
    value = str(url or DEFAULT_REPOSITORY_URL).strip()
    parsed = urllib.parse.urlsplit(value)
    if parsed.hostname and parsed.hostname.lower() == "github.com":
        parts = [part for part in parsed.path.split("/") if part]
        if len(parts) >= 5 and parts[2] == "blob":
            owner, repository = parts[0], parts[1]
            tail = parts[3:]
            raw_path = "/".join([owner, repository, *tail])
            return f"https://raw.githubusercontent.com/{raw_path}"
    return value


def config_signature(value: ProxyProfile | str) -> str:
    raw = value.source_uri if isinstance(value, ProxyProfile) else str(value or "")
    parsed = urllib.parse.urlsplit(raw.strip())
    scheme = parsed.scheme.lower()
    raw_identity, separator, _authority_host = parsed.netloc.rpartition("@")
    identity = urllib.parse.unquote(raw_identity) if separator else ""
    hostname = (parsed.hostname or "").lower()
    try:
        port = parsed.port or 443
    except ValueError:
        port = 443
    pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    normalized_query = tuple(sorted((str(key).lower(), str(item)) for key, item in pairs))
    return repr((scheme, identity, hostname, port, parsed.path, normalized_query))


def dedupe_profiles(profiles: Iterable[ProxyProfile]) -> list[ProxyProfile]:
    output: list[ProxyProfile] = []
    signatures: set[str] = set()
    for profile in profiles:
        signature = config_signature(profile)
        if signature in signatures:
            continue
        signatures.add(signature)
        output.append(profile)
    return output


def _unsupported_parsed_profile(profile: ProxyProfile) -> bool:
    return profile.protocol.lower() not in SUPPORTED_PROTOCOLS


def is_sni_config(value: ProxyProfile | str) -> bool:
    profile = value if isinstance(value, ProxyProfile) else None
    raw = profile.source_uri if profile else str(value or "")
    if profile and (profile.verified_spoof or profile.spoof_fake_sni):
        return True
    try:
        parsed = urllib.parse.urlsplit(raw.strip())
        host = (parsed.hostname or "").strip().lower()
        port = parsed.port or 443
        loopback = host == "localhost"
        if not loopback:
            try:
                loopback = ipaddress.ip_address(host).is_loopback
            except ValueError:
                loopback = False
        return parsed.scheme.lower() in SUPPORTED_PROTOCOLS and loopback and port == LOCAL_SNI_PORT
    except (TypeError, ValueError):
        return False


def _compatibility_error(profile: ProxyProfile) -> str:
    try:
        parsed = urllib.parse.urlsplit(profile.source_uri)
        protocol = parsed.scheme.lower()
        if protocol not in SUPPORTED_PROTOCOLS or not parsed.hostname:
            return "Unsupported config protocol"
        query = {
            str(key).lower(): str(value)
            for key, value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        }
        credential = urllib.parse.unquote(parsed.username or "").strip()
        if protocol == "vless" and not credential:
            return "Missing VLESS UUID"
        elif protocol == "trojan" and not credential:
            return "Missing Trojan password"
        security = query.get("security", "").strip().lower()
        if security not in {"", "tls"}:
            return f"Unsupported security: {security}"
        insecure = (
            query.get("allowinsecure")
            or query.get("insecure")
            or ""
        ).strip().lower()
        if insecure in {"1", "true", "yes", "on"}:
            return "Unsupported insecure TLS option"
        network = (
            query.get("type") or query.get("network")
            or "ws"
        ).strip().lower()
        if network not in {"ws", "httpupgrade", "grpc", "xhttp", "tcp", "raw"}:
            return f"Unsupported transport: {network}"
        sni = next(
            (
                query.get(key.lower(), "").strip()
                for key in ("sni", "servername", "serverName", "host", "authority")
                if query.get(key.lower(), "").strip()
            ),
            (parsed.hostname or "").strip(),
        )
        if not sni:
            return "Missing TLS route name"
        parsed.port
        return ""
    except (TypeError, ValueError):
        return "Invalid config URI"


def convert_to_sni(
        profile: ProxyProfile,
        edge: str = VERIFIED_SPOOF_EDGE,
        fallback_edge: str = "",
        fake_sni: str = VERIFIED_SPOOF_FAKE_SNI,
        local_host: str = LOCAL_SNI_HOST,
        local_port: int = LOCAL_SNI_PORT) -> SniConversionResult:
    source = replace(profile)
    error = _compatibility_error(profile)
    if error:
        return SniConversionResult(source, None, "incompatible", error)
    parsed = urllib.parse.urlsplit(profile.source_uri)
    query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    query = {
        str(key).lower(): str(value)
        for key, value in query_pairs
    }
    server_name = next(
        (
            query.get(key, "").strip()
            for key in ("sni", "servername", "host", "authority")
            if query.get(key, "").strip()
        ),
        (parsed.hostname or profile.sni).strip(),
    )
    if is_sni_config(profile):
        return SniConversionResult(source, replace(profile), "already_sni")
    if not any(query.get(key, "").strip() for key in ("sni", "servername")):
        rewritten_query = (
            f"{parsed.query}&sni={urllib.parse.quote(server_name, safe='')}"
            if parsed.query else
            f"sni={urllib.parse.quote(server_name, safe='')}"
        )
    else:
        rewritten_query = parsed.query
    username, separator, _host = parsed.netloc.rpartition("@")
    userinfo = f"{username}@" if separator else ""
    rewritten = urllib.parse.urlunsplit(
        (
            parsed.scheme,
            f"{userinfo}{local_host}:{int(local_port)}",
            parsed.path,
            rewritten_query,
            parsed.fragment,
        )
    )
    converted = replace(profile)
    converted.id = str(uuid.uuid5(uuid.NAMESPACE_URL, config_signature(rewritten)))
    converted.name = (
        profile.name if profile.name.lower().endswith(" sni")
        else f"{profile.name} · SNI"
    )
    converted.source_uri = rewritten
    converted.protocol = parsed.scheme.lower()
    converted.config_host = local_host
    converted.config_port = int(local_port)
    converted.address = str(edge).strip() or VERIFIED_SPOOF_EDGE
    converted.fallback_address = str(fallback_edge).strip()
    converted.port = parsed.port or 443
    converted.sni = server_name
    converted.origin = "sni-maker"
    converted.route_mode = "sni"
    converted.verified_route = False
    converted.last_ping_ok = False
    converted.last_ping_ms = 0.0
    converted.country_code = ""
    converted.country_latency_ms = 0
    converted.verified_spoof = False
    converted.spoof_fake_sni = str(fake_sni).strip()
    converted.rotating_exit = False
    converted.observed_exit_ip = ""
    converted.observed_country_code = ""
    converted.observed_country_name = ""
    converted.country_verified_at = 0.0
    converted.country_source = ""
    return SniConversionResult(source, converted, "converted")


def preflight_probe(
        profile: ProxyProfile,
        timeout: float,
        cancelled: Callable[[], bool]) -> SniProbeResult:
    if cancelled():
        return SniProbeResult(False, stage="preflight", error="Cancelled")
    ok, ping_ms = profile_ping(
        profile.address,
        profile.port,
        profile.sni,
        timeout=max(0.1, float(timeout)),
    )
    if cancelled():
        return SniProbeResult(False, stage="preflight", error="Cancelled")
    return SniProbeResult(
        success=ok,
        ping_ms=ping_ms,
        stage="preflight",
        route_verified=False,
        error="" if ok else "TLS preflight failed",
    )


def _test_result(profile: ProxyProfile, outcome: SniProbeResult) -> SniTestResult:
    tested_profile = replace(profile)
    ping_ms = max(0.0, float(outcome.ping_ms or 0.0))
    tested_profile.last_ping_ok = bool(outcome.success)
    tested_profile.last_ping_ms = ping_ms if outcome.success else 0.0
    hint = _normalized_country_code(profile.country_code)
    code = ""
    name = ""
    city = ""
    exit_ip = ""
    geo_source = ""
    verified_at = 0.0
    geo_confidence = ""
    if outcome.success and outcome.route_verified and outcome.location:
        location = outcome.location
        code = _normalized_country_code(location.country_code)
        if code:
            name = country_name(code, location.country)
            city = str(location.city or "").strip()
            exit_ip = str(location.ip or "").strip()
            geo_source = str(location.source or "").strip()
            verified_at = time.time()
            geo_confidence = "live"
            tested_profile.country_code = code
            tested_profile.observed_country_code = code
            tested_profile.observed_country_name = name
            tested_profile.observed_exit_ip = exit_ip
            tested_profile.country_verified_at = verified_at
            tested_profile.country_source = geo_source
    if not code:
        tested_profile.country_code = ""
        tested_profile.observed_country_code = ""
        tested_profile.observed_country_name = ""
        tested_profile.observed_exit_ip = ""
        tested_profile.country_verified_at = 0.0
        tested_profile.country_source = ""
    if outcome.success and outcome.route_verified:
        if tested_profile.route_mode == "reality-direct":
            tested_profile.verified_route = True
            tested_profile.verified_spoof = False
        else:
            tested_profile.verified_spoof = True
    status = "failed"
    if outcome.success:
        status = "healthy" if outcome.route_verified else "preflight_ok"
    elif str(outcome.error or "").lower() == "cancelled":
        status = "cancelled"
    return SniTestResult(
        profile=tested_profile,
        success=bool(outcome.success),
        ping_ms=ping_ms,
        status=status,
        stage=str(outcome.stage or "preflight"),
        route_verified=bool(outcome.route_verified),
        country_code=code,
        country_name=name,
        city=city,
        exit_ip=exit_ip,
        geo_source=geo_source,
        country_verified_at=verified_at,
        geo_confidence=geo_confidence,
        country_hint=hint,
        error=str(outcome.error or ""),
    )


def group_healthy_by_country(
        results: Iterable[SniTestResult]) -> dict[str, list[SniTestResult]]:
    grouped: dict[str, list[SniTestResult]] = defaultdict(list)
    for result in results:
        if not result.success or not result.route_verified:
            continue
        code = _normalized_country_code(result.country_code)
        if code:
            grouped[code].append(result)
    for values in grouped.values():
        values.sort(key=lambda result: (result.ping_ms, result.profile.name.lower()))
    return dict(sorted(grouped.items()))


class SniConfigMaker:
    def __init__(
            self,
            profiles: Iterable[ProxyProfile] | None = None,
            edge: str = VERIFIED_SPOOF_EDGE,
            fallback_edge: str = "",
            fake_sni: str = VERIFIED_SPOOF_FAKE_SNI,
            local_host: str = LOCAL_SNI_HOST,
            local_port: int = LOCAL_SNI_PORT) -> None:
        self.edge = str(edge).strip() or VERIFIED_SPOOF_EDGE
        self.fallback_edge = str(fallback_edge).strip()
        self.fake_sni = str(fake_sni).strip() or VERIFIED_SPOOF_FAKE_SNI
        self.local_host = str(local_host).strip() or LOCAL_SNI_HOST
        self.local_port = int(local_port)
        self._lock = threading.RLock()
        self._profiles: list[ProxyProfile] = []
        self._signatures: set[str] = set()
        if profiles:
            self.add_profiles(profiles)

    @property
    def profiles(self) -> list[ProxyProfile]:
        with self._lock:
            return list(self._profiles)

    def clear(self) -> None:
        with self._lock:
            self._profiles.clear()
            self._signatures.clear()

    def add_profiles(
            self,
            profiles: Iterable[ProxyProfile],
            source: str = "") -> SniImportResult:
        parsed = list(profiles)
        added: list[ProxyProfile] = []
        duplicates = 0
        with self._lock:
            for profile in parsed:
                signature = config_signature(profile)
                if signature in self._signatures:
                    duplicates += 1
                    continue
                self._signatures.add(signature)
                self._profiles.append(profile)
                added.append(profile)
        return SniImportResult(
            profiles=added,
            source=source,
            parsed_count=len(parsed),
            duplicate_count=duplicates,
        )

    def import_text(
            self,
            text: str,
            source: str = "text",
            suggested: bool = False) -> SniImportResult:
        decoded_input = decode_config_payload(text)
        value = decoded_input.text
        parsed_all = parse_many(value, suggested=suggested)
        parsed = [
            profile for profile in parsed_all
            if not _unsupported_parsed_profile(profile)
        ]
        rejected_parsed = [
            profile for profile in parsed_all
            if _unsupported_parsed_profile(profile)
        ]
        tokens = list(URI_TOKEN_RE.finditer(value))
        supported_tokens = sum(
            match.group(1).lower() in SUPPORTED_PROTOCOLS for match in tokens
        )
        unsupported_matches = [
            match for match in tokens
            if match.group(1).lower() in KNOWN_UNSUPPORTED_PROTOCOLS
        ]
        unsupported_counts = Counter(
            match.group(1).lower() for match in unsupported_matches
        )
        for profile in rejected_parsed:
            unsupported_counts[profile.protocol.lower()] += 1
        merged = self.add_profiles(parsed, source)
        merged.invalid_count = max(0, supported_tokens - len(parsed))
        merged.unsupported_count = len(unsupported_matches) + len(rejected_parsed)
        merged.unsupported_by_protocol = dict(sorted(unsupported_counts.items()))
        merged.unsupported_uris = [
            match.group(0).rstrip("\"'.,;)]}") for match in unsupported_matches
        ]
        merged.unsupported_uris.extend(
            profile.source_uri for profile in rejected_parsed
        )
        merged.input_format = decoded_input.input_format
        merged.detected_count = decoded_input.config_count
        return merged

    def import_file(
            self,
            path: str | Path,
            suggested: bool = False,
            max_bytes: int = MAX_SOURCE_BYTES) -> SniImportResult:
        source_path = Path(path)
        size = source_path.stat().st_size
        if size > max(1, int(max_bytes)):
            raise ValueError("Config source file is too large")
        text = source_path.read_text(encoding="utf-8-sig", errors="replace")
        return self.import_text(text, source=str(source_path), suggested=suggested)

    def import_url(
            self,
            url: str = DEFAULT_REPOSITORY_URL,
            suggested: bool = True,
            timeout: float = 15.0,
            max_bytes: int = MAX_SOURCE_BYTES,
            etag: str = "",
            session=None) -> SniImportResult:
        source_url = normalize_repository_url(url)
        headers = {"User-Agent": "UAC-Spoofer-Desktop/SNI-Maker"}
        if str(etag or "").strip():
            headers["If-None-Match"] = str(etag).strip()
        client = session or requests
        response = client.get(source_url, headers=headers, timeout=timeout)
        if response.status_code == 304:
            return SniImportResult(
                source=source_url,
                etag=str(response.headers.get("ETag", "") or ""),
                not_modified=True,
            )
        response.raise_for_status()
        content = response.content
        if len(content) > max(1, int(max_bytes)):
            raise ValueError("Remote config source is too large")
        encoding = response.encoding or "utf-8"
        text = content.decode(encoding, errors="replace")
        imported = self.import_text(text, source=source_url, suggested=suggested)
        imported.etag = str(response.headers.get("ETag", "") or "")
        return imported

    def convert_profile(self, profile: ProxyProfile) -> SniConversionResult:
        return convert_to_sni(
            profile,
            edge=self.edge,
            fallback_edge=self.fallback_edge,
            fake_sni=self.fake_sni,
            local_host=self.local_host,
            local_port=self.local_port,
        )

    def convert_many(
            self,
            profiles: Iterable[ProxyProfile] | None = None,
            cancelled=None) -> SniConversionBatch:
        items = list(profiles) if profiles is not None else self.profiles
        results: list[SniConversionResult] = []
        was_cancelled = False
        for profile in items:
            if _cancelled(cancelled):
                was_cancelled = True
                break
            results.append(self.convert_profile(profile))
        return SniConversionBatch(
            results=results,
            total=len(items),
            cancelled=was_cancelled,
        )

    def test_many(
            self,
            profiles: Iterable[ProxyProfile],
            probe: ProbeFn | None = None,
            max_workers: int = 64,
            timeout: float = 3.0,
            progress: ProgressFn | None = None,
            cancelled=None) -> SniTestBatch:
        items = dedupe_profiles(profiles)
        if not items:
            return SniTestBatch(total=0)
        check = lambda: _cancelled(cancelled)
        if check():
            return SniTestBatch(total=len(items), cancelled=True)
        test_probe = probe or preflight_probe
        workers = max(1, min(256, int(max_workers)))
        pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=workers,
            thread_name_prefix="sni-maker",
        )

        def run(profile: ProxyProfile) -> SniTestResult:
            candidate = replace(profile)
            if check():
                return _test_result(
                    candidate,
                    SniProbeResult(False, error="Cancelled"),
                )
            try:
                outcome = test_probe(candidate, float(timeout), check)
                if not isinstance(outcome, SniProbeResult):
                    raise TypeError("Probe must return SniProbeResult")
            except Exception as exc:
                outcome = SniProbeResult(
                    False,
                    stage="live",
                    error=str(exc),
                )
            return _test_result(candidate, outcome)

        futures = {
            pool.submit(run, profile): index
            for index, profile in enumerate(items)
        }
        completed_results: dict[int, SniTestResult] = {}
        completed_count = 0
        was_cancelled = False
        pending = set(futures)
        try:
            while pending:
                if check():
                    was_cancelled = True
                    break
                done, pending = concurrent.futures.wait(
                    pending,
                    timeout=0.03,
                    return_when=concurrent.futures.FIRST_COMPLETED,
                )
                for future in done:
                    result = future.result()
                    if result.status == "cancelled" and check():
                        was_cancelled = True
                        continue
                    index = futures[future]
                    completed_results[index] = result
                    completed_count += 1
                    if progress:
                        progress(completed_count, len(items), result)
                if was_cancelled:
                    break
        finally:
            if was_cancelled or check():
                was_cancelled = True
                for future in futures:
                    future.cancel()
                pool.shutdown(wait=False, cancel_futures=True)
            else:
                pool.shutdown(wait=True)
        ordered = [
            completed_results[index]
            for index in sorted(completed_results)
        ]
        return SniTestBatch(
            results=ordered,
            total=len(items),
            cancelled=was_cancelled,
        )
