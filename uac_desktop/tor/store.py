"""Persistent settings, autopilot memory, bridge cache, and unpoisoned DNS cache for UAC Tor."""
from __future__ import annotations

import json
import re
import tempfile
import time
from dataclasses import asdict, dataclass, fields
from pathlib import Path

TRANSPORTS = ("auto", "webtunnel", "snowflake", "obfs4", "custom", "direct")
BRIDGE_SOURCES = ("auto", "moat", "mirrors", "relay", "bundled")
_LEGACY_BAD_EXCLUDE = "ir, ru, cn, by"


def _normalize_country(value: str) -> str:
    code = str(value or "").strip().lower()
    return code if len(code) == 2 and code.isalpha() and code.isascii() else ""


def normalize_country_list(value: str) -> str:
    codes: list[str] = []
    for tok in re.split(r"[\s,،;{}]+", str(value or "").strip().lower()):
        if len(tok) == 2 and tok.isalpha() and tok.isascii() and tok not in codes:
            codes.append(tok)
    return ", ".join(codes)


def _clean_bridges(text: str) -> str:
    lines = []
    seen = set()
    for raw in str(text or "").splitlines():
        line = " ".join(raw.strip().split())
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("bridge "):
            line = line[7:].strip()
        if line not in seen:
            seen.add(line)
            lines.append(line)
    return "\n".join(lines)


@dataclass(frozen=True)
class TorSettings:
    transport: str = "auto"
    auto_fetch_bridges: bool = True
    bridge_source: str = "auto"
    custom_bridges: str = ""
    bridge_relay_url: str = ""
    upstream_proxy: str = ""
    bootstrap_timeout_s: int = 75
    stall_fail_s: int = 24
    auto_reconnect: bool = True
    exit_country_code: str = ""
    strict_nodes: bool = False
    entry_nodes: str = ""
    exclude_nodes: str = ""
    exclude_exit_nodes: str = "ir"
    max_circuit_dirtiness: int = 600
    isolate_streams: bool = False
    reachable_80_443_only: bool = False
    use_ipv6: bool = False
    socks_port: int = 0
    http_port: int = 0
    control_port: int = 0
    dns_port: int = 0
    # Shared Global Settings / TUN filters (matches pow/routing.py contract)
    connection_mode: str = "proxy"
    routing_mode: str = "bypass"
    iran_direct: bool = True
    kill_switch: bool = False
    domains_direct: str = ""
    ips_direct: str = ""
    dns_sinkhole: bool = True
    webrtc_block: bool = True
    quic_block: bool = True
    ipv6_block: bool = True

    @classmethod
    def from_dict(cls, raw: dict) -> "TorSettings":
        defaults = cls()
        raw = raw if isinstance(raw, dict) else {}
        values = {}
        for f in fields(cls):
            default = getattr(defaults, f.name)
            val = raw.get(f.name, default)
            if type(val) is not type(default):
                val = default
            values[f.name] = val
        if values["transport"] not in TRANSPORTS:
            values["transport"] = defaults.transport
        if values["bridge_source"] not in BRIDGE_SOURCES:
            values["bridge_source"] = defaults.bridge_source
        if values["connection_mode"] not in ("vpn", "proxy", "local"):
            values["connection_mode"] = defaults.connection_mode
        if values["routing_mode"] not in ("all", "bypass", "only"):
            values["routing_mode"] = defaults.routing_mode
        values["exit_country_code"] = _normalize_country(values["exit_country_code"])
        values["entry_nodes"] = normalize_country_list(values["entry_nodes"])
        values["exclude_nodes"] = normalize_country_list(values["exclude_nodes"])
        if values["exclude_nodes"] == _LEGACY_BAD_EXCLUDE:
            values["exclude_nodes"] = ""
        values["exclude_exit_nodes"] = normalize_country_list(values["exclude_exit_nodes"])
        values["custom_bridges"] = _clean_bridges(values["custom_bridges"])
        values["bridge_relay_url"] = str(values["bridge_relay_url"] or "").strip()
        values["upstream_proxy"] = str(values["upstream_proxy"] or "").strip()
        values["bootstrap_timeout_s"] = max(25, min(180, int(values["bootstrap_timeout_s"])))
        values["stall_fail_s"] = max(12, min(60, int(values["stall_fail_s"])))
        values["max_circuit_dirtiness"] = max(60, min(3600, int(values["max_circuit_dirtiness"])))
        for pkey in ("socks_port", "http_port", "control_port", "dns_port"):
            p = int(values[pkey])
            values[pkey] = p if (p == 0 or 1024 <= p <= 65535) else 0
        return cls(**values)


def read_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False, mode="w", encoding="utf-8") as fh:
        pending = Path(fh.name)
        try:
            json.dump(data, fh, ensure_ascii=False, indent=2)
            fh.close()
            pending.replace(path)
        finally:
            fh.close()
            pending.unlink(missing_ok=True)


class TorStore:
    def __init__(self, directory: Path) -> None:
        self.directory = Path(directory)
        self.settings_path = self.directory / "settings.json"
        self.bridges_cache_path = self.directory / "bridges_cache.json"
        self.dns_cache_path = self.directory / "dns_cache.json"
        self._migrate()

    def _migrate(self) -> None:
        doc = read_json(self.settings_path)
        changed = False
        if doc.get("exclude_nodes") == _LEGACY_BAD_EXCLUDE:
            doc["exclude_nodes"] = ""
            changed = True
        if "bridge_fetch_mode" in doc and "bridge_source" not in doc:
            old = str(doc.pop("bridge_fetch_mode", "auto"))
            doc["bridge_source"] = "relay" if old == "relay" else "auto"
            changed = True
        if changed:
            try:
                write_json(self.settings_path, doc)
            except OSError:
                pass

    def saved_settings(self) -> dict:
        return read_json(self.settings_path)

    def settings(self) -> TorSettings:
        return TorSettings.from_dict(self.saved_settings())

    def save_settings(self, value: TorSettings, *, exclude=()) -> TorSettings:
        validated = TorSettings.from_dict(asdict(value))
        out = {k: v for k, v in asdict(validated).items() if k not in exclude}
        write_json(self.settings_path, {**self.saved_settings(), **out})
        return validated

    def export_settings(self, path: Path, *, exclude=()) -> None:
        data = {k: v for k, v in asdict(self.settings()).items() if k not in exclude}
        write_json(path, {"format": "uac-tor-settings", "version": 1, "settings": data})

    def import_settings(self, path: Path, *, exclude=()) -> TorSettings:
        doc = read_json(path)
        payload = doc.get("settings")
        if doc.get("format") != "uac-tor-settings" or doc.get("version") != 1 or not isinstance(payload, dict):
            raise ValueError("Unsupported UAC Tor settings backup file")
        return self.save_settings(TorSettings.from_dict(payload), exclude=exclude)

    def cached_bridges(self, transport: str, max_age_s: float = 24 * 3600) -> list[str]:
        doc = read_json(self.bridges_cache_path)
        bucket = doc.get(str(transport).lower())
        if not isinstance(bucket, dict):
            return []
        updated = float(bucket.get("updated_at", 0) or 0)
        if max_age_s > 0 and time.time() - updated > max_age_s:
            return []
        items = bucket.get("bridges")
        return [str(x) for x in items if isinstance(x, str) and x.strip()] if isinstance(items, list) else []

    def save_cached_bridges(self, transport: str, bridges: list[str], method: str = "", source: str = "") -> None:
        doc = read_json(self.bridges_cache_path)
        doc[str(transport).lower()] = {
            "bridges": list(dict.fromkeys(b.strip() for b in bridges if b.strip()))[:40],
            "updated_at": time.time(),
            "method": str(method),
            "source": str(source),
        }
        if method:
            doc["_last_winner_method"] = str(method)
        write_json(self.bridges_cache_path, doc)

    def last_winner_method(self) -> str:
        return str(read_json(self.bridges_cache_path).get("_last_winner_method") or "")

    def save_autopilot_winner(self, transport: str, method: str = "") -> None:
        doc = read_json(self.bridges_cache_path)
        doc["_autopilot"] = {
            "transport": str(transport).strip().lower(),
            "method": str(method).strip(),
            "at": time.time(),
        }
        if method:
            doc["_last_winner_method"] = str(method).strip()
        write_json(self.bridges_cache_path, doc)

    def autopilot_winner(self, max_age_s: float = 7 * 24 * 3600) -> tuple[str, str]:
        doc = read_json(self.bridges_cache_path)
        entry = doc.get("_autopilot")
        if not isinstance(entry, dict):
            return "", ""
        if time.time() - float(entry.get("at", 0) or 0) > max_age_s:
            return "", ""
        return str(entry.get("transport") or ""), str(entry.get("method") or "")

    def load_dns_cache(self, max_age_s: float = 24 * 3600) -> dict[str, list[str]]:
        doc = read_json(self.dns_cache_path)
        now = time.time()
        out: dict[str, list[str]] = {}
        for host, entry in doc.items():
            if not isinstance(entry, dict):
                continue
            if now - float(entry.get("at", 0) or 0) <= max_age_s:
                ips = [str(ip) for ip in (entry.get("ips") or []) if isinstance(ip, str)]
                if ips:
                    out[host.lower()] = ips
        return out

    def save_dns_cache(self, host: str, ips: list[str]) -> None:
        if not host or not ips:
            return
        doc = read_json(self.dns_cache_path)
        doc[host.lower()] = {"ips": list(dict.fromkeys(ips))[:6], "at": time.time()}
        write_json(self.dns_cache_path, doc)
