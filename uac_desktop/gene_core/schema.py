from __future__ import annotations

import json
import os
import tempfile
import time
import uuid
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any

# Methods already implemented in uac_desktop.tls_tools.fragments /
# pattern_core.core (after enabling sni_* in TLS_FRAGMENT_STRATEGIES).
STRATEGY_METHODS = frozenset({
    "wrong_seq",
    "plain",
    "full5",
    "full10",
    "full20",
    "multi64",
    "tls_sni_records",
    "sni_boundary",
    "sni_split",
})

KNOWN_FAKE_SNIS = (
    "chatgpt.com",
    "www.cloudflare.com",
    "www.microsoft.com",
    "www.google.com",
    "cdn.jsdelivr.net",
    "ajax.googleapis.com",
)

STORE_VERSION = 1


def _clamp_int(value: Any, lo: int, hi: int, default: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, number))


def _clamp_float(value: Any, lo: float, hi: float, default: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, number))


MAX_WORKING_IPS = 5


def normalize_working_ips(raw: Any, limit: int = MAX_WORKING_IPS) -> list[dict]:
    """Distinct IPv4 entries {ip, latency_ms, at}, lowest latency first."""
    import ipaddress

    best: dict[str, dict] = {}
    for item in raw or []:
        if isinstance(item, str):
            item = {"ip": item}
        if not isinstance(item, dict):
            continue
        try:
            ip = str(ipaddress.IPv4Address(str(item.get("ip", "")).strip()))
        except (ipaddress.AddressValueError, ValueError):
            continue
        entry = {
            "ip": ip,
            "latency_ms": round(_clamp_float(item.get("latency_ms", 0.0), 0.0, 60000.0, 0.0), 1),
            "at": _clamp_float(item.get("at", 0.0), 0.0, 1e11, 0.0),
        }
        prev = best.get(ip)
        if prev is None or entry["at"] >= prev["at"]:
            best[ip] = entry
    ordered = sorted(best.values(), key=lambda e: (e["latency_ms"] <= 0, e["latency_ms"], -e["at"]))
    return ordered[:max(0, int(limit))]


def merge_working_ips(existing: Any, trials: Any, now: float | None = None,
                      limit: int = MAX_WORKING_IPS) -> list[dict]:
    """Merge (ip, latency_ms) wins into stored working IPs (fresh entries win)."""
    stamp = time.time() if now is None else float(now)
    fresh = [{"ip": ip, "latency_ms": ms, "at": stamp} for ip, ms in (trials or [])]
    return normalize_working_ips([*(existing or []), *fresh], limit)


@dataclass
class GeneStrategy:
    """One selectable Pattern route composition."""

    id: str = ""
    name: str = ""
    method: str = "wrong_seq"
    fake_sni: str = "chatgpt.com"
    fake_repeat: int = 1
    inject_delay_ms: int = 1
    fragment_delay_ms: int = 0
    chunk_size: int = 5
    network_id: str = "unknown"
    score: float = 0.0
    success_rate: float = 0.0
    tests: int = 0
    successes: int = 0
    avg_ms: float = 0.0
    traffic_bytes: int = 0
    created_at: float = 0.0
    updated_at: float = 0.0
    notes: str = ""
    generation: int = 0
    parent_ids: list[str] = field(default_factory=list)
    confirmed: bool = False
    confirmed_ips: list[str] = field(default_factory=list)
    # Distinct edge IPs this gene succeeded on: [{"ip", "latency_ms", "at"}], max 5.
    working_ips: list[dict] = field(default_factory=list)
    confirm_need: int = 3
    recommended: bool = False
    fail_reset: int = 0
    fail_timeout: int = 0
    fail_other: int = 0
    simulated: bool = False
    mode: str = ""  # "" | "dry" | "live"

    def __post_init__(self) -> None:
        if not self.id:
            self.id = f"gene_{uuid.uuid4().hex[:12]}"
        method = str(self.method or "wrong_seq").strip().lower()
        self.method = method if method in STRATEGY_METHODS else "wrong_seq"
        self.fake_sni = (str(self.fake_sni or "chatgpt.com").strip().lower()
                         or "chatgpt.com")
        self.fake_repeat = _clamp_int(self.fake_repeat, 1, 5, 1)
        self.inject_delay_ms = _clamp_int(self.inject_delay_ms, 0, 20, 1)
        self.fragment_delay_ms = _clamp_int(self.fragment_delay_ms, 0, 80, 0)
        self.chunk_size = _clamp_int(self.chunk_size, 1, 128, 5)
        self.network_id = str(self.network_id or "unknown").strip() or "unknown"
        self.score = _clamp_float(self.score, 0.0, 1.0, 0.0)
        self.success_rate = _clamp_float(self.success_rate, 0.0, 1.0, 0.0)
        self.tests = max(0, int(self.tests or 0))
        self.successes = max(0, min(self.tests, int(self.successes or 0)))
        self.avg_ms = max(0.0, float(self.avg_ms or 0.0))
        self.traffic_bytes = max(0, int(self.traffic_bytes or 0))
        now = time.time()
        self.created_at = float(self.created_at or now)
        self.updated_at = float(self.updated_at or self.created_at)
        if not self.name:
            self.name = f"{self.method}@{self.fake_sni}"
        self.generation = max(0, int(self.generation or 0))
        self.parent_ids = [str(x) for x in (self.parent_ids or [])][:4]
        self.notes = str(self.notes or "")
        self.fail_reset = max(0, int(self.fail_reset or 0))
        self.fail_timeout = max(0, int(self.fail_timeout or 0))
        self.fail_other = max(0, int(self.fail_other or 0))
        self.simulated = bool(self.simulated)
        mode = str(self.mode or "").strip().lower()
        self.mode = mode if mode in {"dry", "live"} else ""
        if self.mode == "dry":
            self.simulated = True
        ips = []
        for item in (self.confirmed_ips or []):
            text = str(item or "").strip()
            if text and text not in ips:
                ips.append(text)
        self.confirmed_ips = ips[:16]
        self.working_ips = normalize_working_ips(self.working_ips)
        self.confirm_need = _clamp_int(self.confirm_need, 1, 8, 3)
        # Only live-confirmed strategies may be recommended for Import.
        if self.mode == "live" and not self.simulated:
            if len(self.confirmed_ips) >= self.confirm_need:
                self.confirmed = True
            else:
                self.confirmed = False
        else:
            self.confirmed = False
        self.recommended = bool(self.confirmed)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: dict[str, Any] | None) -> "GeneStrategy":
        data = dict(raw or {})
        valid = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in valid})

    def fingerprint(self) -> str:
        return "|".join([
            self.method,
            self.fake_sni,
            str(self.fake_repeat),
            str(self.inject_delay_ms),
            str(self.fragment_delay_ms),
            str(self.chunk_size),
        ])

    def display_label(self, language: str = "en") -> str:
        rate = int(round(self.success_rate * 100))
        if language == "fa":
            return f"{self.name} · {rate}% · gen {self.generation}"
        return f"{self.name} · {rate}% · gen {self.generation}"


@dataclass
class LabState:
    version: int = STORE_VERSION
    network_id: str = "unknown"
    generation: int = 0
    evaluated: int = 0
    traffic_bytes: int = 0
    traffic_cap_mb: float = 50.0
    dry_run: bool = True
    live_probe: bool = False
    population: list[GeneStrategy] = field(default_factory=list)
    hall_of_fame: list[GeneStrategy] = field(default_factory=list)
    rng_seed: int = 42
    paused: bool = False
    updated_at: float = 0.0
    settings: dict[str, Any] = field(default_factory=dict)
    live_stats: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "network_id": self.network_id,
            "generation": self.generation,
            "evaluated": self.evaluated,
            "traffic_bytes": self.traffic_bytes,
            "traffic_cap_mb": self.traffic_cap_mb,
            "dry_run": self.dry_run,
            "live_probe": self.live_probe,
            "population": [s.to_dict() for s in self.population],
            "hall_of_fame": [s.to_dict() for s in self.hall_of_fame],
            "rng_seed": self.rng_seed,
            "paused": self.paused,
            "updated_at": self.updated_at or time.time(),
            "settings": dict(self.settings or {}),
            "live_stats": dict(self.live_stats or {}),
            "strategies": [s.to_dict() for s in self.exportable_strategies()],
        }

    def prepare_live_session(self) -> None:
        """Quarantine dry-run results and reset counters for a real live run."""
        archive = list(self.settings.get("simulated_archive") or [])
        for strategy in list(self.population) + list(self.hall_of_fame):
            strategy.mode = "dry"
            strategy.simulated = True
            strategy.confirmed = False
            strategy.recommended = False
            if "simulated" not in (strategy.notes or ""):
                strategy.notes = ((strategy.notes or "") + " | simulated-dry-run").strip(" |")
            archive.append(strategy.to_dict())
        # Keep a capped archive; start live from a fresh population.
        self.settings["simulated_archive"] = archive[-200:]
        self.population = []
        self.hall_of_fame = []
        self.generation = 0
        self.evaluated = 0
        self.traffic_bytes = 0
        self.live_stats = {}
        self.dry_run = False
        self.live_probe = True
        if self.traffic_cap_mb < 50:
            self.traffic_cap_mb = 50.0

    def exportable_strategies(self) -> list[GeneStrategy]:

        """Best unique strategies ready for Import into UAC Spoofer."""
        seen: set[str] = set()
        ordered = sorted(
            self.hall_of_fame + self.population,
            key=lambda s: (
                1 if (s.confirmed or s.recommended) else 0,
                s.score,
                s.success_rate,
                -s.avg_ms,
            ),
            reverse=True,
        )
        out: list[GeneStrategy] = []
        for strategy in ordered:
            key = strategy.fingerprint()
            if key in seen:
                continue
            seen.add(key)
            if strategy.tests <= 0 and strategy.score <= 0:
                continue
            if strategy.simulated or strategy.mode != "live":
                strategy.recommended = False
            elif strategy.confirmed and len(strategy.confirmed_ips) >= max(1, strategy.confirm_need):
                strategy.recommended = True
            else:
                strategy.recommended = False
            out.append(strategy)
            if len(out) >= 40:
                break
        return out

    @classmethod
    def from_dict(cls, raw: dict[str, Any] | None) -> "LabState":
        data = dict(raw or {})
        pop = [GeneStrategy.from_dict(x) for x in data.get("population", []) if isinstance(x, dict)]
        hof = [GeneStrategy.from_dict(x) for x in data.get("hall_of_fame", []) if isinstance(x, dict)]
        if not hof:
            hof = [GeneStrategy.from_dict(x) for x in data.get("strategies", []) if isinstance(x, dict)]
        return cls(
            version=int(data.get("version", STORE_VERSION) or STORE_VERSION),
            network_id=str(data.get("network_id", "unknown") or "unknown"),
            generation=max(0, int(data.get("generation", 0) or 0)),
            evaluated=max(0, int(data.get("evaluated", 0) or 0)),
            traffic_bytes=max(0, int(data.get("traffic_bytes", 0) or 0)),
            traffic_cap_mb=_clamp_float(data.get("traffic_cap_mb", 50.0), 1.0, 500.0, 50.0),
            dry_run=bool(data.get("dry_run", True)),
            live_probe=bool(data.get("live_probe", False)),
            population=pop,
            hall_of_fame=hof,
            rng_seed=int(data.get("rng_seed", 42) or 42),
            paused=bool(data.get("paused", False)),
            updated_at=float(data.get("updated_at", 0.0) or 0.0),
            settings=dict(data.get("settings") or {}),
            live_stats=dict(data.get("live_stats") or {}),
        )


class StrategyStore:
    """Crash-safe JSON store: write temp then atomic replace + keep .bak."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def load(self) -> LabState:
        if not self.path.exists():
            return LabState()
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            bak = self.path.with_suffix(self.path.suffix + ".bak")
            if bak.exists():
                try:
                    raw = json.loads(bak.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    return LabState()
            else:
                return LabState()
        if not isinstance(raw, dict):
            return LabState()
        return LabState.from_dict(raw)

    def save(self, state: LabState) -> None:
        state.updated_at = time.time()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(state.to_dict(), ensure_ascii=False, indent=2)
        fd, tmp_name = tempfile.mkstemp(
            prefix=self.path.stem + ".",
            suffix=".tmp",
            dir=str(self.path.parent),
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            if self.path.exists():
                bak = self.path.with_suffix(self.path.suffix + ".bak")
                try:
                    if bak.exists():
                        bak.unlink()
                    os.replace(self.path, bak)
                except OSError:
                    pass
            os.replace(tmp_name, self.path)
        finally:
            if os.path.exists(tmp_name):
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass


def load_strategies(path: str | Path) -> LabState:
    return StrategyStore(path).load()


def save_strategies(path: str | Path, state: LabState) -> None:
    StrategyStore(path).save(state)
