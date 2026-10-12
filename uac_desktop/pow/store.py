"""PoW settings persistence — port of mobile ``PowEngineStore`` (JSON file)."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from .config import (
    DEFAULT_KEY_FETCH,
    KEY_ECH,
    FIREWALL_AUTO,
    OUTER_AUTO,
    RECIPE_AUTO,
    SCAN_BALANCED,
    PowSettings,
    LastConnect,
    strategy_signature,
)

SETTINGS_FILENAME = "pow_settings.json"

_KEY_MAP = (
    ("exit_country_code", "exit_country", ""),
    ("outer_transport", "outer_transport", OUTER_AUTO),
    ("obfuscation_profile", "obfuscation_profile", "balanced"),
    ("h2_fragmentation", "h2_fragmentation", False),
    ("scan_mode", "scan_mode", SCAN_BALANCED),
    ("optimized_mode", "optimized_mode", True),
    ("firewall_profile", "firewall_profile", FIREWALL_AUTO),
    ("link_recipe", "link_recipe", RECIPE_AUTO),
    ("chain_psiphon", "chain_psiphon", True),
    ("key_fetch", "key_fetch", DEFAULT_KEY_FETCH),
    ("parallel_masque", "speed_parallel_masque", False),
    ("irancell_h3", "speed_irancell_h3", False),
    ("direct_psiphon_first", "speed_direct_psiphon_first", False),
    ("lowest_rtt_ip", "speed_lowest_rtt_ip", False),
)

#: v2: key_fetch default moved from "ech" to the mobile "auto" race.
SETTINGS_VERSION = 2


class PowStore:
    """Thread-safe JSON settings store under the app data dir."""

    def __init__(self, data_dir: Path) -> None:
        self._path = Path(data_dir) / SETTINGS_FILENAME
        self._lock = threading.RLock()
        self._doc: dict[str, Any] = self._read()
        self._migrate()

    def _migrate(self) -> None:
        """Older desktop builds saved the then-default "ech" on first save.
        Move those files to the mobile default ("auto") once."""
        with self._lock:
            try:
                version = int(self._doc.get("settings_version", 1) or 1)
            except (TypeError, ValueError):
                version = 1
            if version >= SETTINGS_VERSION:
                return
            if not self._doc:
                return
            if str(self._doc.get("key_fetch", "")).strip().lower() in ("", KEY_ECH):
                self._doc["key_fetch"] = DEFAULT_KEY_FETCH
            self._doc["settings_version"] = SETTINGS_VERSION
            try:
                self._write()
            except OSError:
                pass

    # -- raw io -----------------------------------------------------------
    def _read(self) -> dict[str, Any]:
        try:
            return json.loads(self._path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _write(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        try:
            tmp.write_text(json.dumps(self._doc, ensure_ascii=False, indent=2), encoding="utf-8")
            tmp.replace(self._path)
        finally:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass

    # -- settings ---------------------------------------------------------
    def snapshot(self) -> PowSettings:
        with self._lock:
            kwargs: dict[str, Any] = {}
            for attr, key, default in _KEY_MAP:
                kwargs[attr] = self._doc.get(key, default)
            return PowSettings(**kwargs).validated()

    def save(self, settings: PowSettings) -> PowSettings:
        validated = settings.validated()
        with self._lock:
            for attr, key, _default in _KEY_MAP:
                self._doc[key] = getattr(validated, attr)
            self._doc["settings_version"] = SETTINGS_VERSION
            self._write()
        return validated

    # -- last connect -----------------------------------------------------
    def save_last_connect(self, last: LastConnect) -> None:
        with self._lock:
            self._doc["last_connect_protocol"] = last.protocol
            self._doc["last_connect_transport"] = last.transport
            self._doc["last_connect_ip"] = last.ip
            self._doc["last_connect_peer"] = last.peer
            self._doc["last_connect_psiphon"] = last.through_psiphon
            self._write()

    def read_last_connect(self) -> LastConnect:
        with self._lock:
            return LastConnect(
                protocol=str(self._doc.get("last_connect_protocol", "")),
                transport=str(self._doc.get("last_connect_transport", "")),
                ip=str(self._doc.get("last_connect_ip", "")),
                peer=str(self._doc.get("last_connect_peer", "")),
                through_psiphon=bool(self._doc.get("last_connect_psiphon", True)),
            )

    # -- psiphon strategy memory ------------------------------------------
    def remembered_strategy_index(self, ladder_size: int, shape: str | None = None) -> int:
        with self._lock:
            shape = shape or strategy_signature()
            if self._doc.get("strategy_shape") != shape:
                self._doc["strategy_shape"] = shape
                self._doc["strategy_index"] = 0
                self._write()
                return 0
            try:
                return max(0, min(int(self._doc.get("strategy_index", 0)), ladder_size - 1))
            except (TypeError, ValueError):
                return 0

    def save_strategy_winner(self, index: int, shape: str | None = None) -> None:
        with self._lock:
            self._doc["strategy_shape"] = shape or strategy_signature()
            self._doc["strategy_index"] = int(index)
            self._write()

    # -- per-network psiphon memory (mirrors mobile PowNetworkScoreboard) --
    _MAX_NETWORKS = 32

    def _network(self, network: str, create: bool = False) -> dict[str, Any]:
        networks = self._doc.get("networks")
        if not isinstance(networks, dict):
            networks = {}
            if create:
                self._doc["networks"] = networks
        entry = networks.get(network)
        if not isinstance(entry, dict):
            entry = {}
            if create:
                if len(networks) >= self._MAX_NETWORKS:
                    oldest = min(networks, key=lambda k: networks[k].get("seen", 0) if isinstance(networks[k], dict) else 0)
                    networks.pop(oldest, None)
                networks[network] = entry
        if create:
            import time as _time

            entry["seen"] = int(_time.time())
        return entry

    def network_strategy_index(self, network: str, shape: str, ladder_size: int) -> int | None:
        """Winner saved for this network and ladder shape, or None."""
        with self._lock:
            entry = self._network(network)
            if entry.get("strategy_shape") != shape:
                return None
            try:
                index = int(entry.get("strategy_index"))
            except (TypeError, ValueError):
                return None
            return index if 0 <= index < ladder_size else None

    def save_network_strategy(self, network: str, shape: str, index: int) -> None:
        with self._lock:
            entry = self._network(network, create=True)
            entry["strategy_shape"] = shape
            entry["strategy_index"] = int(index)
            self._doc["strategy_shape"] = shape
            self._doc["strategy_index"] = int(index)
            self._write()

    def strategy_rtts(self, network: str, keys: list[str]) -> dict[str, int]:
        with self._lock:
            saved = self._network(network).get("rtt", {})
            if not isinstance(saved, dict):
                return {}
            out: dict[str, int] = {}
            for key in keys:
                try:
                    value = int(saved.get(key, 0))
                except (TypeError, ValueError):
                    continue
                if value > 0:
                    out[key] = value
            return out

    def save_strategy_rtt(self, network: str, key: str, rtt_ms: int) -> None:
        if rtt_ms <= 0:
            return
        with self._lock:
            entry = self._network(network, create=True)
            saved = entry.get("rtt")
            if not isinstance(saved, dict):
                saved = {}
                entry["rtt"] = saved
            saved[key] = int(rtt_ms)
            self._write()

    def clean_pool(self, network: str) -> dict[str, int]:
        """Accepted MASQUE HTTP/2 addresses on this network -> last RTT (0 = unmeasured)."""
        with self._lock:
            saved = self._network(network).get("clean_h2")
            if not isinstance(saved, dict):
                return {}
            out: dict[str, int] = {}
            for peer, rtt in saved.items():
                try:
                    out[str(peer)] = max(0, int(rtt))
                except (TypeError, ValueError):
                    out[str(peer)] = 0
            return out

    def save_clean_pool(self, network: str, pool: dict[str, int], limit: int = 12) -> None:
        with self._lock:
            entry = self._network(network, create=True)
            ranked = sorted(pool.items(), key=lambda kv: (kv[1] <= 0, kv[1]))[:limit]
            entry["clean_h2"] = {peer: int(rtt) for peer, rtt in ranked}
            self._write()

    def remembered_region(self, network: str) -> str | None:
        with self._lock:
            value = str(self._network(network).get("region", "")).strip().upper()
        return value or None

    def save_region(self, network: str, code: str) -> None:
        clean = (code or "").strip().upper()
        if len(clean) != 2:
            return
        with self._lock:
            self._network(network, create=True)["region"] = clean
            self._write()

    def learned_networks(self) -> list[dict[str, Any]]:
        """Per-network memory, most recently used first (for the settings UI)."""
        with self._lock:
            networks = self._doc.get("networks")
            if not isinstance(networks, dict):
                return []
            rows = []
            for key, entry in networks.items():
                if isinstance(entry, dict):
                    row = dict(entry)
                    row["key"] = key
                    rows.append(row)
        return sorted(rows, key=lambda row: int(row.get("seen", 0) or 0), reverse=True)

    def last_learned_region(self) -> str | None:
        """Nearby exit remembered on the most recently used network."""
        for row in self.learned_networks():
            region = str(row.get("region", "") or "").strip().upper()
            if region:
                return region
        return None

    def forget_learned(self) -> None:
        with self._lock:
            self._doc.pop("networks", None)
            self._doc.pop("strategy_index", None)
            self._doc.pop("strategy_shape", None)
            self._write()

    # -- outer protocol memory --------------------------------------------
    def remembered_outer_protocol(self) -> str | None:
        with self._lock:
            value = str(self._doc.get("outer_protocol", "")).strip().lower()
            from .config import OUTER_LADDER

            return value if value in OUTER_LADDER else None

    def save_outer_protocol(self, protocol: str) -> None:
        from .config import OUTER_LADDER

        clean = (protocol or "").strip().lower()
        if clean not in OUTER_LADDER:
            return
        with self._lock:
            self._doc["outer_protocol"] = clean
            self._write()

    # -- regions -----------------------------------------------------------
    def available_regions(self) -> list[str]:
        from .regions import is_code

        with self._lock:
            raw = str(self._doc.get("available_regions", ""))
        return sorted(
            {part.strip().upper() for part in raw.split(",") if is_code(part)}
        )

    def remember_available_regions(self, codes: list[str]) -> None:
        from .regions import is_code

        clean = sorted({code.strip().upper() for code in codes if is_code(code)})
        if not clean:
            return
        with self._lock:
            self._doc["available_regions"] = ",".join(clean)
            self._write()
