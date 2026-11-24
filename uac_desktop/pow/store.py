"""PoW settings persistence — port of mobile ``PowEngineStore`` (JSON file)."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

from .config import (
    DEFAULT_KEY_FETCH,
    KEY_ECH,
    KEY_FETCHES_RETIRED,
    FIREWALL_AUTO,
    OUTER_AUTO,
    RECIPE_MASQUE_H2,
    SCAN_BALANCED,
    PowSettings,
    LastConnect,
    clean_h2_path,
    lastconn_path,
    masque_cache_path,
    strategy_signature,
)
from .warmup import normalize_host

SETTINGS_FILENAME = "pow_settings.json"

_KEY_MAP = (
    ("exit_country_code", "exit_country", ""),
    ("outer_transport", "outer_transport", OUTER_AUTO),
    ("obfuscation_profile", "obfuscation_profile", "balanced"),
    ("h2_fragmentation", "h2_fragmentation", False),
    ("scan_mode", "scan_mode", SCAN_BALANCED),
    ("optimized_mode", "optimized_mode", True),
    ("firewall_profile", "firewall_profile", FIREWALL_AUTO),
    ("link_recipe", "link_recipe", RECIPE_MASQUE_H2),
    ("chain_psiphon", "chain_psiphon", True),
    ("exit_mode", "exit_mode", ""),
    ("key_fetch", "key_fetch", DEFAULT_KEY_FETCH),
    ("parallel_masque", "speed_parallel_masque", False),
    ("irancell_h3", "speed_irancell_h3", False),
    ("direct_psiphon_first", "speed_direct_psiphon_first", False),
    ("lowest_rtt_ip", "speed_lowest_rtt_ip", False),
    ("quic_tuned", "quic_tuned", False),
    ("h2_large_windows", "h2_large_windows", True),
    ("h2_socket_tuning", "h2_socket_tuning", True),
    ("h2_speed_pick", "h2_speed_pick", True),
    ("h2_fragment_mode", "h2_fragment_mode", "auto"),
    ("h2_fingerprint", "h2_fingerprint", "default"),
    ("masque_ip_version", "masque_ip_version", "auto"),
    ("h2_obfuscation", "h2_obfuscation", "unchanged"),
    ("tun_mtu", "tun_mtu", 1400),
    ("tun_backend", "tun_backend", "stable"),
    ("startup_speed_test", "startup_speed_test", False),
    ("psiphon_tunnel_pool", "psiphon_tunnel_pool", False),
    ("routing_mode", "routing_mode", "bypass"),
    ("iran_direct", "iran_direct", True),
    ("dns_sinkhole", "dns_sinkhole", True),
    ("webrtc_block", "webrtc_block", True),
    ("quic_block", "quic_block", False),
    ("ipv6_block", "ipv6_block", True),
    ("kill_switch", "kill_switch", False),
    ("auto_connect", "auto_connect", False),
    ("lan_share", "lan_share", False),
    ("lan_share_mode", "lan_share_mode", "socks5"),
    ("lan_share_port", "lan_share_port", 18080),
)

#: v2: key_fetch default moved from "ech" to the mobile "auto" race.
SETTINGS_VERSION = 3


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
            retired = str(self._doc.get("key_fetch", "")).strip().lower() in KEY_FETCHES_RETIRED
            try:
                version = int(self._doc.get("settings_version", 1) or 1)
            except (TypeError, ValueError):
                version = 1
            if version >= SETTINGS_VERSION:
                if retired:
                    self._doc["key_fetch"] = DEFAULT_KEY_FETCH
                    self._write()
                return
            if not self._doc:
                return
            try:
                with self._path.with_suffix(".before-v3.json").open("xb") as backup:
                    backup.write(self._path.read_bytes())
            except FileExistsError:
                pass
            if retired or (version < 2 and str(self._doc.get("key_fetch", "")).strip().lower() in ("", KEY_ECH)):
                self._doc["key_fetch"] = DEFAULT_KEY_FETCH
            if "exit_mode" not in self._doc:
                self._doc["exit_mode"] = "warp" if self._doc.get("chain_psiphon") is False else "chain"
            self._doc["settings_version"] = SETTINGS_VERSION
            try:
                self._write()
            except OSError:
                pass

    # -- raw io -----------------------------------------------------------
    def _read(self) -> dict[str, Any]:
        try:
            doc = json.loads(self._path.read_text(encoding="utf-8"))
            return doc if isinstance(doc, dict) else {}
        except (OSError, ValueError):
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
    def saved_settings(self) -> dict:
        with self._lock:
            return self._doc.copy()

    def snapshot(self) -> PowSettings:
        with self._lock:
            kwargs: dict[str, Any] = {}
            for attr, key, default in _KEY_MAP:
                value = self._doc.get(key, default)
                kwargs[attr] = value if type(value) is type(default) else default
            return PowSettings(**kwargs).validated()

    def save(self, settings: PowSettings, *, exclude=()) -> PowSettings:
        validated = settings.validated()
        with self._lock:
            for attr, key, _default in _KEY_MAP:
                if key not in exclude:
                    self._doc[key] = getattr(validated, attr)
            self._doc["settings_version"] = SETTINGS_VERSION
            self._write()
        return validated

    def user_stopped(self) -> bool:
        with self._lock:
            return self._doc.get("user_stopped") is True

    def set_user_stopped(self, value: bool) -> None:
        with self._lock:
            if self._doc.get("user_stopped", False) != value:
                self._doc["user_stopped"] = value
                self._write()

    def export_settings(self) -> dict:
        with self._lock:
            settings = self.snapshot()
            return {
                "settings_version": SETTINGS_VERSION,
                "exit_proxy_mode": self.exit_proxy_mode(),
                "proxy_http_port": self.proxy_http_port(),
                "psiphon_socks_port": self.psiphon_socks_port(),
                **{key: getattr(settings, attr) for attr, key, _ in _KEY_MAP},
            }

    def import_settings(self, document: dict, *, exclude=()) -> None:
        if not isinstance(document, dict):
            raise ValueError("Expected a PoW settings object")
        with self._lock:
            baseline = self._doc.copy()
            try:
                for _attr, key, default in _KEY_MAP:
                    value = document.get(key)
                    if key not in exclude and type(value) is type(default):
                        self._doc[key] = value
                if "exit_mode" not in document and type(document.get("chain_psiphon")) is bool:
                    self._doc["exit_mode"] = "chain" if document["chain_psiphon"] else "warp"
                settings = self.snapshot()
                for key in ("proxy_http_port", "psiphon_socks_port"):
                    port = document.get(key)
                    if type(port) is int and 1 <= port <= 65535:
                        self._doc[key] = port
                if "exit_proxy_mode" not in exclude and type(document.get("exit_proxy_mode")) is bool:
                    self._doc["exit_proxy_mode"] = document["exit_proxy_mode"]
                self.save(settings, exclude=exclude)
            except (OSError, ValueError):
                self._doc = baseline
                raise

    # -- exit mode (TUN vs Windows proxy) --------------------------------
    def exit_proxy_mode(self) -> bool:
        """Saved exit choice: False = TUN (the default), True = Windows proxy."""
        with self._lock:
            return bool(self._doc.get("exit_proxy_mode", False))

    def save_exit_proxy_mode(self, proxy: bool) -> None:
        with self._lock:
            self._doc["exit_proxy_mode"] = bool(proxy)
            self._write()

    # -- local proxy port (Windows proxy / App Bypass mixed port) ---------
    def proxy_http_port(self) -> int:
        """Saved local HTTP port; 1822 (the built-in port) when unset."""
        from ..proxy_ports import POW_HTTP_DEFAULT, POW_HTTP_KEY, pow_port_from_value
        with self._lock:
            return pow_port_from_value(self._doc.get(POW_HTTP_KEY, POW_HTTP_DEFAULT))

    def psiphon_socks_port(self) -> int:
        """Saved Psiphon local SOCKS port; 1821 (the built-in port) when unset."""
        from ..proxy_ports import POW_SOCKS_DEFAULT, POW_SOCKS_KEY, pow_socks_from_value
        with self._lock:
            return pow_socks_from_value(self._doc.get(POW_SOCKS_KEY, POW_SOCKS_DEFAULT))

    def save_psiphon_socks_port(self, port: int) -> int:
        from ..proxy_ports import POW_SOCKS_KEY, pow_socks_from_value
        value = pow_socks_from_value(port)
        with self._lock:
            self._doc[POW_SOCKS_KEY] = value
            self._write()
        return value

    def save_proxy_http_port(self, port: int) -> int:
        from ..proxy_ports import POW_HTTP_KEY, pow_port_from_value
        value = pow_port_from_value(port)
        with self._lock:
            self._doc[POW_HTTP_KEY] = value
            self._write()
        return value

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

    def _path_cache_files(self) -> tuple[Path, ...]:
        data = self._path.parent
        return (
            masque_cache_path(data), lastconn_path(data), clean_h2_path(data),
            data / "uac-pow-gool-lastconn.toml",
        )

    def expire_path_cache(self, now: float | None = None) -> int:
        cutoff = (time.time() if now is None else now) - 12 * 60
        expired = 0
        for path in self._path_cache_files():
            try:
                if path.stat().st_mtime < cutoff:
                    path.unlink()
                    expired += 1
            except FileNotFoundError:
                pass
        return expired

    def forget_learned(self) -> None:
        with self._lock:
            for key in ("networks", "strategy_index", "strategy_shape", "outer_protocol", "dns_warm_hosts"):
                self._doc.pop(key, None)
            self._write()
            self.forget_path_cache()

    def forget_path_cache(self, *, keep_clean_h2: bool = False) -> None:
        keep = clean_h2_path(self._path.parent) if keep_clean_h2 else None
        for path in self._path_cache_files():
            if path != keep:
                path.unlink(missing_ok=True)

    def dns_warm_hosts(self) -> list[str]:
        with self._lock:
            saved = self._doc.get("dns_warm_hosts", {})
            if not isinstance(saved, dict):
                return []
            return [host for host in saved if normalize_host(host) == host][:20]

    def save_dns_warm_hosts(self, observations: dict[str, int]) -> None:
        with self._lock:
            saved = self._doc.get("dns_warm_hosts", {})
            counts = {}
            if isinstance(saved, dict):
                counts = {host: max(1, count // 2) for host, count in saved.items()
                          if normalize_host(host) == host and type(count) is int and count > 0}
            for host, count in observations.items():
                counts[host] = counts.get(host, 0) + count
            self._doc["dns_warm_hosts"] = dict(sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:20])
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
