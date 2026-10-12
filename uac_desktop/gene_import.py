"""Import Gene Lab strategies.json into UAC Spoofer Xray Pattern settings."""
from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Any

MAX_WORKING_IPS = 5

# Ops that survive a real end-to-end TLS tunnel (Pattern forwards xray's own
# ClientHello). pad_ext/shuffle_ext/grease/junk_record/reorder_send cannot.
TUNNEL_SAFE_KINDS = frozenset({"tcp_frag", "delay", "record_cut", "sni_cut"})


def ops_tunnel_safe(ops: Any) -> bool:
    return all(
        isinstance(op, dict) and str(op.get("kind", "") or "").strip().lower() in TUNNEL_SAFE_KINDS
        for op in (ops or [])
    )

SUPPORTED_METHODS = frozenset({
    "wrong_seq",
    "plain",
    "full5",
    "full10",
    "full20",
    "multi64",
    "tls_sni_records",
    "sni_boundary",
    "sni_split",
    "primitive",
})


def normalize_working_ips(raw: Any, fallback_ips: Any = None) -> list[dict[str, Any]]:
    """Distinct IPv4 working edges [{ip, latency_ms, at}] (max 5, faster first).

    Older Gene Lab files only carry ``confirmed_ips``; those are used (without
    latency) when ``working_ips`` is absent.
    """
    items = list(raw) if isinstance(raw, list) else []
    if not items and isinstance(fallback_ips, list):
        items = [{"ip": ip} for ip in fallback_ips]
    best: dict[str, dict[str, Any]] = {}
    for item in items:
        if isinstance(item, str):
            item = {"ip": item}
        if not isinstance(item, dict):
            continue
        try:
            ip = str(ipaddress.IPv4Address(str(item.get("ip", "")).strip()))
        except (ipaddress.AddressValueError, ValueError):
            continue
        try:
            latency = max(0.0, min(60000.0, float(item.get("latency_ms", 0.0) or 0.0)))
            stamp = max(0.0, float(item.get("at", 0.0) or 0.0))
        except (TypeError, ValueError):
            latency, stamp = 0.0, 0.0
        entry = {"ip": ip, "latency_ms": round(latency, 1), "at": stamp}
        if ip not in best or stamp >= best[ip]["at"]:
            best[ip] = entry
    ordered = sorted(best.values(), key=lambda e: (e["latency_ms"] <= 0, e["latency_ms"], -e["at"]))
    return ordered[:MAX_WORKING_IPS]


def gene_edge_ips(strategy: dict[str, Any] | None) -> list[str]:
    """Working IPs of an imported strategy, in try order ([] = none)."""
    if not isinstance(strategy, dict):
        return []
    return [e["ip"] for e in normalize_working_ips(strategy.get("working_ips"))]


def _clamp_int(value: Any, lo: int, hi: int, default: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, number))


def normalize_ops(raw: Any) -> list[dict[str, Any]]:
    """Keep Gene Lab primitive ops as plain dicts for Pattern runtime."""
    out: list[dict[str, Any]] = []
    if not isinstance(raw, list):
        return out
    for item in raw[:12]:
        if not isinstance(item, dict):
            continue
        kind = str(item.get("kind", "") or "").strip().lower()
        if not kind:
            continue
        op = {
            "kind": kind,
            "size": _clamp_int(item.get("size", 5), 0, 1_000_000, 5),
            "delay_ms": _clamp_int(item.get("delay_ms", 0), 0, 80, 0),
            "offset": _clamp_int(item.get("offset", 0), 0, 4096, 0),
            "content_type": _clamp_int(item.get("content_type", 0x17), 0, 255, 0x17),
            "ttl": _clamp_int(item.get("ttl", 0), 0, 255, 0),
            "checksum_mode": str(item.get("checksum_mode", "valid") or "valid").strip().lower(),
        }
        if op["checksum_mode"] not in {"valid", "corrupt", "zero"}:
            op["checksum_mode"] = "valid"
        out.append(op)
    return out


def _ops_timing(ops: list[dict[str, Any]]) -> tuple[int, int]:
    """Derive (chunk_size, fragment_delay_ms) from tcp_frag ops for Tuning fields."""
    frags = [op for op in ops if op.get("kind") == "tcp_frag"]
    if not frags:
        return 5, 0
    chunk = max(1, min(128, int(frags[0].get("size", 5) or 5)))
    delays = [int(op.get("delay_ms", 0) or 0) for op in frags if int(op.get("delay_ms", 0) or 0) > 0]
    delay = max(0, min(80, delays[0] if delays else 0))
    return chunk, delay


def _ops_fingerprint(ops: list[dict[str, Any]]) -> str:
    parts = []
    for op in ops:
        parts.append(
            f"{op.get('kind')}:{op.get('size')}:{op.get('delay_ms')}:"
            f"{op.get('offset')}:{op.get('ttl')}:{op.get('checksum_mode')}"
        )
    return ",".join(parts)


def normalize_strategy(raw: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    genome = str(raw.get("genome", "") or "").strip().lower()
    method = str(raw.get("method", "") or "").strip().lower()
    ops = normalize_ops(raw.get("ops"))
    if method == "primitive" or genome == "primitive" or (ops and method in {"", "primitive"}):
        if not ops:
            return None
        method = "primitive"
        chunk_size, fragment_delay_ms = _ops_timing(ops)
    else:
        if method not in SUPPORTED_METHODS or method == "primitive":
            return None
        ops = []
        try:
            fragment_delay_ms = max(0, min(80, int(raw.get("fragment_delay_ms", 0) or 0)))
            chunk_size = max(1, min(128, int(raw.get("chunk_size", 5) or 5)))
        except (TypeError, ValueError):
            return None
    try:
        fake_repeat = max(1, min(5, int(raw.get("fake_repeat", 1) or 1)))
        inject_delay_ms = max(0, min(20, int(raw.get("inject_delay_ms", 1) or 0)))
        score = max(0.0, min(1.0, float(raw.get("score", 0.0) or 0.0)))
        success_rate = max(0.0, min(1.0, float(raw.get("success_rate", 0.0) or 0.0)))
    except (TypeError, ValueError):
        return None
    strategy_id = str(raw.get("id", "") or "").strip()
    if not strategy_id:
        strategy_id = f"gene_{method}_{abs(hash(str(raw))) % 10_000_000:x}"
    name = str(raw.get("name", "") or f"{method}@{raw.get('fake_sni', '')}").strip()
    return {
        "id": strategy_id,
        "name": name,
        "method": method,
        "genome": "primitive" if method == "primitive" else "legacy",
        "ops": ops,
        "fake_sni": str(raw.get("fake_sni", "chatgpt.com") or "chatgpt.com").strip().lower(),
        "fake_repeat": fake_repeat,
        "inject_delay_ms": inject_delay_ms,
        "fragment_delay_ms": fragment_delay_ms,
        "chunk_size": chunk_size,
        "network_id": str(raw.get("network_id", "") or ""),
        "score": score,
        "success_rate": success_rate,
        "tests": max(0, int(raw.get("tests", 0) or 0)),
        "avg_ms": max(0.0, float(raw.get("avg_ms", 0.0) or 0.0)),
        "generation": max(0, int(raw.get("generation", 0) or 0)),
        "notes": str(raw.get("notes", "") or ""),
        "confirmed": bool(raw.get("confirmed", False)),
        "confirmed_ips": [str(x) for x in (raw.get("confirmed_ips") or []) if str(x).strip()][:16],
        "working_ips": normalize_working_ips(raw.get("working_ips"), raw.get("confirmed_ips")),
        "confirm_need": max(1, min(8, int(raw.get("confirm_need", 3) or 3))),
        "recommended": bool(raw.get("confirmed", False)),
        "mode": str(raw.get("mode", "") or ""),
        "simulated": bool(raw.get("simulated", False)),
        "tunnel_safe": bool(ops_tunnel_safe(ops) and raw.get("tunnel_safe", True) is not False)
        if method == "primitive" else True,
    }


def load_strategies_file(path: str | Path) -> list[dict[str, Any]]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("strategies.json root must be an object")
    buckets = []
    for key in ("strategies", "hall_of_fame", "population"):
        value = payload.get(key)
        if isinstance(value, list):
            buckets.extend(value)
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for item in buckets:
        normalized = normalize_strategy(item if isinstance(item, dict) else None)
        if not normalized:
            continue
        # Import only live-confirmed strategies (Gene Lab gate).
        if not normalized.get("confirmed") or normalized.get("simulated"):
            continue
        # Primitive genes must be tunnel-safe (all ops reshape framing/timing only).
        if normalized["method"] == "primitive" and not normalized.get("tunnel_safe"):
            continue
        if normalized["method"] == "primitive":
            fingerprint = "|".join([
                "primitive",
                normalized["fake_sni"],
                str(normalized["fake_repeat"]),
                _ops_fingerprint(normalized.get("ops") or []),
            ])
        else:
            fingerprint = "|".join([
                normalized["method"],
                normalized["fake_sni"],
                str(normalized["fake_repeat"]),
                str(normalized["inject_delay_ms"]),
                str(normalized["fragment_delay_ms"]),
                str(normalized["chunk_size"]),
            ])
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        out.append(normalized)
    out.sort(
        key=lambda s: (
            1 if s.get("recommended") or s.get("confirmed") else 0,
            s["score"],
            s["success_rate"],
            -s["avg_ms"],
        ),
        reverse=True,
    )
    return out


def display_label(strategy: dict[str, Any], language: str = "fa") -> str:
    rate = int(round(float(strategy.get("success_rate", 0) or 0) * 100))
    name = strategy.get("name") or strategy.get("method")
    method = strategy.get("method")
    mark = "* " if strategy.get("confirmed") or strategy.get("recommended") else ""
    if language == "en":
        return f"{mark}{name} · {method} · {rate}%"
    return f"{mark}{name} · {method} · {rate}%"
