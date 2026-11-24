from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .schema import GeneStrategy


@dataclass(slots=True)
class ScoreResult:
    success: bool
    score: float
    latency_ms: float
    traffic_bytes: int
    detail: str = ""


# Heuristic priors for dry-run: favor known working seeds around existing methods.
_METHOD_BASE = {
    "wrong_seq": 0.78,
    "full5": 0.74,
    "sni_boundary": 0.70,
    "tls_sni_records": 0.68,
    "sni_split": 0.66,
    "full10": 0.60,
    "full20": 0.55,
    "multi64": 0.52,
    "plain": 0.20,
}

_SNI_BONUS = {
    "chatgpt.com": 0.08,
    "www.cloudflare.com": 0.05,
    "www.microsoft.com": 0.04,
    "cdn.jsdelivr.net": 0.03,
    "www.google.com": 0.02,
    "ajax.googleapis.com": 0.02,
}


def _stable_noise(strategy: GeneStrategy, network_id: str) -> float:
    digest = hashlib.sha256(
        f"{network_id}|{strategy.fingerprint()}".encode("utf-8")
    ).hexdigest()
    # Deterministic pseudo-noise in [-0.08, +0.08]
    value = int(digest[:8], 16) / 0xFFFFFFFF
    return (value - 0.5) * 0.16


def score_dry_run(strategy: GeneStrategy, network_id: str = "unknown") -> ScoreResult:
    """Score a strategy without sending packets.

    Models relative fitness of parameter neighborhoods already used by the
    Xray Pattern engine so the GA can evolve offline tonight.
    """
    base = _METHOD_BASE.get(strategy.method, 0.4)
    base += _SNI_BONUS.get(strategy.fake_sni, 0.0)

    # Mild preferences learned from existing presets.
    if strategy.method == "wrong_seq":
        if strategy.fake_repeat == 1:
            base += 0.04
        elif strategy.fake_repeat >= 3:
            base -= 0.06
        if 0 <= strategy.inject_delay_ms <= 2:
            base += 0.03
        else:
            base -= 0.02 * min(5, strategy.inject_delay_ms)
    elif strategy.method in {"full5", "sni_boundary", "sni_split", "tls_sni_records"}:
        if 0 <= strategy.fragment_delay_ms <= 15:
            base += 0.05
        elif strategy.fragment_delay_ms > 40:
            base -= 0.08
        if strategy.method == "full5" and strategy.chunk_size in {5, 10}:
            base += 0.02
    elif strategy.method == "plain":
        base -= 0.05

    carrier = (network_id or "unknown").lower()
    if "mci" in carrier or "hamrah" in carrier:
        if strategy.method in {"wrong_seq", "tls_sni_records", "sni_boundary"}:
            base += 0.04
        if strategy.method == "full5":
            base += 0.02
    if "iran" in carrier or "mtn" in carrier:
        if strategy.method in {"full5", "sni_split", "sni_boundary"}:
            base += 0.05
        if strategy.method == "wrong_seq":
            base += 0.01

    base += _stable_noise(strategy, network_id)
    base = max(0.02, min(0.97, base))

    # Latency model: smaller delays and coarser fragments are quicker.
    latency = 120.0
    latency += strategy.inject_delay_ms * 3.0
    latency += strategy.fragment_delay_ms * 1.5
    latency += max(0, strategy.fake_repeat - 1) * 25.0
    if strategy.method in {"full5", "sni_split"}:
        latency += 15.0
    if strategy.method == "plain":
        latency += 40.0
    latency = max(40.0, min(900.0, latency + abs(_stable_noise(strategy, network_id)) * 200))

    # Soft success threshold with confirmation bias for strong scores.
    success = base >= 0.55
    if base >= 0.72:
        success = True
    elif base < 0.40:
        success = False

    # Dry-run traffic accounting (~7 KB handshake-ish).
    traffic = 7000 if success else 2500
    score = base
    if success:
        # Reward lower latency.
        score = min(1.0, score + max(0.0, (250.0 - latency) / 2000.0))
    else:
        score = max(0.0, score * 0.35)

    detail = "dry-run heuristic"
    return ScoreResult(
        success=success,
        score=round(score, 4),
        latency_ms=round(latency, 1),
        traffic_bytes=traffic,
        detail=detail,
    )


def apply_score(strategy: GeneStrategy, result: ScoreResult) -> GeneStrategy:
    strategy.tests += 1
    if result.success:
        strategy.successes += 1
    strategy.success_rate = strategy.successes / max(1, strategy.tests)
    # Exponential moving average of fitness + success.
    blended = 0.65 * result.score + 0.35 * strategy.success_rate
    if strategy.tests == 1:
        strategy.score = blended
        strategy.avg_ms = result.latency_ms
    else:
        strategy.score = 0.6 * strategy.score + 0.4 * blended
        strategy.avg_ms = 0.6 * strategy.avg_ms + 0.4 * result.latency_ms
    strategy.traffic_bytes += result.traffic_bytes
    strategy.updated_at = __import__("time").time()
    return strategy
