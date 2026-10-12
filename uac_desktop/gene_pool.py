"""Smart multi-gene pool: ordering, learning and cooldown for Gene Lab genes.

Pure, deterministic helpers (no Qt, no I/O) so they can be unit tested.
Stats layout (persisted in settings["gene_stats"]):
    {gene_id: {"score": float, "successes": int, "failures": int,
               "consecutive_failures": int, "last_success_at": float,
               "last_fail_at": float, "cooldown_until": float}}
"""
from __future__ import annotations

from typing import Any

VALID_METHODS = frozenset({
    "wrong_seq", "plain", "full5", "full10", "full20", "multi64",
    "tls_sni_records", "sni_boundary", "sni_split", "primitive",
})
SUCCESS_BONUS = 0.10
FAIL_PENALTY = 0.05
SCORE_MIN = 0.0
SCORE_MAX = 2.0
FAILS_BEFORE_COOLDOWN = 3
COOLDOWN_SECONDS = 3 * 3600
MAX_GENES_PER_PROFILE = 3
MAX_GENE_ATTEMPTS_TOTAL = 9
COUNTER_CAP = 10_000


def _num(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def is_confirmed(gene: Any) -> bool:
    return (isinstance(gene, dict) and bool(gene.get("confirmed"))
            and str(gene.get("id", "") or "") != ""
            and str(gene.get("method", "") or "").strip().lower() in VALID_METHODS)


def base_score(gene: dict) -> float:
    return max(SCORE_MIN, min(SCORE_MAX, _num(gene.get("score"), 0.0)))


def local_score(gene: dict, stats: dict | None) -> float:
    entry = (stats or {}).get(str(gene.get("id", "")))
    if isinstance(entry, dict) and "score" in entry:
        return max(SCORE_MIN, min(SCORE_MAX, _num(entry.get("score"), base_score(gene))))
    return base_score(gene)


def in_cooldown(gene_id: str, stats: dict | None, now: float) -> bool:
    entry = (stats or {}).get(str(gene_id))
    return isinstance(entry, dict) and _num(entry.get("cooldown_until")) > now


def ordered_pool(strategies: list, stats: dict | None, now: float,
                 last_winner: str = "", include_cooldown: bool = False) -> list[dict]:
    """Confirmed genes, last winner first, then local score desc, then id."""
    seen: set[str] = set()
    pool = []
    for gene in strategies or []:
        if not is_confirmed(gene):
            continue
        gene_id = str(gene["id"])
        if gene_id in seen:
            continue
        seen.add(gene_id)
        if not include_cooldown and in_cooldown(gene_id, stats, now):
            continue
        pool.append(gene)
    return sorted(pool, key=lambda g: (
        0 if str(g["id"]) == str(last_winner or "") else 1,
        -local_score(g, stats),
        -base_score(g),
        str(g["id"]),
    ))


def cooled_down(strategies: list, stats: dict | None, now: float) -> list[str]:
    return [str(g["id"]) for g in strategies or []
            if is_confirmed(g) and in_cooldown(str(g["id"]), stats, now)]


def record_result(stats: dict | None, gene: dict, ok: bool, now: float) -> tuple[dict, bool]:
    """Return (new_stats, entered_cooldown). Never mutates the input."""
    stats = {k: dict(v) for k, v in (stats or {}).items() if isinstance(v, dict)}
    gene_id = str(gene.get("id", ""))
    entry = stats.get(gene_id) or {"score": base_score(gene)}
    score = _num(entry.get("score"), base_score(gene))
    entered = False
    if ok:
        entry["score"] = min(SCORE_MAX, score + SUCCESS_BONUS)
        entry["successes"] = min(COUNTER_CAP, int(_num(entry.get("successes"))) + 1)
        entry["consecutive_failures"] = 0
        entry["last_success_at"] = float(now)
        entry["cooldown_until"] = 0.0
    else:
        entry["score"] = max(SCORE_MIN, score - FAIL_PENALTY)
        entry["failures"] = min(COUNTER_CAP, int(_num(entry.get("failures"))) + 1)
        streak = int(_num(entry.get("consecutive_failures"))) + 1
        entry["last_fail_at"] = float(now)
        if streak >= FAILS_BEFORE_COOLDOWN:
            entry["cooldown_until"] = float(now) + COOLDOWN_SECONDS
            streak = 0
            entered = True
        entry["consecutive_failures"] = streak
    stats[gene_id] = entry
    return stats, entered


def prune_stats(stats: dict | None, strategies: list) -> dict:
    """Keep stats only for genes that still exist (bounded storage)."""
    ids = {str(g.get("id")) for g in strategies or [] if isinstance(g, dict)}
    return {k: dict(v) for k, v in (stats or {}).items() if k in ids and isinstance(v, dict)}


def plan_profile_genes(pool: list[dict], attempts_used: int,
                       per_profile: int = MAX_GENES_PER_PROFILE,
                       total_cap: int = MAX_GENE_ATTEMPTS_TOTAL) -> list[dict]:
    remaining = max(0, int(total_cap) - int(attempts_used))
    return list(pool[:max(0, min(int(per_profile), remaining))])