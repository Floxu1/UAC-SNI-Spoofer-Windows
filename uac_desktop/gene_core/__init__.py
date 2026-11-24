"""Shared gene strategy core for Gene Lab and UAC Spoofer Xray Pattern engine.

Strategies only compose parameters already supported by pattern_core / tls_tools:
wrong_seq, full5/10/20, multi64, plain, tls_sni_records, sni_boundary, sni_split.
"""
from .schema import (
    STRATEGY_METHODS,
    GeneStrategy,
    LabState,
    StrategyStore,
    load_strategies,
    save_strategies,
)
from .evolve import EvolutionEngine, EvolutionConfig
from .score import score_dry_run, ScoreResult
from .live_probe import LiveScorer, LiveProbeConfig, is_admin, DEFAULT_TEST_HOSTS, DEFAULT_EDGE_IPS
from .edges import EdgeCache, EdgeResult, edge_sources, resolve_edge_pool, sample_ips, scan_ranges, select_diverse
from .edge_scan import EdgeScanConfig, EdgeScanner

__all__ = [
    "STRATEGY_METHODS",
    "GeneStrategy",
    "LabState",
    "StrategyStore",
    "load_strategies",
    "save_strategies",
    "EvolutionEngine",
    "EvolutionConfig",
    "score_dry_run",
    "ScoreResult",
    "LiveScorer",
    "LiveProbeConfig",
    "is_admin",
    "DEFAULT_TEST_HOSTS",
    "DEFAULT_EDGE_IPS",
    "EdgeCache",
    "EdgeResult",
    "EdgeScanConfig",
    "EdgeScanner",
    "edge_sources",
    "resolve_edge_pool",
    "sample_ips",
    "scan_ranges",
    "select_diverse",
]
__version__ = "1.0.0"
