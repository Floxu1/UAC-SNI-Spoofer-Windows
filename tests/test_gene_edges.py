"""Gene Lab working IPs: import keeps them; engine 1 tries them first."""
from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from uac_desktop.gene_import import gene_edge_ips, load_strategies_file, normalize_strategy
from uac_desktop.models import Tuning
from uac_desktop.pattern_core.core import PatternSniCore
from uac_desktop.ui import MainWindow

WORKING = [
    {"ip": "104.18.8.20", "latency_ms": 210.0, "at": 100.0},
    {"ip": "104.19.229.7", "latency_ms": 95.5, "at": 101.0},
    {"ip": "172.64.155.3", "latency_ms": 150.0, "at": 102.0},
    {"ip": "104.18.8.20", "latency_ms": 180.0, "at": 103.0},  # duplicate, newer
    {"ip": "not-an-ip", "latency_ms": 1.0, "at": 1.0},
    {"ip": "104.18.9.1", "latency_ms": 300.0, "at": 1.0},
    {"ip": "104.18.9.2", "latency_ms": 310.0, "at": 1.0},
    {"ip": "104.18.9.3", "latency_ms": 320.0, "at": 1.0},
]


def _raw(**extra):
    base = {"id": "g1", "method": "full5", "fake_sni": "chatgpt.com", "score": 0.9,
            "confirmed": True, "mode": "live",
            "confirmed_ips": ["104.18.8.20", "104.19.229.7", "172.64.155.3"]}
    base.update(extra)
    return base


def test_import_keeps_working_ips_distinct_capped_fastest_first(tmp_path: Path):
    path = tmp_path / "strategies.json"
    path.write_text(json.dumps({"strategies": [_raw(working_ips=WORKING)]}), encoding="utf-8")
    gene = load_strategies_file(path)[0]
    ips = [w["ip"] for w in gene["working_ips"]]
    assert ips == ["104.19.229.7", "172.64.155.3", "104.18.8.20", "104.18.9.1", "104.18.9.2"]
    assert gene["working_ips"][2] == {"ip": "104.18.8.20", "latency_ms": 180.0, "at": 103.0}
    assert gene_edge_ips(gene) == ips


def test_import_falls_back_to_confirmed_ips_and_empty_stays_empty():
    gene = normalize_strategy(_raw())
    assert gene_edge_ips(gene) == ["104.18.8.20", "104.19.229.7", "172.64.155.3"]
    bare = normalize_strategy(_raw(confirmed_ips=[]))
    assert bare["working_ips"] == [] and gene_edge_ips(bare) == []
    assert gene_edge_ips({"id": "old", "method": "full5"}) == []  # stored before this feature


def test_overlay_sets_gene_edges_and_logs_single_and_multi_path_share_it():
    logs = []
    gene = normalize_strategy(_raw(working_ips=WORKING[:3]))
    method, tuning = MainWindow._overlay_gene(gene, "wrong_seq", Tuning(), log=logs.append)
    assert method == "full5"
    assert tuning.pattern_gene_edges == "104.19.229.7,172.64.155.3,104.18.8.20"
    assert logs == ["GENE EDGES: g1 using 3 ips"]
    # later route/edge rewrites (replace) keep the gene edges
    rerouted = replace(tuning, pattern_connect_ip="104.18.1.1", pattern_fallback_ips="172.66.0.1")
    assert rerouted.pattern_gene_edges == tuning.pattern_gene_edges


def test_overlay_without_ips_is_unchanged_behaviour():
    logs = []
    base = Tuning()
    gene = normalize_strategy(_raw(confirmed_ips=[]))
    _m, tuning = MainWindow._overlay_gene(gene, "wrong_seq", base, log=logs.append)
    assert tuning.pattern_gene_edges == "" and logs == []
    assert replace(tuning, pattern_fake_sni=base.pattern_fake_sni,
                   pattern_fake_repeat=base.pattern_fake_repeat,
                   pattern_inject_delay_ms=base.pattern_inject_delay_ms,
                   sni_split_delay_ms=base.sni_split_delay_ms,
                   multi_fragment_size=base.multi_fragment_size,
                   multi_delay_ms=base.multi_delay_ms) == base


def _edges(**tuning_kw):
    profile = SimpleNamespace(address="104.18.8.83", fallback_address="104.18.9.83")
    tuning = SimpleNamespace(pattern_connect_ip="104.18.32.47",
                             pattern_fallback_ips="172.64.155.209,188.114.99.0",
                             pattern_use_profile_edges=False)
    for key, value in tuning_kw.items():
        setattr(tuning, key, value)
    return PatternSniCore(log=lambda _m: None)._build_edges(profile, tuning)


def test_pattern_core_tries_gene_ips_first_then_normal_list():
    normal = _edges()
    assert normal == ["104.18.32.47", "172.64.155.209", "188.114.99.0"]
    assert _edges(pattern_gene_edges="") == normal
    gene_first = _edges(pattern_gene_edges="104.19.229.7, 188.114.99.0,bogus")
    assert gene_first == ["104.19.229.7", "188.114.99.0", "104.18.32.47", "172.64.155.209"]
    with_profile = _edges(pattern_gene_edges="104.19.229.7", pattern_use_profile_edges=True)
    assert with_profile[:3] == ["104.19.229.7", "104.18.8.83", "104.18.9.83"]


def test_gene_edges_are_never_persisted():
    from uac_desktop.storage import Storage

    store = Storage.__new__(Storage)
    store.settings = {}
    store.save_settings = lambda: None
    store.set_tuning(replace(Tuning(), pattern_gene_edges="104.19.229.7"))
    assert store.settings["tuning"]["pattern_gene_edges"] == ""
    assert store.tuning.pattern_gene_edges == ""
