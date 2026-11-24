import json, random, threading, time
from types import SimpleNamespace

from uac_desktop import clean_ip as c


def test_cache_counts_streak_and_cooldown(tmp_path):
    cache = c.CleanIpCache(tmp_path / "clean_ips.json")
    cache.record("mci", "104.16.1.1", True, 120, now=1000)
    for _ in range(3):
        cache.record("mci", "104.16.1.2", False, now=1000)
    e = cache.entries("mci")
    assert e["104.16.1.1"]["ok"] == 1 and e["104.16.1.1"]["last_ok"] == 1000
    assert e["104.16.1.2"]["streak_fail"] == 3
    assert cache.is_cooled("mci", "104.16.1.2", now=1000 + 60)
    assert not cache.is_cooled("mci", "104.16.1.2", now=1000 + c.COOLDOWN_SECONDS + 1)
    cache.record("mci", "104.16.1.2", True, 50, now=1001)
    assert cache.entries("mci")["104.16.1.2"]["streak_fail"] == 0
    reloaded = c.CleanIpCache(tmp_path / "clean_ips.json")
    assert "104.16.1.1" in reloaded.entries("mci")
    assert reloaded.entries("irancell") == {}
    json.loads((tmp_path / "clean_ips.json").read_text())


def test_cache_thread_safe_writes(tmp_path):
    cache = c.CleanIpCache(tmp_path / "x.json")
    def worker(n):
        for i in range(20):
            cache.record("auto", f"104.17.{n}.{i + 1}", i % 2 == 0, 100)
    threads = [threading.Thread(target=worker, args=(n,)) for n in range(5)]
    [t.start() for t in threads]; [t.join() for t in threads]
    data = json.loads((tmp_path / "x.json").read_text())
    assert len(data["auto"]) <= c.MAX_CACHE_PER_CARRIER


def test_ranking_prefers_fast_stable():
    bucket = {
        "1.1.1.1": {"ok": 10, "fail": 0, "latency_ms": 200},
        "2.2.2.2": {"ok": 1, "fail": 9, "latency_ms": 100},
        "3.3.3.3": {"ok": 5, "fail": 0, "latency_ms": 90},
        "4.4.4.4": {"ok": 5, "fail": 0, "latency_ms": 50, "cool_until": 9e18},
    }
    assert c.rank_entries(bucket, now=0) == ["3.3.3.3", "1.1.1.1", "2.2.2.2"]
    res = [c.ProbeResult("a", True, 300), c.ProbeResult("b", False, 10), c.ProbeResult("c", True, 100)]
    assert [r.ip for r in c.rank_results(res, 3)] == ["c", "a"]


def test_edge_ordering():
    assert c.order_edges("", "9.9.9.9,8.8.8.8", ["1.1.1.1", "9.9.9.9"]) == ["9.9.9.9", "8.8.8.8", "1.1.1.1"]
    assert c.order_edges("5.5.5.5", "9.9.9.9", ["1.1.1.1", "bad", ""]) == ["5.5.5.5", "9.9.9.9", "1.1.1.1"]


def test_pattern_core_build_edges():
    from uac_desktop.pattern_core.core import PatternSniCore
    t = SimpleNamespace(pattern_connect_ip="1.1.1.1", pattern_fallback_ips="2.2.2.2",
                        pattern_use_profile_edges=False, pattern_gene_edges="",
                        pattern_clean_edges="9.9.9.9,2.2.2.2")
    p = SimpleNamespace(address="127.0.0.1", fallback_address="")
    assert PatternSniCore._build_edges(PatternSniCore, p, t) == ["9.9.9.9", "2.2.2.2", "1.1.1.1"]
    t.pattern_gene_edges = "5.5.5.5"
    assert PatternSniCore._build_edges(PatternSniCore, p, t)[:2] == ["5.5.5.5", "9.9.9.9"]


def test_find_uses_cache_then_scan(tmp_path):
    cache = c.CleanIpCache(tmp_path / "c.json")
    good = {"104.16.0.10"}
    def fake_probe(ip, sni, port=443, timeout=2.0):
        return c.ProbeResult(ip, ip in good, 40.0)
    out = c.find_clean_ips(cache, "mci", "a.com", ["104.16.0.10"], sample=20,
                           probe=fake_probe, rng=random.Random(1), budget=3)
    assert [r.ip for r in out] == ["104.16.0.10"] and out[0].source == "scan"
    out = c.find_clean_ips(cache, "mci", "a.com", [], probe=fake_probe, budget=3)
    assert out[0].source == "cache"


def test_find_never_raises(tmp_path):
    cache = c.CleanIpCache(tmp_path / "c.json")
    def boom(*a, **k):
        raise RuntimeError("x")
    assert c.find_clean_ips(cache, "mci", "a.com", ["1.1.1.1"], sample=5, probe=boom, budget=1) == []
    msgs = []
    cache.good_ips = boom
    assert c.find_clean_ips(cache, "mci", "a.com", log=msgs.append) == []
    assert msgs and msgs[0].startswith("CLEAN IP:")


def test_sample_in_cloudflare_ranges():
    import ipaddress
    nets = [ipaddress.IPv4Network(n) for n in c.CLOUDFLARE_RANGES]
    ips = c.sample_cloudflare(50, random.Random(2))
    assert len(ips) == 50 and len(set(ips)) == 50
    assert all(any(ipaddress.IPv4Address(ip) in n for n in nets) for ip in ips)


def test_session_edge_beats_gene_and_clean():
    assert c.order_edges("5.5.5.5", "9.9.9.9", ["1.1.1.1"], "7.7.7.7")[:3] == ["7.7.7.7", "5.5.5.5", "9.9.9.9"]
    from uac_desktop.pattern_core.core import PatternSniCore
    t = SimpleNamespace(pattern_connect_ip="7.7.7.7", pattern_fallback_ips="1.1.1.1",
                        pattern_use_profile_edges=False, pattern_gene_edges="104.18.32.47",
                        pattern_clean_edges="9.9.9.9", pattern_session_edge="7.7.7.7")
    p = SimpleNamespace(address="127.0.0.1", fallback_address="")
    assert PatternSniCore._build_edges(PatternSniCore, p, t)[0] == "7.7.7.7"


def test_storage_never_persists_runtime_edges():
    from uac_desktop.models import Tuning
    from uac_desktop.storage import Storage
    v = Storage._enforced_carrier_tuning("auto", Tuning(pattern_session_edge="7.7.7.7", pattern_clean_edges="9.9.9.9"))
    assert v.pattern_session_edge == "" and v.pattern_clean_edges == ""
