from __future__ import annotations

from uac_desktop import gene_pool
from uac_desktop.models import Tuning
from uac_desktop.ui import MainWindow


def gene(gid, score, method="wrong_seq", sni=None, confirmed=True):
    return {"id": gid, "method": method, "fake_sni": sni or f"{gid}.example.com",
            "score": score, "confirmed": confirmed}


GENES = [gene("a", 0.5), gene("b", 0.9, "full5"), gene("c", 0.7, "tls_sni_records"),
         gene("x", 0.99, confirmed=False), gene("d", 0.6), gene("e", 0.4)]


def test_pool_orders_confirmed_by_score_and_winner_first():
    pool = gene_pool.ordered_pool(GENES, {}, 1000.0)
    assert [g["id"] for g in pool] == ["b", "c", "d", "a", "e"]
    pool = gene_pool.ordered_pool(GENES, {}, 1000.0, last_winner="e")
    assert [g["id"] for g in pool][:2] == ["e", "b"]


def test_learning_success_raises_and_failures_cooldown():
    stats, cooled = gene_pool.record_result({}, GENES[0], True, 100.0)
    assert not cooled and abs(stats["a"]["score"] - 0.6) < 1e-9
    assert stats["a"]["last_success_at"] == 100.0
    for i in range(2):
        stats, cooled = gene_pool.record_result(stats, GENES[1], False, 200.0 + i)
        assert not cooled
    stats, cooled = gene_pool.record_result(stats, GENES[1], False, 300.0)
    assert cooled
    assert stats["b"]["cooldown_until"] == 300.0 + gene_pool.COOLDOWN_SECONDS
    assert "b" not in [g["id"] for g in gene_pool.ordered_pool(GENES, stats, 301.0)]
    assert gene_pool.cooled_down(GENES, stats, 301.0) == ["b"]
    later = 300.0 + gene_pool.COOLDOWN_SECONDS + 1
    assert "b" in [g["id"] for g in gene_pool.ordered_pool(GENES, stats, later)]
    # success clears streak
    stats, _ = gene_pool.record_result(stats, GENES[2], False, 1.0)
    stats, _ = gene_pool.record_result(stats, GENES[2], True, 2.0)
    assert stats["c"]["consecutive_failures"] == 0


def test_score_is_bounded_and_prune():
    stats = {}
    for i in range(100):
        stats, _ = gene_pool.record_result(stats, GENES[0], True, float(i))
    assert stats["a"]["score"] == gene_pool.SCORE_MAX
    assert gene_pool.prune_stats({**stats, "gone": {"score": 1}}, GENES) == stats


def test_plan_off_is_unchanged():
    snis = ["s1", "s2", "s3"]
    pool = gene_pool.ordered_pool(GENES, {}, 0.0)
    attempts, used = MainWindow._plan_profile_attempts(snis, pool, 0, False, False)
    assert attempts == [("s1", None), ("s2", None), ("s3", None)] and used == 0
    attempts, _ = MainWindow._plan_profile_attempts(snis, pool, 0, True, False, reality_direct=True)
    assert attempts == [("s1", None), ("s2", None), ("s3", None)]


def test_plan_lock_on_genes_only_and_lock_off_builtin_fallback():
    snis = ["s1", "s2", "s3"]
    pool = gene_pool.ordered_pool(GENES, {}, 0.0)
    locked, used = MainWindow._plan_profile_attempts(snis, pool, 0, True, True)
    assert [g["id"] for _s, g in locked] == ["b", "c", "d"] and used == 3
    assert [s for s, _g in locked] == ["b.example.com", "c.example.com", "d.example.com"]
    unlocked, _ = MainWindow._plan_profile_attempts(snis, pool, 0, True, False)
    assert unlocked[-1] == ("s1", None) and len(unlocked) == 4
    capped, used = MainWindow._plan_profile_attempts(snis, pool, 8, True, True)
    assert len(capped) == 1 and used == 9
    none_left, _ = MainWindow._plan_profile_attempts(snis, pool, 9, True, True)
    assert none_left == []


def test_overlay_gene_uses_gene_method_and_sni():
    tuning = Tuning()
    method, out = MainWindow._overlay_gene(GENES[1], "wrong_seq", tuning)
    assert method == "full5" and out.pattern_fake_sni == "b.example.com"
    assert MainWindow._overlay_gene(None, "wrong_seq", tuning) == ("wrong_seq", tuning)


def test_storage_multi_gene_default_off_and_records():
    from uac_desktop.storage import Storage

    store = Storage.__new__(Storage)
    store.settings = {}
    store.save_settings = lambda: None
    assert store.multi_gene_enabled is False
    store.set_multi_gene_enabled(True)
    assert store.multi_gene_enabled is True
    assert store.record_gene_result(GENES[2], True, now=50.0) is False
    assert store.gene_last_winner == "c"
    assert store.gene_stats["c"]["last_success_at"] == 50.0