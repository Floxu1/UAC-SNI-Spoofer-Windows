from __future__ import annotations

from uac_desktop.ui import MainWindow


def test_strategy_lock_blocks_method_rotation():
    assert MainWindow._fallback_strategies("auto", "full5", "wrong_seq", locked=True) == ["full5"]
    assert MainWindow._fallback_strategies("irancell", "tls_sni_records", locked=True) == ["tls_sni_records"]
    assert MainWindow._fallback_strategies("mci", "tls_sni_records", locked=True) == ["tls_sni_records"]


def test_strategy_unlocked_keeps_adaptive_rotation():
    assert MainWindow._fallback_strategies("auto", "wrong_seq") == MainWindow._adaptive_strategies("auto", "wrong_seq")
    assert len(MainWindow._fallback_strategies("irancell", "full5", "wrong_seq", locked=False)) > 1


def test_storage_strategy_lock_default_and_persist():
    from uac_desktop.storage import Storage

    store = Storage.__new__(Storage)
    store.settings = {}
    saved = []
    store.save_settings = lambda: saved.append(dict(store.settings))
    assert store.strategy_locked is False
    store.set_strategy_locked(True)
    assert store.strategy_locked is True
    assert saved[-1]["strategy_locked"] is True