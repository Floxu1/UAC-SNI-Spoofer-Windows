import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from uac_desktop.application_settings import ApplicationSettings, ConnectionPreferences
from uac_desktop.direct.store import DirectSettings, DirectStore
from uac_desktop.pow.config import PowSettings
from uac_desktop.pow.store import PowStore


def test_migration_keeps_legacy_values_and_has_one_authority(tmp_path):
    pow_store = PowStore(tmp_path / "pow")
    direct_store = DirectStore(tmp_path / "direct")
    pow_store.save_exit_proxy_mode(True)
    pow_store.save(replace(pow_store.snapshot(), auto_connect=True))
    direct_store.save_settings(replace(direct_store.settings(), iran_direct=False, routing_mode="only"))
    written = tmp_path / "settings.json"
    storage = SimpleNamespace(settings={"language": "en", "unrelated": "keep"})
    storage.save_settings = lambda: written.write_text(json.dumps(storage.settings), encoding="utf-8")
    app = ApplicationSettings(storage)
    app.migrate("direct", pow_store, direct_store)
    assert app.snapshot().connection_mode == "vpn"
    assert app.snapshot().routing_mode == "only"
    assert not app.snapshot().iran_direct
    assert app.snapshot().auto_connect
    app.change(connection_mode="proxy", iran_direct=True, kill_switch=True)
    persisted = json.loads(written.read_text(encoding="utf-8"))
    reloaded = ApplicationSettings(SimpleNamespace(settings=persisted))
    reloaded.migrate("pow", pow_store, direct_store)
    assert reloaded.snapshot() == app.snapshot()
    assert persisted["unrelated"] == "keep"
    pow_effective = reloaded.snapshot().for_pow(pow_store.snapshot())
    direct_effective = reloaded.snapshot().for_direct(direct_store.settings())
    assert pow_effective.kill_switch and direct_effective.kill_switch
    assert not direct_store.settings().iran_direct
    assert not pow_store.snapshot().kill_switch


def test_backup_has_shared_fields_and_validates_on_restore():
    config = {"language": "fa", "bypass_processes": ["sample.exe"],
              "token": "private", "tuning": {"private_key": "private"}}
    app = ApplicationSettings(SimpleNamespace(settings=config, save_settings=lambda: None))
    app.change(connection_mode="proxy", lan_share_port=18800)
    backup = app.export()
    assert "private" not in json.dumps(backup)
    app.change(connection_mode="vpn", iran_direct=False)
    app.restore(backup)
    assert app.snapshot().connection_mode == "proxy"
    assert app.snapshot().lan_share_port == 18800
    assert app.snapshot().iran_direct
    assert app.processes() == ("sample.exe",)
    with pytest.raises(ValueError):
        app.restore({"version": 1, "connection": {"lan_share_port": -1, "kill_switch": "false"}})
    assert app.snapshot().lan_share_port == 18800
    assert app.snapshot().kill_switch is False


def test_legacy_tun_proxy_preference_does_not_enable_proxy_in_tun():
    raw = {"connection_mode": "vpn", "windows_proxy_with_tun": True}
    storage = SimpleNamespace(settings={"global_connection": raw}, save_settings=lambda: None)
    app = ApplicationSettings(storage)
    assert not app.snapshot().windows_proxy_enabled
    app.restore({"version": 1, "connection": raw})
    assert app.snapshot().connection_mode == "vpn"
    assert not app.snapshot().windows_proxy_enabled
    assert "windows_proxy_with_tun" not in app.export()["connection"]


def test_missing_engine_preferences_use_the_same_application_defaults(tmp_path):
    pow_store = PowStore(tmp_path / "pow")
    direct_store = DirectStore(tmp_path / "direct")
    for engine in ("pow", "direct"):
        app = ApplicationSettings(SimpleNamespace(settings={}, save_settings=lambda: None))
        app.migrate(engine, pow_store, direct_store)
        assert app.snapshot() == ConnectionPreferences()


def test_older_appearance_backups_still_restore_connection_settings():
    storage = SimpleNamespace(settings={}, save_settings=lambda: None)
    app = ApplicationSettings(storage)
    app.restore({"version": 1, "desktop_theme": "solaris", "connection": {"routing_mode": "only"}})
    assert app.snapshot().routing_mode == "only"
    assert "desktop_theme" not in storage.settings
    assert "desktop_theme" not in app.export()


def test_backup_excludes_invalid_domains_and_full_process_paths():
    settings = {"global_connection": {"domains_direct": "example.net, https://user:secret@example.org"},
                "bypass_processes": ["sample.exe", r"C:\Users\secret\private.exe"]}
    app = ApplicationSettings(SimpleNamespace(settings=settings, save_settings=lambda: None))
    backup = app.export()
    assert backup["connection"]["domains_direct"] == "example.net"
    assert backup["bypass_processes"] == ["sample.exe"]
    with pytest.raises(ValueError):
        app.restore({"version": 1, "connection": {"domains_direct": "https://user:secret@example.org"}})
    assert "secret" in app.snapshot().domains_direct  # Legacy local data is left intact.


def test_site_routing_preserves_existing_domains_and_persists_ip_exceptions():
    stored = {"global_connection": {"domains_direct": "old.example"}}
    app = ApplicationSettings(SimpleNamespace(settings=stored, save_settings=lambda: None))
    app.change(ips_direct="192.0.2.7/32, 192.0.2.7, 2001:db8::2/64, 2001:db8::/64")
    saved = app.snapshot()
    assert (saved.domains_direct, saved.ips_direct) == ("old.example", "192.0.2.7, 2001:db8::/64")
    assert saved.for_pow(PowSettings()).ips_direct == saved.for_direct(DirectSettings()).ips_direct
    restored = ApplicationSettings(SimpleNamespace(settings={}, save_settings=lambda: None))
    restored.restore(app.export())
    assert restored.snapshot() == saved
    with pytest.raises(ValueError):
        restored.change(ips_direct="fe80::1%7, 192.0.2.999")
    assert restored.snapshot() == saved
