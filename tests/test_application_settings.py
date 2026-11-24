import json
from dataclasses import replace
from types import SimpleNamespace

from uac_desktop.application_settings import ApplicationSettings, ConnectionPreferences
from uac_desktop.direct.store import DirectStore
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
    app.restore({"version": 1, "connection": {"lan_share_port": -1, "kill_switch": "false"}})
    assert app.snapshot().lan_share_port == 18080
    assert app.snapshot().kill_switch is False


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
