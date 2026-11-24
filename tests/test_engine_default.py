from uac_desktop.ui import ENGINE_POW, ENGINE_XRAY, ENGINE_DEFAULT_MARKER, resolve_startup_engine


def test_fresh_install_defaults_to_engine2():
    s = {}
    assert resolve_startup_engine(s) == (ENGINE_POW, True)
    assert s[ENGINE_DEFAULT_MARKER] is True and s["engine_mode"] == ENGINE_POW


def test_old_settings_migrate_once_and_keep_other_values():
    s = {"engine_mode": ENGINE_XRAY, "language": "fa", "tuning": {"x": 1}}
    assert resolve_startup_engine(s) == (ENGINE_POW, True)
    assert s["language"] == "fa" and s["tuning"] == {"x": 1}
    assert resolve_startup_engine(s) == (ENGINE_POW, False)


def test_marker_respects_user_choice_engine1():
    s = {"engine_mode": ENGINE_XRAY, ENGINE_DEFAULT_MARKER: True}
    assert resolve_startup_engine(s) == (ENGINE_XRAY, False)
    assert s["engine_mode"] == ENGINE_XRAY
