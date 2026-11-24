"""k9: built-in ECH fallback key (engine 1) + optional ECH via Pattern core."""
import base64
import json
import pathlib
import re
import threading

import pytest

from uac_desktop import ech_keys
from uac_desktop import engine as engine_mod
from uac_desktop.connect_summary import format_connected_block
from uac_desktop.engine import (Engine, FRAGMENT_PORT, build_xray_config,
                                ech_via_pattern_enabled, plan_ech_via_pattern)
from uac_desktop.models import ProxyProfile, Tuning, parse_many, parse_outbound

ECH_URI = ("vless://3f1c2a4e-1111-4222-8333-444455556666@188.114.97.6:443?encryption=none"
           "&security=tls&type=ws&host=innersni.example&sni=innersni.example&fp=chrome"
           "&ech=cloudflare-ech.com%2Budp%3A%2F%2F1.1.1.1&path=%2F#ech-test")
LOOPBACK_ECH_URI = ("vless://d1c0ffee-1234-4567-8abc-0123456789ab@127.0.0.1:40443?encryption=none"
                    "&security=tls&sni=loopback-sni.example&fp=chrome"
                    "&ech=cloudflare-ech.com+https://dns.alidns.com/dns-query&type=ws"
                    "&host=loopback-sni.example&path=/#ech-loopback")
PLAIN_URI = ECH_URI.replace("&ech=cloudflare-ech.com%2Budp%3A%2F%2F1.1.1.1", "")
REALITY_URI = ("vless://3f1c2a4e-1111-4222-8333-444455556666@1.2.3.4:443?encryption=none"
               "&security=reality&sni=www.example.com&pbk=abc&sid=01&type=tcp#r")
VALUE = "cloudflare-ech.com+udp://1.1.1.1"
DNS_RS = pathlib.Path(__file__).resolve().parents[1] / "core/aether/src/dns.rs"


def _key(n=8):
    body = bytes([0xFE, 0x0D, 0, n]) + bytes(range(n))
    return base64.b64encode(len(body).to_bytes(2, "big") + body).decode()


LIVE = _key(12)


def _fail():
    raise OSError("blocked")


# ----------------------------------------------------------- built-in fallback

def test_fallback_bytes_match_aether_dns_rs():
    assert ech_keys.is_base64_list(ech_keys.ECH_FALLBACK_B64)
    assert len(ech_keys.ECH_CONFIG_FALLBACK) == 71
    if not DNS_RS.is_file():
        pytest.skip("aether source not present")
    text = DNS_RS.read_text(encoding="utf-8")
    block = re.search(r"ECH_CONFIG_FALLBACK: &\[u8\] = &\[(.*?)\];", text, re.S).group(1)
    rust = bytes(int(x, 16) for x in re.findall(r"0x([0-9a-fA-F]{2})", block))
    assert rust == ech_keys.ECH_CONFIG_FALLBACK
    assert "2026-10-09" in text and ech_keys.ECH_FALLBACK_CAPTURED == "2026-10-09"


def test_fallback_used_only_when_all_fetchers_fail_and_no_cache(tmp_path):
    cache_path = tmp_path / "ech_keys.json"
    cache = ech_keys.EchKeyCache(cache_path)
    logs = []
    res = ech_keys.resolve(VALUE, cache, logs.append,
                           fetchers=[("udp 1.1.1.1", _fail), ("udp 8.8.8.8", lambda: "")],
                           doh=[("doh x", _fail)])
    assert (res.state, res.value, res.source) == ("fallback", ech_keys.ECH_FALLBACK_B64, "built-in")
    assert any("BUILT-IN fallback key" in line for line in logs)
    # never stored as if it were live
    assert not cache_path.exists() and cache.get("cloudflare-ech.com") == {}


def test_live_key_wins_over_fallback_and_is_cached(tmp_path):
    cache = ech_keys.EchKeyCache(tmp_path / "k.json")
    first = ech_keys.resolve(VALUE, cache, None, fetchers=[("u", _fail)], doh=[])
    assert first.state == "fallback"
    second = ech_keys.resolve(VALUE, cache, None, fetchers=[("udp 1.1.1.1", lambda: LIVE)], doh=[])
    assert (second.state, second.value) == ("fresh", LIVE)
    assert cache.get("cloudflare-ech.com")["key"] == LIVE
    # DoH-only success also beats the fallback
    doh_only = ech_keys.resolve(VALUE, ech_keys.EchKeyCache(tmp_path / "d.json"), None,
                                fetchers=[("u", _fail)], doh=[("doh y", lambda: LIVE)])
    assert doh_only.state == "fresh"


def test_valid_cache_beats_fallback(tmp_path):
    cache = ech_keys.EchKeyCache(tmp_path / "k.json")
    cache.put("cloudflare-ech.com", LIVE, "udp 1.1.1.1", now=1000)
    res = ech_keys.resolve(VALUE, cache, None, fetchers=[("u", _fail)], doh=[], now=5000)
    assert (res.state, res.value) == ("cached", LIVE)


def test_fallback_not_used_for_other_domains_or_when_disabled(tmp_path):
    cache = ech_keys.EchKeyCache(tmp_path / "k.json")
    other = ech_keys.resolve("ip.gs+udp://8.8.8.8", cache, None, fetchers=[], doh=[])
    assert (other.state, other.value) == ("none", "ip.gs+udp://8.8.8.8")
    off = ech_keys.resolve(VALUE, cache, None, fetchers=[], doh=[], use_fallback=False)
    assert (off.state, off.value) == ("none", VALUE)
    raw = ech_keys.resolve(LIVE, cache, None, fetchers=[], doh=[])
    assert raw.state == "raw"


def test_connected_block_labels_fallback():
    block = format_connected_block("c", None, "plain", "", "1.2.3.4", "config", "mci", False, False,
                                   ech_state="fallback")
    assert "key built-in fallback" in block


# ------------------------------------------------------- ECH via Pattern core

def test_option_env_and_setting(monkeypatch):
    monkeypatch.delenv("UAC_ECH_VIA_PATTERN", raising=False)
    assert ech_via_pattern_enabled() is False
    assert ech_via_pattern_enabled(True) is True
    monkeypatch.setenv("UAC_ECH_VIA_PATTERN", "1")
    assert ech_via_pattern_enabled(False) is True
    monkeypatch.setenv("UAC_ECH_VIA_PATTERN", "0")
    assert ech_via_pattern_enabled(True) is False


def test_plan_routes_ech_to_local_core_without_touching_real_sni(monkeypatch):
    monkeypatch.delenv("UAC_ECH_PATTERN_FAKE_SNI", raising=False)
    profile = parse_many(ECH_URI)[0]
    tuning = Tuning(pattern_fake_sni="innersni.example", pattern_connect_ip="104.18.32.47",
                    pattern_fallback_ips="188.114.99.0,104.18.8.83")
    core_profile, core_tuning = plan_ech_via_pattern(profile, tuning, parse_outbound(profile), "188.114.97.6")
    assert core_profile.config_port == FRAGMENT_PORT and core_profile.port == 443
    assert core_tuning.pattern_connect_ip == "188.114.97.6"
    assert core_tuning.pattern_fallback_ips == "104.18.32.47,188.114.99.0,104.18.8.83"
    assert core_tuning.pattern_fake_sni.lower() != "innersni.example"  # never the inner name
    assert profile.config_port == 443 and tuning.pattern_fake_sni == "innersni.example"  # inputs untouched


def test_plan_loopback_ech_keeps_tuning_edges_and_port_443():
    profile = parse_many(LOOPBACK_ECH_URI)[0]
    tuning = Tuning(pattern_connect_ip="104.18.32.47", pattern_fallback_ips="188.114.99.0")
    core_profile, core_tuning = plan_ech_via_pattern(profile, tuning, None, "127.0.0.1")
    assert core_profile.port == 443 and core_profile.config_port == FRAGMENT_PORT
    assert core_tuning.pattern_connect_ip == "104.18.32.47"
    assert core_tuning.pattern_fallback_ips == "188.114.99.0"


def test_plan_skips_non_ech_routes():
    assert plan_ech_via_pattern(parse_many(PLAIN_URI)[0], Tuning()) is None
    assert plan_ech_via_pattern(parse_many(REALITY_URI)[0], Tuning()) is None


def test_build_xray_config_port_override_keeps_ech_and_sni():
    profile = parse_many(ECH_URI)[0]
    default = build_xray_config(profile, tuning=Tuning(), upstream_address="188.114.97.6", ech_config=LIVE)
    same = build_xray_config(profile, tuning=Tuning(), upstream_address="188.114.97.6", ech_config=LIVE,
                             xray_outbound_port=None)
    assert default == same
    via = build_xray_config(profile, tuning=Tuning(), upstream_address="127.0.0.1", ech_config=LIVE,
                            xray_outbound_port=FRAGMENT_PORT)
    server = via["outbounds"][0]["settings"]["vnext"][0]
    assert (server["address"], server["port"]) == ("127.0.0.1", FRAGMENT_PORT)
    tls = via["outbounds"][0]["streamSettings"]["tlsSettings"]
    assert tls["echConfigList"] == LIVE and tls["serverName"] == "innersni.example"
    assert tls == default["outbounds"][0]["streamSettings"]["tlsSettings"]


class _Fragment:
    running = True
    edge_addresses = ()
    active_edge = ""

    def __init__(self):
        self.starts = []

    def start(self, profile, tuning, strategy=None):
        self.starts.append((profile, tuning, strategy))

    def stop(self):
        pass


class _Proc:
    pid = 4242
    stdout = None
    returncode = None

    def poll(self):
        return None

    def terminate(self):
        pass

    def wait(self, timeout=None):
        return 0


class _Thread:
    def __init__(self, *a, **k):
        pass

    def start(self):
        pass


def _start_engine(monkeypatch, tmp_path, enabled):
    monkeypatch.delenv("UAC_ECH_VIA_PATTERN", raising=False)
    eng = Engine(lambda _m: None, lambda _s: None, lambda _u, _d: None)
    eng.fragment = _Fragment()
    eng.ech_via_pattern = enabled
    monkeypatch.setattr(eng, "_stop_locked", lambda notify=False: None)
    monkeypatch.setattr(eng, "_release_owned_listeners", lambda *a, **k: None)
    monkeypatch.setattr(eng, "_configured_local_ports", lambda: (engine_mod.SOCKS_PORT, engine_mod.HTTP_PORT))
    monkeypatch.setattr(engine_mod, "allocate_local_ports",
                        lambda *a, **k: (engine_mod.SOCKS_PORT, engine_mod.HTTP_PORT, ""))
    monkeypatch.setattr(eng, "reclaim_stale_listeners", lambda *a, **k: [])
    monkeypatch.setattr(eng, "recover_stale_tun", lambda *a, **k: None)
    monkeypatch.setattr(eng, "_binary", lambda: "xray.exe")
    monkeypatch.setattr(eng, "_write_owner_record", lambda *a, **k: None)
    monkeypatch.setattr(engine_mod, "XRAY_CONFIG", tmp_path / "xray.json")
    monkeypatch.setattr(engine_mod.subprocess, "Popen", lambda *a, **k: _Proc())
    monkeypatch.setattr(engine_mod.threading, "Thread", _Thread)
    monkeypatch.setattr(ech_keys, "resolve",
                        lambda value, cache, log=None, **kw: ech_keys.EchResolution(LIVE, "fresh", "test"))
    profile = parse_many(ECH_URI)[0]
    tuning = Tuning(pattern_fake_sni="innersni.example")
    eng.start(profile, tuning, [], notify=False, enable_system_proxy=False, strategy_override="plain")
    config = json.loads((tmp_path / "xray.json").read_text(encoding="utf-8"))
    return eng, config


def test_engine_option_off_keeps_direct_ech_routing(monkeypatch, tmp_path):
    eng, config = _start_engine(monkeypatch, tmp_path, enabled=False)
    server = config["outbounds"][0]["settings"]["vnext"][0]
    assert (server["address"], server["port"]) == ("188.114.97.6", 443)
    assert eng.fragment.starts == [] and eng._fragment_required is False
    assert eng.ech_via_pattern_active is False
    assert config["outbounds"][0]["streamSettings"]["tlsSettings"]["echConfigList"] == LIVE


def test_engine_option_on_routes_ech_via_pattern_core(monkeypatch, tmp_path):
    eng, config = _start_engine(monkeypatch, tmp_path, enabled=True)
    server = config["outbounds"][0]["settings"]["vnext"][0]
    assert (server["address"], server["port"]) == ("127.0.0.1", FRAGMENT_PORT)
    assert len(eng.fragment.starts) == 1
    core_profile, core_tuning, strategy = eng.fragment.starts[0]
    assert strategy == engine_mod.ECH_PATTERN_STRATEGY
    assert core_profile.config_port == FRAGMENT_PORT and core_profile.port == 443
    assert core_tuning.pattern_connect_ip == "188.114.97.6"
    assert core_tuning.pattern_fake_sni.lower() != "innersni.example"
    assert eng._fragment_required is True and eng.ech_via_pattern_active is True
    tls = config["outbounds"][0]["streamSettings"]["tlsSettings"]
    assert tls["echConfigList"] == LIVE and tls["serverName"] == "innersni.example"


# ------------------------------------------------------------- settings toggle

def test_tuning_dialog_toggle_default_off_and_round_trip(monkeypatch):
    import os
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication, QWidget
    from uac_desktop import proxy_port_panel, ui
    app = QApplication.instance() or QApplication([])

    def fake_install(dialog):
        dialog._proxy_ports_section = QWidget()

    # The real panel needs a MainWindow parent (pre-existing test limitation).
    monkeypatch.setattr(proxy_port_panel, "install_xray_ports_into_tuning", fake_install)
    tuning = Tuning.carrier_preset("auto")
    default = ui.TuningDialog(None, tuning, "fa")
    assert default.ech_via_pattern_value() is False
    enabled = ui.TuningDialog(None, tuning, "en", ech_via_pattern=True)
    assert enabled.ech_via_pattern_value() is True
    enabled.ech_via_pattern.setChecked(False)
    assert enabled.ech_via_pattern_value() is False
    assert app is not None
