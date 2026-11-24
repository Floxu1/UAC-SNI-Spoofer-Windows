"""ECH configs: parsed into echConfigList, kept direct (no fake-SNI spoof)."""
import threading

from uac_desktop.engine import build_xray_config
from uac_desktop.models import ProxyProfile, Tuning, is_direct_route, parse_many, parse_outbound, route_label
from uac_desktop.sni_maker import convert_to_sni
from uac_desktop.sni_batch import LiveConfigResult, SniBatchTester

ECH_URI = ("vless://3f1c2a4e-1111-4222-8333-444455556666@188.114.97.6:443?encryption=none"
           "&security=tls&type=ws&host=lucasjow.us.ci&sni=lucasjow.us.ci&fp=chrome"
           "&ech=cloudflare-ech.com%2Budp%3A%2F%2F1.1.1.1&path=%2F#ech-test")
PLAIN_URI = ECH_URI.replace("&ech=cloudflare-ech.com%2Budp%3A%2F%2F1.1.1.1", "")


def _profile(uri):
    return ProxyProfile(name="t", source_uri=uri, protocol="vless")


def test_parse_outbound_reads_ech_verbatim():
    assert parse_outbound(_profile(ECH_URI))["ech"] == "cloudflare-ech.com+udp://1.1.1.1"
    assert parse_outbound(_profile(PLAIN_URI))["ech"] == ""


def test_xray_config_has_ech_config_list():
    cfg = build_xray_config(_profile(ECH_URI), tuning=Tuning())
    tls = cfg["outbounds"][0]["streamSettings"]["tlsSettings"]
    assert tls["echConfigList"] == "cloudflare-ech.com+udp://1.1.1.1"
    assert "echConfigList" not in build_xray_config(
        _profile(PLAIN_URI), tuning=Tuning())["outbounds"][0]["streamSettings"]["tlsSettings"]


def test_parse_many_marks_ech_direct_and_label():
    profile = parse_many(ECH_URI)[0]
    assert profile.route_mode == "ech-direct"
    assert is_direct_route(profile) and route_label(profile) == "ECH"
    assert parse_many(PLAIN_URI)[0].route_mode == "sni"


def test_sni_maker_keeps_ech_address_and_uri():
    result = convert_to_sni(_profile(ECH_URI))
    assert result.status == "converted"
    p = result.profile
    assert p.route_mode == "ech-direct"
    assert p.source_uri == ECH_URI           # round-trips for export/copy
    assert p.address == "188.114.97.6" and p.port == 443
    assert "127.0.0.1" not in p.source_uri and not p.spoof_fake_sni
    plain = convert_to_sni(_profile(PLAIN_URI)).profile
    assert plain.route_mode == "sni" and "127.0.0.1:40443" in plain.source_uri


def test_batch_tests_ech_once_direct(monkeypatch):
    ech = convert_to_sni(_profile(ECH_URI)).profile
    calls = []

    def fake_run(self, selected, tuning, cancel, workers=64, timeout=8.0,
                 strategy=None, progress=None, **kw):
        calls.append(([p.route_mode for p in selected], strategy))
        return [LiveConfigResult(profile=p, ok=True, ping_ms=100.0, country_code="SE") for p in selected]

    monkeypatch.setattr(SniBatchTester, "run", fake_run)
    from uac_desktop import ech_keys
    monkeypatch.setattr(ech_keys, "resolve", lambda value, cache, log=None, **kw: ech_keys.EchResolution("AAAA", "none"))
    res = SniBatchTester().run_all_modes([ech], Tuning(), threading.Event())
    assert calls == [(["ech-direct"], None)]     # one direct round, no carrier rounds
    assert res[0].ok and res[0].strategy == "ech"



def test_ech_disables_mux():
    t = Tuning(); t.xray_mux_enabled = True
    assert "mux" not in build_xray_config(_profile(ECH_URI), tuning=t)["outbounds"][0]
    assert "mux" in build_xray_config(_profile(PLAIN_URI), tuning=t)["outbounds"][0]
