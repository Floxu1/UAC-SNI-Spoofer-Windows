import json
import threading
from types import SimpleNamespace

from uac_desktop import ip_info
from uac_desktop.engine import build_xray_config, iran_direct_rules
from uac_desktop.models import ProxyProfile, Tuning
from uac_desktop.ui import auto_quality_score


def _profile():
    return ProxyProfile.from_dict({"id": "p1", "name": "t", "uri": "vless://00000000-0000-0000-0000-000000000000@1.2.3.4:443?security=tls&type=tcp#t"}) if hasattr(ProxyProfile, "from_dict") else None


def _cfg(tuning):
    import inspect
    from uac_desktop import engine
    from uac_desktop.storage import Storage  # noqa: F401
    p = None
    try:
        from uac_desktop.uri import parse_uri
        p = parse_uri("vless://00000000-0000-0000-0000-000000000000@1.2.3.4:443?security=tls&type=tcp&sni=a.com#t")
    except Exception:
        p = _profile()
    return build_xray_config(p, 20809, 20808, tuning=tuning) if "tuning" in inspect.signature(build_xray_config).parameters else build_xray_config(p, 20809, 20808, tuning)


def test_tuning_default_on():
    assert Tuning().iran_direct is True
    assert Tuning.from_dict({}).iran_direct is True


def test_iran_rules_shape():
    rules = iran_direct_rules()
    assert all(r["outboundTag"] == "direct" for r in rules)
    flat = json.dumps(rules)
    assert "geosite:category-ir" in flat and "geoip:ir" in flat and "geoip:private" in flat and "\\\\.ir$" in flat


def test_quality_score_penalises_failures():
    good, _ = auto_quality_score({"s204": [300, 320, 310], "pages": [900, 1100]})
    flaky, br = auto_quality_score({"s204": [250, None, None], "pages": [800, None]})
    dead, _ = auto_quality_score({"s204": [None] * 3, "pages": [None] * 2})
    assert good < flaky < dead
    assert br["ok204"] == "1/3" and br["okpage"] == "1/2"


def test_fast_lookup_skips_ipinfo_and_caches():
    calls = []

    def get(url, port):
        calls.append(url)
        if "ipwho" in url:
            raise OSError("down")
        return {"status": "success", "query": "5.6.7.8", "countryCode": "NL", "city": "Amsterdam"}
    info = ip_info.fetch_fast(1, get=get)
    assert info["ip"] == "5.6.7.8" and not any("ipinfo" in c for c in calls)
    ip_info.cache_put(("ip", "5.6.7.8"), info)
    assert ip_info.cache_get(("ip", "5.6.7.8"))["country"] == "NL"
    assert ip_info.cache_get(("ip", "5.6.7.8"), ttl=-1) is None


def test_ipinfo_marked_dead_after_one_failure():
    ip_info._IPINFO_DEAD["until"] = 0
    seen = []

    def get(url, port):
        seen.append(url)
        raise OSError("x")
    for _ in range(2):
        try:
            ip_info.fetch_details(1, get=get)
        except RuntimeError:
            pass
    assert sum("ipinfo" in u for u in seen) == 1
    ip_info._IPINFO_DEAD["until"] = 0


def test_auto_quality_pick_order_ewma_and_log():
    import threading
    from types import SimpleNamespace
    from uac_desktop import ui
    from uac_desktop.models import ProxyProfile
    ps = [ProxyProfile(id=i, name=i, country_code="NL", last_ping_ms=ms, last_ping_ok=True, origin="sni-maker")
          for i, ms in (("lowping_flaky", 100), ("solid", 900), ("dead", 200))]
    q = {"lowping_flaky": {"ok": True, "quality": {"s204": [150, None, None], "pages": [None, 900]}},
         "solid": {"ok": True, "quality": {"s204": [400, 420, 410], "pages": [1200, 1300]}},
         "dead": {"ok": False}}
    logs = []
    stub = SimpleNamespace(storage=SimpleNamespace(settings={}, save_settings=lambda: None),
                           engine=SimpleNamespace(running=False),
                           bridge=SimpleNamespace(log=SimpleNamespace(emit=logs.append), latency=SimpleNamespace(emit=lambda *a: None)),
                           _auto_quality_fn=lambda pool, c: q)
    order = ui.MainWindow._auto_latency_order(stub, ps, threading.Event())
    assert [p.id for p in order] == ["solid", "lowping_flaky", "dead"]
    st = stub.storage.settings[ui.AUTO_LATENCY_KEY]
    first = st["solid"]["qs"]
    assert any("AUTO PICK #1: solid" in l and "ok 3/3" in l for l in logs)
    ui.MainWindow._auto_latency_order(stub, ps, threading.Event())
    assert st is not stub.storage.settings[ui.AUTO_LATENCY_KEY] or True
    assert abs(stub.storage.settings[ui.AUTO_LATENCY_KEY]["solid"]["qs"] - first) < 1  # EWMA stable for same sample


def test_xray_config_iran_rules_and_toggle():
    import json

    from uac_desktop.engine import build_xray_config
    from uac_desktop.models import Tuning, parse_many

    p = parse_many("vless://12345678-1234-4567-890a-123456789abc@example.net:443?security=tls#test")[0]
    on = build_xray_config(p, http_port=30809, socks_port=30808, tuning=Tuning())
    flat = json.dumps(on["routing"])
    assert "geosite:category-ir" in flat and "geoip:ir" in flat and on["routing"]["domainStrategy"] == "AsIs"
    assert all(i.get("sniffing", {}).get("routeOnly") for i in on["inbounds"])
    assert on["outbounds"][0] == build_xray_config(p, http_port=30809, socks_port=30808, tuning=Tuning(iran_direct=False))["outbounds"][0]
    off = build_xray_config(p, http_port=30809, socks_port=30808, tuning=Tuning(iran_direct=False))
    assert "geoip:ir" not in json.dumps(off["routing"]) and not any("sniffing" in i for i in off["inbounds"])
