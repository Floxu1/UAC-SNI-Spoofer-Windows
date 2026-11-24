import threading
from dataclasses import replace
from types import SimpleNamespace

from uac_desktop import sni_finder as F
from uac_desktop.clean_ip import ProbeResult
from uac_desktop.models import ProxyProfile, Tuning
from uac_desktop.sni_maker import config_signature


def test_parse_carrier_sources():
    assert F.parse_carrier({"connection": {"asn": 44244, "isp": "Iran Cell"}}) == ("irancell", "AS44244")
    assert F.parse_carrier({"as": "AS197207 Mobile Communication Company of Iran PLC"}) == ("mci", "AS197207")
    assert F.parse_carrier({"org": "AS44244 Iran Cell Service and Communication"})[0] == "irancell"
    assert F.parse_carrier({"connection": {"asn": 58224, "isp": "TCI"}}) == ("", "AS58224")
    assert F.parse_carrier("bad") == ("", "")


def test_detect_carrier_fallback_and_success():
    assert F.detect_carrier("mci", get=lambda u: {"as": "AS1 X"})["carrier"] == "mci"
    out = F.detect_carrier("mci", get=lambda u: (_ for _ in ()).throw(OSError()))
    assert out["fallback"] and out["source"] == "setting"
    assert F.detect_carrier("auto", get=lambda u: {"connection": {"asn": 44244}})["carrier"] == "irancell"


def test_connect_route_builtin_and_gene():
    t = Tuning(); t.pattern_fake_sni = "a.com"
    assert F.connect_route("irancell", t) == ("full5", "a.com", "")
    assert F.connect_route("mci", t)[0] == "tls_sni_records"
    gene = {"method": "primitive", "fake_sni": "g.com", "ops": [{"kind": "tcp_frag"}]}
    m, sni, ops = F.connect_route("irancell", t, gene)
    assert (m, sni) == ("primitive", "g.com") and "tcp_frag" in ops
    assert F.connect_route("mci", t, gene)[0] == "tls_sni_records"   # MCI never uses genes


def test_edge_rounds():
    assert F.edge_rounds(["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"], ["9.9.9.9"]) == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
    assert F.edge_rounds([], ["9.9.9.9", "bad", "9.9.9.9"]) == ["9.9.9.9"]


def test_rank_by_success_latency_throughput():
    p = ProxyProfile()
    a = F.FinderResult(p, True, "e", 300, 2, 2, 100)
    b = F.FinderResult(p, True, "e", 100, 1, 2, 900)
    c = F.FinderResult(p, True, "e", 100, 2, 2, 50)
    d = F.FinderResult(p, False)
    assert F.rank([a, b, c, d], 10) == [c, a, b]
    assert F.rank([a, b, c], 1) == [c]


def _profile(uri="vless://u@127.0.0.1:40443?security=tls&sni=x.com#n", **kw):
    return ProxyProfile(source_uri=uri, origin="sni-maker", **kw)


def test_tag_and_stale_and_demote():
    p = _profile(address="104.19.229.21")
    r = F.FinderResult(p, True, "104.16.8.34", 200, 2, 2, 400, "DE", "1.2.3.4")
    t = F.tag_profile(p, r, "irancell", "net1", "chatgpt.com", "full5", now=1000)
    assert t.address == "104.16.8.34" and t.fallback_address == "" and t.spoof_fake_sni == "chatgpt.com"
    assert t.maker_meta["carrier"] == "irancell" and t.maker_meta["score"] > 0 and t.country_code == "DE"
    assert p.maker_meta == {}                                   # original untouched
    assert not F.is_stale(t, "irancell", "net1", now=1000 + 3600)
    assert F.is_stale(t, "mci", "net1", now=1001)
    assert F.is_stale(t, "irancell", "net2", now=1001)
    assert F.is_stale(t, "irancell", "net1", now=1000 + F.STALE_SECONDS + 1)
    assert not F.is_stale(p, "mci", "x")                        # non-finder profiles never revalidated
    f1 = F.mark_revalidated(t, False, now=2000)
    assert f1.maker_meta["fail_streak"] == 1 and not f1.maker_meta["demoted"]
    f2 = F.mark_revalidated(f1, False, now=2001)
    assert f2.maker_meta["demoted"] and f2.last_ping_ok is False
    ok = F.mark_revalidated(f2, True, 150, "irancell", "net1", now=3000)
    assert ok.maker_meta["fail_streak"] == 0 and not ok.maker_meta["demoted"]


def test_merge_never_touches_user_profiles():
    user = _profile(name="my irancell", address="5.5.5.5")
    user_dict = user.to_dict()
    finder_old = F.tag_profile(_profile("vless://u@127.0.0.1:40443?security=tls&sni=y.com#m"),
                               F.FinderResult(None, True, "1.1.1.1", 100), "irancell", "n", "s", "full5", now=1)
    new_same_as_user = F.tag_profile(_profile(), F.FinderResult(None, True, "2.2.2.2", 90), "irancell", "n", "s", "full5")
    new_update = replace(finder_old, address="3.3.3.3")
    brand_new = F.tag_profile(_profile("trojan://p@127.0.0.1:40443?security=tls&sni=z.com#z"),
                              F.FinderResult(None, True, "4.4.4.4", 80), "irancell", "n", "s", "full5")
    merged, added, updated, skipped = F.merge_profiles(
        [user, finder_old], [new_same_as_user, new_update, brand_new], config_signature)
    assert merged[0].to_dict() == user_dict                      # untouched
    assert merged[1].address == "3.3.3.3" and merged[1].id == finder_old.id
    assert (added, updated, skipped) == (1, 1, 1) and len(merged) == 3


class _FakeTester:
    """Config 'a' works only on edge 2.2.2.2, 'b' on 1.1.1.1."""
    calls = []

    def __init__(self):
        pass

    def run(self, profiles, tuning, cancel, workers, timeout, strategy, probe):
        _FakeTester.calls.append((tuning.pattern_connect_ip, strategy, tuning.pattern_session_edge, len(profiles)))
        out = []
        for p in profiles:
            ok = (p.name == "a" and p.address == "2.2.2.2") or (p.name == "b" and p.address == "1.1.1.1")
            out.append(SimpleNamespace(profile=p, ok=ok, ping_ms=120.0, samples=2, samples_ok=2 if ok else 0,
                                       throughput_kbps=300.0, country_code="NL", exit_ip="", error=""))
        return out

    def stop(self):
        pass


def test_run_finder_per_edge_rounds_stop_at_first_win():
    _FakeTester.calls.clear()
    recorded = []
    cache = SimpleNamespace(record=lambda *a, **k: recorded.append(a))
    profiles = [_profile(name="a", id="A"), _profile("vless://u@127.0.0.1:40443?security=tls&sni=q.com#b", name="b", id="B"),
                _profile("vless://u@127.0.0.1:40443?security=tls&sni=r.com#c", name="c", id="C")]
    t = Tuning(); t.pattern_fake_sni = "chatgpt.com"
    rep = F.run_finder(profiles, t, carrier_info={"carrier": "irancell", "source": "asn", "asn": "AS44244"},
                       network="n", gene=None, cache=cache, cancel=threading.Event(),
                       tester_factory=_FakeTester,
                       clean_finder=lambda *a, **k: [ProbeResult("1.1.1.1", True, 50), ProbeResult("2.2.2.2", True, 60)])
    assert rep.clean_ips == ["1.1.1.1", "2.2.2.2"] and rep.method == "full5"
    assert _FakeTester.calls == [("1.1.1.1", "full5", "1.1.1.1", 3), ("2.2.2.2", "full5", "2.2.2.2", 2)]
    names = {p.name: p for p in rep.profiles}
    assert set(names) == {"a", "b"} and names["a"].address == "2.2.2.2" and names["b"].address == "1.1.1.1"
    assert all(p.maker_meta["carrier"] == "irancell" for p in rep.profiles)
    assert [r[0] for r in recorded] == ["irancell", "irancell"]   # carrier bucket only
    assert profiles[0].address != "2.2.2.2"                       # inputs not mutated
