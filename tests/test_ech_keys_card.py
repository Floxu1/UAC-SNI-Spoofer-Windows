"""ECH key cache/fallback + Active Route card text cleanup."""
import base64

from uac_desktop import ech_keys
from uac_desktop.connect_summary import format_connected_block
from uac_desktop.models import ProxyProfile
from uac_desktop.route_card import card_title, clean_profile_name, ping_color, route_kind

def _key(n=8):
    body = bytes([0xFE, 0x0D, 0, n]) + bytes(range(n))
    return base64.b64encode(len(body).to_bytes(2, "big") + body).decode()

KEY1, KEY2 = _key(8), _key(10)
VALUE = "cloudflare-ech.com+udp://1.1.1.1"


def test_parse_and_base64_detection():
    assert ech_keys.parse_ech_value(VALUE) == ("cloudflare-ech.com", "udp://1.1.1.1")
    assert ech_keys.is_base64_list(KEY1)
    assert not ech_keys.is_base64_list(VALUE)
    assert ech_keys.parse_ech_value(KEY1) == ("", "")


def test_first_success_wins_and_is_cached(tmp_path):
    cache = ech_keys.EchKeyCache(tmp_path / "ech_keys.json")
    def fail(): raise OSError("blocked")
    logs = []
    res = ech_keys.resolve(VALUE, cache, logs.append,
                           fetchers=[("udp 1.1.1.1", fail), ("udp 8.8.8.8", lambda: KEY1)], doh=[], now=1000)
    assert (res.state, res.value, res.source) == ("fresh", KEY1, "udp 8.8.8.8")
    assert cache.get("cloudflare-ech.com")["key"] == KEY1
    assert any("ECH KEY: fetched via udp 8.8.8.8 (age 0m)" in l for l in logs)


def test_doh_is_last_resort(tmp_path):
    cache = ech_keys.EchKeyCache(tmp_path / "k.json")
    res = ech_keys.resolve(VALUE, cache, None, fetchers=[("udp", lambda: "")], doh=[("doh x", lambda: KEY2)])
    assert res.state == "fresh" and res.source == "doh x"


def test_all_fail_uses_cached_then_raw(tmp_path):
    cache = ech_keys.EchKeyCache(tmp_path / "k.json")
    cache.put("cloudflare-ech.com", KEY1, "udp 1.1.1.1", now=1000)
    logs = []
    res = ech_keys.resolve(VALUE, cache, logs.append, fetchers=[("u", lambda: "")], doh=[], now=1000 + 7200)
    assert (res.state, res.value) == ("cached", KEY1)
    assert any("using cached (age 2h)" in l for l in logs)
    empty = ech_keys.EchKeyCache(tmp_path / "none.json")
    res = ech_keys.resolve(VALUE, empty, None, fetchers=[], doh=[], use_fallback=False)
    assert (res.state, res.value) == ("none", VALUE)
    # k9: by default a Cloudflare ECH domain falls back to aether's built-in key
    res = ech_keys.resolve(VALUE, empty, None, fetchers=[], doh=[])
    assert (res.state, res.value) == ("fallback", ech_keys.ECH_FALLBACK_B64)


def test_connected_block_ech_line():
    block = format_connected_block("c", None, "plain", "", "1.2.3.4", "config", "mci", False, False, ech_state="fresh")
    assert "ECH      : on \u00b7 key fresh" in block
    assert "ECH" not in format_connected_block("c", None, "plain", "", "1.2.3.4", "config", "mci", False, False)


def test_clean_profile_name_strips_junk():
    assert clean_profile_name("HK \u00b7 \u672a\u77e5_10111903 \u00b7 ECH") == "HK"
    assert clean_profile_name("Germany \u00b7 By EbraSha \U0001f1e9\U0001f1ea | db7591 \u00b7 SNI") == "Germany EbraSha"
    assert clean_profile_name("@V2ray_chan t.me/x server5") == "server5"


def test_card_title_and_kind():
    p = ProxyProfile(name="HK \u00b7 \u672a\u77e5_10111903 \u00b7 ECH", country_code="HK", sni="h2.whuiy.xyz",
                     route_mode="ech-direct")
    title = card_title(p, "en")
    assert "\u672a" not in title and "10111903" not in title and title.startswith(("Hong Kong", "HK")) and "h2.whuiy.xyz" in title
    assert route_kind(p) == "ECH"
    assert ping_color(300) != ping_color(2849)
