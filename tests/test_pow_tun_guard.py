import io

import pytest

from uac_desktop.engine import build_singbox_tun_config
from uac_desktop.pow import tun_guard
from uac_desktop import logfmt


def _cfg(stack="gvisor", mtu=1280):
    base = build_singbox_tun_config([], [], None, None, None, socks_port=1821,
                                    helper_processes=("aether.exe", "uac-psiphon.exe"))
    return tun_guard.harden_config(base, stack, mtu)


@pytest.mark.parametrize(("preferred", "uplink_mtu", "expected"), [
    (1400, 0, 1400),
    (1500, 9000, 1400),
    (1400, 1270, 1270),
    (1400, 576, 1200),
    (1280, 1500, 1280),
    (1000, 9001, 1200),
])
def test_mtu_follows_android_clamp(preferred, uplink_mtu, expected):
    assert tun_guard.effective_mtu(preferred, uplink_mtu) == expected


def test_harden_config_sniff_dns_v6_strict():
    cfg = _cfg()
    tun = cfg["inbounds"][0]
    assert tun["stack"] == "gvisor" and tun["mtu"] == 1280 and tun["strict_route"] is True
    rules = cfg["route"]["rules"]
    assert rules[0]["action"] == "sniff"
    assert rules[1] == {"protocol": "dns", "action": "hijack-dns"}
    v6 = next(i for i, r in enumerate(rules) if r.get("ip_version") == 6)
    helpers = max(i for i, r in enumerate(rules) if "process_name" in r)
    assert v6 > helpers  # our own cores stay direct (no loop)
    assert cfg["dns"]["final"] == "remote-dns" and cfg["dns"]["strategy"] == "ipv4_only"
    assert cfg["route"]["final"] == "proxy"


def test_site_log_first_per_domain_and_errors():
    lines = [
        "INFO [11 0ms] inbound/tun[tun-in]: sniffed protocol: tls, domain: www.youtube.com",
        "INFO [11 3ms] outbound/socks[proxy]: outbound connection to 142.250.1.1:443",
        "INFO [12 0ms] inbound/tun[tun-in]: sniffed protocol: tls, domain: www.youtube.com",
        "INFO [12 2ms] outbound/socks[proxy]: outbound connection to 142.250.1.1:443",
        "\x1b[31mERROR\x1b[0m [13 1.7s] connection: open connection to bad.invalid:443 using outbound/socks[proxy]: i/o timeout",
    ]
    out = []
    log = tun_guard.SiteLog(io.StringIO("\n".join(lines) + "\n"), out.append)
    log.thread.join(2)
    assert out == ["Site www.youtube.com via tunnel (3ms)", "Site bad.invalid failed: timeout (1.7s)"]
    assert logfmt.classify(out[0]).fa.startswith("سایت www.youtube.com از تونل")


def test_verify_line_is_persian():
    e = logfmt.classify("TUN verified: DNS 4 ms, HTTPS 300 ms, exit 83.143.242.186 (FI)")
    assert e.level == "success" and "تونل سیستم بررسی شد ✔" in e.fa
