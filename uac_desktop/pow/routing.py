"""Rules shared by the Windows POW TUN and local mixed proxy."""

from functools import lru_cache
from pathlib import Path
import sys

from ..application_settings import direct_domains, direct_ips
from ..routing_data import PRIVATE_IPV4_NETWORKS as PRIVATE_NETWORKS, geosite_entries

# Android VPN TrackerBlocklist
TRACKER_DOMAINS = (
    '2mdn.net',
    'ad.doubleclick.net',
    'adform.net',
    'adgrx.com',
    'adinplay.com',
    'adition.com',
    'admob.com',
    'adnxs.com',
    'adroll.com',
    'ads-twitter.com',
    'ads.linkedin.com',
    'ads.tiktok.com',
    'ads.yahoo.com',
    'adservice.google.com',
    'adsafeprotected.com',
    'adsrvr.org',
    'adsymptotic.com',
    'advertising.com',
    'agkn.com',
    'amazon-adsystem.com',
    'amplitude.com',
    'analytics.google.com',
    'analytics.tiktok.com',
    'analytics.twitter.com',
    'analytics.yahoo.com',
    'app-measurement.com',
    'appsflyer.com',
    'bat.bing.com',
    'bidswitch.net',
    'bluekai.com',
    'casalemedia.com',
    'chartbeat.com',
    'clarity.ms',
    'contextweb.com',
    'crash.163.com',
    'criteo.com',
    'crwdcntrl.net',
    'demdex.net',
    'doubleclick.net',
    'doubleverify.com',
    'exelator.com',
    'facebook.net',
    'flashtalking.com',
    'google-analytics.com',
    'googleadservices.com',
    'googlesyndication.com',
    'googletagmanager.com',
    'googletagservices.com',
    'hotjar.com',
    'imrworldwide.com',
    'krxd.net',
    'liadm.com',
    'mathtag.com',
    'mc.yandex.com',
    'mc.yandex.ru',
    'media.net',
    'mixpanel.com',
    'moatads.com',
    'mookie1.com',
    'nr-data.net',
    'omtrdc.net',
    'openx.net',
    'outbrain.com',
    'pagead2.googlesyndication.com',
    'partner.googleadservices.com',
    'pixel.facebook.com',
    'pubmatic.com',
    'quantserve.com',
    'rlcdn.com',
    'rubiconproject.com',
    'scorecardresearch.com',
    'segment.io',
    'serving-sys.com',
    'smartadserver.com',
    'snap.licdn.com',
    'taboola.com',
    'tapad.com',
    'tpc.googlesyndication.com',
    'tr.outbrain.com',
    'trafficshaper.dsp.rkdms.com',
    'turn.com',
    'yieldmo.com',
)
@lru_cache(maxsize=1)
def iran_domains(geosite: Path) -> list[str]:
    matches = {"ir"}
    try:
        for category in ("category-ir", "ir"):
            matches.update(dns.lower() for _, dns in geosite_entries(geosite, category)
                           if dns and all(ch in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-" for ch in dns))
    except (OSError, ValueError):
        pass
    return sorted(matches)


def apply_rules(cfg: dict, settings, selected: list[str], geosite: Path, *, tun: bool, warp_only: bool) -> None:
    rules = cfg["route"]["rules"]
    if settings.routing_mode == "only":
        # The app must be able to validate and display its own tunnel status.
        rules.append({"process_path": [sys.executable], "action": "route", "outbound": "proxy"})
        if selected:
            rules.append({
                "process_name": selected, "invert": True,
                "action": "route", "outbound": "direct",
            })
        else:
            rules.append({"action": "route", "outbound": "direct"})
    if tun:
        apply_tun_filters(cfg, settings)
    if not (tun and settings.kill_switch):
        if settings.iran_direct:
            rules.append({"domain_suffix": iran_domains(geosite), "action": "route", "outbound": "direct"})
        if domains := direct_domains(settings.domains_direct):
            rules.append({"domain_suffix": list(domains), "action": "route", "outbound": "direct"})
        if addresses := direct_ips(settings.ips_direct):
            rules.append({"ip_cidr": list(addresses), "action": "route", "outbound": "direct"})
    if not tun:
        rules.insert(0, {"action": "sniff", "timeout": "300ms"})
        return
    if not warp_only:
        rules.append({"network": "udp", "action": "reject"})


def apply_tun_filters(cfg: dict, settings, *, ipv6_block=False, quic_block=False) -> None:
    """Apply the shared filters to traffic captured by the app's TUN."""
    ipv6_block = ipv6_block or settings.ipv6_block
    quic_block = quic_block or settings.quic_block
    rules = cfg["route"]["rules"]
    if (settings.webrtc_block or quic_block) and not any(rule["action"] == "sniff" for rule in rules):
        rules.insert(0, {"action": "sniff", "timeout": "300ms"})
    # Gateway builds end with an explicit proxy route instead of only a final outbound.
    index = next((i for i, rule in enumerate(rules)
                  if rule.get("source_ip_cidr") and rule.get("outbound") == "proxy"), len(rules))
    filters = []
    if ipv6_block and not any(rule.get("ip_version") == 6 and rule.get("action") == "reject" for rule in rules):
        filters.append({"ip_version": 6, "action": "reject"})
    if settings.webrtc_block:
        filters.append({"protocol": "stun", "action": "reject"})
    if quic_block:
        filters.extend(({"protocol": "quic", "action": "reject"},
                        {"network": "udp", "port": 443, "action": "reject"}))
    rules[index:index] = filters
    cfg["dns"]["strategy"] = "ipv4_only" if ipv6_block else "prefer_ipv4"
    if settings.dns_sinkhole:
        cfg["dns"].setdefault("rules", []).insert(0, {
            "domain_suffix": list(TRACKER_DOMAINS), "action": "predefined", "rcode": "NXDOMAIN",
        })


def add_tun_proxy_listener(cfg: dict, port: int, *, dns_sinkhole: bool, ipv6_block: bool) -> None:
    """Keep explicit proxy requests on the same app routing and TUN filters."""
    tag = "tun-system-proxy"
    cfg["inbounds"].append({
        "type": "mixed", "tag": tag, "listen": "127.0.0.1", "listen_port": port,
    })
    rules = cfg["route"]["rules"]
    # Explicit proxies can receive a hostname without a DNS packet to hijack.
    if ipv6_block:
        rules[0:0] = [
            {"inbound": tag, "ip_version": 6, "action": "reject"},
            {"inbound": tag, "action": "resolve", "strategy": "ipv4_only"},
        ]
    if dns_sinkhole:
        rules.insert(0, {"inbound": tag, "domain_suffix": list(TRACKER_DOMAINS), "action": "reject"})
