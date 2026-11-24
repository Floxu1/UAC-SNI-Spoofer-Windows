"""Rules shared by the Windows POW TUN and local mixed proxy."""

from functools import lru_cache
from pathlib import Path
import sys

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
PRIVATE_NETWORKS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")


def _varint(data, offset):
    value = 0
    for shift in range(0, 70, 7):
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7f) << shift
        if byte < 128:
            return value, offset
    raise ValueError("invalid geosite varint")


def _fields(data):
    offset = 0
    while offset < len(data):
        tag, offset = _varint(data, offset)
        kind = tag & 7
        if kind == 0:
            _, offset = _varint(data, offset)
        elif kind == 2:
            size, offset = _varint(data, offset)
            yield tag >> 3, data[offset:offset + size]
            offset += size
        else:
            raise ValueError("invalid geosite wire type")


@lru_cache(maxsize=1)
def iran_domains(geosite: Path) -> list[str]:
    matches = {"ir"}
    try:
        for field, body in _fields(geosite.read_bytes()):
            if field != 1:
                continue
            site = list(_fields(body))
            if not any(field == 1 and label.upper() in (b"CATEGORY-IR", b"IR") for field, label in site):
                continue
            for field, domain in site:
                if field == 2:
                    matches.update(
                        text.decode("ascii").lower()
                        for key, text in _fields(domain)
                        if key == 2 and text and all(byte in b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-" for byte in text)
                    )
    except (OSError, IndexError, ValueError):
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
    if settings.iran_direct:
        rules.append({"domain_suffix": iran_domains(geosite), "action": "route", "outbound": "direct"})
    if not tun:
        rules.insert(0, {"action": "sniff", "timeout": "300ms"})
        return
    if settings.webrtc_block:
        rules.append({"protocol": "stun", "action": "reject"})
    if settings.quic_block:
        rules.append({"network": "udp", "port": 443, "action": "reject"})
    if not warp_only:
        rules.append({"network": "udp", "action": "reject"})
    if settings.dns_sinkhole:
        cfg["dns"].setdefault("rules", []).insert(0, {
            "domain_suffix": list(TRACKER_DOMAINS), "action": "predefined", "rcode": "NXDOMAIN",
        })
