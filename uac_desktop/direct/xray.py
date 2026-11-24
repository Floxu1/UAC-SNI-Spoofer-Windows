from __future__ import annotations

from collections.abc import Mapping, Sequence

from .probe import Resolver
from .store import DEFAULT_UNFILTERED_DNS, DirectSettings

_PLAIN = "direct-plain"
_UDP = "direct-udp"
_NOISE = "direct-udp-noise"
_WIREGUARD = "direct-wireguard"
_ADAPTIVE = "direct-hello-"
_BALANCER = "direct-clienthello"
_YOUTUBE = [
    "domain:youtube.com", "domain:youtu.be", "domain:youtube-nocookie.com",
    "domain:googlevideo.com", "domain:ytimg.com", "full:yt3.ggpht.com",
    "full:youtubei.googleapis.com", "full:youtube.googleapis.com",
]
_IR_DOMAINS = [
    "geosite:category-ir", "geosite:category-bank-ir", "domain:ir", r"regexp:\.ir$",
    "domain:bmi.ir", "full:www.bmi.ir",
]
_MASKS = {
    "record-small": ("tlshello", "6,98,48-96", "0", 7),
    "record-medium": ("tlshello", "48-128", "0", 6),
    "tcp-small": ("1-1", "32-64", "1-2", 6),
    "tcp-medium": ("1-1", "80-160", "1-2", 5),
}


def _fragment(packets: str, lengths: str, delays: str, limit: int) -> dict:
    return {"type": "fragment", "settings": {
        "packets": packets, "lengths": lengths.split(","), "delays": delays.split(","),
        "maxSplit": str(limit),
    }}


def _socks(tag: str, port: int) -> dict:
    return {"tag": tag, "protocol": "socks", "settings": {
        "servers": [{"address": "127.0.0.1", "port": port}],
    }}


def _freedom(tag: str, sockopt: dict, finalmask: dict | None = None) -> dict:
    stream = {"sockopt": sockopt}
    if finalmask:
        stream["finalmask"] = finalmask
    return {"tag": tag, "protocol": "freedom", "settings": {}, "streamSettings": stream}


def _route(tag: str, **criteria) -> dict:
    return {"type": "field", **criteria, "outboundTag": tag}


def build_config(
    settings: DirectSettings, socks_port: int, *, http_port: int = 0,
    stats_port: int = 0,
    exit_port: int = 0, country_exit: bool = False, session_dns: Resolver | None = None,
    paused: bool = False, noise_allowed: bool = True,
    mask_ports: Mapping[str, int] | None = None, whitelist: Sequence[str] = (),
) -> dict:
    chained = bool(exit_port) and not paused
    adaptive = settings.adaptive_client_hello and not paused and not chained
    mask_ports = mask_ports or {}
    ip_strategy = "ForceIP" if settings.ipv6 else "ForceIPv4"
    ip = {"domainStrategy": ip_strategy}
    happy = {**ip, "happyEyeballs": {
        "tryDelayMs": 300, "prioritizeIPv6": settings.ipv6, "interleave": 4, "maxConcurrentTry": 20,
    }}
    noise = settings.udp_noise and noise_allowed
    use_frag = not settings.adaptive_client_hello and settings.fragment_enabled and not paused
    outbounds = [
        {"tag": "block", "protocol": "blackhole", "settings": {}},
        {"tag": "dns-out", "protocol": "dns", "settings": {"rewriteNetwork": "tcp", "rules": [
            {"qType": "1,28", "action": "hijack"}, {"action": "return", "rCode": 0},
        ]}},
        _freedom(_PLAIN, happy),
        _freedom(_UDP, ip),
    ]
    if chained:
        outbounds.append(_socks(_WIREGUARD, exit_port))
    tls_tag = _PLAIN
    if use_frag:
        tls_tag = "direct-tls"
        fragments = [_fragment("tlshello", settings.hello_lengths, settings.hello_delays, settings.hello_max_split)]
        if settings.second_stage_enabled:
            fragments.append(_fragment("1-1", settings.second_lengths, settings.second_delays, settings.second_max_split))
        outbounds.append(_freedom(tls_tag, happy, {"tcp": fragments}))
    if adaptive:
        for name, config in _MASKS.items():
            outbounds.append(_freedom(_ADAPTIVE + name, happy, {"tcp": [_fragment(*config)]}))
        for name in ("oob", "record-sni"):
            if name in mask_ports:
                local = "direct-local-" + name
                outbounds.append(_socks(local, mask_ports[name]))
                outbounds.append(_freedom(_ADAPTIVE + name, {**ip, "dialerProxy": local}))
    if settings.tcp_fragment_enabled:
        fragment = _fragment("1-1", settings.tcp_lengths, settings.tcp_delays, settings.tcp_max_split)
        outbounds.append(_freedom("direct-tcp-frag", happy, {"tcp": [fragment]}))
    if noise:
        outbounds.append(_freedom(_NOISE, ip, {"udp": [{
            "type": "noise", "settings": {"reset": "28", "noise": [
                {"rand": "1200-1230", "delay": "10"} for _ in range(24)
            ]},
        }]}))
    sniff = {"enabled": True, "destOverride": ["tls", "http", "quic"], "routeOnly": True}
    inbounds = [{
        "tag": "socks-in", "listen": "127.0.0.1", "port": socks_port, "protocol": "socks",
        "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1", "userLevel": 8},
        "sniffing": sniff,
    }]
    if http_port:
        inbounds.append({
            "tag": "http-in", "listen": "127.0.0.1", "port": http_port, "protocol": "http",
            "settings": {"userLevel": 8}, "sniffing": sniff,
        })
    dns_record = _ADAPTIVE + "record-sni" if adaptive and "record-sni" in mask_ports else tls_tag
    dns_oob = _ADAPTIVE + "oob" if adaptive and "oob" in mask_ports else dns_record
    rules = [_route("dns-out", inboundTag=[item["tag"] for item in inbounds], port="53")]
    if chained:
        rules.append(_route(_WIREGUARD, inboundTag=["dns-unfiltered", "dns-cloudflare", "dns-google"]))
    else:
        rules.extend([
            _route(tls_tag, inboundTag=["dns-unfiltered"]),
            _route(dns_record, inboundTag=["dns-cloudflare"]),
            _route(dns_oob, inboundTag=["dns-google"]),
        ])
    rules.append(_route(_PLAIN, inboundTag=["dns-domestic", "dns-fallback"]))
    if paused:
        rules.append(_route(_PLAIN, network="tcp,udp"))
    if whitelist:
        rules.append(_route(_PLAIN, network="tcp,udp", domain=list(whitelist)))
    if settings.iran_direct:
        if chained:
            rules.append(_route(_WIREGUARD, network="tcp", domain=_YOUTUBE))
        rules.extend([
            _route(_PLAIN, network="tcp", domain=_IR_DOMAINS),
            _route(_UDP, network="udp", domain=_IR_DOMAINS),
            _route(_PLAIN, network="tcp", ip=["geoip:ir"]),
            _route(_UDP, network="udp", ip=["geoip:ir"]),
        ])
    rules.extend([
        _route("block", ip=["10.10.34.0/24"]),
        _route(_PLAIN, network="tcp", ip=["geoip:private"]),
        _route(_UDP, network="udp", ip=["geoip:private"]),
    ])
    if not settings.ipv6:
        rules.append(_route("block", ip=["::/0"]))
    if settings.block_quic:
        rules.extend([_route("block", network="udp", protocol=["quic"]), _route("block", network="udp", port="443")])
    if chained:
        if country_exit:
            rules.append(_route("block", network="udp"))
        rules.append(_route(_WIREGUARD, network="tcp,udp"))
    tls_route = {"balancerTag": _BALANCER} if adaptive else {"outboundTag": tls_tag}
    rules.extend([
        _route(_NOISE if noise else _UDP, network="udp"),
        {"type": "field", "network": "tcp", "protocol": ["tls"], **tls_route},
        {"type": "field", "network": "tcp", "port": "443", **tls_route},
        _route("direct-tcp-frag" if settings.tcp_fragment_enabled else _PLAIN, network="tcp"),
    ])
    routing = {"domainStrategy": "IPOnDemand", "rules": rules}
    config = {
        "log": {"loglevel": "warning", "dnsLog": False},
        "dns": _dns(settings, chained, None if paused else session_dns),
        "inbounds": inbounds, "outbounds": outbounds, "routing": routing,
        "policy": {"levels": {"8": {"handshake": 8, "connIdle": 300, "uplinkOnly": 2, "downlinkOnly": 5}}},
    }
    if stats_port:
        config["api"] = {"tag": "direct-stats", "listen": f"127.0.0.1:{stats_port}", "services": ["StatsService"]}
        config["stats"] = {}
        config["policy"]["system"] = {"statsInboundUplink": True, "statsInboundDownlink": True}
    if adaptive:
        selector = [_PLAIN, _ADAPTIVE]
        routing["balancers"] = [{
            "tag": _BALANCER, "selector": selector, "fallbackTag": dns_record,
            "strategy": {"type": "leastLoad", "settings": {"expected": 1, "tolerance": 0.2}},
        }]
        config["burstObservatory"] = {"subjectSelector": selector, "pingConfig": {
            "destination": "https://www.youtube.com/generate_204", "interval": "10s",
            "sampling": 2, "timeout": "5s", "httpMethod": "HEAD",
        }}
    return config


def _dns_server(tag: str, address: str, timeout: int, **options) -> dict:
    return {"tag": tag, "address": address, "timeoutMs": timeout, **options}


def _dns(settings: DirectSettings, chained: bool, preferred: Resolver | None) -> dict:
    address = preferred.url if preferred else settings.unfiltered_dns
    if not chained and preferred and not preferred.bootstrap:
        address = address.replace("https://", "https+local://", 1)
    elif chained and "://" not in address:
        host = f"[{address.strip('[]')}]" if ":" in address else address
        address = f"tcp://{host}"
    servers = []
    if settings.iran_direct:
        if chained:
            servers.append(_dns_server("dns-unfiltered", address, 2500, domains=_YOUTUBE, skipFallback=True))
        servers.append(_dns_server("dns-domestic", settings.domestic_dns, 3000,
                                   domains=_IR_DOMAINS, skipFallback=True, finalQuery=True))
    if preferred or settings.unfiltered_dns != DEFAULT_UNFILTERED_DNS:
        servers.append(_dns_server("dns-unfiltered", address, 2000))
    servers.extend([
        _dns_server("dns-cloudflare", "https://cloudflare-dns.com/dns-query", 1800),
        _dns_server("dns-google", "https://dns.google/dns-query", 1800),
        _dns_server("dns-cloudflare", "https://mozilla.cloudflare-dns.com/dns-query", 1800),
    ])
    if chained:
        servers.append(_dns_server("dns-unfiltered", DEFAULT_UNFILTERED_DNS, 2500))
    else:
        servers.extend([
            _dns_server("dns-unfiltered", "https+local://1.1.1.1/dns-query", 1800),
            _dns_server("dns-fallback", settings.domestic_dns, 1200, unexpectedIPs=["10.10.34.0/24"]),
        ])
    hosts = {
        "cloudflare-dns.com": ["104.16.248.249", "104.16.249.249"],
        "mozilla.cloudflare-dns.com": ["172.64.41.4", "162.159.61.4"],
        "dns.google": ["8.8.8.8", "8.8.4.4"],
    }
    if preferred and preferred.bootstrap:
        hosts[preferred.host] = list(preferred.bootstrap)
    return {"hosts": hosts, "servers": servers, "queryStrategy": "UseIP" if settings.ipv6 else "UseIPv4",
            "serveStale": True, "tag": "dns-query"}
