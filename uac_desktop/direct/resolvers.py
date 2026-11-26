"""DNS addresses shared by the Direct session, settings and DNS Lab."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit


@dataclass(frozen=True)
class Resolver:
    key: str
    label: str
    host: str
    bootstrap: tuple[str, ...] = ()
    address: str = ""

    @property
    def url(self) -> str:
        return self.address or f"https://{self.host}/dns-query"

    @property
    def protocol(self) -> str:
        return {"tcp": "TCP", "udp": "UDP"}.get(self.url.partition(":")[0], "DoH")


RESOLVERS = (
    Resolver("cloudflare", "Cloudflare", "cloudflare-dns.com", ("1.1.1.1", "1.0.0.1")),
    Resolver("google", "Google", "dns.google", ("8.8.8.8", "8.8.4.4")),
    Resolver("quad9", "Quad9", "dns.quad9.net", ("9.9.9.9", "149.112.112.112")),
    Resolver("adguard", "AdGuard unfiltered", "unfiltered.adguard-dns.com", ("94.140.14.140", "94.140.14.141")),
    Resolver("opendns", "OpenDNS", "doh.opendns.com", ("208.67.222.222", "208.67.220.220")),
    Resolver("rethink-sky", "ReThinkDNS Sky", "sky.rethinkdns.com"),
    Resolver("rethink-max", "ReThinkDNS Max", "max.rethinkdns.com"),
)
# Public addresses from AetherST's DnsBenchmarkRepository.
_AETHERST_DNS = (
    ("Cloudflare", ("1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001")),
    ("Google", ("8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844")),
    ("Quad9", ("9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9")),
    ("OpenDNS", ("208.67.222.222", "208.67.220.220", "2620:119:35::35", "2620:119:53::53")),
    ("AdGuard", ("94.140.14.14", "94.140.15.15", "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff")),
    ("Shecan", ("178.22.122.100", "185.51.200.2")),
    ("Begzar", ("185.55.226.26", "185.55.225.25")),
    ("Electro", ("78.157.42.100", "78.157.42.101")),
    ("Radar", ("10.202.10.10", "10.202.10.11")),
    ("403.online", ("10.202.10.202", "10.202.10.102")),
)


def _authority(host: str) -> str:
    return f"[{host}]" if ":" in host else host


BUILTIN_RESOLVERS = RESOLVERS + tuple(
    Resolver(f"udp:{host}", label, host, address=f"udp://{_authority(host)}")
    for label, hosts in _AETHERST_DNS for host in hosts
)
_BY_URL = {resolver.url: resolver for resolver in BUILTIN_RESOLVERS}
MOZILLA_DOH = "https://mozilla.cloudflare-dns.com/dns-query"
_HOST = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def parse_resolver(value: str) -> Resolver:
    value = value.strip()
    if not value or len(value) > 2048 or any(ch.isspace() or ord(ch) < 32 for ch in value):
        raise ValueError("Invalid DNS address")
    if "://" not in value:
        value = f"tcp://{_authority(str(ipaddress.ip_address(value)))}"
    target = urlsplit(value)
    if target.scheme not in ("https", "tcp", "udp") or not target.hostname or target.username is not None or "#" in value:
        raise ValueError("Use an HTTPS DNS URL or a DNS server IP address")
    port = target.port
    if port == 0 or "%" in target.hostname:
        raise ValueError("Invalid DNS host or port")
    try:
        host = str(ipaddress.ip_address(target.hostname))
    except ValueError:
        host = target.hostname.rstrip(".").encode("idna").decode("ascii").lower()
        if target.scheme != "https" or len(host) > 253 or not all(_HOST.fullmatch(part) for part in host.split(".")):
            raise ValueError("TCP and UDP DNS need an IP address and HTTPS needs a valid host")
    if target.scheme != "https" and (target.path or target.query):
        raise ValueError("Plain DNS addresses cannot contain a path or query")
    authority = _authority(host)
    if port and port != (443 if target.scheme == "https" else 53):
        authority += f":{port}"
    path = target.path or ("/dns-query" if target.scheme == "https" else "")
    url = urlunsplit((target.scheme, authority, path, target.query, ""))
    return _BY_URL.get(url) or Resolver(url, authority, host, address=url)


def resolver_catalog(addresses=(), configured=()) -> tuple[Resolver, ...]:
    items = dict(_BY_URL)
    for address in (*addresses, *configured):
        if not isinstance(address, str):
            continue
        try:
            resolver = parse_resolver(address)
        except ValueError:
            continue
        items.setdefault(resolver.url, resolver)
    return tuple(items.values())
