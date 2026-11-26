from ipaddress import ip_address, ip_network
import re
from dataclasses import asdict, dataclass, replace
from pathlib import PureWindowsPath


TUN_FILTERS = frozenset(("ipv6_block", "dns_sinkhole", "webrtc_block", "quic_block"))
LAN_SETTINGS = frozenset(("lan_share", "lan_share_mode", "lan_share_port"))


def direct_domains(text, *, strict=False):
    """Accept bare DNS suffixes, including internationalized domain names."""
    domains = []
    for item in re.split(r"[\s,،;]+", text.strip()):
        if not item:
            continue
        try:
            domain = item.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError:
            domain = ""
        labels = domain.split(".")
        if (len(labels) < 2 or len(domain) > 253 or not any(c.isalpha() for c in labels[-1])
                or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                           for label in labels)):
            if strict:
                raise ValueError("Enter domain names without URLs or credentials.")
            continue
        domains.append(domain)
    return tuple(dict.fromkeys(domains))


def direct_ips(text, *, strict=False):
    """Normalize literal IPs and CIDRs, with hosts equivalent to /32 or /128."""
    entries = {}
    for item in filter(None, re.split(r"[\s,،;]+", text.strip())):
        _, slash, prefix = item.rpartition("/")
        try:
            if "%" in item or (slash and not (prefix.isascii() and prefix.isdecimal())):
                raise ValueError
            network = ip_network(item if slash else ip_address(item), strict=False)
        except ValueError:
            if strict:
                raise ValueError("Enter an IPv4, IPv6 or CIDR address.") from None
            continue
        address = network.network_address if network.prefixlen == network.max_prefixlen else network
        entries.setdefault(network, str(address))
    return tuple(entries.values())


def _is_process_name(item):
    return (isinstance(item, str) and bool(item) and item.strip() == item
            and PureWindowsPath(item).name == item
            and not re.search(r'[<>:"/\\|?*\x00-\x1f]', item))

@dataclass(frozen=True)
class ConnectionPreferences:
    # "local" leaves Windows Proxy and TUN off.
    connection_mode: str = "vpn"
    routing_mode: str = "bypass"
    iran_direct: bool = True
    domains_direct: str = ""
    ips_direct: str = ""
    dns_sinkhole: bool = True
    webrtc_block: bool = True
    quic_block: bool = False
    ipv6_block: bool = True
    kill_switch: bool = False
    auto_connect: bool = False
    lan_share: bool = False
    lan_share_mode: str = "socks5"
    lan_share_port: int = 18080

    @classmethod
    def from_dict(cls, raw):
        defaults = asdict(cls())
        raw = raw if isinstance(raw, dict) else {}
        values = {name: raw[name] for name, default in defaults.items()
                  if type(raw.get(name)) is type(default)}
        for name, choices in (
            ("connection_mode", ("vpn", "proxy", "local")),
            ("routing_mode", ("all", "bypass", "only")),
            ("lan_share_mode", ("socks5", "ps5")),
        ):
            if values.get(name) not in choices:
                values.pop(name, None)
        if not 1 <= values.get("lan_share_port", defaults["lan_share_port"]) <= 65535:
            values.pop("lan_share_port", None)
        return cls(**values)

    def for_pow(self, settings):
        return replace(settings, **{name: value for name, value in asdict(self).items()
                                    if name != "connection_mode"})

    @property
    def windows_proxy_enabled(self):
        return self.connection_mode == "proxy"

    def for_direct(self, settings):
        return replace(settings, connection_mode=self.connection_mode,
                       routing_mode=self.routing_mode, iran_direct=self.iran_direct,
                       kill_switch=self.kill_switch, domains_direct=self.domains_direct, ips_direct=self.ips_direct)


class ApplicationSettings:
    """Application preferences backed by the existing desktop settings file."""

    KEY = "global_connection"
    direct_legacy_fields = frozenset(("connection_mode", "routing_mode", "iran_direct", "kill_switch",
                                      "domains_direct", "ips_direct"))
    pow_legacy_fields = frozenset(asdict(ConnectionPreferences())) | {"exit_proxy_mode"}

    def __init__(self, storage):
        self._storage = storage

    def migrate(self, engine, pow_store, direct_store):
        stored = self._storage.settings.get(self.KEY)
        if isinstance(stored, dict) and asdict(ConnectionPreferences()).keys() <= stored.keys():
            return
        config = self._storage.settings
        pow_saved = pow_store.saved_settings()
        direct_saved = direct_store.saved_settings()
        values = {name: pow_saved[name] for name in asdict(ConnectionPreferences()) if name in pow_saved}
        if "domains_direct" in direct_saved:
            values["domains_direct"] = direct_saved["domains_direct"]
        if engine == "direct":
            values.update({name: direct_saved[name] for name in self.direct_legacy_fields if name in direct_saved})
        elif engine == "xray":
            values["connection_mode"] = ("vpn" if config.get("tun_mode") else
                                         "proxy" if config.get("proxy_mode", True) else "local")
            values["iran_direct"] = self._storage.tuning.iran_direct
        elif type(pow_saved.get("exit_proxy_mode")) is bool:
            values["connection_mode"] = "proxy" if pow_saved["exit_proxy_mode"] else "vpn"
        self._store(ConnectionPreferences.from_dict({**values, **(stored if isinstance(stored, dict) else {})}))

    def snapshot(self):
        return ConnectionPreferences.from_dict(self._storage.settings.get(self.KEY))

    def change(self, **values):
        current = asdict(self.snapshot())
        for key, parse in (("domains_direct", direct_domains), ("ips_direct", direct_ips)):
            if key in values:
                if not isinstance(values[key], str):
                    raise ValueError("Invalid routing list.")
                values[key] = ", ".join(parse(values[key], strict=True))
        with_updates = ConnectionPreferences.from_dict({**current, **values})
        if asdict(with_updates) != current:
            self._store(with_updates)

    def processes(self):
        raw = self._storage.settings.get("bypass_processes", [])
        return tuple(dict.fromkeys(item for item in raw if isinstance(item, str) and item.strip())) if isinstance(raw, list) else ()

    def set_processes(self, processes):
        config = self._storage.settings
        previous = config.get("bypass_processes")
        config["bypass_processes"] = list(processes)
        try:
            self._storage.save_settings()
        except OSError:
            if previous is None:
                config.pop("bypass_processes", None)
            else:
                config["bypass_processes"] = previous
            raise

    @property
    def reduce_navigation_motion(self):
        return self._storage.settings.get("reduce_navigation_motion") is True

    def set_navigation_motion(self, reduced):
        config = self._storage.settings
        key = "reduce_navigation_motion"
        previous = config.get(key)
        config[key] = bool(reduced)
        try:
            self._storage.save_settings()
        except OSError:
            if previous is None:
                config.pop(key, None)
            else:
                config[key] = previous
            raise

    def export(self):
        config = self._storage.settings
        connection = asdict(self.snapshot())
        connection["domains_direct"] = ", ".join(direct_domains(connection["domains_direct"]))
        connection["ips_direct"] = ", ".join(direct_ips(connection["ips_direct"]))
        language = config.get("language")
        return {"version": 1, "connection": connection,
                "language": language if language in ("fa", "en") else "fa",
                "reduce_navigation_motion": self.reduce_navigation_motion,
                "bypass_processes": [item for item in self.processes() if _is_process_name(item)]}

    def restore(self, document):
        if (not isinstance(document, dict) or type(document.get("version")) is not int
                or document["version"] != 1
                or not isinstance(document.get("connection"), dict)):
            raise ValueError("Invalid Global Settings backup")
        incoming = document["connection"]
        current = asdict(self.snapshot())
        if not current.keys() & incoming.keys():
            raise ValueError("The backup has no recognized connection settings.")
        preferences = ConnectionPreferences.from_dict({**current, **incoming})
        normalized = asdict(preferences)
        if any(type(incoming[key]) is not type(current[key]) or incoming[key] != normalized[key]
               for key in current.keys() & incoming.keys()):
            raise ValueError("The backup contains invalid connection settings.")
        if "domains_direct" in incoming:
            preferences = replace(preferences, domains_direct=", ".join(
                direct_domains(preferences.domains_direct, strict=True)))
        if "ips_direct" in incoming:
            preferences = replace(preferences, ips_direct=", ".join(direct_ips(preferences.ips_direct, strict=True)))
        if ("language" in document and document["language"] not in ("fa", "en")
                or "reduce_navigation_motion" in document and type(document["reduce_navigation_motion"]) is not bool):
            raise ValueError("The backup contains invalid appearance settings.")
        processes = document.get("bypass_processes")
        if "bypass_processes" in document:
            if not isinstance(processes, list) or not all(map(_is_process_name, processes)):
                raise ValueError("Invalid application names in the backup.")
        config = self._storage.settings
        original = config.copy()
        try:
            language = document.get("language")
            if language in ("fa", "en"):
                config["language"] = language
            reduced = document.get("reduce_navigation_motion")
            if isinstance(reduced, bool):
                config["reduce_navigation_motion"] = reduced
            if isinstance(processes, list):
                config["bypass_processes"] = list(dict.fromkeys(processes))
            self._store(preferences)
        except OSError:
            config.update(original)
            for name in ("language", "bypass_processes", "reduce_navigation_motion"):
                if name not in original:
                    config.pop(name, None)
            raise

    def reset_connection(self):
        self._store(ConnectionPreferences())

    def _store(self, values):
        config = self._storage.settings
        previous = config.get(self.KEY)
        config[self.KEY] = {**(previous if isinstance(previous, dict) else {}), **asdict(values)}
        config[self.KEY].pop("windows_proxy_with_tun", None)
        try:
            self._storage.save_settings()
        except OSError:
            if previous is None:
                config.pop(self.KEY, None)
            else:
                config[self.KEY] = previous
            raise
