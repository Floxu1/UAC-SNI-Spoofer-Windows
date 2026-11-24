from dataclasses import asdict, dataclass, replace

@dataclass(frozen=True)
class ConnectionPreferences:
    # "local" leaves Windows Proxy and TUN off.
    connection_mode: str = "vpn"
    routing_mode: str = "bypass"
    iran_direct: bool = True
    domains_direct: str = ""
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
                                    if name not in ("connection_mode", "domains_direct")})

    def for_direct(self, settings):
        return replace(settings, connection_mode=self.connection_mode,
                       routing_mode=self.routing_mode, iran_direct=self.iran_direct,
                       kill_switch=self.kill_switch, domains_direct=self.domains_direct)


class ApplicationSettings:
    """Application preferences backed by the existing desktop settings file."""

    KEY = "global_connection"
    direct_legacy_fields = frozenset(("connection_mode", "routing_mode", "iran_direct", "kill_switch", "domains_direct"))
    pow_legacy_fields = frozenset(asdict(ConnectionPreferences())) | {"exit_proxy_mode"}

    def __init__(self, storage):
        self._storage = storage

    def migrate(self, engine, pow_store, direct_store):
        if isinstance(self._storage.settings.get(self.KEY), dict):
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
        self._store(ConnectionPreferences.from_dict(values))

    def snapshot(self):
        return ConnectionPreferences.from_dict(self._storage.settings.get(self.KEY))

    def change(self, **values):
        current = asdict(self.snapshot())
        with_updates = ConnectionPreferences.from_dict({**current, **values})
        if asdict(with_updates) != current:
            self._store(with_updates)

    def processes(self):
        raw = self._storage.settings.get("bypass_processes", [])
        return tuple(dict.fromkeys(item for item in raw if isinstance(item, str) and item.strip())) if isinstance(raw, list) else ()

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
        return {"version": 1, "connection": asdict(self.snapshot()),
                "language": config.get("language", "fa"),
                "reduce_navigation_motion": self.reduce_navigation_motion,
                "bypass_processes": list(self.processes())}

    def restore(self, document):
        if (not isinstance(document, dict) or document.get("version") != 1
                or not isinstance(document.get("connection"), dict)):
            raise ValueError("Invalid Global Settings backup")
        config = self._storage.settings
        original = config.copy()
        try:
            language = document.get("language")
            if language in ("fa", "en"):
                config["language"] = language
            reduced = document.get("reduce_navigation_motion")
            if isinstance(reduced, bool):
                config["reduce_navigation_motion"] = reduced
            processes = document.get("bypass_processes")
            if isinstance(processes, list):
                config["bypass_processes"] = list(dict.fromkeys(
                    item for item in processes if isinstance(item, str) and item.strip()
                ))
            self._store(ConnectionPreferences.from_dict(document["connection"]))
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
        try:
            self._storage.save_settings()
        except OSError:
            if previous is None:
                config.pop(self.KEY, None)
            else:
                config[self.KEY] = previous
            raise
