"""User-configurable local proxy ports for both desktop engines.

Engine 1 (Xray) listens on a SOCKS/HTTP pair; engine 2 (UAC PoW) exposes one
local HTTP port (a mixed HTTP+SOCKS port in App Bypass mode) that the Windows
system proxy points at. The defaults are exactly the ports the app always used,
so nothing changes until the user picks another port.
"""
from __future__ import annotations

import os
import socket
from typing import Callable, Iterable

XRAY_SOCKS_DEFAULT = 20808
XRAY_HTTP_DEFAULT = 20809
POW_HTTP_DEFAULT = 1822
#: Psiphon local SOCKS: the engine-2 exit SOCKS when chained through Psiphon.
POW_SOCKS_DEFAULT = 1821

PORT_MIN = 1024
PORT_MAX = 65535

#: settings.json keys (engine 1) and pow_settings.json key (engine 2).
XRAY_SOCKS_KEY = "proxy_socks_port"
XRAY_HTTP_KEY = "proxy_http_port"
POW_HTTP_KEY = "proxy_http_port"
POW_SOCKS_KEY = "psiphon_socks_port"

#: Internal ports each engine already uses; a user port must not take them.
XRAY_RESERVED = {40443: ("پروکسی فرگمنت Patterniha", "Patterniha fragment proxy")}
POW_RESERVED = {
    1819: ("پورت قدیمی aether", "legacy aether port"),
    1820: ("SOCKS زنجیره WARP", "WARP chain SOCKS"),
    1821: ("SOCKS سایفون", "Psiphon SOCKS"),
    1825: ("روتر سرعت", "speed router"),
    1830: ("MASQUE موازی", "parallel MASQUE"),
    1831: ("MASQUE موازی", "parallel MASQUE"),
}

Translate = Callable[[str, str], str]


def _english(_fa: str, en: str) -> str:
    return en


def coerce_port(value, default: int) -> int:
    """Return ``value`` as an int port, or ``default`` when it is unusable."""
    try:
        port = int(value)
    except (TypeError, ValueError):
        return int(default)
    return port if PORT_MIN <= port <= PORT_MAX else int(default)


def validate_port(port, reserved: dict, tr: Translate = _english) -> list[str]:
    try:
        number = int(port)
    except (TypeError, ValueError):
        return [tr("پورت باید عدد باشد", "The port must be a number")]
    if not PORT_MIN <= number <= PORT_MAX:
        return [tr(f"پورت {number} باید بین {PORT_MIN} و {PORT_MAX} باشد",
                   f"Port {number} must be between {PORT_MIN} and {PORT_MAX}")]
    if number in reserved:
        fa_name, en_name = reserved[number]
        return [tr(f"پورت {number} برای {fa_name} رزرو است",
                   f"Port {number} is reserved for the {en_name}")]
    return []


def validate_xray_ports(socks, http, tr: Translate = _english) -> list[str]:
    errors = validate_port(socks, XRAY_RESERVED, tr) + validate_port(http, XRAY_RESERVED, tr)
    if not errors and int(socks) == int(http):
        errors.append(tr("پورت SOCKS و HTTP موتور ۱ نباید یکی باشند",
                         "Engine 1 SOCKS and HTTP ports must be different"))
    return errors


def validate_pow_port(port, tr: Translate = _english) -> list[str]:
    return validate_port(port, POW_RESERVED, tr)


#: The Psiphon SOCKS field may keep 1821 itself, but not the other internal ports.
POW_SOCKS_RESERVED = {port: name for port, name in POW_RESERVED.items() if port != POW_SOCKS_DEFAULT}


def validate_pow_socks_port(port, tr: Translate = _english) -> list[str]:
    return validate_port(port, POW_SOCKS_RESERVED, tr)


def validate_pow_ports(http, socks, tr: Translate = _english) -> list[str]:
    errors = validate_pow_port(http, tr) + validate_pow_socks_port(socks, tr)
    if not errors and int(http) == int(socks):
        errors.append(tr("پورت HTTP و SOCKS موتور ۲ نباید یکی باشند",
                         "Engine 2 HTTP and SOCKS ports must be different"))
    return errors


def xray_ports_from_settings(settings: dict | None) -> tuple[int, int]:
    """Saved engine-1 pair, or the default pair when unset or invalid."""
    settings = settings or {}
    socks = coerce_port(settings.get(XRAY_SOCKS_KEY, XRAY_SOCKS_DEFAULT), XRAY_SOCKS_DEFAULT)
    http = coerce_port(settings.get(XRAY_HTTP_KEY, XRAY_HTTP_DEFAULT), XRAY_HTTP_DEFAULT)
    if validate_xray_ports(socks, http):
        return XRAY_SOCKS_DEFAULT, XRAY_HTTP_DEFAULT
    return socks, http


def pow_port_from_value(value) -> int:
    port = coerce_port(value, POW_HTTP_DEFAULT)
    return POW_HTTP_DEFAULT if validate_pow_port(port) else port


def pow_socks_from_value(value) -> int:
    port = coerce_port(value, POW_SOCKS_DEFAULT)
    return POW_SOCKS_DEFAULT if validate_pow_socks_port(port) else port


# -- busy checks -------------------------------------------------------------
def _bind_error(port: int) -> OSError | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", int(port)))
    except OSError as exc:
        return exc
    else:
        return None
    finally:
        sock.close()


def listener_pid(port: int) -> int:
    """PID of a process listening on ``port`` (any local address), 0 if none/unknown."""
    try:
        import psutil

        for connection in psutil.net_connections(kind="tcp"):
            if connection.status != psutil.CONN_LISTEN or not connection.laddr:
                continue
            if int(connection.laddr.port) == int(port) and connection.pid:
                return int(connection.pid)
    except Exception:
        pass
    return 0


def process_name(pid: int) -> str:
    try:
        import psutil

        return psutil.Process(int(pid)).name()
    except Exception:
        return "unknown"


def is_app_helper(pid: int) -> bool:
    """True for a helper binary shipped in this app's bin folder (xray, sing-box…)."""
    try:
        import psutil

        from .paths import BIN

        exe = os.path.normcase(os.path.abspath(psutil.Process(int(pid)).exe()))
        return os.path.dirname(exe) == os.path.normcase(os.path.abspath(str(BIN)))
    except Exception:
        return False


def busy_reason(port: int, allow: Callable[[int], bool] | None = None) -> str:
    """Why ``port`` cannot be used, or "" when it is free (or held by us).

    Only certain conflicts are reported: a foreign listener, or a Windows
    excluded port range. An unexplained bind error is left to the engine's own
    start-up checks so a transient state never blocks a connect.
    """
    pid = listener_pid(port)
    ours = bool(pid) and (pid == os.getpid() or bool(allow and allow(pid)))
    if pid and not ours:
        return f"127.0.0.1:{port} is used by {process_name(pid)} (PID {pid})"
    error = _bind_error(port)
    if error is None or ours:
        return ""
    winerror = getattr(error, "winerror", None)
    if winerror == 10013 or error.errno in (13, 10013):
        return f"127.0.0.1:{port} is inside a Windows excluded port range"
    return ""


def busy_reasons(ports: Iterable[int], allow: Callable[[int], bool] | None = None) -> list[str]:
    return [reason for reason in (busy_reason(port, allow) for port in dict.fromkeys(ports)) if reason]
