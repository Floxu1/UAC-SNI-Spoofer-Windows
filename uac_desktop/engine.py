from __future__ import annotations

import ctypes
import json
import os
import platform
import subprocess
import sys
import threading
import time
import uuid
import winreg
from collections.abc import Callable
from contextlib import contextmanager

import psutil
import requests

from . import __version__
from .models import ProxyProfile, Tuning, parse_outbound
from .pattern_core import PatternSniCore
from .paths import BIN, DATA_DIR, XRAY_CONFIG, XRAY_OWNER_FILE



SOCKS_PORT = 20808
HTTP_PORT = 20809
FRAGMENT_PORT = 40443
INTERNET_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
PROXY_STATE_FILE = DATA_DIR / "windows-proxy-restore.json"
USER_AGENT = f"UAC-Spoofer-Desktop/{__version__}"
DOWNLOAD_PROBE_BYTES = 256 * 1024
DOWNLOAD_PROBE_MIN_BYTES = 32 * 1024
DOWNLOAD_PROBE_URL = "https://speed.cloudflare.com/__down"

_PROXY_GUARD = threading.RLock()
_PROXY_GUARD_LOCAL = threading.local()


@contextmanager
def _proxy_state_guard(timeout: float = 5.0):
    """Serialize proxy snapshot/registry transactions across app processes."""
    with _PROXY_GUARD:
        depth = int(getattr(_PROXY_GUARD_LOCAL, "depth", 0))
        if depth:
            _PROXY_GUARD_LOCAL.depth = depth + 1
            try:
                yield
            finally:
                _PROXY_GUARD_LOCAL.depth = depth
            return
        _PROXY_GUARD_LOCAL.depth = 1
        descriptor = None
        locked = False
        try:
            if sys.platform == "win32":
                import msvcrt
                lock_file = PROXY_STATE_FILE.with_suffix(".lock")
                lock_file.parent.mkdir(parents=True, exist_ok=True)
                descriptor = os.open(str(lock_file), os.O_RDWR | os.O_CREAT)
                if os.fstat(descriptor).st_size < 1:
                    os.write(descriptor, b"\0")
                deadline = time.monotonic() + max(0.2, timeout)
                while True:
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    try:
                        msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
                        locked = True
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise TimeoutError("Timed out waiting for Windows proxy state lock")
                        time.sleep(0.04)
            yield
        finally:
            if descriptor is not None:
                try:
                    if locked:
                        import msvcrt
                        os.lseek(descriptor, 0, os.SEEK_SET)
                        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
                finally:
                    os.close(descriptor)
            _PROXY_GUARD_LOCAL.depth = 0


class EngineCancelled(RuntimeError):
    """Internal control-flow exception for a cancelled connect generation."""


def mci_quality_score(page_start_ms: float, download_mbps: float | None = None,
                      first_byte_ms: float | None = None) -> int:
    """Score one MCI route using page start and a short real download sample.

    A missing Cloudflare sample is deliberately neutral: the optional endpoint
    is useful ranking telemetry, not a reason to reject a page-verified route.
    """
    page_ms = max(0.0, float(page_start_ms or 0.0))
    page_score = max(0.0, min(100.0, 100.0 - min(page_ms, 12000.0) / 120.0))
    if download_mbps is None or float(download_mbps) <= 0:
        throughput_score = 50.0
    else:
        throughput_score = max(0.0, min(100.0, float(download_mbps) * 10.0))
    if first_byte_ms is None or float(first_byte_ms) < 0:
        video_start_score = 50.0
    else:
        first_byte_ms = max(0.0, float(first_byte_ms))
        video_start_score = max(
            0.0, min(100.0, 100.0 - min(first_byte_ms, 6000.0) / 60.0)
        )
    return max(1, min(100, round(
        page_score * 0.40 + video_start_score * 0.25 + throughput_score * 0.35
    )))


class _CountingPayload:
    """File-like request body that records how many bytes Requests consumed."""

    def __init__(self, size: int) -> None:
        self._data = b"U" * size
        self._position = 0

    def __len__(self) -> int:
        return len(self._data)

    def tell(self) -> int:
        return self._position

    def read(self, amount: int = -1) -> bytes:
        if amount is None or amount < 0:
            amount = len(self._data) - self._position
        start = self._position
        self._position = min(len(self._data), start + amount)
        return self._data[start:self._position]


class WindowsProxy:
    """Transactional owner-scoped WinINET proxy override.

    The restore file is written before the first registry mutation and is kept
    until every original value has been restored.  A detached watchdog owns
    the same token and can therefore restore after a forced parent exit without
    touching a newer app instance's proxy snapshot.
    """

    _NAMES = ("ProxyEnable", "ProxyServer", "ProxyOverride")
    _STATE_VERSION = 2

    def __init__(self, log: Callable[[str], None]) -> None:
        self.log = log
        self._previous: dict[str, object] = {}
        self._state_token = ""

    @staticmethod
    def _read(name: str, default=None):
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS) as key:
                return winreg.QueryValueEx(key, name)[0]
        except OSError:
            return default

    @staticmethod
    def _read_entry(name: str) -> dict[str, object]:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS) as key:
            try:
                value, value_type = winreg.QueryValueEx(key, name)
            except FileNotFoundError:
                return {"exists": False}
        return {"exists": True, "value": value, "type": int(value_type)}

    @staticmethod
    def process_identity(token: str = "") -> dict[str, object]:
        pid = os.getpid()
        try:
            created = float(psutil.Process(pid).create_time())
        except (psutil.Error, OSError) as exc:
            
            
            
            raise RuntimeError("Could not determine proxy owner process identity") from exc
        owner: dict[str, object] = {"pid": pid, "create_time": created}
        if token:
            owner["token"] = token
        return owner

    @classmethod
    def _normalize_state(cls, raw: object) -> dict[str, object]:
        """Accept v2 state and legacy flat JSON written by versions <= 1.4."""
        try:
            version = int(raw.get("version", 0) or 0) if isinstance(raw, dict) else 0
        except (TypeError, ValueError):
            version = 0
        if isinstance(raw, dict) and version >= 2:
            raw_values = raw.get("values", {})
            values: dict[str, dict[str, object]] = {}
            if isinstance(raw_values, dict):
                for name in cls._NAMES:
                    entry = raw_values.get(name)
                    if not isinstance(entry, dict):
                        continue
                    if not bool(entry.get("exists", False)):
                        values[name] = {"exists": False}
                        continue
                    default_type = winreg.REG_DWORD if name == "ProxyEnable" else winreg.REG_SZ
                    try:
                        value_type = int(entry.get("type", default_type))
                    except (TypeError, ValueError):
                        value_type = default_type
                    values[name] = {"exists": True, "value": entry.get("value"),
                                    "type": value_type}
            if "ProxyEnable" not in values:
                values["ProxyEnable"] = {
                    "exists": True, "value": 0, "type": winreg.REG_DWORD,
                }
            owner = raw.get("owner", {})
            return {
                "version": cls._STATE_VERSION,
                "owner": dict(owner) if isinstance(owner, dict) else {},
                "values": values,
            }

        
        
        values = {}
        if isinstance(raw, dict):
            for name in cls._NAMES:
                if name not in raw:
                    continue
                value = raw.get(name)
                if value is None:
                    values[name] = {"exists": False}
                else:
                    values[name] = {
                        "exists": True,
                        "value": value,
                        "type": winreg.REG_DWORD if name == "ProxyEnable" else winreg.REG_SZ,
                    }
        if "ProxyEnable" not in values:
            
            
            values["ProxyEnable"] = {
                "exists": True, "value": 0, "type": winreg.REG_DWORD,
            }
        return {"version": 1, "owner": {}, "values": values}

    @classmethod
    def _load_state(cls) -> dict[str, object] | None:
        if not PROXY_STATE_FILE.exists():
            return None
        try:
            raw = json.loads(PROXY_STATE_FILE.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            state = cls._normalize_state({})
            state["_corrupt"] = True
            return state
        return cls._normalize_state(raw)

    @staticmethod
    def _write_state(state: dict[str, object]) -> None:
        PROXY_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        temp = PROXY_STATE_FILE.with_suffix(".json.tmp")
        temp.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")
        temp.replace(PROXY_STATE_FILE)

    @staticmethod
    def _owner_matches(owner: object, pid: int, create_time: float,
                       token: str | None = None) -> bool:
        if not isinstance(owner, dict):
            return False
        try:
            same_process = (int(owner.get("pid", -1)) == int(pid)
                            and abs(float(owner.get("create_time", -1))
                                    - float(create_time)) < 0.01)
        except (TypeError, ValueError):
            return False
        return same_process and (token is None or str(owner.get("token", "")) == token)

    @classmethod
    def _owner_is_alive(cls, owner: object) -> bool:
        if not isinstance(owner, dict):
            return False
        try:
            process = psutil.Process(int(owner.get("pid", -1)))
            return (process.is_running()
                    and abs(process.create_time()
                            - float(owner.get("create_time", -1))) < 0.01)
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            return False
        except (psutil.AccessDenied, OSError):
            
            
            return True
        except (TypeError, ValueError):
            return False

    @staticmethod
    def _other_app_instance_alive() -> bool:
        """Protect ownerless legacy snapshots from a still-running old GUI."""
        current_pid = os.getpid()
        source_entrypoint = os.path.normcase(os.path.abspath(
            os.path.join(os.path.dirname(__file__), os.pardir, "main.py")))
        frozen_name = os.path.basename(sys.executable).lower() if getattr(sys, "frozen", False) else ""
        for process in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                info = process.info
                if int(info.get("pid", -1)) == current_pid:
                    continue
                command = [str(value) for value in (info.get("cmdline") or [])]
                if "--proxy-watchdog" in command:
                    continue
                name = str(info.get("name") or "").lower()
                if frozen_name and name == frozen_name:
                    return True
                for argument in command[1:]:
                    try:
                        if os.path.normcase(os.path.abspath(argument)) == source_entrypoint:
                            return True
                    except (OSError, TypeError, ValueError):
                        continue
            except (psutil.Error, OSError, TypeError, ValueError):
                continue
        return False

    @staticmethod
    def _launch_watchdog(owner: dict[str, object]) -> None:
        args = ["--proxy-watchdog", str(owner["pid"]),
                repr(float(owner["create_time"])), str(owner["token"])]
        if getattr(sys, "frozen", False):
            command = [sys.executable, *args]
        else:
            entrypoint = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, "main.py"))
            command = [sys.executable, entrypoint, *args]
        kwargs: dict[str, object] = {
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
            "close_fds": True,
        }
        if getattr(sys, "frozen", False):
            
            
            
            
            environment = os.environ.copy()
            environment["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
            kwargs["env"] = environment
        if sys.platform == "win32":
            kwargs["creationflags"] = (
                getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
                | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
                | 0x00000008  
            )
        else:
            kwargs["start_new_session"] = True
        subprocess.Popen(command, **kwargs)

    def enable(self, bypass: str = "<local>;localhost;127.*") -> None:
        with _proxy_state_guard():
            self._enable_locked(bypass)

    def _enable_locked(self, bypass: str) -> None:
        existing = self._load_state()
        if existing is not None:
            owner = existing.get("owner", {})
            if owner and self._owner_is_alive(owner):
                raise RuntimeError("Windows proxy snapshot is owned by a running app instance")
            if not self.recover_stale(self.log):
                raise RuntimeError("Could not recover the previous Windows proxy snapshot")

        token = uuid.uuid4().hex
        owner = self.process_identity(token)
        state: dict[str, object] = {
            "version": self._STATE_VERSION,
            "owner": owner,
            "values": {name: self._read_entry(name) for name in self._NAMES},
        }
        self._write_state(state)
        self._previous = state
        self._state_token = token
        try:
            
            
            self._launch_watchdog(owner)
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS, 0, winreg.KEY_SET_VALUE) as key:
                
                
                
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ,
                                  f"http=127.0.0.1:{HTTP_PORT};https=127.0.0.1:{HTTP_PORT};socks=127.0.0.1:{SOCKS_PORT}")
                winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, bypass)
                
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
            self._refresh()
        except BaseException:
            try:
                self.disable()
            except Exception as rollback_error:
                self.log(f"Windows proxy rollback pending: {rollback_error}")
            raise
        self.log(f"Windows system proxy enabled HTTP={HTTP_PORT} SOCKS={SOCKS_PORT}")

    @property
    def has_pending_restore(self) -> bool:
        return bool(self._previous) or PROXY_STATE_FILE.exists()

    def disable(self) -> bool:
        with _proxy_state_guard():
            return self._disable_locked()

    def _disable_locked(self) -> bool:
        disk_state = self._load_state()
        disk_corrupt = bool(disk_state and disk_state.get("_corrupt"))
        memory_is_exact = bool(self._previous and not self._previous.get("_corrupt"))
        ownership_state = None if disk_corrupt and memory_is_exact else disk_state
        if ownership_state is not None and self._state_token:
            disk_owner = ownership_state.get("owner", {})
            if str(disk_owner.get("token", "")) != self._state_token:
                self.log("Windows proxy restore skipped: snapshot ownership changed")
                return False
        elif ownership_state is not None:
            disk_owner = ownership_state.get("owner", {})
            if disk_owner:
                current = self.process_identity()
                if not self._owner_matches(disk_owner, int(current["pid"]),
                                           float(current["create_time"])):
                    self.log("Windows proxy restore skipped: snapshot belongs to another process")
                    return False
        state = (self._previous if disk_corrupt and memory_is_exact
                 else disk_state or (self._previous if self._previous else None))
        if state is None:
            return False
        values = state.get("values", {})
        if not isinstance(values, dict):
            values = {}
        
        
        
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
            for name in ("ProxyServer", "ProxyOverride"):
                entry = values.get(name)
                if not isinstance(entry, dict):
                    continue
                if bool(entry.get("exists", False)):
                    default_type = winreg.REG_DWORD if name == "ProxyEnable" else winreg.REG_SZ
                    value_type = int(entry.get("type", default_type))
                    winreg.SetValueEx(key, name, 0, value_type, entry.get("value"))
                else:
                    try:
                        winreg.DeleteValue(key, name)
                    except FileNotFoundError:
                        pass
            entry = values.get("ProxyEnable")
            if isinstance(entry, dict) and bool(entry.get("exists", False)):
                winreg.SetValueEx(key, "ProxyEnable", 0,
                                  int(entry.get("type", winreg.REG_DWORD)),
                                  entry.get("value"))
            elif isinstance(entry, dict):
                try:
                    winreg.DeleteValue(key, "ProxyEnable")
                except FileNotFoundError:
                    pass
        self._refresh()
        
        latest = self._load_state()
        latest_corrupt = bool(latest and latest.get("_corrupt"))
        state_owner = state.get("owner", {})
        latest_owner = latest.get("owner", {}) if latest else {}
        state_token = str(state_owner.get("token", "")) if isinstance(state_owner, dict) else ""
        latest_token = str(latest_owner.get("token", "")) if isinstance(latest_owner, dict) else ""
        if latest is None or latest_corrupt or not state_token or latest_token == state_token:
            PROXY_STATE_FILE.unlink(missing_ok=True)
        self._previous = {}
        self._state_token = ""
        self.log("Windows system proxy restored")
        return True

    @classmethod
    def recover_stale(cls, log: Callable[[str], None] | None = None, *,
                      expected_pid: int | None = None,
                      expected_create_time: float | None = None,
                      expected_token: str | None = None) -> bool:
        """Restore the user's proxy snapshot after a crash or forced exit."""
        state = cls._load_state()
        if state is None:
            return False
        owner = state.get("owner", {})
        strict_owner = (expected_pid is not None or expected_create_time is not None
                        or expected_token is not None)
        if strict_owner:
            if expected_pid is None or expected_create_time is None:
                return False
            if not cls._owner_matches(owner, expected_pid, expected_create_time, expected_token):
                return False
        elif owner and cls._owner_is_alive(owner):
            
            return False
        elif not owner and cls._other_app_instance_alive():
            
            
            return False
        helper = cls(log or (lambda _: None))
        helper._previous = state
        helper._state_token = str(owner.get("token", "")) if isinstance(owner, dict) else ""
        return bool(helper.disable())

    @classmethod
    def run_watchdog(cls, parent_pid: int, parent_create_time: float, token: str,
                     poll_interval: float = 0.25) -> int:
        """Wait outside the GUI process and restore only the matching snapshot."""
        expected_owner = {
            "pid": int(parent_pid), "create_time": float(parent_create_time), "token": token,
        }
        while cls._owner_is_alive(expected_owner):
            state = cls._load_state()
            if state is None:
                return 0
            if not cls._owner_matches(state.get("owner", {}), parent_pid,
                                      parent_create_time, token):
                return 0
            time.sleep(max(0.02, float(poll_interval)))
        delay = max(0.05, float(poll_interval))
        for _attempt in range(20):
            state = cls._load_state()
            if state is None:
                return 0
            if not cls._owner_matches(state.get("owner", {}), parent_pid,
                                      parent_create_time, token):
                return 0
            try:
                if cls.recover_stale(expected_pid=parent_pid,
                                     expected_create_time=parent_create_time,
                                     expected_token=token):
                    return 0
            except Exception:
                pass
            time.sleep(delay)
        
        
        return 1

    @staticmethod
    def _refresh() -> None:
        internet_option_settings_changed = 39
        internet_option_refresh = 37
        try:
            wininet = ctypes.windll.Wininet
            wininet.InternetSetOptionW(0, internet_option_settings_changed, 0, 0)
            wininet.InternetSetOptionW(0, internet_option_refresh, 0, 0)
        except Exception:
            pass


def build_xray_config(profile: ProxyProfile, bypass_processes: list[str] | None = None,
                      tuning: Tuning | None = None) -> dict:
    tuning = tuning or Tuning()
    parsed = parse_outbound(profile)
    inbounds = [
        {"listen": "127.0.0.1", "port": SOCKS_PORT, "protocol": "socks", "tag": "socks-in",
         "settings": {"auth": "noauth", "udp": True}},
        {"listen": "127.0.0.1", "port": HTTP_PORT, "protocol": "http", "tag": "http-in",
         "settings": {"allowTransparent": False}},
    ]
    if parsed["protocol"] == "trojan":
        settings = {"servers": [{"address": parsed["host"], "port": parsed["port"], "password": parsed["user"]}]}
    elif parsed["protocol"] == "vless":
        settings = {"vnext": [{"address": parsed["host"], "port": parsed["port"],
                               "users": [{"id": parsed["user"], "encryption": "none"}]}]}
    else:
        raise ValueError(f"Unsupported protocol: {parsed['protocol']}")
    tls = {"serverName": parsed["sni"]}
    if tuning.carrier_mode == "mci" and parsed["network"] in {"ws", "httpupgrade"}:
        
        
        tls["alpn"] = ["http/1.1"]
    if parsed["fingerprint"]:
        tls["fingerprint"] = parsed["fingerprint"]
    if parsed["pinned"]:
        tls["pinnedPeerCertSha256"] = parsed["pinned"]
    if parsed["verify_name"]:
        tls["verifyPeerCertByName"] = parsed["verify_name"]
    elif parsed["sni"].lower() != parsed["host_header"].lower():
        tls["verifyPeerCertByName"] = f"{parsed['host_header']},{parsed['sni']}"
    stream = {"network": parsed["network"], "security": "tls", "tlsSettings": tls}
    if parsed["network"] == "httpupgrade":
        stream["httpupgradeSettings"] = {"path": parsed["path"], "host": parsed["host_header"]}
    else:
        stream["wsSettings"] = {"path": parsed["path"], "host": parsed["host_header"],
                                "headers": {"Host": parsed["host_header"]}}
    rules = [{"type": "field", "network": "udp", "port": "443", "outboundTag": "block"}]
    
    if bypass_processes:
        rules.insert(0, {"type": "field", "process": bypass_processes, "outboundTag": "direct"})
    requested_log_level = str(tuning.log_level or "normal").strip().lower()
    xray_log_level = {
        "debug": "debug", "verbose": "info", "info": "info",
        "normal": "warning", "minimal": "warning", "warning": "warning",
        "error": "error", "none": "none",
    }.get(requested_log_level, "warning")
    proxy_outbound = {
        "tag": "proxy", "protocol": parsed["protocol"], "settings": settings,
        "streamSettings": stream,
    }
    if bool(tuning.xray_mux_enabled):
        proxy_outbound["mux"] = {
            "enabled": True,
            
            
            "concurrency": max(1, min(32, int(tuning.xray_mux_concurrency))),
        }
    return {
        "log": {"loglevel": xray_log_level},
        "inbounds": inbounds,
        "outbounds": [
            proxy_outbound,
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": {"domainStrategy": "AsIs", "rules": rules},
    }


class Engine:
    def __init__(self, log: Callable[[str], None], state: Callable[[bool], None],
                 traffic: Callable[[int, int], None]) -> None:
        self.log, self.state, self.traffic = log, state, traffic
        self.fragment = PatternSniCore(log, traffic)
        self.system_proxy = WindowsProxy(log)
        self.process: subprocess.Popen | None = None
        self._reader: threading.Thread | None = None
        self._lifecycle_lock = threading.RLock()
        self._run_id = 0
        self._active = False
        self._proxy_enabled = False
        self._log_level = "normal"
        self.last_probe_ms: float | None = None
        self.last_probe_url: str = ""
        self.last_download_ok: bool | None = None
        self.last_download_state: str = "not_tested"
        self.last_download_reason: str = ""
        self.last_download_mbps: float = 0.0
        self.last_download_speed_valid: bool = False
        self.last_download_ms: float | None = None
        self.last_download_first_byte_ms: float | None = None
        self.last_download_bytes: int = 0
        self.last_upload_ok: bool | None = None
        self.last_upload_state: str = "not_tested"
        self.last_upload_reason: str = ""
        self.last_upload_mbps: float = 0.0
        self.last_upload_speed_valid: bool = False
        self.last_upload_ms: float | None = None

    @property
    def running(self) -> bool:
        return self._active and self.process is not None and self.process.poll() is None

    def _binary(self):
        name = "xray.exe" if platform.system() == "Windows" else "xray"
        path = BIN / name
        if not path.exists():
            raise FileNotFoundError(f"Xray binary not found: {path}. Run install-engine.ps1 once.")
        return path

    @staticmethod
    def _check_cancel(cancel_event: threading.Event | None) -> None:
        if cancel_event is not None and cancel_event.is_set():
            raise EngineCancelled("Connection attempt cancelled")

    @staticmethod
    def _normalize_path(value: str) -> str:
        return os.path.normcase(os.path.abspath(value))

    def _write_owner_record(self, process: subprocess.Popen) -> None:
        try:
            created = psutil.Process(process.pid).create_time()
            value = {
                "pid": process.pid,
                "create_time": created,
                "exe": str(self._binary()),
                "config": str(XRAY_CONFIG),
            }
            temp = XRAY_OWNER_FILE.with_suffix(".json.tmp")
            temp.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
            temp.replace(XRAY_OWNER_FILE)
        except (OSError, psutil.Error):
            pass

    @staticmethod
    def _read_owner_record() -> dict:
        try:
            value = json.loads(XRAY_OWNER_FILE.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else {}
        except (OSError, ValueError):
            return {}

    @staticmethod
    def _remove_owner_record(pid: int | None = None) -> None:
        if pid is not None:
            value = Engine._read_owner_record()
            if value and int(value.get("pid", -1)) != int(pid):
                return
        try:
            XRAY_OWNER_FILE.unlink(missing_ok=True)
        except OSError:
            pass

    @staticmethod
    def _listener_owners(ports: set[int]) -> dict[int, int]:
        """Return local TCP listener owners without shelling out to netstat."""
        owners: dict[int, int] = {}
        try:
            for connection in psutil.net_connections(kind="tcp"):
                if connection.status != psutil.CONN_LISTEN or not connection.laddr:
                    continue
                port = int(connection.laddr.port)
                if port in ports and connection.pid:
                    owners[port] = int(connection.pid)
        except (psutil.AccessDenied, psutil.Error):
            pass
        return owners

    def _is_owned_xray(self, pid: int) -> bool:
        """Only identify an Xray process that belongs to this installation."""
        try:
            process = psutil.Process(pid)
            name = process.name().lower()
            executable = self._normalize_path(process.exe())
            expected = self._normalize_path(str(self._binary()))
            command = process.cmdline()
            config_marker = self._normalize_path(str(XRAY_CONFIG))
            config_matches = any(self._normalize_path(arg) == config_marker for arg in command[1:])
            if name != "xray.exe" or not config_matches:
                return False
            owner = self._read_owner_record()
            if owner:
                
                
                
                return (int(owner.get("pid", -1)) == pid
                        and abs(float(owner.get("create_time", -1)) - process.create_time()) < 0.01
                        and self._normalize_path(str(owner.get("exe", ""))) == executable
                        and self._normalize_path(str(owner.get("config", ""))) == config_marker)
            if executable == expected:
                return True
            
            
            
            parent_pid = process.ppid()
            return parent_pid <= 0 or not psutil.pid_exists(parent_pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.Error, OSError, ValueError, TypeError):
            return False

    def reclaim_stale_listeners(self, timeout: float = 3.0) -> list[int]:
        """Terminate orphaned app-owned Xray listeners and reject foreign conflicts.

        A forced GUI exit can leave Xray alive on 20808/20809.  Starting a new
        Xray then fails every profile even though the profiles are healthy.
        """
        ports = {SOCKS_PORT, HTTP_PORT, FRAGMENT_PORT}
        owners = self._listener_owners(ports)
        reclaimed: list[int] = []
        processed: set[int] = set()
        for port, pid in sorted(owners.items()):
            if pid == os.getpid():
                
                continue
            if pid in processed:
                continue
            processed.add(pid)
            if self._is_owned_xray(pid):
                try:
                    process = psutil.Process(pid)
                    self.log(f"RECOVERY stale Xray pid={pid} port={port}")
                    process.terminate()
                    try:
                        process.wait(timeout=1.5)
                    except psutil.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=1.0)
                    reclaimed.append(pid)
                    self._remove_owner_record(pid)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.Error):
                    pass

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            remaining = self._listener_owners(ports)
            remaining = {port: pid for port, pid in remaining.items() if pid != os.getpid()}
            if not remaining:
                if reclaimed:
                    self.log(f"RECOVERY released local ports {SOCKS_PORT}/{HTTP_PORT}")
                return list(dict.fromkeys(reclaimed))
            time.sleep(0.08)

        remaining = self._listener_owners(ports)
        remaining = {port: pid for port, pid in remaining.items() if pid != os.getpid()}
        if remaining:
            details = []
            for port, pid in sorted(remaining.items()):
                try:
                    name = psutil.Process(pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.Error):
                    name = "unknown"
                details.append(f"127.0.0.1:{port} is used by {name} (PID {pid})")
            raise RuntimeError("Local proxy port conflict: " + "; ".join(details))
        return list(dict.fromkeys(reclaimed))

    def start(self, profile: ProxyProfile, tuning: Tuning, bypass_processes: list[str] | None = None,
              notify: bool = True, enable_system_proxy: bool = True,
              strategy_override: str | None = None,
              cancel_event: threading.Event | None = None) -> None:
        with self._lifecycle_lock:
            self._check_cancel(cancel_event)
            self._stop_locked(notify=False)
            self._check_cancel(cancel_event)
            self.reclaim_stale_listeners()
            self._check_cancel(cancel_event)
            self.last_probe_ms = None
            self.last_probe_url = ""
            self.last_download_ok = None
            self.last_download_state = "not_tested"
            self.last_download_reason = ""
            self.last_download_mbps = 0.0
            self.last_download_speed_valid = False
            self.last_download_ms = None
            self.last_download_first_byte_ms = None
            self.last_download_bytes = 0
            self.last_upload_ok = None
            self.last_upload_state = "not_tested"
            self.last_upload_reason = ""
            self.last_upload_mbps = 0.0
            self.last_upload_speed_valid = False
            self.last_upload_ms = None
            if not profile.source_uri:
                raise ValueError("Selected config has no VLESS/Trojan URI")
            self._log_level = tuning.log_level
            self.fragment.start(profile, tuning, strategy_override)
            try:
                self._check_cancel(cancel_event)
                config = build_xray_config(profile, bypass_processes, tuning)
                XRAY_CONFIG.write_text(json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8")
                creation = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
                process = subprocess.Popen([str(self._binary()), "run", "-config", str(XRAY_CONFIG)],
                                           cwd=str(XRAY_CONFIG.parent), stdout=subprocess.PIPE,
                                           stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                                           errors="replace", creationflags=creation)
                self.process = process
                self._run_id += 1
                run_id = self._run_id
                self._write_owner_record(process)
                deadline = time.monotonic() + 0.7
                while time.monotonic() < deadline:
                    self._check_cancel(cancel_event)
                    if process.poll() is not None:
                        break
                    time.sleep(0.05)
                if process.poll() is not None:
                    returncode = process.returncode
                    output = process.stdout.read() if process.stdout else ""
                    raise RuntimeError(f"Xray exited immediately ({returncode}): {output[:1200]}")
                self._check_cancel(cancel_event)
                self._active = True
                self._reader = threading.Thread(target=self._read_logs, args=(process, run_id),
                                                name=f"xray-log-{run_id}", daemon=True)
                self._reader.start()
                if enable_system_proxy:
                    self.enable_system_proxy(cancel_event)
                self.log(f"XRAY started socks=127.0.0.1:{SOCKS_PORT} http=127.0.0.1:{HTTP_PORT}")
                if notify:
                    self.state(True)
            except Exception:
                self._stop_locked(notify=False)
                raise

    def enable_system_proxy(self, cancel_event: threading.Event | None = None) -> None:
        """Expose the verified local proxy only after the real page probe passes."""
        with self._lifecycle_lock:
            self._check_cancel(cancel_event)
            if not self.running:
                raise RuntimeError("Cannot enable Windows proxy before the engine is running")
            if not self._proxy_enabled:
                self.system_proxy.enable()
                self._proxy_enabled = True
            self._check_cancel(cancel_event)

    def probe(self, timeout: float = 10, preferred_url: str | None = None,
              require_preferred: bool = False,
              cancel_event: threading.Event | None = None) -> tuple[bool, str]:
        """Verify usable page traffic through the newly started local proxy."""
        self.last_probe_ms = None
        self.last_probe_url = ""
        proxies = {"http": f"http://127.0.0.1:{HTTP_PORT}",
                   "https": f"http://127.0.0.1:{HTTP_PORT}"}
        urls = ("https://www.gstatic.com/generate_204",
                "https://www.cloudflare.com/cdn-cgi/trace",
                "https://api.ipify.org?format=json")
        def check(url):
            self._check_cancel(cancel_event)
            session = requests.Session()
            session.trust_env = False
            started = time.perf_counter()
            try:
                response = session.get(url, proxies=proxies, timeout=timeout,
                                       headers={"User-Agent": USER_AGENT,
                                                "Connection": "close"})
                elapsed_ms = (time.perf_counter() - started) * 1000
                if 200 <= response.status_code < 500:
                    detail = response.text.strip()[:160] or f"HTTP {response.status_code}"
                    return True, url, response.status_code, detail, elapsed_ms
            except Exception as exc:
                return False, url, 0, type(exc).__name__, (time.perf_counter() - started) * 1000
            finally:
                session.close()
            return False, url, 0, "bad status", (time.perf_counter() - started) * 1000
        if preferred_url:
            preferred_result = check(preferred_url)
            if preferred_result[0]:
                self.last_probe_url = preferred_url
                self.last_probe_ms = preferred_result[4]
                self.log(f"CONNECTIVITY CHECK OK {preferred_url} => {preferred_result[2]}")
                return True, preferred_result[3]
            self.log(f"PREFERRED CHECK RETRY {preferred_url}: {preferred_result[3]}")
            if require_preferred:
                self.last_probe_url = preferred_url
                self.last_probe_ms = preferred_result[4]
                return False, f"{preferred_url}: {preferred_result[3]}"
        errors = []
        
        
        for url in urls:
            self._check_cancel(cancel_event)
            ok, checked_url, status, detail, elapsed_ms = check(url)
            if ok:
                self.last_probe_url = checked_url
                self.last_probe_ms = elapsed_ms
                self.log(f"CONNECTIVITY CHECK OK {checked_url} => {status}")
                return True, detail
            errors.append(f"{checked_url}: {detail}")
        self.log("CONNECTIVITY CHECK FAILED " + " | ".join(errors))
        return False, " | ".join(errors)

    def probe_download(self, size: int = DOWNLOAD_PROBE_BYTES, timeout: float = 2.0,
                       cancel_event: threading.Event | None = None) -> tuple[bool | None, str]:
        """Measure one bounded Cloudflare download through the private proxy.

        The sample is capped at 256 KiB and streamed without retaining its
        contents. Endpoint/status/short-read failures are inconclusive while
        the local engine is alive, so this advisory measurement never vetoes a
        route that already passed :meth:`probe`.
        """
        self.last_download_ok = None
        self.last_download_state = "inconclusive"
        self.last_download_reason = ""
        self.last_download_mbps = 0.0
        self.last_download_speed_valid = False
        self.last_download_ms = None
        self.last_download_first_byte_ms = None
        self.last_download_bytes = 0
        requested = max(DOWNLOAD_PROBE_MIN_BYTES, min(int(size), DOWNLOAD_PROBE_BYTES))
        self._check_cancel(cancel_event)
        if not self.running:
            self.last_download_ok = False
            self.last_download_state = "failed"
            self.last_download_reason = "engine stopped"
            return False, "engine stopped"

        proxies = {"http": f"http://127.0.0.1:{HTTP_PORT}",
                   "https": f"http://127.0.0.1:{HTTP_PORT}"}
        endpoint = f"{DOWNLOAD_PROBE_URL}?bytes={requested}"
        session = requests.Session()
        session.trust_env = False
        response = None
        started = time.perf_counter()
        budget = max(0.5, min(float(timeout), 2.0))
        deadline = started + budget
        downloaded = 0
        try:
            response = session.get(
                endpoint,
                proxies=proxies,
                stream=True,
                
                
                
                timeout=(min(0.8, budget), min(0.55, budget)),
                allow_redirects=False,
                headers={"Accept-Encoding": "identity",
                         "Cache-Control": "no-cache",
                         "Connection": "close",
                         "Range": f"bytes=0-{requested - 1}",
                         "User-Agent": USER_AGENT},
            )
            self._check_cancel(cancel_event)
            if response.status_code not in {200, 206}:
                elapsed = max(0.001, time.perf_counter() - started)
                self.last_download_ms = elapsed * 1000
                detail = f"HTTP {response.status_code}"
                self.last_download_reason = detail
                self.log(f"DOWNLOAD CHECK INCONCLUSIVE {detail}")
                return None, detail

            first_byte_at: float | None = None
            for chunk in response.iter_content(chunk_size=32 * 1024):
                self._check_cancel(cancel_event)
                if not chunk:
                    continue
                now = time.perf_counter()
                if first_byte_at is None:
                    first_byte_at = now
                    self.last_download_first_byte_ms = (now - started) * 1000
                downloaded += min(len(chunk), requested - downloaded)
                self.last_download_bytes = downloaded
                if downloaded >= requested or time.perf_counter() >= deadline:
                    break

            elapsed = max(0.001, time.perf_counter() - started)
            self.last_download_ms = elapsed * 1000
            self.last_download_mbps = downloaded * 8 / elapsed / 1_000_000
            if downloaded >= DOWNLOAD_PROBE_MIN_BYTES:
                self.last_download_ok = True
                self.last_download_state = "verified"
                self.last_download_speed_valid = True
                detail = (f"HTTP {response.status_code}, {downloaded}B, "
                          f"{self.last_download_mbps:.2f} Mbps, "
                          f"{self.last_download_ms:.0f} ms, "
                          f"first-byte {float(self.last_download_first_byte_ms or 0):.0f} ms")
                self.last_download_reason = detail
                self.log(f"DOWNLOAD CHECK VERIFIED {detail}")
                return True, detail

            detail = f"short read {downloaded}/{requested}B"
            self.last_download_reason = detail
            self.log(f"DOWNLOAD CHECK INCONCLUSIVE {detail}")
            return None, detail
        except requests.RequestException as exc:
            elapsed = max(0.001, time.perf_counter() - started)
            self.last_download_ms = elapsed * 1000
            if downloaded >= DOWNLOAD_PROBE_MIN_BYTES:
                self.last_download_mbps = downloaded * 8 / elapsed / 1_000_000
                self.last_download_ok = True
                self.last_download_state = "verified"
                self.last_download_speed_valid = True
                detail = (f"partial {downloaded}B before {type(exc).__name__}, "
                          f"{self.last_download_mbps:.2f} Mbps, "
                          f"{self.last_download_ms:.0f} ms")
                self.last_download_reason = detail
                self.log(f"DOWNLOAD CHECK VERIFIED {detail}")
                return True, detail
            detail = type(exc).__name__
            self.last_download_reason = detail
            if not self.running:
                self.last_download_ok = False
                self.last_download_state = "failed"
                self.log(f"DOWNLOAD CHECK FAILED {detail}")
                return False, detail
            self.log(f"DOWNLOAD CHECK INCONCLUSIVE {detail}")
            return None, detail
        finally:
            if response is not None:
                response.close()
            session.close()

    def _read_logs(self, process: subprocess.Popen, run_id: int) -> None:
        if not process or not process.stdout:
            return
        suppressed_client_aborts = 0
        last_suppression_report = time.monotonic()
        for line in process.stdout:
            clean = line.strip()
            if clean:
                if self._log_level == "minimal" and " accepted " in clean:
                    continue
                if self._log_level == "minimal" and self._is_client_abort_noise(clean):
                    suppressed_client_aborts += 1
                    now = time.monotonic()
                    if now - last_suppression_report >= 30:
                        self.log(f"XRAY client-abort noise suppressed {suppressed_client_aborts} lines")
                        suppressed_client_aborts = 0
                        last_suppression_report = now
                    continue
                self.log("XRAY " + clean)
        if suppressed_client_aborts:
            self.log(f"XRAY client-abort noise suppressed {suppressed_client_aborts} lines")
        with self._lifecycle_lock:
            if self.process is not process or self._run_id != run_id:
                return
            if self._active:
                self.log("XRAY process stopped unexpectedly")
                self._stop_locked(notify=True)

    @staticmethod
    def _is_client_abort_noise(line: str) -> bool:
        """Match routine local HTTP cancellations without hiding dial/core errors."""
        lowered = line.lower()
        if "proxy/http:" not in lowered or "failed to dial" in lowered:
            return False
        closed = ("read/write on closed pipe", "broken pipe",
                  "wsasend: an established connection was aborted",
                  "wsasend: an existing connection was forcibly closed")
        return (("failed to write response" in lowered or "failed to read response" in lowered)
                and any(marker in lowered for marker in closed))

    def probe_upload(self, size: int = 64 * 1024, timeout: float = 8,
                     cancel_event: threading.Event | None = None) -> tuple[bool | None, str]:
        """Advisory request-body test with verified/inconclusive/failed states.

        The former speed.cloudflare.com/__up endpoint can time out even on the
        direct connection. It must never veto a config whose real page probe
        already passed. A small body is verified only when an echo endpoint
        returns the exact bytes; merely filling the local socket buffer is not
        treated as proof that the remote endpoint received the upload.
        """
        self.last_upload_ok = None
        self.last_upload_state = "inconclusive"
        self.last_upload_reason = ""
        self.last_upload_mbps = 0.0
        self.last_upload_speed_valid = False
        self.last_upload_ms = None
        
        
        requested = max(4 * 1024, min(int(size), 16 * 1024))
        proxies = {"http": f"http://127.0.0.1:{HTTP_PORT}",
                   "https": f"http://127.0.0.1:{HTTP_PORT}"}
        endpoints = ("https://postman-echo.com/post",)
        attempts: list[str] = []
        for endpoint in endpoints:
            self._check_cancel(cancel_event)
            if not self.running:
                self.last_upload_ok = False
                self.last_upload_state = "failed"
                self.last_upload_reason = "engine stopped"
                return False, "engine stopped"
            payload = _CountingPayload(requested)
            session = requests.Session()
            session.trust_env = False
            started = time.perf_counter()
            try:
                response = session.post(
                    endpoint,
                    data=payload,
                    proxies=proxies,
                    timeout=(min(4.0, timeout), timeout),
                    allow_redirects=False,
                    headers={"Content-Type": "application/octet-stream",
                             "Content-Length": str(requested),
                             "Connection": "close",
                             "User-Agent": USER_AGENT},
                )
                elapsed = max(0.001, time.perf_counter() - started)
                sent = payload.tell()
                echoed = False
                if response.status_code == 200 and sent >= requested:
                    try:
                        echoed_data = response.json().get("data")
                        if isinstance(echoed_data, dict) and echoed_data.get("type") == "Buffer":
                            values = echoed_data.get("data")
                            echoed = (isinstance(values, list) and len(values) == requested
                                      and all(value == 85 for value in values))
                        elif isinstance(echoed_data, str):
                            echoed = echoed_data.encode("latin-1", "ignore") == b"U" * requested
                    except (ValueError, AttributeError, TypeError):
                        echoed = False
                if echoed:
                    self.last_upload_ms = elapsed * 1000
                    
                    
                    self.last_upload_mbps = 0.0
                    self.last_upload_speed_valid = False
                    self.last_upload_ok = True
                    self.last_upload_state = "verified"
                    self.last_upload_reason = f"HTTP {response.status_code}, exact {requested}B echo"
                    detail = f"HTTP {response.status_code}, exact {requested}B echo"
                    self.log(f"UPLOAD CHECK VERIFIED {detail}")
                    return True, detail
                attempts.append(f"HTTP {response.status_code}/{sent}B echo={'yes' if echoed else 'no'}")
            except requests.RequestException as exc:
                elapsed = max(0.001, time.perf_counter() - started)
                sent = payload.tell()
                attempts.append(f"{type(exc).__name__}/{sent}B")
                self.last_upload_ms = elapsed * 1000
            finally:
                session.close()

        detail = " | ".join(attempts) or "no upload response"
        self.last_upload_reason = detail
        self.last_upload_ok = None
        self.last_upload_state = "inconclusive"
        self.log(f"UPLOAD CHECK INCONCLUSIVE {detail}")
        return None, detail

    def warmup(self, url: str = "https://www.youtube.com/generate_204", timeout: float = 5,
               cancel_event: threading.Event | None = None) -> None:
        """Prime one real HTTPS route after connect without a connection burst."""
        if (cancel_event is not None and cancel_event.is_set()) or not self.running:
            return
        run_id = self._run_id
        session = requests.Session()
        session.trust_env = False
        try:
            self._check_cancel(cancel_event)
            started = time.perf_counter()
            response = session.get(url, proxies={"http": f"http://127.0.0.1:{HTTP_PORT}",
                                                  "https": f"http://127.0.0.1:{HTTP_PORT}"},
                                   timeout=timeout, headers={"User-Agent": USER_AGENT,
                                                            "Connection": "close"})
            self._check_cancel(cancel_event)
            if run_id != self._run_id:
                return
            elapsed = (time.perf_counter() - started) * 1000
            self.log(f"WARMUP {response.status_code} {elapsed:.0f}ms {url}")
        except EngineCancelled:
            self.log("WARMUP cancelled")
        except requests.RequestException as exc:
            self.log(f"WARMUP skipped {type(exc).__name__}")
        finally:
            session.close()

    def stop(self, notify: bool = True) -> None:
        with self._lifecycle_lock:
            self._stop_locked(notify)

    def _stop_locked(self, notify: bool = True) -> None:
        was_active = self._active
        self._active = False
        self._run_id += 1
        process = self.process
        self.process = None
        try:
            if process:
                try:
                    if process.poll() is None:
                        process.terminate()
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        try:
                            process.wait(timeout=1)
                        except subprocess.TimeoutExpired:
                            pass
                except (OSError, PermissionError):
                    pass
                self._remove_owner_record(process.pid)
        finally:
            
            
            
            try:
                self.fragment.stop()
            finally:
                if self._proxy_enabled or self.system_proxy.has_pending_restore:
                    try:
                        self.system_proxy.disable()
                    finally:
                        self._proxy_enabled = self.system_proxy.has_pending_restore
        if was_active:
            self.log("VPN stopped")
            if notify:
                self.state(False)


def format_bytes(value: int) -> str:
    if value < 1024:
        return f"{value} B"
    if value < 1024 ** 2:
        return f"{value / 1024:.1f} KB"
    if value < 1024 ** 3:
        return f"{value / 1024 ** 2:.1f} MB"
    return f"{value / 1024 ** 3:.2f} GB"
