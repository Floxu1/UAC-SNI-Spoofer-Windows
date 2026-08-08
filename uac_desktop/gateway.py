from __future__ import annotations

import base64
import concurrent.futures
import ctypes
import inspect
import ipaddress
import json
import os
import platform
import socket
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import asdict, dataclass
from ctypes import wintypes
from pathlib import Path
from typing import Any, Callable

import psutil

from .device_names import decode_dhcp_fqdn, normalize_device_name
from .paths import DATA_DIR


GATEWAY_DIR = DATA_DIR / "gateway"
GATEWAY_STATE_FILE = GATEWAY_DIR / "gateway-state.json"
GATEWAY_STATE_VERSION = 1
GATEWAY_FIREWALL_PREFIX = "UAC Spoofer Mobile Gateway"
DEFAULT_TUN_ALIAS = "UAC-Spoofer"
SOCKS_HOST = "127.0.0.1"
SOCKS_PORT = 20808
GATEWAY_DNS_RESOLVER = "1.1.1.1"
GATEWAY_TCP_MSS = 1360
GATEWAY_DEVICE_TTL = 45.0
GATEWAY_FORWARDER_TIMEOUT = 6.0
GATEWAY_SOCKS_HEALTH_INTERVAL = 10.0


class GatewayError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class LanAdapter:
    index: int
    alias: str
    address: str
    prefix: int
    gateway: str
    mac: str = ""
    description: str = ""


@dataclass(frozen=True, slots=True)
class TunAdapter:
    index: int
    alias: str


def _normalize_mac(value: object) -> str:
    text = str(value or "").strip().replace("-", ":").lower()
    parts = text.split(":")
    if len(parts) != 6 or any(len(part) != 2 for part in parts):
        return ""
    try:
        if any(not 0 <= int(part, 16) <= 255 for part in parts):
            return ""
    except ValueError:
        return ""
    return ":".join(parts)


def _json_object(value: str) -> dict[str, Any]:
    if not value.strip():
        return {}
    parsed = json.loads(value)
    if isinstance(parsed, list):
        return dict(parsed[0]) if parsed and isinstance(parsed[0], dict) else {}
    return dict(parsed) if isinstance(parsed, dict) else {}


def _json_rows(value: str) -> list[dict[str, Any]]:
    if not value.strip():
        return []
    parsed = json.loads(value)
    if isinstance(parsed, dict):
        return [dict(parsed)]
    if isinstance(parsed, list):
        return [dict(item) for item in parsed if isinstance(item, dict)]
    return []


def _encoded_payload(value: dict[str, Any]) -> str:
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def _payload_script(value: dict[str, Any], body: str) -> str:
    encoded = _encoded_payload(value)
    return (
        "$ErrorActionPreference='Stop';"
        f"$raw=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded}'));"
        "$payload=$raw|ConvertFrom-Json;"
        + body
    )


def _process_identity() -> dict[str, Any]:
    process = psutil.Process(os.getpid())
    return {"pid": os.getpid(), "create_time": float(process.create_time())}


def _process_is_alive(pid: int, create_time: float) -> bool:
    try:
        process = psutil.Process(int(pid))
        return process.is_running() and abs(float(process.create_time()) - float(create_time)) < 0.01
    except (psutil.NoSuchProcess, psutil.ZombieProcess, ValueError, TypeError):
        return False
    except (psutil.AccessDenied, OSError):
        return True


def _atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


class PowerShellRunner:
    def run(self, script: str, timeout: float = 30) -> str:
        startup = None
        creationflags = 0
        if sys.platform == "win32":
            startup = subprocess.STARTUPINFO()
            startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            creationflags = subprocess.CREATE_NO_WINDOW
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            startupinfo=startup,
            creationflags=creationflags,
        )
        if result.returncode:
            detail = (result.stderr or result.stdout).strip()
            if not detail:
                detail = f"PowerShell exited with code {result.returncode}"
            raise GatewayError(detail)
        return result.stdout.strip()


class WindowsGatewayBackend:
    def __init__(self, runner: PowerShellRunner | None = None) -> None:
        self.runner = runner or PowerShellRunner()

    def detect_lan(self, excluded_aliases: set[str] | None = None) -> LanAdapter:
        excluded = sorted(str(item) for item in (excluded_aliases or set()) if str(item))
        script = _payload_script(
            {"excluded": excluded},
            """
$rows=@(Get-NetIPConfiguration -ErrorAction SilentlyContinue|ForEach-Object{
  $config=$_
  $adapter=$config.NetAdapter
  $address=@($config.IPv4Address|Where-Object{$_.IPAddress -and $_.IPAddress -notlike '169.254.*'})|Select-Object -First 1
  $gateway=@($config.IPv4DefaultGateway|Where-Object{$_.NextHop})|Select-Object -First 1
  if($adapter -and $adapter.Status -eq 'Up' -and $address -and $gateway){
    $metric=(Get-NetIPInterface -InterfaceIndex $config.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).InterfaceMetric
    [pscustomobject]@{
      index=[int]$config.InterfaceIndex
      alias=[string]$config.InterfaceAlias
      address=[string]$address.IPAddress
      prefix=[int]$address.PrefixLength
      gateway=[string]$gateway.NextHop
      mac=[string]$adapter.MacAddress
      description=[string]$adapter.InterfaceDescription
      hardware=[bool]$adapter.HardwareInterface
      metric=if($null -eq $metric){9999}else{[int]$metric}
    }
  }
})
$blocked=@($payload.excluded)
$selected=$rows|Where-Object{
  $_.alias -notin $blocked -and
  $_.description -notmatch 'Virtual|Hyper-V|VMware|VirtualBox|Loopback|Wi-Fi Direct|TAP|TUN|Wintun|VPN'
}|Sort-Object @{Expression={if($_.hardware){0}else{1}}},metric|Select-Object -First 1
if(-not $selected){throw 'No active physical LAN adapter with an IPv4 gateway was found.'}
$selected|ConvertTo-Json -Compress
""",
        )
        row = _json_object(self.runner.run(script))
        try:
            return LanAdapter(
                index=int(row["index"]),
                alias=str(row["alias"]),
                address=str(ipaddress.IPv4Address(str(row["address"]))),
                prefix=int(row["prefix"]),
                gateway=str(ipaddress.IPv4Address(str(row["gateway"]))),
                mac=_normalize_mac(row.get("mac", "")),
                description=str(row.get("description", "")),
            )
        except (KeyError, TypeError, ValueError, ipaddress.AddressValueError) as exc:
            raise GatewayError("Detected LAN adapter data is invalid") from exc

    def wait_for_tun(
        self,
        alias: str,
        timeout: float = 15,
        expected_address: str = "172.19.0.1",
    ) -> TunAdapter:
        deadline = time.monotonic() + max(0.1, float(timeout))
        payload = {
            "alias": str(alias),
            "address": str(ipaddress.IPv4Address(expected_address)),
        }
        while time.monotonic() < deadline:
            script = _payload_script(
                payload,
                """
$item=Get-NetIPInterface -InterfaceAlias ([string]$payload.alias) -AddressFamily IPv4 -ErrorAction SilentlyContinue|Select-Object -First 1
$address=if($item){Get-NetIPAddress -InterfaceIndex ([int]$item.ifIndex) -AddressFamily IPv4 -IPAddress ([string]$payload.address) -ErrorAction SilentlyContinue|Select-Object -First 1}
if($item -and $address -and $item.ConnectionState -eq 'Connected'){
  [pscustomobject]@{index=[int]$item.ifIndex;alias=[string]$item.InterfaceAlias}|ConvertTo-Json -Compress
}
exit 0
""",
            )
            row = _json_object(self.runner.run(script))
            if row:
                return TunAdapter(index=int(row["index"]), alias=str(row["alias"]))
            time.sleep(0.1)
        raise GatewayError(f"TUN adapter {alias} was not created")

    def neighbors(self, interface_index: int) -> dict[str, str]:
        script = _payload_script(
            {"index": int(interface_index)},
            """
$rows=@(Get-NetNeighbor -InterfaceIndex ([int]$payload.index) -AddressFamily IPv4 -ErrorAction SilentlyContinue|
  Where-Object{$_.State -in @('Reachable','Delay','Probe','Stale','Permanent') -and $_.LinkLayerAddress}|
  Select-Object @{n='address';e={$_.IPAddress}},@{n='mac';e={$_.LinkLayerAddress}})
$rows|ConvertTo-Json -Compress
""",
        )
        result: dict[str, str] = {}
        for row in _json_rows(self.runner.run(script)):
            try:
                address = str(ipaddress.IPv4Address(str(row.get("address", ""))))
            except ipaddress.AddressValueError:
                continue
            mac = _normalize_mac(row.get("mac", ""))
            if mac:
                result[address] = mac
        return result

    def discover_neighbors(self, lan: LanAdapter) -> dict[str, str]:
        if sys.platform != "win32":
            return {}
        prefix = max(23, min(30, int(lan.prefix)))
        network = ipaddress.ip_network(f"{lan.address}/{prefix}", strict=False)
        source = socket.htonl(int(ipaddress.IPv4Address(lan.address)))
        send_arp = ctypes.windll.iphlpapi.SendARP
        send_arp.argtypes = [
            wintypes.ULONG,
            wintypes.ULONG,
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.ULONG),
        ]
        send_arp.restype = wintypes.DWORD

        def resolve(address: ipaddress.IPv4Address) -> tuple[str, str] | None:
            if str(address) in {lan.address, lan.gateway}:
                return None
            buffer = (ctypes.c_ubyte * 8)()
            length = wintypes.ULONG(len(buffer))
            result = send_arp(
                socket.htonl(int(address)),
                source,
                ctypes.byref(buffer),
                ctypes.byref(length),
            )
            if result != 0 or int(length.value) < 6:
                return None
            mac = _normalize_mac(":".join(
                f"{int(value):02x}" for value in buffer[:int(length.value)]
            ))
            return (str(address), mac) if mac else None

        hosts = list(network.hosts())
        values: dict[str, str] = {}
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(96, max(1, len(hosts))),
            thread_name_prefix="gateway-arp",
        ) as executor:
            for item in executor.map(resolve, hosts):
                if item is not None:
                    values[item[0]] = item[1]
        return values

    def snapshot(self, lan: LanAdapter, tun: TunAdapter) -> dict[str, Any]:
        script = _payload_script(
            {"indices": [int(lan.index), int(tun.index)]},
            """
$interfaces=@()
foreach($index in @($payload.indices)){
  $item=Get-NetIPInterface -InterfaceIndex ([int]$index) -AddressFamily IPv4 -ErrorAction Stop|Select-Object -First 1
  $interfaces+=[pscustomobject]@{
    index=[int]$item.ifIndex
    alias=[string]$item.InterfaceAlias
    forwarding=[string]$item.Forwarding
    weak_send=[string]$item.WeakHostSend
    weak_receive=[string]$item.WeakHostReceive
  }
}
$key='HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters'
$property=Get-ItemProperty -LiteralPath $key -ErrorAction Stop
$exists=$property.PSObject.Properties.Name -contains 'IPEnableRouter'
$router=if($exists){[int]$property.IPEnableRouter}else{0}
[pscustomobject]@{
  interfaces=$interfaces
  ip_router=[pscustomobject]@{exists=[bool]$exists;value=[int]$router}
}|ConvertTo-Json -Depth 5 -Compress
""",
        )
        value = _json_object(self.runner.run(script))
        interfaces = value.get("interfaces", [])
        if isinstance(interfaces, dict):
            interfaces = [interfaces]
        if not isinstance(interfaces, list) or len(interfaces) < 2:
            raise GatewayError("Windows forwarding state snapshot is incomplete")
        return {
            "interfaces": [dict(item) for item in interfaces if isinstance(item, dict)],
            "ip_router": dict(value.get("ip_router", {})),
        }

    def apply(self, state: dict[str, Any]) -> None:
        script = _payload_script(
            state,
            """
$required=@()
$warnings=@()
$key='HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters'
try{
  Set-ItemProperty -LiteralPath $key -Name IPEnableRouter -Type DWord -Value 1 -ErrorAction Stop
}catch{
  $warnings+=('IPEnableRouter: '+$_.Exception.Message)
}
$netsh=Join-Path $env:SystemRoot 'System32\\netsh.exe'
foreach($index in @([int]$payload.lan.index,[int]$payload.tun.index)){
  $forwarding=$false
  try{
    Set-NetIPInterface -InterfaceIndex $index -AddressFamily IPv4 -Forwarding Enabled -ErrorAction Stop
    $forwarding=$true
  }catch{
    try{
      & $netsh interface ipv4 set interface $index forwarding=enabled|Out-Null
      if($LASTEXITCODE -eq 0){$forwarding=$true}
    }catch{}
  }
  if(-not $forwarding){
    $required+=("IPv4 forwarding failed on interface $index")
  }
  try{
    Set-NetIPInterface -InterfaceIndex $index -AddressFamily IPv4 -WeakHostSend Enabled -ErrorAction Stop
  }catch{
    & $netsh interface ipv4 set interface $index weakhostsend=enabled|Out-Null
    if($LASTEXITCODE -ne 0){$warnings+=("WeakHostSend failed on interface $index")}
  }
  try{
    Set-NetIPInterface -InterfaceIndex $index -AddressFamily IPv4 -WeakHostReceive Enabled -ErrorAction Stop
  }catch{
    & $netsh interface ipv4 set interface $index weakhostreceive=enabled|Out-Null
    if($LASTEXITCODE -ne 0){$warnings+=("WeakHostReceive failed on interface $index")}
  }
}
try{
  Get-NetFirewallRule -DisplayName ([string]$payload.firewall_rule) -ErrorAction SilentlyContinue|Remove-NetFirewallRule -ErrorAction SilentlyContinue
  New-NetFirewallRule -DisplayName ([string]$payload.firewall_rule) -Direction Inbound -Action Allow -Profile Any -InterfaceAlias ([string]$payload.lan.alias) -RemoteAddress LocalSubnet -ErrorAction Stop|Out-Null
}catch{
  try{
    & $netsh advfirewall firewall delete rule "name=$([string]$payload.firewall_rule)"|Out-Null
    & $netsh advfirewall firewall add rule "name=$([string]$payload.firewall_rule)" dir=in action=allow profile=any remoteip=localsubnet|Out-Null
    if($LASTEXITCODE -ne 0){$warnings+=('Firewall: '+$_.Exception.Message)}
  }catch{
    $warnings+=('Firewall: '+$_.Exception.Message)
  }
}
if($required.Count -gt 0){throw ($required -join '; ')}
[pscustomobject]@{warnings=$warnings}|ConvertTo-Json -Compress
""",
        )
        self.runner.run(script)

    def restore(self, state: dict[str, Any]) -> None:
        script = _payload_script(
            state,
            """
Get-NetFirewallRule -DisplayName ([string]$payload.firewall_rule) -ErrorAction SilentlyContinue|Remove-NetFirewallRule -ErrorAction SilentlyContinue
$netsh=Join-Path $env:SystemRoot 'System32\\netsh.exe'
foreach($item in @($payload.windows.interfaces)){
  if($item -and $item.index){
    try{
      Set-NetIPInterface -InterfaceIndex ([int]$item.index) -AddressFamily IPv4 -Forwarding ([string]$item.forwarding) -ErrorAction Stop
    }catch{
      $mode=if(([string]$item.forwarding) -eq 'Enabled'){'enabled'}else{'disabled'}
      & $netsh interface ipv4 set interface ([int]$item.index) "forwarding=$mode"|Out-Null
    }
    try{
      Set-NetIPInterface -InterfaceIndex ([int]$item.index) -AddressFamily IPv4 -WeakHostSend ([string]$item.weak_send) -ErrorAction Stop
    }catch{
      $mode=if(([string]$item.weak_send) -eq 'Enabled'){'enabled'}else{'disabled'}
      & $netsh interface ipv4 set interface ([int]$item.index) "weakhostsend=$mode"|Out-Null
    }
    try{
      Set-NetIPInterface -InterfaceIndex ([int]$item.index) -AddressFamily IPv4 -WeakHostReceive ([string]$item.weak_receive) -ErrorAction Stop
    }catch{
      $mode=if(([string]$item.weak_receive) -eq 'Enabled'){'enabled'}else{'disabled'}
      & $netsh interface ipv4 set interface ([int]$item.index) "weakhostreceive=$mode"|Out-Null
    }
  }
}
$key='HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters'
if([bool]$payload.windows.ip_router.exists){
  Set-ItemProperty -LiteralPath $key -Name IPEnableRouter -Type DWord -Value ([int]$payload.windows.ip_router.value) -ErrorAction SilentlyContinue
}else{
  Remove-ItemProperty -LiteralPath $key -Name IPEnableRouter -ErrorAction SilentlyContinue
}
""",
        )
        self.runner.run(script)


class ScapyArpBackend:
    def __init__(self) -> None:
        self._api: dict[str, Any] | None = None
        self._responder: Any | None = None
        self._responder_lock = threading.RLock()

    def _load(self) -> dict[str, Any]:
        if self._api is None:
            from .npcap import npcap_available

            if not npcap_available():
                raise GatewayError(
                    "Npcap is required for Mobile Gateway; restart UAC Spoofer "
                    "and complete the automatic Npcap setup"
                )
            try:
                from scapy.arch.windows import get_windows_if_list
                from scapy.config import conf
                from scapy.layers.dhcp import BOOTP, DHCP
                from scapy.layers.inet import IP
                from scapy.layers.l2 import ARP, Ether
                from scapy.sendrecv import AsyncSniffer, sendp, srp
            except (ImportError, OSError) as exc:
                raise GatewayError("Npcap and Scapy are required for automatic LAN gateway mode") from exc
            conf.verb = 0
            self._api = {
                "interfaces": get_windows_if_list,
                "ARP": ARP,
                "BOOTP": BOOTP,
                "DHCP": DHCP,
                "Ether": Ether,
                "IP": IP,
                "AsyncSniffer": AsyncSniffer,
                "sendp": sendp,
                "srp": srp,
            }
        return self._api

    def interface_for(self, local_address: str) -> dict[str, str]:
        api = self._load()
        for item in api["interfaces"]():
            if local_address in item.get("ips", []):
                name = str(item.get("name") or item.get("network_name") or "")
                mac = _normalize_mac(item.get("mac", ""))
                if name and mac:
                    return {"name": name, "mac": mac}
        raise GatewayError(f"Npcap interface for {local_address} was not found")

    def resolve(
        self,
        address: str,
        interface_name: str,
        source_address: str = "",
        source_mac: str = "",
    ) -> str:
        api = self._load()
        mac = _normalize_mac(source_mac)
        ethernet = api["Ether"](dst="ff:ff:ff:ff:ff:ff", **(
            {"src": mac} if mac else {}
        ))
        arp_values: dict[str, Any] = {"op": 1, "pdst": address}
        if source_address:
            arp_values["psrc"] = str(ipaddress.IPv4Address(source_address))
        if mac:
            arp_values["hwsrc"] = mac
        packet = ethernet / api["ARP"](**arp_values)
        answers, _ = api["srp"](
            packet,
            iface=interface_name,
            timeout=1.2,
            retry=1,
            verbose=False,
        )
        for _, response in answers:
            mac = _normalize_mac(getattr(response, "hwsrc", ""))
            if mac:
                return mac
        raise GatewayError(f"MAC address for {address} was not resolved")

    def discover(
        self,
        lan: LanAdapter,
        interface_name: str,
        source_mac: str = "",
    ) -> dict[str, str]:
        api = self._load()
        prefix = max(22, min(30, int(lan.prefix)))
        network = ipaddress.ip_network(f"{lan.address}/{prefix}", strict=False)
        mac = _normalize_mac(source_mac) or _normalize_mac(lan.mac)
        ethernet = api["Ether"](dst="ff:ff:ff:ff:ff:ff", **(
            {"src": mac} if mac else {}
        ))
        arp_values: dict[str, Any] = {
            "op": 1,
            "pdst": str(network),
            "psrc": lan.address,
        }
        if mac:
            arp_values["hwsrc"] = mac
        packet = ethernet / api["ARP"](**arp_values)
        answers, _ = api["srp"](
            packet,
            iface=interface_name,
            timeout=1.2,
            retry=1,
            verbose=False,
        )
        result: dict[str, str] = {}
        for _, response in answers:
            try:
                address = str(ipaddress.IPv4Address(str(getattr(response, "psrc", ""))))
            except ipaddress.AddressValueError:
                continue
            mac = _normalize_mac(getattr(response, "hwsrc", ""))
            if mac:
                result[address] = mac
        return result

    @staticmethod
    def _dhcp_identity(
        packet: Any,
        api: dict[str, Any],
    ) -> tuple[str, str, str]:
        dhcp_type = api.get("DHCP")
        if dhcp_type is None:
            return "", "", ""
        try:
            dhcp = packet.getlayer(dhcp_type)
        except (AttributeError, TypeError):
            return "", "", ""
        if dhcp is None:
            return "", "", ""
        name = ""
        requested_address = ""
        for option in getattr(dhcp, "options", ()) or ():
            if not isinstance(option, tuple) or len(option) < 2:
                continue
            key = str(option[0]).strip().casefold().replace("-", "_")
            value = option[1]
            if key in {"hostname", "host_name"}:
                if isinstance(value, bytes):
                    value = value.decode("utf-8", "replace")
                name = normalize_device_name(value)
            elif key in {"client_fqdn", "fqdn"}:
                name = decode_dhcp_fqdn(value) or name
            elif key in {"requested_addr", "requested_address"}:
                if isinstance(value, bytes):
                    try:
                        value = socket.inet_ntoa(value[:4])
                    except OSError:
                        value = ""
                requested_address = str(value or "")
        if not name:
            return "", "", ""
        bootp = None
        bootp_type = api.get("BOOTP")
        if bootp_type is not None:
            try:
                bootp = packet.getlayer(bootp_type)
            except (AttributeError, TypeError):
                bootp = None
        mac = ""
        ether_type = api.get("Ether")
        if ether_type is not None:
            try:
                ether = packet.getlayer(ether_type)
            except (AttributeError, TypeError):
                ether = None
            mac = _normalize_mac(getattr(ether, "src", ""))
        if not mac and bootp is not None:
            chaddr = getattr(bootp, "chaddr", b"")
            if isinstance(chaddr, (bytes, bytearray, memoryview)):
                raw = bytes(chaddr)[:6]
                if len(raw) == 6:
                    mac = ":".join(f"{part:02x}" for part in raw)
            else:
                mac = _normalize_mac(chaddr)
        candidates = []
        if bootp is not None:
            candidates.extend([
                getattr(bootp, "ciaddr", ""),
                getattr(bootp, "yiaddr", ""),
            ])
        candidates.append(requested_address)
        ip_type = api.get("IP")
        if ip_type is not None:
            try:
                ip_layer = packet.getlayer(ip_type)
            except (AttributeError, TypeError):
                ip_layer = None
            candidates.append(getattr(ip_layer, "src", ""))
        address = ""
        for candidate in candidates:
            try:
                parsed = ipaddress.IPv4Address(str(candidate or ""))
            except ipaddress.AddressValueError:
                continue
            if parsed.is_unspecified or parsed.is_multicast or int(parsed) == 0xFFFFFFFF:
                continue
            address = str(parsed)
            break
        return address, mac, name

    def start_responder(
        self,
        state: dict[str, Any],
        device_seen: Callable[[str, str], Any] | None = None,
        device_named: Callable[[str, str, str], Any] | None = None,
    ) -> None:
        self.stop_responder()
        api = self._load()
        lan = dict(state["lan"])
        capture = dict(state["capture"])
        gateway = str(ipaddress.IPv4Address(str(lan["gateway"])))
        local_address = str(ipaddress.IPv4Address(str(lan["address"])))
        network = ipaddress.ip_network(
            f"{local_address}/{int(lan['prefix'])}",
            strict=False,
        )
        pc_mac = _normalize_mac(capture.get("mac", ""))
        if not pc_mac:
            raise GatewayError("LAN capture MAC is missing")
        dhcp_names: dict[str, str] = {}

        def answer(packet: Any) -> None:
            try:
                dhcp_address, dhcp_mac, dhcp_name = self._dhcp_identity(
                    packet,
                    api,
                )
                if dhcp_name and dhcp_mac:
                    dhcp_names[dhcp_mac] = dhcp_name
                    if dhcp_address:
                        if callable(device_seen):
                            device_seen(dhcp_address, dhcp_mac)
                        if callable(device_named):
                            device_named(dhcp_address, dhcp_mac, dhcp_name)
                arp = packet.getlayer(api["ARP"])
                if arp is None:
                    return
                source = ipaddress.IPv4Address(str(arp.psrc))
                if source not in network or str(source) in {local_address, gateway}:
                    return
                source_mac = _normalize_mac(arp.hwsrc)
                if not source_mac or source_mac == pc_mac:
                    return
                if callable(device_seen):
                    device_seen(str(source), source_mac)
                known_name = dhcp_names.get(source_mac, "")
                if known_name and callable(device_named):
                    device_named(str(source), source_mac, known_name)
                if int(arp.op) != 1 or str(arp.pdst) != gateway:
                    return
                response = (
                    api["Ether"](dst=source_mac, src=pc_mac)
                    / api["ARP"](
                        op=2,
                        psrc=gateway,
                        hwsrc=pc_mac,
                        pdst=str(source),
                        hwdst=source_mac,
                    )
                )
                api["sendp"](
                    response,
                    iface=str(capture["name"]),
                    verbose=False,
                )
            except Exception:
                return

        responder = api["AsyncSniffer"](
            iface=str(capture["name"]),
            filter="arp or (udp and (port 67 or port 68))",
            prn=answer,
            store=False,
        )
        responder.start()
        with self._responder_lock:
            self._responder = responder

    def stop_responder(self) -> bool:
        with self._responder_lock:
            responder = self._responder
            self._responder = None
        if responder is None:
            return False
        try:
            responder.stop(join=True)
        except (OSError, RuntimeError, AttributeError):
            pass
        return True

    def redirect(
        self,
        state: dict[str, Any],
        devices: dict[str, str],
        repeat: int = 1,
    ) -> None:
        api = self._load()
        pc_mac = str(state["capture"]["mac"])
        gateway = str(state["lan"]["gateway"])
        if devices:
            packets = [
                api["Ether"](dst=mac, src=pc_mac)
                / api["ARP"](
                    op=2,
                    psrc=gateway,
                    hwsrc=pc_mac,
                    pdst=address,
                    hwdst=mac,
                )
                for address, mac in devices.items()
            ]
        else:
            lan = dict(state["lan"])
            prefix = max(24, min(30, int(lan["prefix"])))
            network = ipaddress.ip_network(
                f"{lan['address']}/{prefix}",
                strict=False,
            )
            blocked = {str(lan["address"]), gateway}
            packets = [
                api["Ether"](dst="ff:ff:ff:ff:ff:ff", src=pc_mac)
                / api["ARP"](
                    op=2,
                    psrc=gateway,
                    hwsrc=pc_mac,
                    pdst=str(address),
                    hwdst="ff:ff:ff:ff:ff:ff",
                )
                for address in network.hosts()
                if str(address) not in blocked
            ]
        if not packets:
            return
        attempts = max(1, min(5, int(repeat)))
        if not devices:
            attempts = min(2, attempts)
        for attempt in range(attempts):
            api["sendp"](
                packets,
                iface=str(state["capture"]["name"]),
                inter=0.01 if devices else 0.001,
                verbose=False,
            )
            if attempt + 1 < attempts:
                time.sleep(0.05)

    def restore(self, state: dict[str, Any]) -> None:
        devices = {
            str(address): str(mac)
            for address, mac in dict(state.get("devices", {})).items()
            if _normalize_mac(mac)
        }
        api = self._load()
        gateway_mac = _normalize_mac(state.get("gateway_mac", ""))
        if not gateway_mac:
            raise GatewayError("The original gateway MAC is missing from the recovery state")
        gateway = str(state["lan"]["gateway"])
        if devices:
            packets = [
                api["Ether"](dst=mac, src=gateway_mac)
                / api["ARP"](
                    op=2,
                    psrc=gateway,
                    hwsrc=gateway_mac,
                    pdst=address,
                    hwdst=mac,
                )
                for address, mac in devices.items()
            ]
        else:
            lan = dict(state["lan"])
            prefix = max(24, min(30, int(lan["prefix"])))
            network = ipaddress.ip_network(
                f"{lan['address']}/{prefix}",
                strict=False,
            )
            blocked = {str(lan["address"]), gateway}
            packets = [
                api["Ether"](dst="ff:ff:ff:ff:ff:ff", src=gateway_mac)
                / api["ARP"](
                    op=2,
                    psrc=gateway,
                    hwsrc=gateway_mac,
                    pdst=str(address),
                    hwdst="ff:ff:ff:ff:ff:ff",
                )
                for address in network.hosts()
                if str(address) not in blocked
            ]
        if not packets:
            return
        for _ in range(5):
            api["sendp"](
                packets,
                iface=str(state["capture"]["name"]),
                inter=0.01 if devices else 0.001,
                verbose=False,
            )
            time.sleep(0.15)


class ForwardPathHelper:
    FILTER = (
        "ip and !impostor and "
        "((udp and (udp.DstPort == 53 or udp.SrcPort == 53)) or "
        "(tcp and (tcp.DstPort == 53 or "
        "tcp.SrcPort == 53 or tcp.Syn)))"
    )

    def __init__(
        self,
        log: Callable[[str], None] | None = None,
        resolver: str = GATEWAY_DNS_RESOLVER,
        tcp_mss: int = GATEWAY_TCP_MSS,
        block_quic: bool = False,
        rewrite_dns: bool = False,
        mapping_ttl: float = 180,
        divert_factory: Callable[[str], Any] | None = None,
    ) -> None:
        self.log = log or (lambda _message: None)
        self.resolver = str(ipaddress.IPv4Address(resolver))
        self.tcp_mss = max(536, min(1460, int(tcp_mss)))
        self.block_quic = bool(block_quic)
        self.rewrite_dns = bool(rewrite_dns)
        self.mapping_ttl = max(10.0, float(mapping_ttl))
        self.divert_factory = divert_factory
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._ready_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._handle: Any | None = None
        self._startup_error: BaseException | None = None
        self._lan: LanAdapter | None = None
        self._network: ipaddress.IPv4Network | None = None
        self._devices: set[str] = set()
        self._dns_flows: dict[tuple[str, str, int], tuple[str, float]] = {}

    @property
    def running(self) -> bool:
        thread = self._thread
        return bool(thread and thread.is_alive() and self._startup_error is None)

    def configure(
        self,
        lan: LanAdapter,
        devices: dict[str, str] | None = None,
    ) -> None:
        network = ipaddress.ip_network(f"{lan.address}/{lan.prefix}", strict=False)
        with self._lock:
            self._lan = lan
            self._network = network  # type: ignore[assignment]
            self._devices = {
                str(ipaddress.IPv4Address(address))
                for address in dict(devices or {})
                if ipaddress.IPv4Address(address) in network
            }

    def set_devices(self, devices: dict[str, str]) -> None:
        with self._lock:
            network = self._network
            if network is None:
                return
            values: set[str] = set()
            for address in devices:
                try:
                    parsed = ipaddress.IPv4Address(address)
                except ipaddress.AddressValueError:
                    continue
                if parsed in network:
                    values.add(str(parsed))
            self._devices = values

    def _new_handle(self) -> Any:
        packet_filter = "ip and !impostor and tcp and tcp.Syn"
        if self.rewrite_dns:
            packet_filter = f"({packet_filter}) or ({self.FILTER})"
        if self.block_quic:
            packet_filter = (
                f"({packet_filter}) or "
                "(ip and !impostor and udp and udp.DstPort == 443)"
            )
        if self.divert_factory is not None:
            return self.divert_factory(packet_filter)
        try:
            import pydivert
        except (ImportError, OSError) as exc:
            raise GatewayError("WinDivert packet forwarding support is unavailable") from exc
        return pydivert.WinDivert(
            packet_filter,
            layer=pydivert.Layer.NETWORK_FORWARD,
            priority=-900,
        )

    @staticmethod
    def _close_handle(handle: Any) -> None:
        try:
            is_open = getattr(handle, "is_open", True)
            if is_open:
                handle.close()
        except (OSError, RuntimeError):
            pass

    def start(
        self,
        lan: LanAdapter,
        devices: dict[str, str] | None = None,
        timeout: float = GATEWAY_FORWARDER_TIMEOUT,
    ) -> None:
        self.stop()
        with self._lock:
            previous = self._thread
        if previous is not None and previous.is_alive():
            raise GatewayError("Previous Mobile Gateway forwarding filter is still stopping")
        self.configure(lan, devices)
        with self._lock:
            stop_event = threading.Event()
            ready_event = threading.Event()
            self._stop_event = stop_event
            self._ready_event = ready_event
            self._startup_error = None
            self._thread = threading.Thread(
                target=self._run,
                args=(stop_event, ready_event),
                name="mobile-gateway-forward-path",
                daemon=True,
            )
            thread = self._thread
        thread.start()
        if not ready_event.wait(max(0.05, float(timeout))):
            self.stop()
            raise GatewayError("Mobile Gateway forwarding filter startup timed out")
        if self._startup_error is not None:
            error = self._startup_error
            self.stop()
            raise GatewayError(f"Mobile Gateway forwarding filter failed: {error}") from error
        if not self.running:
            self.stop()
            raise GatewayError("Mobile Gateway forwarding filter did not stay active")

    def stop(self) -> bool:
        with self._lock:
            thread = self._thread
            handle = self._handle
            stop_event = self._stop_event
            was_running = bool(thread or handle)
            stop_event.set()
            self._handle = None
        if handle is not None:
            self._close_handle(handle)
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2.0)
        with self._lock:
            if thread is None or not thread.is_alive():
                if self._thread is thread:
                    self._thread = None
                self._dns_flows.clear()
                self._devices.clear()
                self._lan = None
                self._network = None
                self._startup_error = None
        return was_running

    def _run(
        self,
        stop_event: threading.Event,
        ready_event: threading.Event,
    ) -> None:
        handle: Any | None = None
        try:
            handle = self._new_handle()
            assert handle is not None
            handle.open()
            with self._lock:
                if stop_event.is_set():
                    ready_event.set()
                    return
                self._handle = handle
                ready_event.set()
            while not stop_event.is_set():
                try:
                    packet = handle.recv()
                except StopIteration:
                    break
                except (OSError, RuntimeError):
                    if stop_event.is_set():
                        break
                    raise
                reinject = True
                try:
                    reinject = self.process_packet(packet)
                except Exception as exc:
                    self.log(f"MOBILE GATEWAY packet retry: {exc}")
                if reinject:
                    handle.send(packet)
        except Exception as exc:
            with self._lock:
                if self._thread is threading.current_thread():
                    self._startup_error = exc
                ready_event.set()
            if not stop_event.is_set():
                self.log(f"MOBILE GATEWAY forwarding filter stopped: {exc}")
        finally:
            with self._lock:
                if self._handle is handle:
                    self._handle = None
                ready_event.set()
            if handle is not None:
                self._close_handle(handle)

    def _is_client(self, address: ipaddress.IPv4Address) -> bool:
        with self._lock:
            lan = self._lan
            network = self._network
        return bool(
            lan is not None
            and network is not None
            and address in network
            and str(address) not in {lan.address, lan.gateway}
            and address not in {network.network_address, network.broadcast_address}
        )

    @staticmethod
    def _is_external(address: ipaddress.IPv4Address) -> bool:
        return not (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
        )

    def _rewrite_private_dns(
        self,
        destination: ipaddress.IPv4Address,
    ) -> bool:
        with self._lock:
            lan = self._lan
            network = self._network
        if not self.rewrite_dns or lan is None or network is None:
            return False
        return str(destination) == lan.gateway or (
            destination.is_private and destination not in network
        )

    def _expire_dns_flows(self, now: float) -> None:
        with self._lock:
            expired = [
                key for key, value in self._dns_flows.items()
                if value[1] <= now
            ]
            for key in expired:
                self._dns_flows.pop(key, None)

    def _remember_dns(
        self,
        protocol: str,
        client: str,
        port: int,
        original: str,
        now: float,
    ) -> None:
        with self._lock:
            self._dns_flows[(protocol, client, port)] = (
                original,
                now + self.mapping_ttl,
            )

    def _original_dns(
        self,
        protocol: str,
        client: str,
        port: int,
        remove: bool,
    ) -> str:
        key = (protocol, client, port)
        with self._lock:
            value = self._dns_flows.get(key)
            if value is None:
                return ""
            if remove:
                self._dns_flows.pop(key, None)
            return value[0]

    def _clamp_tcp_mss(self, tcp: Any) -> bool:
        try:
            raw = tcp.raw
            header_len = int(tcp.header_len)
        except (AttributeError, TypeError, ValueError):
            return False
        limit = min(header_len, len(raw))
        offset = 20
        while offset < limit:
            kind = int(raw[offset])
            if kind == 0:
                break
            if kind == 1:
                offset += 1
                continue
            if offset + 1 >= limit:
                break
            length = int(raw[offset + 1])
            if length < 2 or offset + length > limit:
                break
            if kind == 2 and length == 4:
                current = int.from_bytes(raw[offset + 2:offset + 4], "big")
                if current > self.tcp_mss:
                    raw[offset + 2:offset + 4] = self.tcp_mss.to_bytes(2, "big")
                    return True
                return False
            offset += length
        return False

    def process_packet(self, packet: Any) -> bool:
        try:
            source = ipaddress.IPv4Address(str(packet.src_addr))
            destination = ipaddress.IPv4Address(str(packet.dst_addr))
            source_port = int(packet.src_port or 0)
            destination_port = int(packet.dst_port or 0)
        except (AttributeError, TypeError, ValueError, ipaddress.AddressValueError):
            return True
        tcp = getattr(packet, "tcp", None)
        udp = getattr(packet, "udp", None)
        if tcp is None and udp is None:
            return True
        protocol = "tcp" if tcp is not None else "udp"
        now = time.monotonic()
        self._expire_dns_flows(now)
        source_is_client = self._is_client(source)
        destination_is_client = self._is_client(destination)
        if source_is_client and destination_port == 53 and self._rewrite_private_dns(destination):
            self._remember_dns(
                protocol,
                str(source),
                source_port,
                str(destination),
                now,
            )
            packet.dst_addr = self.resolver
            destination = ipaddress.IPv4Address(self.resolver)
        elif (
            destination_is_client
            and source_port == 53
            and str(source) == self.resolver
        ):
            original = self._original_dns(
                protocol,
                str(destination),
                destination_port,
                remove=protocol == "udp",
            )
            if original:
                packet.src_addr = original
                source = ipaddress.IPv4Address(original)
        if tcp is not None and bool(getattr(tcp, "syn", False)):
            if (
                source_is_client and self._is_external(destination)
            ) or (
                destination_is_client and self._is_external(source)
            ):
                self._clamp_tcp_mss(tcp)
        if (
            self.block_quic
            and udp is not None
            and source_is_client
            and destination_port == 443
            and self._is_external(destination)
        ):
            return False
        return True


class GatewayManager:
    def __init__(
        self,
        engine: Any | None = None,
        log: Callable[[str], None] | None = None,
        state_changed: Callable[[str, int, str], None] | None = None,
        devices_changed: Callable[[dict[str, str]], None] | None = None,
        state_file: Path | str = GATEWAY_STATE_FILE,
        windows: WindowsGatewayBackend | None = None,
        arp: ScapyArpBackend | None = None,
        forwarder: ForwardPathHelper | None = None,
        poll_interval: float = 1.25,
        discovery_interval: float = 12,
        device_ttl: float = GATEWAY_DEVICE_TTL,
        failure_limit: int = 2,
        process_alive: Callable[[int, float], bool] | None = None,
        watchdog_launcher: Callable[[dict[str, Any]], None] | None = None,
        device_names_changed: Callable[[dict[str, str]], None] | None = None,
    ) -> None:
        self.engine = engine
        self.log = log or (lambda _message: None)
        self.state_changed = state_changed or (lambda _state, _count, _detail: None)
        self.devices_changed = devices_changed or (lambda _devices: None)
        self.device_names_changed = device_names_changed or (lambda _names: None)
        self.state_file = Path(state_file)
        self.windows = windows or WindowsGatewayBackend()
        self.arp = arp or ScapyArpBackend()
        self.forwarder = forwarder or ForwardPathHelper(
            log=self.log,
            block_quic=False,
            rewrite_dns=True,

        )
        self.poll_interval = max(0.05, float(poll_interval))
        self.discovery_interval = max(self.poll_interval, float(discovery_interval))
        self.device_ttl = max(self.discovery_interval, float(device_ttl))
        self.failure_limit = max(1, int(failure_limit))
        self.process_alive = process_alive or _process_is_alive
        self.watchdog_launcher = watchdog_launcher or self._launch_watchdog
        self._lock = threading.RLock()
        self._stop_serial = threading.Lock()
        self._stop_event = threading.Event()
        self._worker: threading.Thread | None = None
        self._discovery_worker: threading.Thread | None = None
        self._active = False
        self._stopping = False
        self._token = ""
        self._devices: dict[str, str] = {}
        self._device_names: dict[str, str] = {}
        self._device_last_seen: dict[str, float] = {}
        self._health_check: Callable[[], bool] | None = None
        self._last_socks_health_at = 0.0
        self._socks_health_ok = False

    @property
    def active(self) -> bool:
        return bool(self._active)

    @property
    def devices(self) -> dict[str, str]:
        with self._lock:
            return dict(self._devices)

    @property
    def device_names(self) -> dict[str, str]:
        with self._lock:
            return dict(self._device_names)

    @property
    def gateway_address(self) -> str:
        with self._lock:
            state = self._read_state()
            if not state:
                return ""
            return str(dict(state.get("lan", {})).get("gateway", ""))

    def _read_state(self) -> dict[str, Any] | None:
        try:
            value = json.loads(self.state_file.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except (OSError, ValueError, TypeError):
            return {}
        return dict(value) if isinstance(value, dict) else {}

    def _write_state(self, value: dict[str, Any]) -> None:
        _atomic_write_json(self.state_file, value)

    def _remove_state(self, token: str | None = None) -> bool:
        current = self._read_state()
        if current is None:
            return False
        if token is not None and str(current.get("token", "")) != str(token):
            return False
        self.state_file.unlink(missing_ok=True)
        return True

    def _state_owner_alive(self, state: dict[str, Any]) -> bool:
        owner = state.get("owner", {})
        if not isinstance(owner, dict):
            return False
        try:
            return self.process_alive(int(owner["pid"]), float(owner["create_time"]))
        except (KeyError, TypeError, ValueError):
            return False

    @staticmethod
    def _call(method: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        try:
            signature = inspect.signature(method)
        except (TypeError, ValueError):
            return method(*args, **kwargs)
        accepts_kwargs = any(
            parameter.kind == inspect.Parameter.VAR_KEYWORD
            for parameter in signature.parameters.values()
        )
        accepted = kwargs if accepts_kwargs else {
            name: value for name, value in kwargs.items()
            if name in signature.parameters
        }
        return method(*args, **accepted)

    def _engine_ready(self, engine: Any) -> bool:
        ready = bool(getattr(engine, "running", False)) and self._socks_ready()
        self._last_socks_health_at = time.monotonic()
        self._socks_health_ok = ready
        return ready

    @staticmethod
    def _socks_ready() -> bool:
        try:
            with socket.create_connection((SOCKS_HOST, SOCKS_PORT), timeout=0.8) as connection:
                connection.settimeout(0.8)
                connection.sendall(b"\x05\x01\x00")
                return connection.recv(2) == b"\x05\x00"
        except OSError:
            return False

    def _acquire_tun(self, engine: Any, lan: LanAdapter) -> str:
        network = str(ipaddress.ip_network(
            f"{lan.address}/{lan.prefix}",
            strict=False,
        ))
        acquire = getattr(engine, "acquire_tun", None)
        if callable(acquire):
            self._call(
                acquire,
                owner="gateway",
                expected_run_id=getattr(engine, "run_id", None),
                gateway_networks=[network],
                gateway_host_addresses=[lan.address],
                gateway_interface=lan.alias,
            )
            return "lease"
        if bool(getattr(engine, "tun_running", False)):
            return "borrowed"
        enable = getattr(engine, "enable_tun", None)
        if not callable(enable):
            raise GatewayError("The active engine has no TUN interface")
        self._call(
            enable,
            expected_run_id=getattr(engine, "run_id", None),
            gateway_networks=[network],
            gateway_host_addresses=[lan.address],
            gateway_interface=lan.alias,
        )
        if not bool(getattr(engine, "tun_running", False)):
            raise GatewayError("The engine TUN interface did not start")
        return "owned"

    def _release_tun(self, state: dict[str, Any], engine_stopping: bool) -> None:
        if engine_stopping:
            return
        engine = self.engine
        if engine is None:
            return
        mode = str(state.get("tun_runtime", ""))
        if mode == "lease":
            release = getattr(engine, "release_tun", None)
            if callable(release):
                self._call(
                    release,
                    owner="gateway",
                    expected_run_id=getattr(engine, "run_id", None),
                )
            return
        if mode == "owned":
            disable = getattr(engine, "disable_tun", None)
            if callable(disable):
                self._call(disable, expected_run_id=getattr(engine, "run_id", None))

    def _devices_for(
        self,
        lan: LanAdapter,
        capture: dict[str, str],
        gateway_mac: str,
    ) -> dict[str, str]:
        sources: list[tuple[str, Callable[[], dict[str, str]]]] = [
            ("neighbor-cache", lambda: self.windows.neighbors(lan.index)),
            (
                "npcap",
                lambda: self._call(
                    self.arp.discover,
                    lan,
                    capture["name"],
                    source_mac=capture.get("mac", ""),
                ),
            ),
        ]
        native_discover = getattr(self.windows, "discover_neighbors", None)
        if callable(native_discover):
            sources.append(
                ("native-arp", lambda: self._call(native_discover, lan))
            )
        values: dict[str, str] = {}
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=len(sources),
            thread_name_prefix="gateway-discovery",
        ) as executor:
            futures = {
                executor.submit(source): name
                for name, source in sources
            }
            for future, name in futures.items():
                try:
                    values.update(dict(future.result() or {}))
                except Exception as exc:
                    self.log(f"MOBILE GATEWAY {name} discovery retry: {exc}")
        return self._filter_devices(lan, capture, gateway_mac, values)

    @staticmethod
    def _filter_devices(
        lan: LanAdapter,
        capture: dict[str, str],
        gateway_mac: str,
        values: dict[str, str],
    ) -> dict[str, str]:
        network = ipaddress.ip_network(f"{lan.address}/{lan.prefix}", strict=False)
        result: dict[str, str] = {}
        for raw_address, raw_mac in values.items():
            try:
                address = ipaddress.IPv4Address(str(raw_address))
            except ipaddress.AddressValueError:
                continue
            mac = _normalize_mac(raw_mac)
            if (
                address not in network
                or address in {network.network_address, network.broadcast_address}
                or str(address) in {lan.address, lan.gateway}
                or address.is_multicast
                or not mac
                or mac in {capture["mac"], gateway_mac}
            ):
                continue
            result[str(address)] = mac
        return dict(sorted(result.items(), key=lambda item: ipaddress.IPv4Address(item[0])))

    def _emit_state(self, name: str, detail: str = "") -> None:
        self.state_changed(name, len(self.devices), detail)
        
    @staticmethod
    def _should_use_arp_spoofing(lan: LanAdapter) -> bool:
        identity = f"{lan.alias} {lan.description}".casefold()

        wireless_markers = (
            "wi-fi",
            "wifi",
            "wireless",
            "wlan",
            "802.11",
        )

        return any(marker in identity for marker in wireless_markers)
    def start(
        self,
        engine: Any | None = None,
        health_check: Callable[[], bool] | None = None,
        tun_alias: str = DEFAULT_TUN_ALIAS,
        cancel_event: threading.Event | None = None,
    ) -> dict[str, Any]:
        def check_cancelled() -> None:
            if cancel_event is not None and cancel_event.is_set():
                raise GatewayError("Mobile Gateway activation cancelled")

        check_cancelled()
        with self._lock:
            check_cancelled()
            if self._active:
                state = self._read_state()
                return state or {}
            current = self._read_state()
            if current:
                if self._state_owner_alive(current):
                    raise GatewayError("Mobile Gateway state belongs to a running app instance")
                if not self.recover(force=True):
                    raise GatewayError("Previous Mobile Gateway state was not fully restored")
            check_cancelled()
            selected_engine = engine or self.engine
            if selected_engine is None:
                raise GatewayError("UAC engine is not available")
            self.engine = selected_engine
            if not self._engine_ready(selected_engine):
                raise GatewayError("Connect UAC Spoofer before enabling Mobile Gateway")
            self._emit_state("starting")
            tun_runtime = ""
            state: dict[str, Any] | None = None
            try:
                lan = self.windows.detect_lan({tun_alias})

                arp_spoofing = self._should_use_arp_spoofing(lan)

                gateway_mode = (
                    "arp-spoof"
                    if arp_spoofing
                    else "router-gateway"
                )

                self.log(
                    f"MOBILE GATEWAY mode={gateway_mode} "
                    f"interface={lan.alias}"
                )

                check_cancelled()
                tun = None
                tun_error: Exception | None = None
                for attempt in range(3):
                    tun_runtime = self._acquire_tun(selected_engine, lan)
                    check_cancelled()
                    try:
                        tun = self.windows.wait_for_tun(tun_alias, timeout=20)
                        tun_error = None
                        break
                    except Exception as exc:
                        tun_error = exc
                        self._release_tun(
                            {"tun_runtime": tun_runtime},
                            engine_stopping=False,
                        )
                        tun_runtime = ""
                        if attempt < 2:
                            time.sleep(1.5 * (attempt + 1))
                            check_cancelled()
                if tun is None:
                    if tun_error is not None:
                        raise tun_error
                    raise GatewayError(f"TUN adapter {tun_alias} was not created")
                check_cancelled()
                capture = self.arp.interface_for(lan.address)
                capture["mac"] = _normalize_mac(capture.get("mac", "")) or lan.mac
                if not capture.get("name") or not capture.get("mac"):
                    raise GatewayError("LAN capture interface data is incomplete")
                neighbor_rows = self.windows.neighbors(lan.index)
                gateway_mac = _normalize_mac(neighbor_rows.get(lan.gateway, ""))
                if not gateway_mac:
                    gateway_mac = self._call(
                        self.arp.resolve,
                        lan.gateway,
                        capture["name"],
                        source_address=lan.address,
                        source_mac=capture["mac"],
                    )
                check_cancelled()
                devices = self._filter_devices(
                    lan,
                    capture,
                    gateway_mac,
                    neighbor_rows,
                )
                check_cancelled()
                token = uuid.uuid4().hex
                owner = _process_identity()
                firewall_rule = f"{GATEWAY_FIREWALL_PREFIX} {token}"
                windows_state = self.windows.snapshot(lan, tun)
                state = {
                    "version": GATEWAY_STATE_VERSION,
                    "token": token,
                    "owner": owner,
                    "started_at": time.time(),
                    "status": "starting",
                    "arp_spoofing": arp_spoofing, # apr spoofing mode enabled or not
                    "lan": asdict(lan),
                    "tun": asdict(tun),
                    "tun_runtime": tun_runtime,
                    "capture": dict(capture),
                    "gateway_mac": gateway_mac,
                    "devices": devices,
                    "device_names": {},
                    "firewall_rule": firewall_rule,
                    "forward_path": {
                        "resolver": self.forwarder.resolver,
                        "tcp_mss": self.forwarder.tcp_mss,
                        "block_quic": self.forwarder.block_quic,
                        "rewrite_dns": bool(getattr(
                            self.forwarder,
                            "rewrite_dns",
                            False,
                        )),
                    },
                    "windows": windows_state,
                }
                self._write_state(state)
                self.watchdog_launcher(state)
                check_cancelled()
                self._call(
                    self.forwarder.start,
                    lan,
                    devices,
                    timeout=GATEWAY_FORWARDER_TIMEOUT,
                )
                check_cancelled()
                self.windows.apply(state)
                check_cancelled()
                if arp_spoofing:
                    self.log("MOBILE GATEWAY ARP responder starting")

                    start_responder = getattr(
                        self.arp,
                        "start_responder",
                        None,
                    )

                    if callable(start_responder):
                        self._call(
                            start_responder,
                            state,
                            device_seen=self._record_device,
                            device_named=self._record_device_name,
                        )

                    check_cancelled()

                    self._call(
                        self.arp.redirect,
                        state,
                        devices,
                        repeat=3,
                    )

                check_cancelled()
                state["status"] = "active"
                self._write_state(state)
                self._token = token
                self._devices = devices
                self._device_names = {}
                now = time.monotonic()
                self._device_last_seen = {
                    address: now for address in devices
                }
                self._health_check = health_check
                self._active = True
                self._stopping = False
                self._stop_event = threading.Event()
                self._worker = threading.Thread(
                    target=self._run,
                    name="mobile-gateway",
                    daemon=True,
                )
                self._worker.start()
                self.devices_changed(dict(devices))
                self.device_names_changed({})
                self._emit_state("active")
                self.log(f"MOBILE GATEWAY active lan={lan.alias} devices={len(devices)}")
                self._start_device_refresh()
                return dict(state)
            except Exception:
                if state is not None:
                    errors = self._restore_state(state, include_arp=True)
                    if not errors:
                        self._remove_state(str(state.get("token", "")))
                if tun_runtime:
                    fallback = {"tun_runtime": tun_runtime}
                    try:
                        self._release_tun(fallback, False)
                    except Exception as release_error:
                        self.log(f"MOBILE GATEWAY TUN rollback pending: {release_error}")
                self._active = False
                self._devices = {}
                self._device_names = {}
                self._device_last_seen = {}
                self._token = ""
                self._emit_state("error")
                raise

    def _health_ok(self) -> bool:
        engine = self.engine
        if (
            engine is None
            or not bool(getattr(engine, "running", False))
            or not bool(getattr(engine, "tun_running", False))
        ):
            return False
        now = time.monotonic()
        if now - self._last_socks_health_at >= GATEWAY_SOCKS_HEALTH_INTERVAL:
            self._socks_health_ok = self._socks_ready()
            self._last_socks_health_at = now
        if not self._socks_health_ok:
            return False
        check = self._health_check
        if check is not None:
            try:
                return bool(check())
            except Exception:
                return False
        return self._socks_ready()

    @staticmethod
    def _lan_from_state(state: dict[str, Any]) -> LanAdapter:
        lan_value = dict(state["lan"])
        return LanAdapter(
            index=int(lan_value["index"]),
            alias=str(lan_value["alias"]),
            address=str(lan_value["address"]),
            prefix=int(lan_value["prefix"]),
            gateway=str(lan_value["gateway"]),
            mac=str(lan_value.get("mac", "")),
            description=str(lan_value.get("description", "")),
        )

    def _ensure_forwarder(self) -> bool:
        if bool(getattr(self.forwarder, "running", True)):
            return True
        with self._lock:
            state = self._read_state()
            token = self._token
            devices = dict(self._devices)
            if (
                not self._active
                or self._stopping
                or not state
                or str(state.get("token", "")) != token
            ):
                return False
        try:
            self._call(
                self.forwarder.start,
                self._lan_from_state(state),
                devices,
                timeout=GATEWAY_FORWARDER_TIMEOUT,
            )
            self.log("MOBILE GATEWAY forwarding filter restarted")
            return bool(getattr(self.forwarder, "running", True))
        except Exception as exc:
            self.log(f"MOBILE GATEWAY forwarding filter retry: {exc}")
            return False

    def _record_device(self, raw_address: str, raw_mac: str) -> bool:
        try:
            address = ipaddress.IPv4Address(str(raw_address))
        except ipaddress.AddressValueError:
            return False
        mac = _normalize_mac(raw_mac)
        if not mac:
            return False
        now = time.monotonic()
        with self._lock:
            state = self._read_state()
            if (
                not self._active
                or self._stopping
                or self._stop_event.is_set()
                or not state
                or str(state.get("token", "")) != self._token
            ):
                return False
            lan = self._lan_from_state(state)
            network = ipaddress.ip_network(
                f"{lan.address}/{lan.prefix}",
                strict=False,
            )
            blocked_macs = {
                _normalize_mac(state.get("gateway_mac", "")),
                _normalize_mac(dict(state.get("capture", {})).get("mac", "")),
            }
            if (
                address not in network
                or address in {network.network_address, network.broadcast_address}
                or str(address) in {lan.address, lan.gateway}
                or address.is_multicast
                or mac in blocked_macs
            ):
                return False
            key = str(address)
            changed = self._devices.get(key) != mac
            self._devices[key] = mac
            self._devices = dict(sorted(
                self._devices.items(),
                key=lambda item: ipaddress.IPv4Address(item[0]),
            ))
            self._device_last_seen[key] = now
            devices = dict(self._devices)
            if changed:
                state["devices"] = devices
                self._write_state(state)
        if changed:  #changed devices, update forwarder and emit state
            self.forwarder.set_devices(devices)

            if bool(state.get("arp_spoofing", True)):
                try:
                    self._call(
                        self.arp.redirect,
                        state,
                        {key: mac},
                        repeat=2,
                    )
                except Exception as exc:
                    self.log(
                        f"MOBILE GATEWAY device redirect retry: {exc}"
                    )

            self.devices_changed(devices)
            self._emit_state("active")
        return changed

    def _record_device_name(
        self,
        raw_address: str,
        raw_mac: str,
        raw_name: str,
    ) -> bool:
        name = normalize_device_name(raw_name)
        mac = _normalize_mac(raw_mac)
        if not name or not mac:
            return False
        self._record_device(raw_address, mac)
        try:
            address = str(ipaddress.IPv4Address(str(raw_address)))
        except ipaddress.AddressValueError:
            return False
        with self._lock:
            state = self._read_state()
            if (
                not self._active
                or self._stopping
                or self._stop_event.is_set()
                or not state
                or str(state.get("token", "")) != self._token
                or self._devices.get(address) != mac
            ):
                return False
            changed = self._device_names.get(address) != name
            if not changed:
                return False
            self._device_names[address] = name
            self._device_names = {
                key: value
                for key, value in self._device_names.items()
                if key in self._devices
            }
            names = dict(self._device_names)
            state["device_names"] = names
            self._write_state(state)
        self.device_names_changed(names)
        return True

    def _refresh_devices(self) -> bool:
        with self._lock:
            state = self._read_state()
            token = self._token
            previous = dict(self._devices)
            last_seen = dict(self._device_last_seen)
            if (
                not self._active
                or self._stopping
                or not state
                or str(state.get("token", "")) != token
            ):
                return False
            lan = self._lan_from_state(state)
            capture = dict(state["capture"])
            gateway_mac = str(state.get("gateway_mac", ""))
        discovered = self._devices_for(lan, capture, gateway_mac)
        now = time.monotonic()
        cutoff = now - self.device_ttl
        for address in discovered:
            last_seen[address] = now
        devices = dict(discovered)
        network = ipaddress.ip_network(f"{lan.address}/{lan.prefix}", strict=False)
        for address, mac in previous.items():
            try:
                valid = ipaddress.IPv4Address(address) in network
            except ipaddress.AddressValueError:
                valid = False
            if valid and last_seen.get(address, 0.0) >= cutoff:
                devices.setdefault(address, mac)
        last_seen = {
            address: seen
            for address, seen in last_seen.items()
            if address in devices and seen >= cutoff
        }
        with self._lock:
            current = self._read_state()
            if (
                not self._active
                or self._stopping
                or self._stop_event.is_set()
                or not current
                or str(current.get("token", "")) != token
            ):
                return False
            for address, mac in self._devices.items():
                seen = self._device_last_seen.get(address, 0.0)
                if (
                    seen > last_seen.get(address, 0.0)
                    and seen >= cutoff
                ):
                    devices[address] = mac
                    last_seen[address] = seen
            changed = devices != self._devices
            self._devices = devices
            self._device_last_seen = last_seen
            names = {
                address: name
                for address, name in self._device_names.items()
                if address in devices
            }
            names_changed = names != self._device_names
            self._device_names = names
            current["devices"] = devices
            current["device_names"] = names
            self._write_state(current)
        self.forwarder.set_devices(devices)
        if changed:
            self.devices_changed(dict(devices))
            self._emit_state("active")
        if names_changed:
            self.device_names_changed(dict(names))
        with self._lock:
            if (
                not self._active
                or self._stopping
                or self._stop_event.is_set()
                or self._token != token
            ):
                return False
        if bool(current.get("arp_spoofing", True)): #if arp spoofing mode enabled, update arp redirect
            self._call(
                self.arp.redirect,
                current,
                devices,
                repeat=3 if changed else 1,
            )
        return True

    def _refresh_devices_async(self) -> None:
        try:
            self._refresh_devices()
        except Exception as exc:
            self.log(f"MOBILE GATEWAY discovery retry: {exc}")
        finally:
            with self._lock:
                if self._discovery_worker is threading.current_thread():
                    self._discovery_worker = None

    def _start_device_refresh(self) -> bool:
        with self._lock:
            worker = self._discovery_worker
            if worker is not None and worker.is_alive():
                return False
            worker = threading.Thread(
                target=self._refresh_devices_async,
                name="mobile-gateway-discovery",
                daemon=True,
            )
            self._discovery_worker = worker
        worker.start()
        return True

    def _run(self) -> None:
        failures = 0
        next_discovery = time.monotonic()
        while not self._stop_event.wait(self.poll_interval):
            if self._health_ok() and self._ensure_forwarder():
                failures = 0
            else:
                failures += 1
                if failures >= self.failure_limit:
                    self.log("MOBILE GATEWAY source offline; restoring LAN")
                    self.stop("source-offline")
                    return
            now = time.monotonic()
            if now >= next_discovery:
                started = self._start_device_refresh()
                next_discovery = now + (
                    self.discovery_interval
                    if self.devices
                    else min(2.0, self.discovery_interval)
                ) if started else now + self.poll_interval
            with self._lock:
                state = self._read_state()
                devices = dict(self._devices)
                active = (
                    self._active
                    and not self._stopping
                    and not self._stop_event.is_set()
                )
                #if apr zan jende period shod 
            if ( 
                state
                and devices
                and active
                and bool(state.get("arp_spoofing", True)) 
            ):
                try:
                    self._call(
                        self.arp.redirect,
                        state,
                        devices,
                        repeat=1,
                    )
                except Exception as exc:
                    self.log(
                        f"MOBILE GATEWAY ARP retry: {exc}"
                    )

    def _restore_state(
        self,
        state: dict[str, Any],
        include_arp: bool,
    ) -> list[str]:
        errors: list[str] = []
        stop_responder = getattr(self.arp, "stop_responder", None)
        if callable(stop_responder):
            try:
                self._call(stop_responder)
            except Exception as exc:
                self.log(f"MOBILE GATEWAY ARP responder cleanup: {exc}")
        try:
            self.forwarder.stop()
        except Exception as exc:
            self.log(f"MOBILE GATEWAY forwarding filter cleanup: {exc}")
        if (
            include_arp
            and bool(state.get("arp_spoofing", True))
        ):
            try:
                self.arp.restore(state)
            except Exception as exc:
                self.log(
            f"MOBILE GATEWAY ARP restore skipped: {exc}"
        )
        try:
            self.windows.restore(state)
        except Exception as exc:
            errors.append(f"Windows restore: {exc}")
        for error in errors:
            self.log(f"MOBILE GATEWAY restore pending: {error}")
        return errors

    def stop(self, reason: str = "user", engine_stopping: bool = False) -> bool:
        with self._stop_serial:
            with self._lock:
                state = self._read_state()
                token = self._token or str((state or {}).get("token", ""))
                if state is None and not self._active:
                    return False
                self._stopping = True
                self._stop_event.set()
                worker = self._worker
                self._emit_state("stopping", reason)
            if worker is not None and worker is not threading.current_thread():
                worker.join(timeout=max(2.0, self.poll_interval * 2))
            with self._lock:
                state = self._read_state() or state or {}
                if token and str(state.get("token", "")) not in {"", token}:
                    self._stopping = False
                    return False
                errors = self._restore_state(state, include_arp=True) if state else []
                try:
                    if state:
                        self._release_tun(state, engine_stopping)
                except Exception as exc:
                    errors.append(f"TUN release: {exc}")
                    self.log(f"MOBILE GATEWAY restore pending: TUN release: {exc}")
                if not errors:
                    self._remove_state(token or None)
                elif state:
                    state["status"] = "restore-pending"
                    state["restore_errors"] = list(errors)
                    self._write_state(state)
                self._active = False
                self._stopping = False
                self._worker = None
                self._health_check = None
                self._token = ""
                self._devices = {}
                self._device_names = {}
                self._device_last_seen = {}
                self.devices_changed({})
                self.device_names_changed({})
                self._emit_state("inactive" if not errors else "restore-pending", reason)
                self.log(
                    f"MOBILE GATEWAY stopped reason={reason}"
                    if not errors
                    else f"MOBILE GATEWAY cleanup pending reason={reason}"
                )
                return not errors

    def before_engine_stop(self) -> bool:
        return self.stop("engine-stop", engine_stopping=True)

    def recover(
        self,
        force: bool = False,
        expected_token: str | None = None,
    ) -> bool:
        with self._stop_serial:
            with self._lock:
                state = self._read_state()
                if state is None:
                    return True
                if not state:
                    return False
                token = str(state.get("token", ""))
                if expected_token is not None and token != str(expected_token):
                    return False
                if not force and self._state_owner_alive(state):
                    return False
                errors = self._restore_state(state, include_arp=True)
                if errors:
                    state["status"] = "restore-pending"
                    state["restore_errors"] = list(errors)
                    self._write_state(state)
                    return False
                self._remove_state(token or None)
                self._active = False
                self._token = ""
                self._devices = {}
                self._device_names = {}
                self.devices_changed({})
                self.device_names_changed({})
                self.log("MOBILE GATEWAY stale state restored")
                return True

    def _launch_watchdog(self, state: dict[str, Any]) -> None:
        owner = dict(state["owner"])
        arguments = [
            "--gateway-watchdog",
            str(owner["pid"]),
            repr(float(owner["create_time"])),
            str(state["token"]),
            str(self.state_file),
        ]
        if getattr(sys, "frozen", False):
            command = [sys.executable, *arguments]
        else:
            entrypoint = Path(__file__).resolve().parents[1] / "main.py"
            command = [sys.executable, str(entrypoint), *arguments]
        environment = os.environ.copy()
        if getattr(sys, "frozen", False):
            environment["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
        kwargs: dict[str, Any] = {
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
            "close_fds": True,
            "env": environment,
        }
        if sys.platform == "win32":
            kwargs["creationflags"] = (
                getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
                | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
                | 0x00000008
            )
        else:
            kwargs["start_new_session"] = True
        subprocess.Popen(command, **kwargs)

    @classmethod
    def run_watchdog(
        cls,
        parent_pid: int,
        parent_create_time: float,
        token: str,
        state_file: Path | str = GATEWAY_STATE_FILE,
        process_alive: Callable[[int, float], bool] | None = None,
        manager_factory: Callable[[], "GatewayManager"] | None = None,
        poll_interval: float = 0.5,
        restore_attempts: int = 20,
    ) -> int:
        alive = process_alive or _process_is_alive
        while alive(int(parent_pid), float(parent_create_time)):
            time.sleep(max(0.05, float(poll_interval)))
        manager = (
            manager_factory()
            if manager_factory is not None
            else cls(
                state_file=state_file,
                process_alive=alive,
                watchdog_launcher=lambda _state: None,
            )
        )
        for _ in range(max(1, int(restore_attempts))):
            current = manager._read_state()
            if current is None:
                return 0
            if str(current.get("token", "")) != str(token):
                return 0
            if manager.recover(force=True, expected_token=token):
                return 0
            time.sleep(max(0.05, float(poll_interval)))
        return 1

    @classmethod
    def watchdog_mode(cls, arguments: list[str]) -> int | None:
        if not arguments or arguments[0] != "--gateway-watchdog":
            return None
        if len(arguments) != 5:
            return 2
        try:
            parent_pid = int(arguments[1])
            parent_create_time = float(arguments[2])
            token = str(arguments[3])
            state_file = Path(arguments[4])
            if parent_pid <= 0 or parent_create_time <= 0 or not token:
                return 2
        except (TypeError, ValueError):
            return 2
        return cls.run_watchdog(
            parent_pid,
            parent_create_time,
            token,
            state_file=state_file,
        )


__all__ = [
    "DEFAULT_TUN_ALIAS",
    "ForwardPathHelper",
    "GATEWAY_DNS_RESOLVER",
    "GATEWAY_STATE_FILE",
    "GATEWAY_TCP_MSS",
    "GatewayError",
    "GatewayManager",
    "LanAdapter",
    "PowerShellRunner",
    "ScapyArpBackend",
    "TunAdapter",
    "WindowsGatewayBackend",
]
