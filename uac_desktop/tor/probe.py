"""Verification probes and real GeoIP country detection for UAC Tor."""
from __future__ import annotations

import time
from dataclasses import dataclass

import requests

_INVALID_CODES = frozenset({"", "XX", "T1", "??", "A1", "A2"})


@dataclass(frozen=True)
class TorExitInfo:
    ok: bool = False
    is_tor: bool = False
    ip: str = ""
    country: str = ""
    city: str = ""
    isp: str = ""
    latency_ms: int = 0
    detail: str = ""


def _valid_cc(value: str) -> str:
    cc = str(value or "").strip().upper()
    return cc if (len(cc) == 2 and cc.isalpha() and cc.isascii() and cc not in _INVALID_CODES) else ""


def verify_tor_exit(socks_port: int, *, control=None, timeout: float = 14.0) -> TorExitInfo:
    """Verify live Tor exit IP and resolve its real 2-letter ISO country (never 'T1')."""
    proxies = {
        "http": f"socks5h://127.0.0.1:{int(socks_port)}",
        "https": f"socks5h://127.0.0.1:{int(socks_port)}",
    }
    session = requests.Session()
    session.trust_env = False
    headers = {"User-Agent": "Mozilla/5.0 UAC-Tor/1.0", "Connection": "close"}
    ip = ""
    country = ""
    city = ""
    isp = ""
    is_tor = False
    latency_ms = 0
    errors: list[str] = []

    try:
        started = time.perf_counter()
        resp = session.get("https://check.torproject.org/api/ip", proxies=proxies, timeout=timeout, headers=headers)
        if resp.ok:
            data = resp.json()
            is_tor = bool(data.get("IsTor", False))
            ip = str(data.get("IP", "") or "").strip()
            latency_ms = max(1, int((time.perf_counter() - started) * 1000))
    except Exception as exc:
        errors.append(f"torproject: {type(exc).__name__}")

    if not ip:
        try:
            started = time.perf_counter()
            resp = session.get("https://www.cloudflare.com/cdn-cgi/trace", proxies=proxies, timeout=min(8.0, timeout), headers=headers)
            if resp.ok:
                fields = dict(line.split("=", 1) for line in resp.text.splitlines() if "=" in line)
                ip = str(fields.get("ip", "") or "").strip()
                country = _valid_cc(fields.get("loc", ""))
                latency_ms = max(1, int((time.perf_counter() - started) * 1000))
        except Exception as exc:
            errors.append(f"trace: {type(exc).__name__}")

    # 1. Instant real GeoIP from Tor's local geoip database via ControlPort (never returns T1)
    if ip and not country and control is not None:
        try:
            country = _valid_cc(control.ip_to_country(ip))
        except Exception:
            pass

    # 2. Online real GeoIP metadata via ipwho.is / ipapi.co / ip-api.com
    if ip and (not country or not city):
        for url in (
            f"https://ipwho.is/{ip}",
            f"https://ipapi.co/{ip}/json/",
            f"http://ip-api.com/json/{ip}?fields=status,countryCode,city,isp",
        ):
            try:
                resp = session.get(url, proxies=proxies, timeout=6.0, headers=headers)
                if not resp.ok:
                    continue
                doc = resp.json()
                cc = _valid_cc(doc.get("country_code") or doc.get("countryCode") or doc.get("country"))
                if cc:
                    country = cc
                city = city or str(doc.get("city") or "").strip()
                conn = doc.get("connection") if isinstance(doc.get("connection"), dict) else {}
                isp = isp or str(conn.get("isp") or doc.get("org") or doc.get("isp") or "").strip()
                if country:
                    break
            except Exception:
                continue

    session.close()

    if ip:
        return TorExitInfo(
            ok=True,
            is_tor=is_tor,
            ip=ip,
            country=country,
            city=city,
            isp=isp,
            latency_ms=latency_ms,
            detail="Tor verified" if is_tor else "SOCKS exit verified",
        )
    return TorExitInfo(ok=False, detail="; ".join(errors) or "Tor exit probe failed")


def verify_http_proxy(http_port: int, timeout: float = 10.0) -> tuple[bool, str]:
    """Confirm browsers can actually load HTTPS websites through the Windows Proxy port."""
    proxies = {
        "http": f"http://127.0.0.1:{int(http_port)}",
        "https": f"http://127.0.0.1:{int(http_port)}",
    }
    session = requests.Session()
    session.trust_env = False
    try:
        for url in ("https://check.torproject.org/api/ip", "https://www.gstatic.com/generate_204"):
            try:
                resp = session.get(url, proxies=proxies, timeout=timeout, headers={"Connection": "close"})
                if resp.status_code == 204 or (resp.status_code == 200 and resp.json().get("IP")):
                    return True, f"HTTPS {resp.status_code}"
            except Exception as exc:
                last_err = f"{type(exc).__name__}: {exc}"
        return False, locals().get("last_err", "proxy probe failed")
    finally:
        session.close()


def quick_tor_ping(socks_port: int, timeout: float = 8.0) -> int:
    proxies = {"https": f"socks5h://127.0.0.1:{int(socks_port)}"}
    session = requests.Session()
    session.trust_env = False
    started = time.perf_counter()
    try:
        resp = session.get("https://www.gstatic.com/generate_204", proxies=proxies, timeout=timeout)
        if resp.status_code in (200, 204):
            return max(1, int((time.perf_counter() - started) * 1000))
        return 0
    except Exception:
        return 0
    finally:
        session.close()
