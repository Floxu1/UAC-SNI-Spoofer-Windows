"""Readable Live Logs: classify, rewrite, collapse and summarise log lines.

Pure Python (no Qt) so it is easy to test. The window feeds every log line
into :class:`LogModel`; the Live Logs page renders :meth:`LogModel.rows` as
HTML and shows :class:`LogState` in the summary header. Nothing here changes
what the engines do; it only changes how their lines are presented.
"""

from __future__ import annotations

import html
import re
import time
from dataclasses import dataclass, field

# -- categories ----------------------------------------------------------------

#: tag -> (label shown in the row, colour of the small tag)
CATEGORY_TAGS: dict[str, tuple[str, str]] = {
    "KEY": ("KEY", "#c9a2ff"),
    "SCAN": ("SCAN", "#7fb4e6"),
    "MASQUE": ("MASQUE", "#5fd4c8"),
    "WG": ("WG", "#5fd4c8"),
    "WOW": ("WOW", "#5fd4c8"),
    "PSIPHON": ("PSIPHON", "#f0a3c9"),
    "PARALLEL": ("PARALLEL", "#e8c46a"),
    "LOWLAT": ("LOW-RTT", "#e8c46a"),
    "H3": ("H3", "#e8c46a"),
    "DIRECT": ("DIRECT", "#e8c46a"),
    "SPEED": ("SPEED", "#e8c46a"),
    "NET": ("NET", "#8fb8d8"),
    "STATE": ("STATE", "#3cf0af"),
    "DROP": ("DROP", "#ff7a8a"),
    "SET": ("SET", "#b0bccb"),
    "APP": ("APP", "#8394a6"),
    "XRAY": ("XRAY", "#8fb8d8"),
}

#: phase -> (English title, Persian title)
PHASES: dict[str, tuple[str, str]] = {
    "key": ("Key / Cert", "کلید و گواهی"),
    "scan": ("Clean-IP scan", "اسکن آی‌پی تمیز"),
    "outer": ("Outer tunnel", "تونل بیرونی"),
    "psiphon": ("Psiphon", "سایفون"),
    "speed": ("Speed features", "قابلیت‌های سرعت"),
    "connected": ("Connected", "وصل"),
    "drop": ("Drops / reconnects", "قطعی و اتصال دوباره"),
    "app": ("App", "برنامه"),
}

_CATEGORY_PHASE = {
    "KEY": "key", "SCAN": "scan", "MASQUE": "outer", "WG": "outer", "WOW": "outer",
    "PSIPHON": "psiphon", "PARALLEL": "speed", "LOWLAT": "speed", "H3": "speed",
    "DIRECT": "speed", "SPEED": "speed", "STATE": "connected", "DROP": "drop",
    "NET": "connected", "SET": "app", "APP": "app", "XRAY": "app",
}

LEVEL_COLORS = {
    "info": "#a9b6c4",
    "muted": "#738396",
    "success": "#3cf0af",
    "warning": "#f2b84b",
    "error": "#ff6b7d",
}

_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b")
_STAMP_RE = re.compile(r"^\[(\d{1,2}:\d{2}:\d{2})\]\s?(.*)$", re.S)

# (regex, category) — first match wins. Order matters.
_CATEGORY_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"^Setting changed", re.I), "SET"),
    (re.compile(r"path lost|UAC PoW (?:cancelled|failed|error|stopped|disconnected)|Tunnel did not stay up|tunnel ended", re.I), "DROP"),
    (re.compile(r"^UAC PoW ready"), "STATE"),
    (re.compile(r"^Parallel MASQUE"), "PARALLEL"),
    (re.compile(r"^Lowest-latency"), "LOWLAT"),
    (re.compile(r"^HTTP/3 on Irancell"), "H3"),
    (re.compile(r"^Direct Psiphon"), "DIRECT"),
    (re.compile(r"^Speed options"), "SPEED"),
    (re.compile(r"^(?:Key|Cert)\b|^Key fetch|^Clean IP for key|^Clean-IP scan for the key|certificate", re.I), "KEY"),
    (re.compile(r"^Scan|^Rejected |^Accepted |^Saved clean|^Clean (?:HTTP|list)|clean address|^Trying saved clean", re.I), "SCAN"),
    (re.compile(r"^Psiphon"), "PSIPHON"),
    (re.compile(r"WireGuard|\bWG\b", re.I), "WG"),
    (re.compile(r"\bWoW\b|WARP-in-WARP", re.I), "WOW"),
    (re.compile(r"MASQUE|^Outer attempt|^HTTP/\d started|^No WARP transport|outer leg", re.I), "MASQUE"),
    (re.compile(r"^Network:|^Exit IP|^Public IP|^Connected in|Windows system proxy|^IP check", re.I), "NET"),
    (re.compile(r"^Engine switched|^PoW exit country|آماده است"), "APP"),
    (re.compile(r"xray|\bSNI\b|config try|probe", re.I), "XRAY"),
]

# Raw engine chatter: hidden unless Details is on; folded into one pulse row.
_NOISE_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"^Scan \d|^Scanning \d|^Rejected |^Accepted \d|^Scan MASQUE gateways trying"), "SCAN"),
    (re.compile(r"^Key: clean key address .* answered|^Key: trying \d|^Key: \d.* handshake ready|^Key: resolving "
                r"|^Key: racing |^Key: probing |^Key: key request will use|^Key: account key (?:won|saved) via"), "KEY"),
    (re.compile(r"^MASQUE start via |^Windows system proxy →|^Clean HTTP/\d list: "), "ECHO"),
    (re.compile(r"^Psiphon: (?!server entries imported|filtered)"), "PSIPHON"),
]

_PULSE_TEXT = {
    "SCAN": ("Probing Cloudflare addresses for a clean IP", "بررسی آدرس‌های کلادفلر برای آی‌پی تمیز"),
    "KEY": ("Testing routes for the key request", "آزمودن مسیرها برای گرفتن کلید"),
    "PSIPHON": ("Psiphon working", "سایفون در حال کار"),
}

# Plain-language rewrites: (regex, en, fa, level, event). {n} = group n.
_REWRITES: list[tuple[re.Pattern, str, str, str, str]] = [
    (re.compile(r"^TUN verified: DNS (\d+) ms, HTTPS (\d+) ms, exit (\S+) \((\S+)\)$"), "System tunnel verified ✔ (DNS {1} ms, HTTPS {2} ms, exit {3} {4})", "تونل سیستم بررسی شد ✔ (DNS {1} ms، HTTPS {2} ms، خروجی {3} {4})", "success", ""),
    (re.compile(r"^Another VPN is active: (.+)$"), "Another VPN is active ({1}); it can block the system tunnel. Turn it off for TUN", "یک VPN دیگر روشن است ({1}) و جلوی تونل سیستم را می‌گیرد؛ برای حالت TUN خاموشش کنید", "warning", ""),
    (re.compile(r"^UAC PoW leg lost: (.+)$"), "Tunnel leg lost: {1}", "یک بخش تونل قطع شد: {1}", "warning", ""),
    (re.compile(r"^Main session down; (\d+) parallel session\(s\) keep carrying traffic$"), "Main session down; {1} parallel session(s) keep traffic flowing", "جلسه‌ی اصلی قطع شد؛ {1} جلسه‌ی موازی ترافیک را ادامه می‌دهند", "warning", ""),
    (re.compile(r"^Main session back on (.+)$"), "Main session back ✔ ({1})", "جلسه‌ی اصلی برگشت ✔ ({1})", "success", ""),
    (re.compile(r"^Reconnecting: (.+)$"), "Reconnecting… ({1})", "در حال اتصال مجدد… ({1})", "warning", ""),
    (re.compile(r"^Reconnected in (\d+)s \(attempt (\d+)\)$"), "Connection back ✔ in {1}s (attempt {2})", "اتصال برگشت ✔ (بعد از {1} ثانیه، تلاش {2})", "success", ""),
    (re.compile(r"^Reconnect attempt (\d+) failed: (.+)$"), "Reconnect attempt {1} failed: {2}", "تلاش {1} برای اتصال مجدد ناموفق بود: {2}", "warning", ""),
    (re.compile(r"^Reconnect is taking long; normal internet restored while retrying$"), "Reconnect is taking long; normal internet restored while retrying", "اتصال مجدد طول کشید؛ اینترنت عادی برگشت و تلاش ادامه دارد", "warning", ""),
    (re.compile(r"^TUN verified again after reconnect$"), "System tunnel verified again ✔", "تونل سیستم دوباره بررسی شد ✔", "success", ""),
    (re.compile(r"^TUN check failed: (.+)$"), "System tunnel check failed: {1}", "بررسی تونل سیستم ناموفق بود: {1}", "warning", ""),
    (re.compile(r"^TUN repair (\d+)/(\d+): stack (\S+), MTU (\d+)$"), "Repairing system tunnel ({1}/{2}, stack {3}, MTU {4})", "تعمیر خودکار تونل سیستم ({1} از {2}، stack {3}، MTU {4})", "info", ""),
    (re.compile(r"^TUN unavailable, using Windows proxy instead: (.+)$"), "TUN unavailable; using Windows proxy ({1})", "تونل سیستم در دسترس نبود؛ اتصال با پروکسی ویندوز ادامه پیدا کرد ({1})", "warning", ""),
    (re.compile(r"^TUN health check failed; repairing the system tunnel$"), "System tunnel stalled; repairing", "تونل سیستم جواب نداد؛ در حال تعمیر خودکار", "warning", ""),
    (re.compile(r"^TUN repaired$"), "System tunnel repaired ✔", "تونل سیستم دوباره سالم شد ✔", "success", ""),
    (re.compile(r"^TUN cleanup: removed (\d+) leftover sing-box from a previous run$"), "Cleaned {1} leftover tunnel process from a previous run", "{1} پردازش تونل باقی‌مانده از اجرای قبلی پاک شد", "info", ""),
    (re.compile(r"^Site (\S+) via tunnel \((\S+)\)$"), "Site {1} → tunnel ({2})", "سایت {1} از تونل وصل شد ({2})", "info", ""),
    (re.compile(r"^Site (\S+) via direct \((\S+)\)$"), "Site {1} → direct ({2})", "سایت {1} مستقیم وصل شد ({2})", "info", ""),
    (re.compile(r"^Site (\S+) failed: (.+) \((\S+)\)$"), "Site {1} failed: {2} ({3})", "سایت {1} باز نشد: {2} ({3})", "warning", ""),
    (re.compile(r"^UAC PoW ready · Tunnel through (\w+) over (.+)$"), "Connected: {1} over {2}", "وصل شد: {1} روی {2}", "success", "connected"),
    (re.compile(r"^UAC PoW ready · Tunnel through (\w+)$"), "Connected: {1} (direct)", "وصل شد: {1} (مستقیم)", "success", "connected"),
    (re.compile(r"^UAC PoW ready · (WARP only|Tunnel VPN through WARP)$"), "Connected: {1}", "وصل شد: {1}", "success", "connected"),
    (re.compile(r"^UAC PoW ready · Proxy (\S+)$"), "Local proxy ready on {1}", "پروکسی محلی آماده است: {1}", "success", ""),
    (re.compile(r"^UAC PoW path lost: (.+)$"), "Connection dropped: {1}", "اتصال قطع شد: {1}", "error", "drop"),
    (re.compile(r"^UAC PoW cancelled$"), "Connect cancelled", "اتصال لغو شد", "warning", "stopped"),
    (re.compile(r"^UAC PoW failed: (.+)$"), "Connect failed: {1}", "اتصال ناموفق: {1}", "error", "failed"),
    (re.compile(r"^Outer attempt (\d+)/(\d+): (.+?) \((\d+)s.*$"), "Trying {3} (attempt {1}/{2}, up to {4}s)", "تلاش با {3} (دفعه {1} از {2}، تا {4} ثانیه)", "info", "attempt"),
    (re.compile(r"^(.+?) did not connect; fell back to (.+?), which is carrying the outer leg$"), "{1} failed → {2}", "{1} نشد ← {2}", "warning", "fallback"),
    (re.compile(r"^(\S+) is carrying the outer leg$"), "{1} is carrying the tunnel", "{1} تونل را می‌برد", "success", ""),
    (re.compile(r"^No WARP transport came up; Psiphon will connect on its own$"), "WARP did not come up → Psiphon alone", "وارپ بالا نیامد ← سایفون به‌تنهایی", "warning", "fallback"),
    (re.compile(r"^Tunnel did not stay up on (\S+?)\.? .*$"), "{1} stopped working; looking for another clean IP", "{1} از کار افتاد؛ جستجوی آی‌پی تمیز دیگر", "warning", "reconnect"),
    (re.compile(r"^Key: saved WARP key and MASQUE certificate found.*$"), "Using the saved WARP key and certificate", "استفاده از کلید و گواهی ذخیره‌شده وارپ", "success", ""),
    (re.compile(r"^Key fetch: (\S+) won the race.*$"), "Key route: {1} won", "مسیر کلید: {1} برنده شد", "success", ""),
    (re.compile(r"^Key fetch done in (\S+) via (\S+)$"), "Key ready in {1} via {2}", "کلید در {1} با {2} آماده شد", "success", ""),
    (re.compile(r"^Cert: MASQUE certificate saved.*$"), "MASQUE certificate saved", "گواهی MASQUE ذخیره شد", "success", ""),
    (re.compile(r"^Clean IP for key/cert: (\S+) .*$"), "Clean IP for the key request: {1}", "آی‌پی تمیز برای گرفتن کلید: {1}", "success", ""),
    (re.compile(r"^Saved clean HTTP/2 address (\S+)$"), "Clean IP found and saved: {1}", "آی‌پی تمیز پیدا و ذخیره شد: {1}", "success", ""),
    (re.compile(r"^Saved clean address accepted (\S+)$"), "Saved clean IP still works: {1}", "آی‌پی تمیز ذخیره‌شده هنوز کار می‌کند: {1}", "success", ""),
    (re.compile(r"^Clean list empty\..*$"), "No saved clean IP; scanning", "آی‌پی تمیز ذخیره‌شده‌ای نیست؛ اسکن شروع شد", "info", ""),
    (re.compile(r"^Psiphon connected via (\S+)$"), "Psiphon connected (strategy {1})", "سایفون وصل شد (روش {1})", "success", ""),
    (re.compile(r"^Exit IP (\S+) \((\w+)\)$"), "Exit IP {1} ({2})", "آی‌پی خروجی {1} ({2})", "success", ""),
    (re.compile(r"^Parallel MASQUE: session to (\S+) is up on (\d+); (\d+) sessions.*$"), "Parallel: session {1} is up · {3} sessions", "موازی: نشست {1} بالا آمد · {3} نشست", "success", "parallel"),
    (re.compile(r"^Parallel MASQUE sessions: (.+)$"), "Parallel sessions: {1}", "نشست‌های موازی: {1}", "info", "parallel"),
    (re.compile(r"^Speed options on: (.+)$"), "Speed features on: {1}", "قابلیت‌های سرعت روشن: {1}", "info", "start"),
    (re.compile(r"^Setting changed: (.+) \(applies on next connect\)$"), "Setting changed: {1} (applies on next connect)", "تغییر تنظیم: {1} (در اتصال بعدی اعمال می‌شود)", "info", "setting"),
    (re.compile(r"^Setting changed: (.+)$"), "Setting changed: {1}", "تغییر تنظیم: {1}", "info", "setting"),
    (re.compile(r"^Engine switched to (\w+)$"), "Engine: {1}", "موتور: {1}", "info", ""),
    (re.compile(r"^Key fetch for (\S+): racing .*?\(up to (\d+s)\)$"), "Getting the WARP key for {1}: racing ECH, split hello and direct (up to {2})", "گرفتن کلید وارپ برای {1}: رقابت ECH، تقسیم ClientHello و مستقیم (تا {2})", "info", "start"),
    (re.compile(r"^Clean-IP scan for the key/cert request: probing (\d+) addresses.*$"), "Looking for a clean IP for the key request ({1} addresses)", "جستجوی آی‌پی تمیز برای گرفتن کلید ({1} آدرس)", "info", ""),
    (re.compile(r"^Trying saved clean address (\S+)$"), "Trying saved clean IP {1}", "امتحان آی‌پی تمیز ذخیره‌شده {1}", "info", ""),
    (re.compile(r"^Connecting MASQUE over (\S+) · .*$"), "Connecting MASQUE over {1}", "اتصال MASQUE روی {1}", "info", ""),
    (re.compile(r"^HTTP/(\d) started$"), "MASQUE HTTP/{1} session started", "نشست MASQUE روی HTTP/{1} شروع شد", "info", ""),
    (re.compile(r"^Windows system proxy enabled HTTP=(\d+) SOCKS=(\d+)$"), "Windows proxy on (HTTP {1}, SOCKS {2})", "پروکسی ویندوز روشن شد (HTTP {1}، SOCKS {2})", "success", ""),
    (re.compile(r"^Connected in (.+)$"), "Psiphon exit: {1}", "خروجی سایفون: {1}", "success", ""),
]

_SUCCESS = re.compile(r"\b(ready|won|saved|accepted|is up|started|connected|done)\b", re.I)
_WARNING = re.compile(r"timeout|did not|fall(?:s|ing)? ?back|fell back|cancel|not used|skipped|no second|retry|stopped working", re.I)
_ERROR = re.compile(r"\b(error|fail(?:ed|ure)?|lost|exited|denied|exception|fatal)\b", re.I)


@dataclass
class Entry:
    stamp: str
    raw: str
    cat: str
    level: str
    phase: str
    noise: bool
    en: str
    fa: str
    event: str = ""
    translated: bool = False
    pulse: bool = True
    extra: dict = field(default_factory=dict)


def _fill(template: str, match: re.Match) -> str:
    return re.sub(r"\{(\d)\}", lambda m: match.group(int(m.group(1))) or "", template)


def classify(message: str, stamp: str = "") -> Entry:
    """One log line -> Entry (category, level, phase, plain text en/fa)."""
    text = str(message).strip()
    matched = _STAMP_RE.match(text)
    if matched and not stamp:
        stamp, text = matched.group(1), matched.group(2).strip()
    stamp = stamp or time.strftime("%H:%M:%S")
    cat = "APP"
    for rule, name in _CATEGORY_RULES:
        if rule.search(text):
            cat = name
            break
    noise, pulse = False, True
    for rule, name in _NOISE_RULES:
        if rule.search(text):
            noise = True
            if name == "ECHO":
                pulse = False
            else:
                cat = name
            break
    if _ERROR.search(text):
        level = "error"
    elif _WARNING.search(text):
        level = "warning"
    elif _SUCCESS.search(text):
        level = "success"
    else:
        level = "info"
    en, fa, event, translated = text, text, "", False
    for rule, en_t, fa_t, lvl, ev in _REWRITES:
        hit = rule.match(text)
        if hit:
            en, fa, level, event, translated = _fill(en_t, hit), _fill(fa_t, hit), lvl, ev, True
            break
    if cat == "SET":
        event, level = "setting", "info"
    if noise:
        level = "muted"
    elif cat == "SCAN" and level == "success" and not translated:
        level = "info"
    if cat == "DROP" and not event:
        event = "drop" if level == "error" else "reconnect"
    phase = _CATEGORY_PHASE.get(cat, "app")
    if cat == "NET" and not re.match(r"^(?:Exit IP|Public IP|Connected in)", text):
        phase = ""  # belongs to whatever phase it shows up in
    return Entry(stamp, text, cat, level, phase, noise, en, fa, event, translated, pulse)


# -- rows (sections + collapse) -----------------------------------------------------


@dataclass
class Row:
    kind: str  # "section" | "entry" | "pulse"
    entry: Entry | None = None
    count: int = 1
    phase: str = ""
    first_stamp: str = ""
    key: str = ""


def _collapse_key(entry: Entry, details: bool) -> str:
    text = entry.raw if details else entry.en
    return f"{entry.cat}|{entry.level}|{text}"


class LogModel:
    """All lines (capped) + the derived, collapsed view."""

    def __init__(self, limit: int = 5000):
        self.limit = limit
        self.entries: list[Entry] = []
        self.state = LogState()

    def add(self, message: str, stamp: str = "", now: float | None = None) -> Entry:
        entry = classify(message, stamp)
        self.entries.append(entry)
        if len(self.entries) > self.limit:
            del self.entries[: len(self.entries) - self.limit]
        self.state.feed(entry, now)
        if entry.event == "connected":
            self._connected_entry = entry
            entry.extra.update(parallel=0)
        elif entry.event in ("drop", "stopped", "failed") or entry.event == "start":
            self._connected_entry = None
        target = getattr(self, "_connected_entry", None)
        if target is not None:
            if entry.cat == "NET" and self.state.exit_ip and entry.raw.startswith(("Exit IP", "Public IP")):
                target.extra.update(exit_ip=self.state.exit_ip, country=self.state.exit_country)
            if entry.cat == "PARALLEL" and self.state.parallel:
                target.extra.update(parallel=self.state.parallel)
        return entry

    def clear(self) -> None:
        self.entries.clear()

    def rows(self, details: bool = False, query: str = "", sections: bool = True, max_rows: int = 1500) -> list[Row]:
        q = query.strip().lower()
        items: list[Row] = []
        for entry in self.entries:
            if q and q not in entry.raw.lower() and q not in entry.en.lower() and q not in entry.fa.lower():
                continue
            last = items[-1] if items else None
            if entry.noise and not details:
                if not entry.pulse:
                    continue
                key, kind = "pulse|" + entry.cat, "pulse"
            else:
                key, kind = _collapse_key(entry, details), "entry"
            if last is not None and last.kind == kind and last.key == key:
                last.count += 1
                last.entry = entry
                continue
            items.append(Row(kind, entry, 1, entry.phase, entry.stamp, key))
        if len(items) > max_rows:
            items = items[-max_rows:]
        if not sections:
            return items
        # Phase per row; rows without a phase inherit the previous one.
        phase = ""
        for row in items:
            phase = row.phase or phase or "app"
            row.phase = phase
        # Smooth: a lone row between two rows of one phase joins
        # that phase, so interleaved engine lines do not spray headers.
        for i, row in enumerate(items):
            if row.phase in ("connected", "drop", "key", "scan"):
                continue
            j = i
            while j < len(items) and items[j].phase == row.phase:
                j += 1
            if i > 0 and j - i <= 1 and items[i - 1].phase != row.phase:
                before = items[i - 1].phase
                after = items[j].phase if j < len(items) else before
                if before == after and before not in ("connected", "drop"):
                    for k in range(i, j):
                        items[k].phase = before
        out: list[Row] = []
        current = None
        for row in items:
            if row.phase != current:
                current = row.phase
                out.append(Row("section", phase=current))
            out.append(row)
        return out

    def plain_text(self) -> str:
        return "\n".join(f"[{e.stamp}] {e.raw}" for e in self.entries)


# -- summary state -------------------------------------------------------------------

_EXIT_RE = re.compile(r"^(?:Exit IP|Public IP \(PoW exit\):) (\S+) \(?([A-Z]{2})?\)?")
_SESSIONS_RE = re.compile(r"(\d+) sessions")


@dataclass
class LogState:
    status: str = "idle"  # idle | connecting | connected | dropped
    route: str = ""
    exit_ip: str = ""
    exit_country: str = ""
    parallel: int = 0
    connected_at: float | None = None
    last_drop: str = ""
    last_drop_stamp: str = ""
    drops: int = 0
    history: list = field(default_factory=list)

    def feed(self, entry: Entry, now: float | None = None) -> None:
        now = time.time() if now is None else now
        text = entry.raw
        if entry.event in ("start", "attempt") and self.status != "connected":
            if self.status in ("idle", "dropped"):
                self.parallel = 0
            self.status = "connecting"
        if entry.event == "connected":
            self.status = "connected"
            self.connected_at = now
            hit = re.search(r"Tunnel through (.+)$|· (WARP only|Tunnel VPN through WARP)$", text)
            if hit:
                self.route = (hit.group(1) or hit.group(2) or "").strip()
        elif entry.event == "drop":
            self.status = "dropped"
            self.connected_at = None
            self.last_drop = text.split(":", 1)[-1].strip() if ":" in text else text
            self.last_drop_stamp = entry.stamp
            self.drops += 1
            self.parallel = 0
        elif entry.event in ("stopped", "failed"):
            self.status = "idle"
            self.connected_at = None
            self.parallel = 0
            if entry.event == "failed":
                self.last_drop = entry.en
                self.last_drop_stamp = entry.stamp
        elif text.startswith(("UAC PoW stopped", "UAC PoW disconnected")):
            self.status = "idle"
            self.connected_at = None
            self.parallel = 0
        hit = _EXIT_RE.match(text)
        if hit:
            self.exit_ip = hit.group(1)
            self.exit_country = (hit.group(2) or "").upper()
        if entry.cat == "PARALLEL":
            sessions = _SESSIONS_RE.search(text)
            if sessions:
                self.parallel = int(sessions.group(1))
            elif text.startswith("Parallel MASQUE sessions:"):
                self.parallel = len([p for p in text.split(":", 1)[1].split(";") if p.strip()])

    def uptime(self, now: float | None = None) -> str:
        if self.status != "connected" or self.connected_at is None:
            return ""
        seconds = max(0, int((time.time() if now is None else now) - self.connected_at))
        hours, rest = divmod(seconds, 3600)
        minutes, secs = divmod(rest, 60)
        return f"{hours}:{minutes:02d}:{secs:02d}" if hours else f"{minutes:02d}:{secs:02d}"


# -- settings diff -------------------------------------------------------------------

#: PowSettings field -> (English name, Persian name, applies live?)
SETTING_NAMES: dict[str, tuple[str, str]] = {
    "parallel_masque": ("Parallel MASQUE", "MASQUE موازی"),
    "irancell_h3": ("HTTP/3 on Irancell", "HTTP/3 روی ایرانسل"),
    "direct_psiphon_first": ("Direct Psiphon first", "اول سایفون مستقیم"),
    "lowest_rtt_ip": ("Lowest-latency clean IP", "آی‌پی تمیز کم‌تأخیر"),
    "outer_transport": ("Transport", "ترابری"),
    "firewall_profile": ("Firewall", "فایروال"),
    "chain_psiphon": ("Psiphon chain", "زنجیره سایفون"),
    "optimized_mode": ("Optimized", "حالت بهینه"),
    "h2_fragmentation": ("HTTP/2 fragmentation", "فرگمنت HTTP/2"),
    "exit_country_code": ("Exit country", "کشور خروجی"),
    "key_fetch": ("Key fetch", "دریافت کلید"),
    "scan_mode": ("IP scan", "اسکن آی‌پی"),
    "link_recipe": ("Link recipe", "دستور اتصال"),
}


def _value_text(value) -> str:
    if isinstance(value, bool):
        return "on" if value else "off"
    if value in ("", None):
        return "auto"
    return str(value)


def setting_changes(old, new, connected: bool) -> list[str]:
    """'Setting changed: X on/off' lines for the fields that changed."""
    lines = []
    for name, (label, _fa) in SETTING_NAMES.items():
        if not hasattr(old, name) or not hasattr(new, name):
            continue
        before, after = getattr(old, name), getattr(new, name)
        if before == after:
            continue
        suffix = " (applies on next connect)" if connected else ""
        if isinstance(after, bool):
            lines.append(f"Setting changed: {label} {_value_text(after)}{suffix}")
        else:
            lines.append(f"Setting changed: {label} {_value_text(before)} → {_value_text(after)}{suffix}")
    return lines


# -- HTML rendering --------------------------------------------------------------------

LRE, PDF = "\u202a", "\u202c"
LRM, RLM = "\u200e", "\u200f"
_LATIN_RUN = re.compile(r"[A-Za-z0-9][A-Za-z0-9 .:/\-_·()×+%]*[A-Za-z0-9)%]|[A-Za-z0-9]")


def ltr_runs(text: str) -> str:
    """Isolate Latin runs (IPs, ports, tags) inside RTL Persian lines.

    Prefer LRM markers around Latin tokens. Qt's QTextEdit HTML path mishandles
    LRE/PDF isolates and used to garble mixed FA+EN log lines.
    """
    return _LATIN_RUN.sub(lambda m: f"{LRM}{m.group(0)}{LRM}", text)


def ltr_html(text: str) -> str:
    """HTML-escaped text with Latin runs wrapped in dir=ltr spans."""
    parts = []
    last = 0
    for match in _LATIN_RUN.finditer(text):
        if match.start() > last:
            parts.append(_esc(text[last:match.start()]))
        parts.append(
            f'<span dir="ltr" style="unicode-bidi: isolate;">{_esc(match.group(0))}</span>'
        )
        last = match.end()
    if last < len(text):
        parts.append(_esc(text[last:]))
    return "".join(parts)


def _esc(text: str) -> str:
    return html.escape(text, quote=False)


def _connected_suffix(entry: Entry, fa: bool) -> tuple[str, str]:
    """(plain text, country) appended to a Connected row: exit IP and parallel count."""
    extra = entry.extra or {}
    bits = []
    if extra.get("exit_ip"):
        bits.append(("خروجی " if fa else "exit ") + extra["exit_ip"])
    if extra.get("parallel", 0) >= 2:
        bits.append(f"{extra['parallel']} " + ("نشست موازی" if fa else "parallel sessions"))
    return (" · ".join(bits), extra.get("country", ""))


def row_text(row: Row, language: str = "en", details: bool = False) -> tuple[str, str]:
    """(text, direction) for one non-section row."""
    entry = row.entry
    fa = language == "fa"
    if row.kind == "pulse":
        en_t, fa_t = _PULSE_TEXT.get(entry.cat, ("Engine activity", "فعالیت موتور"))
        return (fa_t if fa else en_t) + "…", "rtl" if fa else "ltr"
    if details:
        return entry.raw, "ltr"
    if fa and entry.translated:
        text, direction = entry.fa, "rtl"
    else:
        text, direction = entry.en, "ltr"
    if entry.event == "connected":
        suffix, _country = _connected_suffix(entry, fa and direction == "rtl")
        if suffix:
            text = f"{text} · {suffix}"
    return text, direction


def render_text(rows: list[Row], language: str = "en", details: bool = False) -> str:
    """Plain-text version of the view (Copy / Export)."""
    lines = []
    for row in rows:
        if row.kind == "section":
            en_title, fa_title = PHASES.get(row.phase, (row.phase, row.phase))
            lines.append(f"── {fa_title if language == 'fa' else en_title.upper()} ──")
            continue
        label = CATEGORY_TAGS.get(row.entry.cat, ("LOG", ""))[0]
        text, _direction = row_text(row, language, details)
        count = f" ×{row.count}" if row.count > 1 else ""
        lines.append(f"{row.entry.stamp}  {label:<8} {text}{count}")
    return "\n".join(lines)


def render_html(rows: list[Row], language: str = "en", details: bool = False, mono: str = "JetBrains Mono", flag_path=None) -> str:
    fa = language == "fa"
    direction = "rtl" if fa else "ltr"
    align = "right" if fa else "left"
    parts = []
    for row in rows:
        if row.kind == "section":
            en_title, fa_title = PHASES.get(row.phase, (row.phase, row.phase))
            title = fa_title if fa else en_title.upper()
            parts.append(
                f'<p dir="{direction}" align="{align}" style="margin-top:12px; margin-bottom:4px;">'
                f'<span style="color:#5b6b7d;">── </span>'
                f'<span style="color:#8a9aac; font-size:11px;{"" if fa else " letter-spacing:1px;"}">{_esc(title)}</span>'
                f'<span style="color:#5b6b7d;"> ──</span></p>'
            )
            continue
        entry = row.entry
        assert entry is not None
        label, tag_color = CATEGORY_TAGS.get(entry.cat, ("LOG", "#8394a6"))
        padded = _esc(label) + "&nbsp;" * max(0, 8 - len(label))
        tag = f'<span dir="ltr" style="color:{tag_color}; font-family:\'{mono}\'; font-size:11px; unicode-bidi:isolate;">{padded}</span>'
        stamp = f'<span dir="ltr" style="color:#5f6f80; font-family:\'{mono}\'; font-size:11px; unicode-bidi:isolate;">{_esc(entry.stamp)}</span>'
        text, block_dir = row_text(row, language, details)
        color = LEVEL_COLORS["muted"] if row.kind == "pulse" else LEVEL_COLORS.get(entry.level, LEVEL_COLORS["info"])
        body = ltr_html(text) if block_dir == "rtl" else _esc(text)
        flag = ""
        if flag_path is not None and row.kind == "entry" and not details:
            country = ""
            if entry.event == "connected":
                country = (entry.extra or {}).get("country", "")
            else:
                hit = re.match(r"^Exit IP \S+ \((\w\w)\)$", entry.raw)
                country = hit.group(1) if hit else ""
            path = flag_path(country) if country else ""
            if path:
                flag = f'&nbsp;<img src="{html.escape(path)}" width="16" height="12">'

        count = ""
        if row.count > 1:
            count = f' <span dir="ltr" style="color:#7d8c9c; font-family:\'{mono}\'; font-size:11px; unicode-bidi:isolate;">×{row.count}</span>'
        style = "margin-top:2px; margin-bottom:2px;"
        if entry.event in ("connected", "drop", "fallback", "reconnect", "setting", "failed") and row.kind == "entry":
            bg = {
                "connected": "#0f2a24", "drop": "#2e1419", "failed": "#2e1419",
                "fallback": "#2b2412", "reconnect": "#2b2412", "setting": "#17212d",
            }[entry.event]
            style += f" background-color:{bg};"
        block_align = "right" if block_dir == "rtl" else "left"
        # RLM between the pieces so time, tag and an IP-first message never
        # merge into one LTR run inside a Persian line.
        sep = "\u200f&nbsp;&nbsp;" if block_dir == "rtl" else "&nbsp;&nbsp;"
        parts.append(
            f'<p dir="{block_dir}" align="{block_align}" style="{style}">{stamp}{sep}{tag}{sep}'
            f'<span style="color:{color};">{body}</span>{flag}{count}</p>'
        )
    return "".join(parts)
