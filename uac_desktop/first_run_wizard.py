"""First-run / post-update setup wizard ("Quick start").

Friendly Q&A dialog that detects: existing configs, carrier (ASN) and - more
importantly - the line's DPI *behaviour*, reads the old connect log and then
runs one flow with a live step log:

* ``sni``  (MCI-type, domain-name filtering): fetch the Patterniha list, live
  test it and add the healthy (ECH) configs to User Config.
* ``ip``   (Irancell-type, spoof / clean IP works): find the carrier's clean
  IPs and cache them; connect uses them automatically.

Existing profiles/settings are never removed or edited; the wizard only adds.
Pure logic (log analysis, DPI classification, show rules) is Qt-free and tested.
"""
from __future__ import annotations

import concurrent.futures as _futures
import re
import threading
import time
from pathlib import Path
from typing import Callable, Iterable

from PySide6.QtCore import QObject, QRectF, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import (QDialog, QFrame, QGridLayout, QHBoxLayout, QLabel, QListWidget, QListWidgetItem,
                               QProgressBar, QPushButton, QStackedWidget, QVBoxLayout, QWidget)

PATTERNIHA_URL = "https://raw.githubusercontent.com/patterniha/Free-Configs/main/configs.txt"
SETTING_KEY = "wizard_seen_version"
ECH_OUTER_SNI = "cloudflare-ech.com"

# ASN -> (dpi family hint, fa label, en label)
KNOWN_ASN = {
    197207: ("mci", "همراه اول", "MCI"),
    44244: ("irancell", "ایرانسل", "Irancell"),
    57218: ("irancell", "رایتل", "RighTel"),
    58224: ("tci", "مخابرات", "TCI"),
    12880: ("tci", "مخابرات (DCI)", "TCI / DCI"),
    48159: ("tci", "مخابرات (TIC)", "TCI / TIC"),
    16322: ("isp", "پارس‌آنلاین", "ParsOnline"),
    31549: ("isp", "شاتل", "Shatel"),
    43754: ("isp", "آسیاتک", "Asiatech"),
    44208: ("isp", "فن‌آوا", "Fanava"),
    25184: ("isp", "افرانت", "Afranet"),
    49100: ("isp", "پیشگامان", "Pishgaman"),
}


# ------------------------------------------------------------------ logic
def should_show(settings: dict, version: str) -> bool:
    """Fresh install or first launch after an update."""
    return str((settings or {}).get(SETTING_KEY, "") or "") != str(version)


def mark_seen(settings: dict, version: str) -> None:
    settings[SETTING_KEY] = str(version)


_TS = re.compile(r"^\[[0-9:]+\]\s*")


def analyze_log(text: str, recent: int = 8) -> dict:
    """Outcome of past connect attempts from the persistent log."""
    events = []
    for raw in str(text or "").splitlines():
        line = _TS.sub("", raw).strip()
        if line.startswith("===== CONNECTED"):
            events.append("ok")
        elif line.startswith("CONNECT FAIL"):
            events.append("fail")
    last = events[-recent:]
    ok, fail = last.count("ok"), last.count("fail")
    if not last:
        state = "none"
    elif last[-1] == "fail" or fail > ok:
        state = "failing"
    else:
        state = "working"
    return {"state": state, "ok": ok, "fail": fail, "attempts": len(last),
            "total": len(events), "last": last[-1] if last else ""}


def read_log_tail(path, max_bytes: int = 1_500_000) -> str:
    try:
        p = Path(path)
        with p.open("rb") as fh:
            size = p.stat().st_size
            if size > max_bytes:
                fh.seek(size - max_bytes)
            return fh.read().decode("utf-8", errors="replace")
    except Exception:
        return ""


def carrier_from_asn(asn, isp: str = "") -> dict:
    digits = re.sub(r"\D", "", str(asn or ""))
    number = int(digits) if digits else 0
    family, fa, en = KNOWN_ASN.get(number, ("", "", ""))
    low = str(isp or "").lower()
    if not family:
        hit = isp_family(low)
        if hit:
            family, fa, en = hit
    if not fa:
        name = str(isp or "").strip() or ("AS%d" % number if number else "")
        fa = en = name or "-"
    return {"family": family or "isp", "fa": fa, "en": en,
            "asn": "AS%d" % number if number else "", "isp": str(isp or "")}


NAME_MAP = (
    (("hamrah", "mobile communication", "mcci", "mci "), 197207),
    (("irancell", "mtn"), 44244),
    (("rightel", "righ tel"), 57218),
    (("iran telecommunication", "telecommunication company of iran", "mokhaberat", "tci ", "dci", "data communication"), 58224),
    (("parsonline", "pars online"), 16322), (("shatel",), 31549), (("asiatech", "asia tech"), 43754),
    (("fanava",), 44208), (("afranet",), 25184), (("pishgaman",), 49100),
)


def isp_family(name: str):
    low = " " + str(name or "").lower().replace("-", " ").replace("_", " ") + " "
    for keys, asn in NAME_MAP:
        if any(k in low for k in keys):
            return KNOWN_ASN[asn]
    return None


def cache_carrier(family: str, dpi: str) -> str:
    """Bucket used by clean_ip cache / carrier tunings (mci, irancell, auto)."""
    if family in {"mci", "irancell"}:
        return family
    return "mci" if dpi == "sni" else "irancell" if dpi == "ip" else "auto"


def classify_dpi(reachable: int, frag_ok: int, family: str = "") -> dict:
    """Behaviour first, ASN only as a tie-breaker.

    On edges that answer a normal HTTPS request, send the same TLS ClientHello
    split into small TCP segments (what the spoof/fragment route relies on):
    * fragmented hello still gets an HTTP answer -> 'ip'  (Irancell-type)
    * fragmented hello is killed                 -> 'sni' (MCI-type: reads the
      whole hello and filters by domain name, so ECH is needed)
    * no reachable edge                          -> ASN hint
    """
    reachable = max(int(reachable or 0), 0)
    ratio = (frag_ok / reachable) if reachable else 0.0
    if reachable >= 2:
        dpi = "ip" if ratio >= 0.34 else "sni"
        conf = "high" if (ratio >= 0.6 or ratio <= 0.1) else "medium"
        return {"dpi": dpi, "confidence": conf, "frag_ratio": ratio, "reachable": reachable, "by": "probe"}
    hint = "ip" if family == "irancell" else "sni"
    return {"dpi": hint, "confidence": "low", "frag_ratio": ratio, "reachable": reachable, "by": "asn"}


_TRACE = "GET /cdn-cgi/trace HTTP/1.1\r\nHost: {h}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"


def tls_http_probe(ip: str, sni: str, chunk: int = 0, timeout: float = 3.0) -> bool:
    """Real HTTP request over TLS (not just a handshake). chunk>0 splits the
    ClientHello into small TCP segments. Never raises."""
    import socket
    import ssl
    sock = None
    try:
        sock = socket.create_connection((ip, 443), timeout=timeout)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
        obj = ctx.wrap_bio(inc, out, server_hostname=sni)
        first = True; end = time.monotonic() + timeout
        while True:
            if time.monotonic() > end:
                return False
            try:
                obj.do_handshake(); break
            except ssl.SSLWantReadError:
                pass
            data = out.read()
            if data:
                if first and chunk:
                    for i in range(0, len(data), chunk):
                        sock.sendall(data[i:i + chunk]); time.sleep(0.01)
                else:
                    sock.sendall(data)
                first = False
            got = sock.recv(65536)
            if not got:
                return False
            inc.write(got)
        pending = out.read()
        if pending:
            sock.sendall(pending)
        obj.write(_TRACE.format(h=sni).encode()); sock.sendall(out.read())
        while time.monotonic() <= end:
            got = sock.recv(65536)
            if not got:
                return False
            inc.write(got)
            try:
                return obj.read(16).startswith(b"HTTP/")
            except ssl.SSLWantReadError:
                continue
        return False
    except Exception:
        return False
    finally:
        try:
            if sock is not None:
                sock.close()
        except Exception:
            pass


def dpi_probe(ips: Iterable, probe: Callable = tls_http_probe, want: int = 6, workers: int = 24,
              cancel: threading.Event | None = None) -> dict:
    """reachable = edges answering plain HTTPS; frag_ok = of those, how many still
    answer when the ClientHello is fragmented."""
    ips = list(dict.fromkeys(i for i in ips if i))
    if not ips:
        return {"reachable": 0, "frag_ok": 0, "tested": 0}
    with _futures.ThreadPoolExecutor(max_workers=min(workers, len(ips))) as pool:
        flags = list(pool.map(lambda ip: bool(probe(ip, ECH_OUTER_SNI, 0)), ips))
    good = [ip for ip, ok in zip(ips, flags) if ok][:want]
    if cancel is not None and cancel.is_set() or not good:
        return {"reachable": len(good), "frag_ok": 0, "tested": len(ips)}
    with _futures.ThreadPoolExecutor(max_workers=len(good)) as pool:
        frag = list(pool.map(lambda ip: bool(probe(ip, "chatgpt.com", 8)), good))
    return {"reachable": len(good), "frag_ok": sum(frag), "tested": len(ips)}


def _parse_source(kind: str, body: str) -> dict | None:
    import json
    asn, isp, country = "", "", ""
    if kind == "sdk":
        d = json.loads(body); isp = d.get("ispName", ""); country = (d.get("location") or {}).get("countryCode", "")
    elif kind == "xml":
        m = re.search(r"<client [^>]*>", body or "")
        if not m:
            return None
        tag = m.group(0)
        isp = (re.search(r'isp="([^"]*)"', tag) or [None, ""])[1]
        country = (re.search(r'country="([^"]*)"', tag) or [None, ""])[1]
    else:
        d = json.loads(body)
        conn = d.get("connection") if isinstance(d.get("connection"), dict) else {}
        asn = str(conn.get("asn") or d.get("asn") or d.get("as") or "")
        isp = conn.get("isp") or d.get("isp") or d.get("org") or ""
        country = d.get("countryCode") or d.get("country_code") or ""
    m = re.search(r"(\d{3,7})", asn)
    info = carrier_from_asn(m.group(1) if m else "", isp)
    if not info["asn"] and not isp:
        return None
    info["country"] = str(country or "").upper()
    return info


# (url, parser, weight) - Speedtest first (the user's reference), queried direct.
IDENTITY_SOURCES = (
    ("https://www.speedtest.net/api/js/config-sdk?engine=js", "sdk", 3),
    ("https://www.speedtest.net/speedtest-config.php", "xml", 2),
    ("http://ip-api.com/json/?fields=as,isp,org,countryCode", "json", 2),
    ("http://www.speedtest.net/speedtest-config.php", "xml", 1),
    ("https://ipwho.is/", "json", 1),
)
_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126 Safari/537.36"


def pick_identity(results: list) -> dict:
    """Weighted vote. Iranian answers beat foreign transit egress (MCI's HTTPS
    often exits via Azerbaijan/TCI, which fooled the old single lookup)."""
    results = [r for r in results if r]
    if not results:
        return carrier_from_asn("", "")
    iranian = [r for r in results if r[0].get("country") == "IR" or r[0]["family"] in {"mci", "irancell", "tci"}]
    pool = iranian or results
    score: dict = {}
    for info, weight in pool:
        key = info["en"]
        score[key] = score.get(key, 0) + weight
    best = max(score, key=lambda k: score[k])
    info = dict(next(i for i, _w in pool if i["en"] == best))
    info["votes"] = score
    return info


def lookup_identity(timeout: float = 5.0, get=None) -> dict:
    if get is None:
        import requests
        session = requests.Session(); session.trust_env = False  # bypass app proxy
        get = lambda url: session.get(url, timeout=timeout, headers={"User-Agent": _UA, "Accept": "*/*"}).text

    def one(src):
        url, kind, weight = src
        try:
            info = _parse_source(kind, get(url))
            return (info, weight) if info else None
        except Exception:
            return None
    with _futures.ThreadPoolExecutor(max_workers=len(IDENTITY_SOURCES)) as pool:
        results = list(pool.map(one, IDENTITY_SOURCES))
    return pick_identity(results)


# ------------------------------------------------------------------ bidi helpers
FSI, PDI, RLM = "\u2068", "\u2069", "\u200f"
# Windows has no flag emoji (shows 'DE' letters) -> no flags there.
SHOW_FLAGS = not __import__("sys").platform.startswith("win")
_FA_DIGITS = str.maketrans("0123456789", "۰۱۲۳۴۵۶۷۸۹")
_LATIN_RUN = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?|[A-Za-z][A-Za-z0-9.:/_\-@#]*(?:[ ·|]+[A-Za-z0-9][A-Za-z0-9.:/_\-@#]*)*")


def iso(text) -> str:
    return f"{FSI}{text}{PDI}"


def fa_text(text) -> str:
    """Persian-safe: isolate Latin runs (names, IPs, AS numbers) so the order
    never flips; Persian digits everywhere else."""
    text = str(text or "")
    if not text:
        return text

    def plain(part):
        # Persian zero looks like a dot, so never use '·' between Persian words.
        return part.replace(" · ", "، ").replace("·", "،").translate(_FA_DIGITS)
    out, last = [], 0
    for m in _LATIN_RUN.finditer(text):
        out.append(plain(text[last:m.start()])); out.append(iso(m.group(0))); last = m.end()
    out.append(plain(text[last:]))
    return RLM + "".join(out)


def ms_label(ms, language="fa") -> str:
    value = int(round(float(ms or 0)))
    return f"{str(value).translate(_FA_DIGITS)} میلی‌ثانیه" if language != "en" else f"{value} ms"


# ------------------------------------------------------------------ widgets
_MASCOTS: dict = {}


def mascot_pixmap(mood: str, height: int = 118):
    """Guide character from assets/wizard (None when missing -> emoji fallback)."""
    if mood in _MASCOTS:
        return _MASCOTS[mood]
    pix = None
    try:
        from PySide6.QtGui import QPixmap
        from .paths import ASSETS
        names = {"normal": "01_normal", "thinking": "02_thinking", "waiting": "03_waiting", "happy": "04_happy",
                 "sad": "05_sad", "guiding_right": "06_guiding_right", "confused": "07_confused",
                 "surprised": "08_surprised"}
        path = ASSETS / "wizard" / f"wizard_{names.get(mood, mood)}.png"
        if path.exists():
            loaded = QPixmap(str(path))
            if not loaded.isNull():
                pix = loaded.scaledToHeight(height, Qt.SmoothTransformation)
    except Exception:
        pix = None
    _MASCOTS[mood] = pix
    return pix

ACCENT = "#23f5e0"; OK = "#3ee08f"; BAD = "#ff6b81"; DIM = "#5d7690"


class StepIcon(QWidget):
    """pending dot / spinning arc / check / cross."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(22, 22)
        self.state = "pending"; self._angle = 0
        self._timer = QTimer(self); self._timer.setInterval(16); self._timer.timeout.connect(self._spin)

    def set_state(self, state: str):
        self.state = state
        if state == "run":
            self._timer.start()
        else:
            self._timer.stop()
        self.update()

    def _spin(self):
        self._angle = (self._angle + 9) % 360; self.update()

    def paintEvent(self, _event):
        p = QPainter(self); p.setRenderHint(QPainter.Antialiasing)
        r = QRectF(3, 3, 16, 16)
        if self.state == "run":
            p.setPen(QPen(QColor(255, 255, 255, 30), 2.4)); p.drawEllipse(r)
            pen = QPen(QColor(ACCENT), 2.4); pen.setCapStyle(Qt.RoundCap); p.setPen(pen)
            p.drawArc(r, -self._angle * 16, 100 * 16)
        elif self.state in ("ok", "fail", "warn"):
            color = QColor(OK if self.state == "ok" else BAD if self.state == "fail" else "#ffc857")
            p.setPen(Qt.NoPen); fill = QColor(color); fill.setAlpha(40); p.setBrush(fill); p.drawEllipse(r)
            pen = QPen(color, 2.2); pen.setCapStyle(Qt.RoundCap); p.setPen(pen)
            if self.state == "ok":
                p.drawLine(7, 11, 10, 14); p.drawLine(10, 14, 15, 8)
            elif self.state == "fail":
                p.drawLine(8, 8, 14, 14); p.drawLine(14, 8, 8, 14)
            else:
                p.drawLine(11, 7, 11, 12); p.drawPoint(11, 15)
        else:
            p.setPen(Qt.NoPen); p.setBrush(QColor(DIM)); p.drawEllipse(QRectF(8, 8, 6, 6))
        p.end()


class StepRow(QFrame):
    def __init__(self, text: str, parent=None, fx=None):
        super().__init__(parent)
        self.fx = fx or (lambda v: v)
        self.setObjectName("wizStep")
        lay = QHBoxLayout(self); lay.setContentsMargins(4, 3, 4, 3); lay.setSpacing(10)
        self.icon = StepIcon(); self.label = QLabel(self.fx(text)); self.label.setObjectName("wizStepText")
        self.detail = QLabel(""); self.detail.setObjectName("wizStepDetail")
        lay.addWidget(self.icon); lay.addWidget(self.label, 1); lay.addWidget(self.detail)

    def set(self, state: str, text: str | None = None, detail: str | None = None):
        self.icon.set_state(state)
        self.setProperty("state", state)
        if text is not None:
            self.label.setText(self.fx(text))
        if detail is not None:
            self.detail.setText(self.fx(detail))
        self.label.setStyleSheet("color: %s;" % ("#eaf6ff" if state != "pending" else "#7f97ad"))


class StepLog(QWidget):
    """Step list + progress + counters + best-found card + friendly activity
    feed (never raw core output). Updates are throttled (250 ms)."""

    FEED_MAX = 80

    def __init__(self, t, parent=None, fx=None, rtl=False):
        super().__init__(parent)
        self.t = t; self.rows: dict = {}; self.fx = fx or (lambda v: v)
        self._pending: list = []; self._progress = None
        direction = Qt.RightToLeft if rtl else Qt.LeftToRight
        self.setLayoutDirection(direction)
        root = QVBoxLayout(self); root.setContentsMargins(0, 0, 0, 0); root.setSpacing(8)
        self.box = QFrame(); self.box.setObjectName("wizCard")
        self.list = QVBoxLayout(self.box); self.list.setContentsMargins(14, 10, 14, 10); self.list.setSpacing(2)
        root.addWidget(self.box)
        bar_row = QHBoxLayout(); bar_row.setSpacing(10)
        self.progress = QProgressBar(); self.progress.setObjectName("wizProgress"); self.progress.setTextVisible(False)
        self.progress.setFixedHeight(6); self.progress.setRange(0, 0); self.progress.setLayoutDirection(direction)
        self.counter = QLabel(""); self.counter.setObjectName("wizCounter")
        bar_row.addWidget(self.progress, 1); bar_row.addWidget(self.counter)
        root.addLayout(bar_row)
        self.best = QFrame(); self.best.setObjectName("wizBest"); self.best.setVisible(False)
        self.best_grid = QGridLayout(self.best); self.best_grid.setContentsMargins(12, 8, 12, 8)
        self.best_grid.setHorizontalSpacing(10); self.best_grid.setVerticalSpacing(3)
        root.addWidget(self.best)
        self.toggle = QPushButton(t("جزئیات ▾", "Details ▾")); self.toggle.setObjectName("wizLink")
        self.toggle.setCursor(Qt.PointingHandCursor); self.toggle.clicked.connect(self._toggle)
        tr = QHBoxLayout(); tr.addWidget(self.toggle); tr.addStretch(1); root.addLayout(tr)
        self.raw = QListWidget(); self.raw.setObjectName("wizFeed"); self.raw.setLayoutDirection(direction)
        self.raw.setFixedHeight(128); self.raw.setVisible(False); self.raw.setFocusPolicy(Qt.NoFocus)
        self.raw.setSelectionMode(QListWidget.NoSelection); self.raw.setWordWrap(False)
        self.raw.setTextElideMode(Qt.ElideMiddle)
        root.addWidget(self.raw)
        self._timer = QTimer(self); self._timer.setInterval(250); self._timer.timeout.connect(self._flush)
        self._timer.start()

    def _toggle(self):
        show = not self.raw.isVisible(); self.raw.setVisible(show)
        self.toggle.setText(self.t("جزئیات ▴", "Details ▴") if show else self.t("جزئیات ▾", "Details ▾"))
        if show:
            self.raw.scrollToBottom()

    def clear(self):
        for row in self.rows.values():
            row.icon.set_state("pending"); row.setParent(None); row.deleteLater()
        self.rows = {}; self.raw.clear(); self.counter.setText(""); self._pending = []; self._progress = None
        self.set_best([])
        self.progress.setProperty("state", ""); self.progress.setRange(0, 0)
        self.progress.style().unpolish(self.progress); self.progress.style().polish(self.progress)

    def add(self, key: str, text: str) -> StepRow:
        row = StepRow(text, fx=self.fx); row.setLayoutDirection(self.layoutDirection())
        row.set("pending"); self.rows[key] = row; self.list.addWidget(row); return row

    def set(self, key, state, text=None, detail=None):
        row = self.rows.get(key) or self.add(key, text or key)
        row.set(state, text, detail)

    def set_progress(self, done: int, total: int, text: str = "", immediate: bool = True):
        self._progress = (done, total, text)
        if immediate:
            self._apply_progress()

    def _apply_progress(self):
        if self._progress is None:
            return
        done, total, text = self._progress; self._progress = None
        if total <= 0:
            self.progress.setRange(0, 0)
        else:
            self.progress.setRange(0, total); self.progress.setValue(min(done, total))
        self.counter.setText(self.fx(text))

    def finish_progress(self, ok=True):
        self._flush()
        self.progress.setRange(0, 100); self.progress.setValue(100)
        self.progress.setProperty("state", "ok" if ok else "fail")
        self.progress.style().unpolish(self.progress); self.progress.style().polish(self.progress)

    def event_line(self, text: str):
        """Queue one friendly line (already human text)."""
        self._pending.append(self.fx(text))

    def log(self, _line: str):
        """Raw core output is never shown here (file log only)."""
        return

    def _flush(self):
        self._apply_progress()
        if not self._pending:
            return
        lines, self._pending = self._pending[-8:], []
        for line in lines:
            item = QListWidgetItem(line)
            item.setTextAlignment((Qt.AlignRight if self.layoutDirection() == Qt.RightToLeft else Qt.AlignLeft) | Qt.AlignVCenter)
            self.raw.addItem(item)
        while self.raw.count() > self.FEED_MAX:
            self.raw.takeItem(0)
        self.raw.scrollToBottom()

    def set_best(self, rows):
        """rows: [(flag, country, ping_text)] - separate columns, no bidi mixing."""
        while self.best_grid.count():
            w = self.best_grid.takeAt(0).widget()
            if w:
                w.hide(); w.setParent(None); w.deleteLater()
        if not rows:
            self.best.setVisible(False); return
        head = QLabel(self.t("🏆 بهترین‌ها تا الان", "🏆 Best so far")); head.setObjectName("wizBestHead")
        self.best_grid.addWidget(head, 0, 0, 1, 3)
        for i, (flag, country, ping) in enumerate(rows[:3], 1):
            for col, (value, name) in enumerate(((flag, "wizBestFlag"), (country, "wizBestName"), (ping, "wizBestPing"))):
                lab = QLabel(self.fx(value) if col else value); lab.setObjectName(name)
                if col == 2:
                    lab.setAlignment((Qt.AlignLeft if self.layoutDirection() == Qt.RightToLeft else Qt.AlignRight) | Qt.AlignVCenter)
                self.best_grid.addWidget(lab, i, col)
        self.best_grid.setColumnStretch(1, 1)
        self.best.setVisible(True)


STYLE = """
QDialog#firstRunWizard { background: qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #071428, stop:1 #0a1d33);
  border: 1px solid rgba(35,245,224,0.35); }
QLabel { background: transparent; color: #cfe3f2; }
QLabel#wizEmoji { font-size: 40px; }
QLabel#wizTitle { color: #f2fbff; font-size: 21px; font-weight: 700; }
QLabel#wizSub { color: #9db4c8; font-size: 13px; }
QLabel#wizStepText { font-size: 13px; }
QLabel#wizStepDetail { color: #8fb4c9; font-size: 12px; }
QLabel#wizCounter { color: #9ff8ee; font-size: 12px; font-weight: 600; }
QLabel#wizChip { background: rgba(35,245,224,0.09); border: 1px solid rgba(35,245,224,0.28);
  border-radius: 11px; padding: 4px 11px; color: #bff9f1; font-size: 12px; }
QLabel#wizChipWarn { background: rgba(255,107,129,0.10); border: 1px solid rgba(255,107,129,0.35);
  border-radius: 11px; padding: 4px 11px; color: #ffc2cc; font-size: 12px; }
QFrame#wizCard { background: rgba(255,255,255,0.035); border: 1px solid rgba(255,255,255,0.07); border-radius: 12px; }
QProgressBar#wizProgress { background: rgba(255,255,255,0.07); border: none; border-radius: 3px; }
QProgressBar#wizProgress::chunk { border-radius: 3px; background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #23f5e0, stop:1 #4d8dff); }
QProgressBar#wizProgress[state="ok"]::chunk { background: #3ee08f; }
QProgressBar#wizProgress[state="fail"]::chunk { background: #ff6b81; }
QPushButton#wizGo { background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #19d9c6, stop:1 #3f7dff);
  color: #04111f; border: none; border-radius: 14px; font-size: 16px; font-weight: 800; padding: 13px 26px; min-height: 26px; }
QPushButton#wizGo:hover { background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #35f0dd, stop:1 #5c93ff); }
QPushButton#wizGo:disabled { background: rgba(255,255,255,0.10); color: #6f8698; }
QPushButton#wizLink { background: transparent; border: none; color: #7fa6c2; font-size: 12px; padding: 2px 4px; }
QPushButton#wizLink:hover { color: #23f5e0; }
QListWidget#wizFeed { background: rgba(255,255,255,0.03); color: #b9cfdf; border: 1px solid rgba(255,255,255,0.06);
  border-radius: 10px; font-size: 12px; padding: 4px; outline: none; }
QListWidget#wizFeed::item { padding: 3px 6px; border: none; }
QFrame#wizBest { background: rgba(62,224,143,0.06); border: 1px solid rgba(62,224,143,0.22); border-radius: 10px; }
QLabel#wizBestHead { color: #9ff3c8; font-size: 12px; font-weight: 700; }
QLabel#wizBestFlag { font-size: 14px; }
QLabel#wizBestName { color: #e4f4ee; font-size: 12px; }
QLabel#wizBestPing { color: #3ee08f; font-size: 12px; font-weight: 700; }
"""


class _Relay(QObject):
    call = Signal(object)


class FirstRunWizard(QDialog):
    """host provides (all optional, duck-typed):
    wizard_config_count() -> int, wizard_fake_sni() -> str, wizard_seed_ips() -> list,
    wizard_tunnel_active() -> bool, wizard_log_path() -> path,
    wizard_start_flow(kind, wizard, carrier_key), wizard_stop_flow()."""

    PAGE_HELLO, PAGE_CHECK, PAGE_VERDICT, PAGE_RUN, PAGE_DONE = range(5)

    def __init__(self, parent=None, host=None, language="fa", identity=None, probe=None,
                 autostart=False):
        super().__init__(parent)
        self.host = host; self.language = "en" if language == "en" else "fa"
        self.t = (lambda fa, en: en if self.language == "en" else fa)
        self.fx = (lambda v: v) if self.language == "en" else fa_text
        self._best: list = []
        self._identity = identity or lookup_identity
        self._probe = probe or tls_http_probe
        self._cancel = threading.Event(); self._relay = _Relay(); self._relay.call.connect(lambda fn: fn())
        self.facts: dict = {}; self.flow_running = False
        self.setObjectName("firstRunWizard"); self.setModal(True)
        self.setWindowTitle(self.t("شروع سریع", "Quick start"))
        self.setLayoutDirection(Qt.LeftToRight if self.language == "en" else Qt.RightToLeft)
        self.setFixedWidth(520); self.setMinimumHeight(470); self.setStyleSheet(STYLE)
        root = QVBoxLayout(self); root.setContentsMargins(28, 24, 28, 20); root.setSpacing(0)
        self.stack = QStackedWidget(); root.addWidget(self.stack, 1)
        foot = QHBoxLayout(); self.dots = []
        for _ in range(5):
            d = QLabel("●"); d.setStyleSheet("color:#2a4258; font-size:9px;"); self.dots.append(d); foot.addWidget(d)
        foot.addStretch(1)
        self.skip_btn = QPushButton(self.t("بعداً", "Later")); self.skip_btn.setObjectName("wizLink")
        self.skip_btn.setCursor(Qt.PointingHandCursor); self.skip_btn.clicked.connect(self.reject)
        foot.addWidget(self.skip_btn); root.addLayout(foot)
        self._build_hello(); self._build_check(); self._build_verdict(); self._build_run(); self._build_done()
        self._goto(self.PAGE_HELLO)
        if autostart:
            QTimer.singleShot(0, self.start_check)

    # ---------------------------------------------------------- helpers
    def _mascot(self, label, mood):
        pix = mascot_pixmap(mood)
        if pix is not None:
            label.setPixmap(pix); label.setAlignment(Qt.AlignHCenter)
            return True
        return False

    def _page(self, emoji, title, sub, mood=""):
        page = QWidget(); lay = QVBoxLayout(page); lay.setContentsMargins(0, 0, 0, 8); lay.setSpacing(10)
        e = QLabel(emoji); e.setObjectName("wizEmoji")
        if mood and self._mascot(e, mood):
            e.setObjectName("wizMascot")
        tl = QLabel(title); tl.setObjectName("wizTitle"); tl.setWordWrap(True)
        sl = QLabel(sub); sl.setObjectName("wizSub"); sl.setWordWrap(True)
        for w in (e, tl, sl):
            lay.addWidget(w)
        self.stack.addWidget(page)
        return page, lay, e, tl, sl

    def _set_mood(self, label, mood, emoji):
        if not self._mascot(label, mood):
            label.setText(emoji)

    def _go_button(self, text):
        b = QPushButton(text); b.setObjectName("wizGo"); b.setCursor(Qt.PointingHandCursor); return b

    def _goto(self, index):
        self.stack.setCurrentIndex(index)
        for i, d in enumerate(self.dots):
            d.setStyleSheet("color:%s; font-size:9px;" % (ACCENT if i == index else "#2a4258"))

    def _ui(self, fn):
        self._relay.call.emit(fn)

    # ---------------------------------------------------------- pages
    def _build_hello(self):
        _p, lay, *_ = self._page("👋", self.t("سلام رفیق! خوش اومدی", "Hey there, welcome!"),
                                 self.t("چند ثانیه بهم وقت بده ببینم اینترنتت چه حالیه؛ بعدش خودم بهترین راه رو برات می‌چینم. "
                                        "به کانفیگ‌ها و تنظیمات قبلیت هم دست نمی‌زنم، فقط اضافه می‌کنم.",
                                        "Give me a few seconds to check your connection, then I'll set up the best route for you. "
                                        "Your existing configs and settings stay untouched; I only add."), "normal")
        lay.addStretch(1)
        self.hello_btn = self._go_button(self.t("بریم ببینیم 🔍", "Let's check 🔍"))
        self.hello_btn.clicked.connect(self.start_check); lay.addWidget(self.hello_btn)

    def _build_check(self):
        _p, lay, *_ = self._page("🔎", self.t("دارم خطت رو بررسی می‌کنم…", "Checking your line…"),
                                 self.t("یه لحظه صبر کن، زود تموم می‌شه.", "Hang on, this is quick."), "thinking")
        self.check_log = StepLog(self.t, fx=self.fx, rtl=self.language == "fa")
        self.check_log.add("configs", self.t("کانفیگ‌های فعلی", "Your configs"))
        self.check_log.add("carrier", self.t("اپراتور اینترنت", "Internet provider"))
        self.check_log.add("dpi", self.t("نوع فیلترینگ خط", "How your line filters"))
        self.check_log.add("logs", self.t("اتصال‌های قبلی", "Previous connections"))
        lay.addWidget(self.check_log); lay.addStretch(1)

    def _build_verdict(self):
        _p, lay, self.v_emoji, self.v_title, self.v_sub = self._page("🎉", "", "", "happy")
        self.v_chips = QHBoxLayout(); self.v_chips.setSpacing(6); lay.addLayout(self.v_chips)
        self.v_plan = QLabel(""); self.v_plan.setObjectName("wizSub"); self.v_plan.setWordWrap(True)
        card = QFrame(); card.setObjectName("wizCard"); cl = QVBoxLayout(card); cl.setContentsMargins(14, 12, 14, 12)
        cl.addWidget(self.v_plan); lay.addWidget(card); lay.addStretch(1)
        self.go_btn = self._go_button(self.t("بزن بریم! 🚀", "Let's go! 🚀"))
        self.go_btn.clicked.connect(self.start_flow); lay.addWidget(self.go_btn)

    def _build_run(self):
        _p, lay, self.r_emoji, self.r_title, self.r_sub = self._page("⚔️", self.t("بریم به جنگش!", "Into battle!"), "", "guiding_right")
        self.run_log = StepLog(self.t, fx=self.fx, rtl=self.language == "fa"); lay.addWidget(self.run_log); lay.addStretch(1)

    def _build_done(self):
        _p, lay, self.d_emoji, self.d_title, self.d_sub = self._page("🎉", "", "", "happy")
        lay.addStretch(1)
        self.done_btn = self._go_button(self.t("حله، بریم وصل شیم", "Great, let's connect"))
        self.done_btn.clicked.connect(self._done_clicked); lay.addWidget(self.done_btn)

    def _done_clicked(self):
        if getattr(self, "last_ok", True):
            self.accept()
        else:
            self.start_flow()

    def _chip(self, text, warn=False):
        c = QLabel(self.fx(text)); c.setObjectName("wizChipWarn" if warn else "wizChip"); self.v_chips.addWidget(c)

    # ---------------------------------------------------------- detection
    def _host(self, name, default=None, *args):
        fn = getattr(self.host, name, None)
        if not callable(fn):
            return default
        try:
            return fn(*args)
        except Exception:
            return default

    def start_check(self):
        self._goto(self.PAGE_CHECK)
        count = int(self._host("wizard_config_count", 0) or 0)
        self.facts["configs"] = count
        self.check_log.set("configs", "ok", None,
                           self.t(f"{count} تا داری", f"{count} found") if count else self.t("هنوز نداری", "none yet"))
        self.check_log.set("carrier", "run", None, self.t("ASN…", "ASN…"))
        self.check_log.set_progress(0, 0, "")
        tunnel = bool(self._host("wizard_tunnel_active", False))
        fake = str(self._host("wizard_fake_sni", "chatgpt.com") or "chatgpt.com")
        seeds = list(self._host("wizard_seed_ips", []) or [])
        log_path = self._host("wizard_log_path", "")
        threading.Thread(target=self._detect, args=(tunnel, fake, seeds, log_path),
                         name="wizard-detect", daemon=True).start()

    def _detect(self, tunnel, fake, seeds, log_path):
        try:
            ident = self._identity()
        except Exception:
            ident = carrier_from_asn("", "")
        self.facts["carrier"] = ident
        name = ident["en"] if self.language == "en" else ident["fa"]
        self._ui(lambda: (self.check_log.set("carrier", "ok" if ident.get("asn") else "warn", None,
                                             f"{name}  {ident.get('asn','')}".strip()),
                          self.check_log.set("dpi", "run", None, self.t("تست رفتار…", "probing…")),
                          self.check_log.set_progress(1, 4, "1/4")))
        if tunnel:
            verdict = classify_dpi(0, 0, ident["family"]); verdict["by"] = "tunnel"
        else:
            try:
                from .clean_ip import sample_cloudflare
                ips = [*seeds[:4], *sample_cloudflare(28)]
            except Exception:
                ips = list(seeds)
            res = dpi_probe(ips, self._probe, cancel=self._cancel)
            verdict = classify_dpi(res["reachable"], res["frag_ok"], ident["family"])
            verdict.update(res)
        self.facts["dpi"] = verdict
        label = self.dpi_label(verdict["dpi"])
        self._ui(lambda: (self.check_log.set("dpi", "ok" if verdict["by"] == "probe" else "warn", None, label),
                          self.check_log.set("logs", "run"), self.check_log.set_progress(3, 4, "3/4")))
        history = analyze_log(read_log_tail(log_path) if log_path else "")
        self.facts["history"] = history
        hist_text = {"none": self.t("سابقه‌ای نیست", "no history"),
                     "failing": self.t(f"{history['fail']} بار نشد 😬", f"{history['fail']} failed 😬"),
                     "working": self.t(f"{history['ok']} بار وصل شدی", f"{history['ok']} connected")}[history["state"]]
        self._ui(lambda: (self.check_log.set("logs", "warn" if history["state"] == "failing" else "ok", None, hist_text),
                          self.check_log.set_progress(4, 4, "4/4"), self.check_log.finish_progress(True)))
        self._ui(lambda: QTimer.singleShot(650, self.show_verdict))

    def dpi_label(self, dpi):
        return (self.t("مثل همراه اول (فیلتر اسم دامنه)", "MCI-style (domain-name filtering)") if dpi == "sni"
                else self.t("مثل ایرانسل (IP تمیز جواب می‌ده)", "Irancell-style (clean IP works)"))

    def dpi_short(self, dpi):
        return self.t("نوع همراه اول", "MCI-type") if dpi == "sni" else self.t("نوع ایرانسل", "Irancell-type")

    def show_verdict(self):
        if self._cancel.is_set():
            return
        f = self.facts; history = f.get("history", {"state": "none"}); dpi = f.get("dpi", {"dpi": "sni", "by": "asn"})
        ident = f.get("carrier", carrier_from_asn("", ""))
        if history["state"] == "failing":
            self._set_mood(self.v_emoji, "sad", "😬")
            self.v_title.setText(self.t("اوه اوه، قبلیا وصل نمی‌شدن…", "Uh-oh, past connects were failing…"))
            self.v_sub.setText(self.t("ولی خبر خوب برات دارم! راهش رو پیدا کردم 😉", "But I've got good news for you! I found a way 😉"))
        elif history["state"] == "working":
            self._set_mood(self.v_emoji, "happy", "😎")
            self.v_title.setText(self.t("به‌به، قبلاً هم وصل می‌شدی!", "Nice, you were connecting fine!"))
            self.v_sub.setText(self.t("بیا یه کم قوی‌ترش کنیم که همیشه پایدار بمونه.", "Let's make it even sturdier."))
        else:
            self._set_mood(self.v_emoji, "surprised", "✨")
            self.v_title.setText(self.t("خبر خوب برات دارم!", "Good news!"))
            self.v_sub.setText(self.t("فهمیدم خطت چطوریه؛ با یه دکمه همه‌چی آماده می‌شه.", "I know how your line behaves; one tap and you're set."))
        while self.v_chips.count():
            w = self.v_chips.takeAt(0).widget()
            if w:
                w.deleteLater()
        self._chip(self.t("📶 اپراتور: ", "📶 Carrier: ") + (ident["en"] if self.language == "en" else ident["fa"]))
        self._chip(self.t("🛡 فیلترینگ: ", "🛡 Filtering: ") + self.dpi_short(dpi["dpi"]))
        n = f.get("configs", 0)
        self._chip("📦 " + self.t(f"{n} کانفیگ", f"{n} configs"), warn=not n)
        self.v_chips.addStretch(1)
        if dpi["dpi"] == "sni":
            plan = self.t("خطت اسم سایت‌ها رو می‌بینه و فیلتر می‌کنه، برای همین از کانفیگ‌های ECH استفاده می‌کنیم که اسم واقعی رو قایم می‌کنن. "
                          "لیست پترنیها رو می‌گیرم، همه رو زنده تست می‌کنم و سالم‌ها رو به User Config اضافه می‌کنم.",
                          "Your line reads site names and filters them, so we use ECH configs that hide the real name. "
                          "I'll fetch the Patterniha list, live-test everything and add the healthy ones to User Config.")
        else:
            plan = self.t("خطت با IP تمیز راحت رد می‌شه. اول بهترین IPهای تمیز اپراتورت رو پیدا می‌کنم، بعد لیست پترنیها رو تست می‌کنم و کانفیگ‌های سالم رو به User Config اضافه می‌کنم.",
                          "Your line passes with a clean IP. I'll find your carrier's best clean IPs, then test the Patterniha list and add the healthy configs to User Config.")
        if dpi.get("by") == "tunnel":
            plan += self.t("\n(تونل الان روشنه، برای همین از روی اپراتور حدس زدم.)", "\n(The tunnel is on, so I guessed from your carrier.)")
        elif dpi.get("by") == "asn":
            plan += self.t("\n(تست رفتار قطعی نبود، از روی اپراتور تصمیم گرفتم.)", "\n(The probe was inconclusive, so I went by your carrier.)")
        self.v_plan.setText(self.fx(plan))
        self._goto(self.PAGE_VERDICT)

    # ---------------------------------------------------------- flow
    @property
    def kind(self):
        return self.facts.get("dpi", {}).get("dpi", "sni")

    @property
    def carrier_key(self):
        ident = self.facts.get("carrier") or {}
        return cache_carrier(ident.get("family", ""), self.kind)

    def start_flow(self):
        self._goto(self.PAGE_RUN); self.flow_running = True
        self.skip_btn.setText(self.t("توقف", "Stop"))
        log = self.run_log
        log.clear(); self._best = []
        if self.kind == "ip":
            log.add("scan", self.t("اسکن IP تمیز", "Scanning clean IPs"))
        self.r_sub.setText(self.t("کانفیگ‌های پترنیها رو می‌گیرم و یکی‌یکی امتحان می‌کنم.", "Fetching Patterniha configs and testing them one by one."))
        log.add("fetch", self.t("گرفتن لیست پترنیها", "Fetching the Patterniha list"))
        log.add("test", self.t("تست زنده کانفیگ‌ها", "Live-testing configs"))
        log.add("add", self.t("اضافه کردن سالم‌ها به User Config", "Adding healthy ones to User Config"))
        start = getattr(self.host, "wizard_start_flow", None)
        if callable(start):
            try:
                start(self.kind, self, self.carrier_key)
            except Exception as exc:
                self.flow_finished(False, self.t("یه مشکلی پیش اومد", "Something went wrong"), str(exc))

    # API used by the host (main thread)
    def flow_step(self, key, state, detail=None, text=None):
        self.run_log.set(key, state, text, detail)

    def flow_progress(self, done, total, healthy=None, added=None):
        if healthy is None:
            text = f"{done}/{total}" if total else ""
        else:
            text = self.t(f"تست: {done} از {total} · سالم: {healthy}", f"Tested {done}/{total} · Healthy {healthy}")
            if added is not None:
                text += self.t(f" · اضافه: {added}", f" · Added {added}")
        self.run_log.set_progress(done, total, text, immediate=False)
        if total and healthy is not None and done < total:
            self.flow_headline(self.t(f"🔍 دارم کانفیگ {done} از {total} رو تست می‌کنم…",
                                      f"🔍 Testing config {done} of {total}…"))

    def flow_headline(self, text):
        self.r_sub.setText(self.fx(text))

    def flow_note(self, fa, en):
        self.run_log.event_line(self.t(fa, en))

    def flow_result(self, ok, flag="", country_fa="", country_en="", ms=0.0):
        """One tested config, as a friendly line (no raw names/URLs)."""
        name = (country_en or self.t("یه کانفیگ", "A config")) if self.language == "en" else (country_fa or "یه کانفیگ")
        flag = (flag + " ") if (flag and SHOW_FLAGS) else ""
        if ok:
            ping = ms_label(ms, self.language)
            self.run_log.event_line(self.t(f"✅ {flag}{name} · {ping} سالمه", f"✅ {flag}{name} · {ping} healthy"))
            self._best.append((float(ms or 0) or 99999.0, flag.strip() or "•", name, ping))
            self._best.sort(key=lambda r: r[0]); self._best = self._best[:3]
            self.run_log.set_best([(f, n, p) for _ms, f, n, p in self._best])
        else:
            self.run_log.event_line(self.t(f"❌ {flag}{name} جواب نداد", f"❌ {flag}{name} didn't respond"))

    def flow_log(self, line):
        """Raw core output is ignored (kept in the file log only)."""
        return

    def flow_finished(self, ok, title, body=""):
        self.flow_running = False
        self.run_log.finish_progress(ok)
        self.skip_btn.setText(self.t("بستن", "Close"))
        self._set_mood(self.d_emoji, "happy" if ok else "confused", "🎉" if ok else "🤔")
        self.d_title.setText(self.fx(title)); self.d_sub.setText(self.fx(body))
        self.last_ok = bool(ok)
        self.done_btn.setText(self.t("حله، بریم وصل شیم", "Great, let's connect") if ok else self.t("دوباره امتحان کن 🔄", "Try again 🔄"))
        QTimer.singleShot(700 if ok else 0, lambda: self._goto(self.PAGE_DONE))

    def reject(self):
        self._cancel.set()
        if self.flow_running:
            self._host("wizard_stop_flow")
            self.flow_running = False
        super().reject()
