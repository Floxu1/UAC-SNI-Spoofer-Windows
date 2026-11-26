"""Read the file portion of a public GitHub blob page."""
import base64
import json
import re
from html.parser import HTMLParser
from urllib.parse import quote, unquote, urlsplit


DEFAULT_REPOSITORY_URL = "https://github.com/patterniha/Free-Configs/blob/main/configs.txt"


def source_routes(url):
    parsed = urlsplit(url)
    parts = parsed.path.strip("/").split("/")
    blob = parsed.hostname == "github.com" and len(parts) >= 5 and parts[2] == "blob"
    if not blob:
        yield "text", url
        if parsed.hostname != "raw.githubusercontent.com" or len(parts) < 4:
            return
    owner, repo = parts[:2]
    tail = parts[3:] if blob else parts[2:]
    if tail[:2] in (["refs", "heads"], ["refs", "tags"]):
        tail = tail[2:]
    yield "blob", f"https://github.com/{owner}/{repo}/blob/" + "/".join(tail)
    # A ref can itself contain slashes. Try the remaining splits on API 404.
    for split in range(1, len(tail)):
        ref = quote(unquote("/".join(tail[:split])), safe="")
        yield "api", f"https://api.github.com/repos/{owner}/{repo}/contents/" + "/".join(tail[split:]) + "?ref=" + ref


class BlobPage(HTMLParser):
    def __init__(self):
        super().__init__()
        self.payload = {}
        self.script = False
        self.lines = {}
        self.cell = None
        self.cell_tag = ""
        self.depth = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "script":
            self.script = attrs.get("type") == "application/json"
        classes = attrs.get("class", "").split()
        if self.cell is None and ("blob-code" in classes or "react-file-line" in classes):
            match = re.fullmatch(r"LC(\d+)", attrs.get("id", ""))
            if match:
                self.cell = int(match[1])
                self.cell_tag = tag
                self.depth = 0
                self.lines[self.cell] = []
        elif self.cell is not None and tag == self.cell_tag:
            self.depth += 1

    def handle_endtag(self, tag):
        if tag == "script":
            self.script = False
        if self.cell is not None and tag == self.cell_tag:
            if self.depth:
                self.depth -= 1
            else:
                self.cell = None

    def handle_data(self, data):
        if self.cell is not None:
            self.lines[self.cell].append(data)
        elif self.script:
            try:
                obj = json.loads(data)
            except ValueError:
                return
            if isinstance(obj, dict) and isinstance(obj.get("payload"), dict):
                self.payload.update(obj["payload"])

    def file_text(self):
        layout = self.payload.get("codeViewBlobLayoutRoute", self.payload)
        blob = layout.get("blob") or {}
        styled = self.payload.get("codeViewBlobLayoutRoute.StyledBlob") or {}
        if blob.get("truncated") or blob.get("isTruncated"):
            raise ValueError("Incomplete GitHub file")
        info = (blob.get("headerInfo") or {}).get("lineInfo") or {}
        size = str(info.get("truncatedLoc", "")).replace(",", "")
        expected = int(size) if size.isascii() and size.isdigit() else None
        lines = styled.get("rawLines", blob.get("rawLines"))
        if isinstance(lines, list) and all(isinstance(line, str) for line in lines):
            if expected is None or len(lines) >= expected:
                return "\n".join(lines)
        count = len(self.lines)
        if count and (expected is None or expected == count) and sorted(self.lines) == list(range(1, count + 1)):
            return "\n".join("".join(self.lines[i]) for i in range(1, count + 1))
        raise ValueError("GitHub page has no complete file content")


def file_content(kind, content):
    if kind == "blob":
        page = BlobPage()
        page.feed(content.decode("utf-8-sig"))
        page.close()
        return page.file_text()
    if kind == "api" and content.lstrip().startswith(b"{"):
        doc = json.loads(content)
        if doc.get("type") != "file" or doc.get("encoding") != "base64":
            raise ValueError("GitHub API did not return file content")
        content = base64.b64decode("".join(doc["content"].split()), validate=True)
        if len(content) != doc.get("size", len(content)):
            raise ValueError("Incomplete GitHub API file")
    if content.lstrip().startswith(b"<"):
        raise ValueError("Expected a subscription file, received HTML")
    return content.decode("utf-8-sig")
