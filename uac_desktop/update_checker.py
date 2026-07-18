"""Small, UI-independent GitHub release update checker.

The module deliberately contains no Qt code.  Callers can run
``check_latest_release`` in a worker thread and deliver the returned immutable
``UpdateInfo`` to the GUI thread.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import total_ordering
from typing import Any, Protocol
from urllib.parse import urlsplit

import requests

from . import __version__


GITHUB_API_VERSION = "2026-03-10"
DEFAULT_TIMEOUT = (3.5, 8.0)

_OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_SEMVER_RE = re.compile(
    r"^[vV]?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)


class UpdateCheckError(RuntimeError):
    """Base class for update-check failures suitable for showing in the UI."""


class InvalidRepositoryUrl(UpdateCheckError):
    """Raised when the configured repository URL is not a safe GitHub URL."""


class InvalidVersion(UpdateCheckError):
    """Raised when the installed or release version is not valid SemVer."""


class UpdateServiceError(UpdateCheckError):
    """Raised when GitHub cannot return a usable latest release."""


class _Response(Protocol):
    status_code: int
    headers: Any

    def json(self) -> Any: ...


class _Session(Protocol):
    def get(self, url: str, **kwargs: Any) -> _Response: ...


@total_ordering
@dataclass(frozen=True, slots=True)
class SemVersion:
    """Strict SemVer 2.0.0 value with optional leading ``v`` on input."""

    major: int
    minor: int
    patch: int
    prerelease: tuple[str, ...] = ()
    build: tuple[str, ...] = ()

    @classmethod
    def parse(cls, value: str) -> "SemVersion":
        raw = str(value).strip()
        match = _SEMVER_RE.fullmatch(raw)
        if not match:
            raise InvalidVersion(f"Invalid semantic version: {value!r}")
        prerelease_raw = match.group(4) or ""
        prerelease = tuple(prerelease_raw.split(".")) if prerelease_raw else ()
        for identifier in prerelease:
            if identifier.isdigit() and len(identifier) > 1 and identifier.startswith("0"):
                raise InvalidVersion(
                    f"Invalid semantic version {value!r}: numeric prerelease identifiers cannot have leading zeroes"
                )
        build_raw = match.group(5) or ""
        build = tuple(build_raw.split(".")) if build_raw else ()
        return cls(int(match.group(1)), int(match.group(2)), int(match.group(3)), prerelease, build)

    def __str__(self) -> str:
        value = f"{self.major}.{self.minor}.{self.patch}"
        if self.prerelease:
            value += "-" + ".".join(self.prerelease)
        if self.build:
            value += "+" + ".".join(self.build)
        return value

    def _precedence_compare(self, other: "SemVersion") -> int:
        core_self = (self.major, self.minor, self.patch)
        core_other = (other.major, other.minor, other.patch)
        if core_self != core_other:
            return -1 if core_self < core_other else 1
        if not self.prerelease and not other.prerelease:
            return 0
        if not self.prerelease:
            return 1
        if not other.prerelease:
            return -1
        for left, right in zip(self.prerelease, other.prerelease):
            if left == right:
                continue
            left_numeric, right_numeric = left.isdigit(), right.isdigit()
            if left_numeric and right_numeric:
                return -1 if int(left) < int(right) else 1
            if left_numeric != right_numeric:
                return -1 if left_numeric else 1
            return -1 if left < right else 1
        if len(self.prerelease) == len(other.prerelease):
            return 0
        return -1 if len(self.prerelease) < len(other.prerelease) else 1

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SemVersion):
            return NotImplemented
        # SemVer build metadata does not participate in precedence.
        return self._precedence_compare(other) == 0

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, SemVersion):
            return NotImplemented
        return self._precedence_compare(other) < 0

    def __hash__(self) -> int:
        # Keep hashing consistent with precedence equality: build metadata is
        # intentionally ignored by both.
        return hash((self.major, self.minor, self.patch, self.prerelease))


@dataclass(frozen=True, slots=True)
class UpdateInfo:
    repo_url: str
    current_version: str
    latest_version: str
    tag_name: str
    release_name: str
    release_url: str
    published_at: str
    release_notes: str
    prerelease: bool
    is_update_available: bool
    download_url: str = ""
    asset_name: str = ""


@dataclass(frozen=True, slots=True)
class GitHubRepository:
    owner: str
    name: str

    @property
    def canonical_url(self) -> str:
        return f"https://github.com/{self.owner}/{self.name}"

    @property
    def latest_release_api_url(self) -> str:
        return f"https://api.github.com/repos/{self.owner}/{self.name}/releases/latest"


def parse_github_repository(repo_url: str) -> GitHubRepository:
    """Validate and split an HTTPS ``github.com/owner/repository`` URL."""

    raw = str(repo_url or "").strip()
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except ValueError as exc:
        raise InvalidRepositoryUrl(f"Invalid GitHub repository URL: {repo_url!r}") from exc
    if (
        parsed.scheme.lower() != "https"
        or (parsed.hostname or "").lower() not in {"github.com", "www.github.com"}
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
        or parsed.query
        or parsed.fragment
    ):
        raise InvalidRepositoryUrl(
            "Repository URL must be an HTTPS GitHub URL such as https://github.com/owner/repository"
        )
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) != 2:
        raise InvalidRepositoryUrl(
            "Repository URL must point to the repository root: https://github.com/owner/repository"
        )
    owner, name = parts
    if name.lower().endswith(".git"):
        name = name[:-4]
    if not _OWNER_RE.fullmatch(owner) or not _REPOSITORY_RE.fullmatch(name):
        raise InvalidRepositoryUrl(f"Invalid GitHub owner or repository name in {repo_url!r}")
    return GitHubRepository(owner, name)


def _preferred_asset(payload: dict[str, Any]) -> tuple[str, str]:
    assets = payload.get("assets")
    if not isinstance(assets, list):
        return "", ""
    candidates: list[tuple[int, str, str]] = []
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        name = str(asset.get("name") or "").strip()
        url = str(asset.get("browser_download_url") or "").strip()
        if not name or not url.startswith("https://github.com/"):
            continue
        lowered = name.lower()
        score = 0
        if "windows" in lowered or "win" in lowered:
            score += 20
        if "x64" in lowered or "amd64" in lowered:
            score += 10
        if lowered.endswith(".exe"):
            score += 6
        elif lowered.endswith(".msi"):
            score += 5
        elif lowered.endswith(".zip"):
            score += 4
        candidates.append((score, name, url))
    if not candidates:
        return "", ""
    _score, name, url = max(candidates, key=lambda item: (item[0], item[1].lower()))
    return name, url


def check_latest_release(
    repo_url: str,
    current_version: str = __version__,
    *,
    session: _Session | None = None,
    timeout: tuple[float, float] = DEFAULT_TIMEOUT,
) -> UpdateInfo:
    """Return the latest published GitHub release and update availability.

    ``session`` is injectable for deterministic tests.  A session created by
    this function is always closed; a caller-owned session is never closed.
    """

    repository = parse_github_repository(repo_url)
    installed = SemVersion.parse(current_version)
    try:
        connect_timeout, read_timeout = (float(timeout[0]), float(timeout[1]))
    except (TypeError, ValueError, IndexError) as exc:
        raise UpdateCheckError("Update timeout must be a (connect, read) tuple") from exc
    if connect_timeout <= 0 or read_timeout <= 0:
        raise UpdateCheckError("Update timeouts must be greater than zero")

    own_session = session is None
    client: _Session = session or requests.Session()
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
        "User-Agent": f"UAC-Spoofer-Desktop/{installed}",
    }
    try:
        try:
            response = client.get(
                repository.latest_release_api_url,
                headers=headers,
                timeout=(connect_timeout, read_timeout),
            )
        except requests.RequestException as exc:
            raise UpdateServiceError(f"Could not contact GitHub: {exc}") from exc

        status = int(getattr(response, "status_code", 0))
        response_headers = getattr(response, "headers", {}) or {}
        if status == 404:
            raise UpdateServiceError(f"No published GitHub release was found for {repository.canonical_url}")
        if status in {403, 429} and str(response_headers.get("X-RateLimit-Remaining", "")) == "0":
            raise UpdateServiceError("GitHub API rate limit exceeded; try again later")
        if status != 200:
            raise UpdateServiceError(f"GitHub update check failed with HTTP {status or 'unknown'}")
        try:
            payload = response.json()
        except (TypeError, ValueError) as exc:
            raise UpdateServiceError("GitHub returned an invalid JSON response") from exc
        if not isinstance(payload, dict):
            raise UpdateServiceError("GitHub returned an invalid release response")

        tag_name = str(payload.get("tag_name") or "").strip()
        if not tag_name:
            raise UpdateServiceError("GitHub latest release response has no tag_name")
        try:
            latest = SemVersion.parse(tag_name)
        except InvalidVersion as exc:
            raise UpdateServiceError(f"GitHub release tag is not valid SemVer: {tag_name!r}") from exc
        release_url = str(payload.get("html_url") or "").strip()
        if not release_url.lower().startswith((repository.canonical_url + "/releases/").lower()):
            raise UpdateServiceError("GitHub latest release response has an invalid release URL")
        asset_name, download_url = _preferred_asset(payload)
        return UpdateInfo(
            repo_url=repository.canonical_url,
            current_version=str(installed),
            latest_version=str(latest),
            tag_name=tag_name,
            release_name=str(payload.get("name") or tag_name).strip(),
            release_url=release_url,
            published_at=str(payload.get("published_at") or "").strip(),
            release_notes=str(payload.get("body") or ""),
            prerelease=bool(payload.get("prerelease", False)),
            is_update_available=latest > installed,
            download_url=download_url,
            asset_name=asset_name,
        )
    finally:
        if own_session:
            close = getattr(client, "close", None)
            if callable(close):
                close()


__all__ = [
    "DEFAULT_TIMEOUT",
    "GITHUB_API_VERSION",
    "GitHubRepository",
    "InvalidRepositoryUrl",
    "InvalidVersion",
    "SemVersion",
    "UpdateCheckError",
    "UpdateInfo",
    "UpdateServiceError",
    "check_latest_release",
    "parse_github_repository",
]
