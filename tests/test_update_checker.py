from __future__ import annotations

import requests
import pytest

from uac_desktop import __version__
from uac_desktop.update_checker import (
    DEFAULT_TIMEOUT,
    GITHUB_API_VERSION,
    InvalidRepositoryUrl,
    InvalidVersion,
    SemVersion,
    UpdateCheckError,
    UpdateServiceError,
    check_latest_release,
    parse_github_repository,
)


REPO_URL = "https://github.com/example/UAC-Spoofer-Desktop"
RELEASE_URL = REPO_URL + "/releases/tag/v1.5.1"


class FakeResponse:
    def __init__(self, payload=None, status=200, headers=None, json_error=None):
        self._payload = payload
        self.status_code = status
        self.headers = headers or {}
        self._json_error = json_error

    def json(self):
        if self._json_error:
            raise self._json_error
        return self._payload


class FakeSession:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error
        self.calls = []
        self.closed = False

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if self.error:
            raise self.error
        return self.response

    def close(self):
        self.closed = True


def release_payload(tag="v1.5.1", **overrides):
    payload = {
        "tag_name": tag,
        "name": "UAC Spoofer 1.5.1",
        "html_url": RELEASE_URL,
        "published_at": "2026-07-13T12:00:00Z",
        "body": "Performance release",
        "prerelease": False,
        "assets": [
            {
                "name": "source.zip",
                "browser_download_url": "https://github.com/example/UAC-Spoofer-Desktop/releases/download/v1.5.1/source.zip",
            },
            {
                "name": "UAC-Spoofer-Desktop-Windows-x64.zip",
                "browser_download_url": "https://github.com/example/UAC-Spoofer-Desktop/releases/download/v1.5.1/windows.zip",
            },
        ],
    }
    payload.update(overrides)
    return payload


def test_semver_accepts_leading_v_and_ignores_build_for_precedence():
    assert str(SemVersion.parse("v1.3.1")) == "1.3.1"
    assert SemVersion.parse("1.3.1+desktop.7") == SemVersion.parse("1.3.1+desktop.8")
    assert hash(SemVersion.parse("1.3.1+desktop.7")) == hash(SemVersion.parse("1.3.1+desktop.8"))


def test_semver_prerelease_order_matches_semver_2():
    ordered = [
        "1.0.0-alpha",
        "1.0.0-alpha.1",
        "1.0.0-alpha.beta",
        "1.0.0-beta",
        "1.0.0-beta.2",
        "1.0.0-beta.11",
        "1.0.0-rc.1",
        "1.0.0",
    ]
    parsed = [SemVersion.parse(value) for value in ordered]
    assert parsed == sorted(reversed(parsed))


@pytest.mark.parametrize("value", ["1.3", "1.03.0", "1.0.0-01", "release-1.0.0", "1.0.0+"])
def test_semver_rejects_invalid_values(value):
    with pytest.raises(InvalidVersion):
        SemVersion.parse(value)


def test_repository_url_validation_and_normalization():
    repository = parse_github_repository("https://www.github.com/example/UAC-Spoofer-Desktop.git/")
    assert repository.owner == "example"
    assert repository.name == "UAC-Spoofer-Desktop"
    assert repository.canonical_url == REPO_URL
    assert repository.latest_release_api_url.endswith("/repos/example/UAC-Spoofer-Desktop/releases/latest")


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/example/repo",
        "https://gitlab.com/example/repo",
        "https://github.com/example",
        "https://github.com/example/repo/releases",
        "https://github.com/example/repo?tab=releases",
        "https://user@github.com/example/repo",
    ],
)
def test_repository_url_rejects_unsafe_or_non_root_urls(url):
    with pytest.raises(InvalidRepositoryUrl):
        parse_github_repository(url)


def test_latest_release_uses_expected_api_headers_timeout_and_package_version():
    session = FakeSession(FakeResponse(release_payload()))
    info = check_latest_release(REPO_URL, session=session)

    assert info.current_version == __version__
    assert info.latest_version == "1.5.1"
    assert info.is_update_available is True
    assert info.release_url == RELEASE_URL
    assert info.asset_name == "UAC-Spoofer-Desktop-Windows-x64.zip"
    assert info.download_url.endswith("/windows.zip")
    assert session.closed is False, "caller-owned sessions must not be closed"
    [(url, kwargs)] = session.calls
    assert url == "https://api.github.com/repos/example/UAC-Spoofer-Desktop/releases/latest"
    assert kwargs["timeout"] == DEFAULT_TIMEOUT
    assert kwargs["headers"]["Accept"] == "application/vnd.github+json"
    assert kwargs["headers"]["X-GitHub-Api-Version"] == GITHUB_API_VERSION
    assert kwargs["headers"]["User-Agent"] == f"UAC-Spoofer-Desktop/{__version__}"


def test_same_or_older_release_is_not_an_update():
    same = FakeSession(FakeResponse(release_payload(tag="v1.3.1", html_url=REPO_URL + "/releases/tag/v1.3.1")))
    older = FakeSession(FakeResponse(release_payload(tag="v1.2.9", html_url=REPO_URL + "/releases/tag/v1.2.9")))
    assert check_latest_release(REPO_URL, "1.3.1", session=same).is_update_available is False
    assert check_latest_release(REPO_URL, "1.3.1", session=older).is_update_available is False


def test_prerelease_tag_is_compared_and_reported():
    session = FakeSession(
        FakeResponse(
            release_payload(
                tag="v1.4.0-beta.2",
                html_url=REPO_URL + "/releases/tag/v1.4.0-beta.2",
                prerelease=True,
            )
        )
    )
    info = check_latest_release(REPO_URL, "1.4.0-beta.1", session=session)
    assert info.latest_version == "1.4.0-beta.2"
    assert info.prerelease is True
    assert info.is_update_available is True


@pytest.mark.parametrize(
    ("response", "message"),
    [
        (FakeResponse({}, status=404), "No published GitHub release"),
        (FakeResponse({}, status=403, headers={"X-RateLimit-Remaining": "0"}), "rate limit exceeded"),
        (FakeResponse({}, status=500), "HTTP 500"),
        (FakeResponse(json_error=ValueError("bad json")), "invalid JSON"),
        (FakeResponse({}), "no tag_name"),
        (FakeResponse(release_payload(tag="release-2")), "not valid SemVer"),
        (FakeResponse(release_payload(html_url="https://attacker.example/release")), "invalid release URL"),
    ],
)
def test_github_response_errors_are_clear(response, message):
    with pytest.raises(UpdateServiceError, match=message):
        check_latest_release(REPO_URL, session=FakeSession(response))


def test_network_errors_are_wrapped_without_closing_injected_session():
    session = FakeSession(error=requests.Timeout("read timed out"))
    with pytest.raises(UpdateServiceError, match="Could not contact GitHub"):
        check_latest_release(REPO_URL, session=session)
    assert session.closed is False


@pytest.mark.parametrize("timeout", [(0, 1), (1, -1), ("bad", 1), (1,)])
def test_timeout_must_be_a_positive_pair(timeout):
    with pytest.raises(UpdateCheckError, match="timeout"):
        check_latest_release(REPO_URL, session=FakeSession(FakeResponse(release_payload())), timeout=timeout)
