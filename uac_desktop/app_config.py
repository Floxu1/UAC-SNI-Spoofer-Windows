from . import __version__


UPDATE_REPOSITORY_URL = "https://github.com/Floxu1/UAC-SNI-Spoofer-Windows"
CURRENT_VERSION = __version__


def github_latest_release_api(repository_url: str) -> str:
    value = repository_url.rstrip("/")
    marker = "github.com/"
    slug = value.split(marker, 1)[1] if marker in value else "OWNER/REPOSITORY"
    return f"https://api.github.com/repos/{slug}/releases/latest"


GITHUB_RELEASES_URL = f"{UPDATE_REPOSITORY_URL.rstrip('/')}/releases"
LATEST_VERSION_URL = github_latest_release_api(UPDATE_REPOSITORY_URL)
UPDATE_CHECK_ENDPOINT = LATEST_VERSION_URL
PORTABLE_DOWNLOAD_URL = (
    f"{GITHUB_RELEASES_URL}/latest/download/"
    f"UAC-Spoofer-Desktop-v{CURRENT_VERSION}-Windows-x64.zip"
)
SUGGESTED_CONFIGS_URL = (
    "https://raw.githubusercontent.com/Floxu1/"
    "UAC-SNI-Spoofer-Windows/main/configs.txt"
)
PROJECT_URL = UPDATE_REPOSITORY_URL
