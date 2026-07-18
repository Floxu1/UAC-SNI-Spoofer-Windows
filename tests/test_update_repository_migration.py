from uac_desktop.app_config import UPDATE_REPOSITORY_URL
from uac_desktop.storage import Storage


def _run_migration(settings):
    storage = Storage.__new__(Storage)
    storage.settings = dict(settings)
    storage.save_settings = lambda: None
    Storage._migrate_update_repository(storage)
    return storage.settings


def test_android_repository_is_migrated_and_stale_cache_is_cleared():
    settings = _run_migration({
        "update_repo_url": "https://github.com/Floxu1/UAC-SNI-Spoofer-Androids/",
        "last_update_checked_at": 123,
        "latest_version": "1.0.5",
        "latest_tag": "v1.0.5",
        "latest_release_name": "Android release",
        "latest_release_url": "https://github.com/Floxu1/UAC-SNI-Spoofer-Android/releases/tag/v1.0.5",
        "update_available": True,
        "last_update_repo_url": "https://github.com/Floxu1/UAC-SNI-Spoofer-Android",
        "last_update_current_version": "1.5.0",
        "notified_update_version": "1.0.5",
    })

    assert settings["update_repo_url"] == UPDATE_REPOSITORY_URL
    assert settings["update_repository_version"] == 1
    assert not set(settings).intersection({
        "last_update_checked_at", "latest_version", "latest_tag",
        "latest_release_name", "latest_release_url", "update_available",
        "last_update_repo_url", "last_update_current_version",
        "notified_update_version",
    })


def test_missing_repository_uses_windows_repository():
    settings = _run_migration({})

    assert settings["update_repo_url"] == UPDATE_REPOSITORY_URL
    assert settings["update_repository_version"] == 1


def test_custom_repository_is_preserved():
    custom = "https://github.com/example/custom-desktop"
    settings = _run_migration({
        "update_repo_url": custom,
        "latest_version": "9.9.9",
    })

    assert settings["update_repo_url"] == custom
    assert settings["latest_version"] == "9.9.9"
    assert settings["update_repository_version"] == 1
