"""Bounded, opt-in authentication limiter housekeeping configuration."""

import pytest
from pydantic import ValidationError
from pydantic_settings import SettingsConfigDict

from app.config import Settings


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@pytest.fixture(autouse=True)
def clear_schedule_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for suffix in ("ENABLED", "INTERVAL_SECONDS", "BATCH_SIZE", "TIMEOUT_SECONDS"):
        monkeypatch.delenv(f"AUTH_RATE_LIMIT_CLEANUP_{suffix}", raising=False)


def test_defaults_do_not_enable_background_deletion() -> None:
    settings = IsolatedSettings()
    assert not settings.auth_rate_limit_cleanup_enabled
    assert settings.auth_rate_limit_cleanup_interval_seconds == 300
    assert settings.auth_rate_limit_cleanup_batch_size == 100
    assert settings.auth_rate_limit_cleanup_timeout_seconds == 5


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("interval_seconds", 60),
        ("interval_seconds", 86400),
        ("batch_size", 1),
        ("batch_size", 1000),
        ("timeout_seconds", 1),
        ("timeout_seconds", 30),
    ],
)
def test_policy_boundaries_are_configurable(field: str, value: int) -> None:
    settings = IsolatedSettings.model_validate({f"auth_rate_limit_cleanup_{field}": value})
    assert getattr(settings, f"auth_rate_limit_cleanup_{field}") == value
    assert not settings.auth_rate_limit_cleanup_enabled


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("interval_seconds", 59),
        ("interval_seconds", 86401),
        ("batch_size", 0),
        ("batch_size", 1001),
        ("timeout_seconds", 0),
        ("timeout_seconds", 31),
        ("interval_seconds", 60.5),
        ("batch_size", 1.5),
        ("timeout_seconds", 1.5),
        ("interval_seconds", "invalid"),
        ("batch_size", None),
        ("timeout_seconds", "invalid"),
    ],
)
def test_invalid_policy_is_rejected(field: str, value: object) -> None:
    with pytest.raises(ValidationError) as caught:
        IsolatedSettings.model_validate({f"auth_rate_limit_cleanup_{field}": value})
    assert any(
        error["loc"] == (f"auth_rate_limit_cleanup_{field}",)
        for error in caught.value.errors(include_input=False)
    )


def test_environment_loading_and_constructor_precedence(monkeypatch: pytest.MonkeyPatch) -> None:
    for name, value in {
        "ENABLED": "true",
        "INTERVAL_SECONDS": "900",
        "BATCH_SIZE": "7",
        "TIMEOUT_SECONDS": "3",
    }.items():
        monkeypatch.setenv(f"AUTH_RATE_LIMIT_CLEANUP_{name}", value)
    settings = IsolatedSettings()
    assert settings.auth_rate_limit_cleanup_enabled
    assert settings.auth_rate_limit_cleanup_interval_seconds == 900
    assert settings.auth_rate_limit_cleanup_batch_size == 7
    assert settings.auth_rate_limit_cleanup_timeout_seconds == 3
    overridden = IsolatedSettings(
        auth_rate_limit_cleanup_enabled=False,
        auth_rate_limit_cleanup_interval_seconds=60,
        auth_rate_limit_cleanup_batch_size=1,
        auth_rate_limit_cleanup_timeout_seconds=1,
    )
    assert not overridden.auth_rate_limit_cleanup_enabled
    assert overridden.auth_rate_limit_cleanup_interval_seconds == 60
    assert overridden.auth_rate_limit_cleanup_batch_size == 1
    assert overridden.auth_rate_limit_cleanup_timeout_seconds == 1


def test_empty_environment_preserves_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    for suffix in ("ENABLED", "INTERVAL_SECONDS", "BATCH_SIZE", "TIMEOUT_SECONDS"):
        monkeypatch.setenv(f"AUTH_RATE_LIMIT_CLEANUP_{suffix}", "")
    assert not IsolatedSettings().auth_rate_limit_cleanup_enabled
    assert IsolatedSettings().auth_rate_limit_cleanup_interval_seconds == 300


@pytest.mark.parametrize(
    ("suffix", "value"),
    [
        ("ENABLED", "invalid"),
        ("INTERVAL_SECONDS", "59"),
        ("BATCH_SIZE", "1001"),
        ("TIMEOUT_SECONDS", "31"),
    ],
)
def test_invalid_environment_fails_validation(
    monkeypatch: pytest.MonkeyPatch, suffix: str, value: str
) -> None:
    monkeypatch.setenv(f"AUTH_RATE_LIMIT_CLEANUP_{suffix}", value)
    with pytest.raises(ValidationError):
        IsolatedSettings()
