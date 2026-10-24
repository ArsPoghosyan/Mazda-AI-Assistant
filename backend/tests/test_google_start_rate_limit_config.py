"""Google-initiation limits use bounded, independent environment policies."""

import pytest
from pydantic import ValidationError
from pydantic_settings import SettingsConfigDict

from app.config import Settings


class IsolatedGoogleSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@pytest.fixture(autouse=True)
def clear_google_start_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "ACCOUNT_GOOGLE_OAUTH_IP_MAX_REQUESTS",
        "ACCOUNT_GOOGLE_OAUTH_IP_WINDOW_SECONDS",
        "ACCOUNT_GOOGLE_OAUTH_API_ENABLED",
    ):
        monkeypatch.delenv(name, raising=False)


def test_defaults_preserve_other_endpoint_budgets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ACCOUNT_SIGN_IN_IP_MAX_REQUESTS", "42")
    settings = IsolatedGoogleSettings()
    assert settings.account_google_oauth_ip_max_requests == 10
    assert settings.account_google_oauth_ip_window_seconds == 600
    assert not settings.account_google_oauth_api_enabled
    assert settings.account_sign_in_ip_max_requests == 42


def test_empty_values_keep_safe_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ACCOUNT_GOOGLE_OAUTH_IP_MAX_REQUESTS", "")
    monkeypatch.setenv("ACCOUNT_GOOGLE_OAUTH_IP_WINDOW_SECONDS", "")
    settings = IsolatedGoogleSettings()
    assert settings.account_google_oauth_ip_max_requests == 10
    assert settings.account_google_oauth_ip_window_seconds == 600


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_requests", 1),
        ("max_requests", 10),
        ("max_requests", 1000),
        ("window_seconds", 60),
        ("window_seconds", 600),
        ("window_seconds", 86400),
    ],
)
def test_valid_google_start_rate_limit_boundaries(field: str, value: int) -> None:
    settings = IsolatedGoogleSettings.model_validate({f"account_google_oauth_ip_{field}": value})
    assert getattr(settings, f"account_google_oauth_ip_{field}") == value
    assert not settings.account_google_oauth_api_enabled


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_requests", 0),
        ("max_requests", -1),
        ("max_requests", 1001),
        ("max_requests", 1.5),
        ("max_requests", "invalid"),
        ("max_requests", None),
        ("window_seconds", 59),
        ("window_seconds", -1),
        ("window_seconds", 86401),
        ("window_seconds", 60.5),
        ("window_seconds", "invalid"),
        ("window_seconds", None),
    ],
)
def test_invalid_google_start_rate_limit_boundaries(field: str, value: object) -> None:
    with pytest.raises(ValidationError) as caught:
        IsolatedGoogleSettings.model_validate({f"account_google_oauth_ip_{field}": value})
    assert any(
        error["loc"] == (f"account_google_oauth_ip_{field}",)
        for error in caught.value.errors(include_input=False)
    )


def test_google_start_rate_policy_environment_and_precedence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ACCOUNT_GOOGLE_OAUTH_IP_MAX_REQUESTS", "7")
    monkeypatch.setenv("ACCOUNT_GOOGLE_OAUTH_IP_WINDOW_SECONDS", "900")
    settings = IsolatedGoogleSettings()
    assert (
        settings.account_google_oauth_ip_max_requests,
        settings.account_google_oauth_ip_window_seconds,
    ) == (7, 900)
    overridden = IsolatedGoogleSettings(
        account_google_oauth_ip_max_requests=2,
        account_google_oauth_ip_window_seconds=60,
    )
    assert (
        overridden.account_google_oauth_ip_max_requests,
        overridden.account_google_oauth_ip_window_seconds,
    ) == (2, 60)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("ACCOUNT_GOOGLE_OAUTH_IP_MAX_REQUESTS", "0"),
        ("ACCOUNT_GOOGLE_OAUTH_IP_MAX_REQUESTS", "invalid"),
        ("ACCOUNT_GOOGLE_OAUTH_IP_WINDOW_SECONDS", "59"),
        ("ACCOUNT_GOOGLE_OAUTH_IP_WINDOW_SECONDS", "86401"),
    ],
)
def test_invalid_google_start_rate_environment(
    monkeypatch: pytest.MonkeyPatch, name: str, value: str
) -> None:
    monkeypatch.setenv(name, value)
    with pytest.raises(ValidationError):
        IsolatedGoogleSettings()
