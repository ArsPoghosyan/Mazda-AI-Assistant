"""Google OAuth settings without private configuration or live services."""

import pytest
from pydantic import ValidationError
from pydantic_settings import SettingsConfigDict

from app.config import Settings


class IsolatedGoogleSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@pytest.fixture(autouse=True)
def clear_account_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "ACCOUNT_GOOGLE_OAUTH_API_ENABLED",
        "ACCOUNT_GOOGLE_OAUTH_TIMEOUT_SECONDS",
        "ACCOUNT_GOOGLE_OAUTH_ATTEMPT_LIFETIME_SECONDS",
        "ACCOUNT_GOOGLE_OAUTH_CALLBACK_URL",
        "ACCOUNT_PASSWORD_RESET_API_ENABLED",
        "ACCOUNT_PASSWORD_RECOVERY_API_ENABLED",
        "ACCOUNT_SIGN_IN_API_ENABLED",
        "ACCOUNT_SIGN_OUT_API_ENABLED",
        "ACCOUNT_SESSION_API_ENABLED",
        "ACCOUNT_SIGN_UP_API_ENABLED",
        "ACCOUNT_EMAIL_CONFIRMATION_API_ENABLED",
    ):
        monkeypatch.delenv(name, raising=False)


def test_google_defaults_are_disabled_and_bounded() -> None:
    settings = IsolatedGoogleSettings()

    assert settings.account_google_oauth_api_enabled is False
    assert settings.account_google_oauth_timeout_seconds == 15
    assert settings.account_google_oauth_attempt_lifetime_seconds == 600
    assert settings.account_google_oauth_callback_url is None


@pytest.mark.parametrize("timeout", [1, 15, 30])
def test_valid_google_timeout_is_accepted(timeout: int) -> None:
    settings = IsolatedGoogleSettings.model_validate(
        {"account_google_oauth_timeout_seconds": timeout}
    )

    assert settings.account_google_oauth_timeout_seconds == timeout


@pytest.mark.parametrize("timeout", [0, -1, 31, 1.5, "invalid"])
def test_invalid_google_timeout_is_rejected(timeout: object) -> None:
    with pytest.raises(ValidationError) as caught:
        IsolatedGoogleSettings.model_validate({"account_google_oauth_timeout_seconds": timeout})

    assert any(
        error["loc"] == ("account_google_oauth_timeout_seconds",) for error in caught.value.errors()
    )


def test_google_settings_load_from_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ACCOUNT_GOOGLE_OAUTH_API_ENABLED", "true")
    monkeypatch.setenv("ACCOUNT_GOOGLE_OAUTH_TIMEOUT_SECONDS", "20")

    settings = IsolatedGoogleSettings()

    assert settings.account_google_oauth_api_enabled is True
    assert settings.account_google_oauth_timeout_seconds == 20


def test_enabling_google_does_not_enable_other_endpoints() -> None:
    settings = IsolatedGoogleSettings.model_validate({"account_google_oauth_api_enabled": True})

    assert settings.account_google_oauth_api_enabled is True
    assert settings.account_password_reset_api_enabled is False
    assert settings.account_password_recovery_api_enabled is False
    assert settings.account_sign_in_api_enabled is False
    assert settings.account_sign_out_api_enabled is False
    assert settings.account_session_api_enabled is False
    assert settings.account_sign_up_api_enabled is False
    assert settings.account_email_confirmation_api_enabled is False


def test_enabling_other_endpoints_does_not_enable_google() -> None:
    settings = IsolatedGoogleSettings.model_validate(
        {
            "account_password_reset_api_enabled": True,
            "account_password_recovery_api_enabled": True,
            "account_sign_in_api_enabled": True,
            "account_sign_out_api_enabled": True,
            "account_session_api_enabled": True,
            "account_sign_up_api_enabled": True,
            "account_email_confirmation_api_enabled": True,
        }
    )

    assert settings.account_google_oauth_api_enabled is False
    assert settings.account_google_oauth_timeout_seconds == 15


def test_empty_environment_values_keep_safe_defaults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ACCOUNT_GOOGLE_OAUTH_API_ENABLED", "")
    monkeypatch.setenv("ACCOUNT_GOOGLE_OAUTH_TIMEOUT_SECONDS", "")
    monkeypatch.setenv("ACCOUNT_GOOGLE_OAUTH_ATTEMPT_LIFETIME_SECONDS", "")
    monkeypatch.setenv("ACCOUNT_GOOGLE_OAUTH_CALLBACK_URL", "")

    settings = IsolatedGoogleSettings()

    assert settings.account_google_oauth_api_enabled is False
    assert settings.account_google_oauth_timeout_seconds == 15
    assert settings.account_google_oauth_attempt_lifetime_seconds == 600
    assert settings.account_google_oauth_callback_url is None


@pytest.mark.parametrize("lifetime", [60, 600, 900])
def test_valid_attempt_lifetime_is_accepted(lifetime: int) -> None:
    settings = IsolatedGoogleSettings.model_validate(
        {"account_google_oauth_attempt_lifetime_seconds": lifetime}
    )

    assert settings.account_google_oauth_attempt_lifetime_seconds == lifetime


@pytest.mark.parametrize("lifetime", [0, 59, 901, 1.5, "invalid"])
def test_invalid_attempt_lifetime_is_rejected(lifetime: object) -> None:
    with pytest.raises(ValidationError) as caught:
        IsolatedGoogleSettings.model_validate(
            {"account_google_oauth_attempt_lifetime_seconds": lifetime}
        )

    assert any(
        error["loc"] == ("account_google_oauth_attempt_lifetime_seconds",)
        for error in caught.value.errors()
    )


def test_attempt_lifetime_is_independent_of_operation_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ACCOUNT_GOOGLE_OAUTH_ATTEMPT_LIFETIME_SECONDS", "900")
    monkeypatch.setenv("ACCOUNT_GOOGLE_OAUTH_TIMEOUT_SECONDS", "20")

    settings = IsolatedGoogleSettings()

    assert settings.account_google_oauth_attempt_lifetime_seconds == 900
    assert settings.account_google_oauth_timeout_seconds == 20
    assert settings.account_google_oauth_api_enabled is False
