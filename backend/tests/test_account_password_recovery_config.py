"""Password-recovery configuration without private files or live services."""

import pytest
from pydantic import ValidationError
from pydantic_settings import SettingsConfigDict

from app.config import Settings


class IsolatedPasswordRecoverySettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@pytest.fixture(autouse=True)
def clear_password_recovery_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "ACCOUNT_PASSWORD_RECOVERY_API_ENABLED",
        "ACCOUNT_PASSWORD_RECOVERY_TIMEOUT_SECONDS",
        "ACCOUNT_SIGN_IN_API_ENABLED",
        "ACCOUNT_SIGN_OUT_API_ENABLED",
        "ACCOUNT_SESSION_API_ENABLED",
        "ACCOUNT_SIGN_UP_API_ENABLED",
        "ACCOUNT_EMAIL_CONFIRMATION_API_ENABLED",
    ):
        monkeypatch.delenv(name, raising=False)


def test_password_recovery_defaults_are_disabled_and_bounded() -> None:
    settings = IsolatedPasswordRecoverySettings()

    assert settings.account_password_recovery_api_enabled is False
    assert settings.account_password_recovery_timeout_seconds == 15


@pytest.mark.parametrize("timeout", [1, 15, 30])
def test_valid_password_recovery_timeout_is_accepted(timeout: int) -> None:
    settings = IsolatedPasswordRecoverySettings.model_validate(
        {"account_password_recovery_timeout_seconds": timeout}
    )

    assert settings.account_password_recovery_timeout_seconds == timeout


@pytest.mark.parametrize("timeout", [0, -1, 31, 1.5, "invalid"])
def test_invalid_password_recovery_timeout_is_rejected(timeout: object) -> None:
    with pytest.raises(ValidationError) as caught:
        IsolatedPasswordRecoverySettings.model_validate(
            {"account_password_recovery_timeout_seconds": timeout}
        )

    assert any(
        error["loc"] == ("account_password_recovery_timeout_seconds",)
        for error in caught.value.errors()
    )


def test_password_recovery_settings_load_from_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ACCOUNT_PASSWORD_RECOVERY_API_ENABLED", "true")
    monkeypatch.setenv("ACCOUNT_PASSWORD_RECOVERY_TIMEOUT_SECONDS", "20")

    settings = IsolatedPasswordRecoverySettings()

    assert settings.account_password_recovery_api_enabled is True
    assert settings.account_password_recovery_timeout_seconds == 20


def test_enabling_recovery_does_not_enable_other_account_endpoints() -> None:
    settings = IsolatedPasswordRecoverySettings.model_validate(
        {"account_password_recovery_api_enabled": True}
    )

    assert settings.account_password_recovery_api_enabled is True
    assert settings.account_sign_in_api_enabled is False
    assert settings.account_sign_out_api_enabled is False
    assert settings.account_session_api_enabled is False
    assert settings.account_sign_up_api_enabled is False
    assert settings.account_email_confirmation_api_enabled is False


def test_empty_environment_values_keep_safe_recovery_defaults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ACCOUNT_PASSWORD_RECOVERY_API_ENABLED", "")
    monkeypatch.setenv("ACCOUNT_PASSWORD_RECOVERY_TIMEOUT_SECONDS", "")

    settings = IsolatedPasswordRecoverySettings()

    assert settings.account_password_recovery_api_enabled is False
    assert settings.account_password_recovery_timeout_seconds == 15
