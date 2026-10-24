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
        "ACCOUNT_PASSWORD_RECOVERY_IP_MAX_REQUESTS",
        "ACCOUNT_PASSWORD_RECOVERY_IP_WINDOW_SECONDS",
        "ACCOUNT_PASSWORD_RESET_API_ENABLED",
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
    assert settings.account_password_recovery_ip_max_requests == 10
    assert settings.account_password_recovery_ip_window_seconds == 600


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
    monkeypatch.setenv("ACCOUNT_PASSWORD_RECOVERY_IP_MAX_REQUESTS", "25")
    monkeypatch.setenv("ACCOUNT_PASSWORD_RECOVERY_IP_WINDOW_SECONDS", "900")

    settings = IsolatedPasswordRecoverySettings()

    assert settings.account_password_recovery_api_enabled is True
    assert settings.account_password_recovery_timeout_seconds == 20
    assert settings.account_password_recovery_ip_max_requests == 25
    assert settings.account_password_recovery_ip_window_seconds == 900


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
    monkeypatch.setenv("ACCOUNT_PASSWORD_RECOVERY_IP_MAX_REQUESTS", "")
    monkeypatch.setenv("ACCOUNT_PASSWORD_RECOVERY_IP_WINDOW_SECONDS", "")

    settings = IsolatedPasswordRecoverySettings()

    assert settings.account_password_recovery_api_enabled is False
    assert settings.account_password_recovery_timeout_seconds == 15
    assert settings.account_password_recovery_ip_max_requests == 10
    assert settings.account_password_recovery_ip_window_seconds == 600


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("account_password_recovery_ip_max_requests", 1),
        ("account_password_recovery_ip_max_requests", 10),
        ("account_password_recovery_ip_max_requests", 1000),
        ("account_password_recovery_ip_window_seconds", 60),
        ("account_password_recovery_ip_window_seconds", 600),
        ("account_password_recovery_ip_window_seconds", 86400),
    ],
)
def test_valid_recovery_ip_limits_are_accepted(field: str, value: int) -> None:
    settings = IsolatedPasswordRecoverySettings.model_validate({field: value})

    assert getattr(settings, field) == value


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("account_password_recovery_ip_max_requests", 0),
        ("account_password_recovery_ip_max_requests", -1),
        ("account_password_recovery_ip_max_requests", 1001),
        ("account_password_recovery_ip_max_requests", 1.5),
        ("account_password_recovery_ip_max_requests", "invalid"),
        ("account_password_recovery_ip_window_seconds", 59),
        ("account_password_recovery_ip_window_seconds", -1),
        ("account_password_recovery_ip_window_seconds", 86401),
        ("account_password_recovery_ip_window_seconds", 60.5),
        ("account_password_recovery_ip_window_seconds", "invalid"),
    ],
)
def test_invalid_recovery_ip_limits_are_rejected(field: str, value: object) -> None:
    with pytest.raises(ValidationError) as caught:
        IsolatedPasswordRecoverySettings.model_validate({field: value})

    assert any(error["loc"] == (field,) for error in caught.value.errors())


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("ACCOUNT_PASSWORD_RECOVERY_IP_MAX_REQUESTS", "0"),
        ("ACCOUNT_PASSWORD_RECOVERY_IP_MAX_REQUESTS", "1001"),
        ("ACCOUNT_PASSWORD_RECOVERY_IP_MAX_REQUESTS", "1.5"),
        ("ACCOUNT_PASSWORD_RECOVERY_IP_WINDOW_SECONDS", "59"),
        ("ACCOUNT_PASSWORD_RECOVERY_IP_WINDOW_SECONDS", "86401"),
        ("ACCOUNT_PASSWORD_RECOVERY_IP_WINDOW_SECONDS", "invalid"),
    ],
)
def test_invalid_environment_ip_limits_fail_settings_validation(
    monkeypatch: pytest.MonkeyPatch, name: str, value: str
) -> None:
    monkeypatch.setenv(name, value)

    with pytest.raises(ValidationError) as caught:
        IsolatedPasswordRecoverySettings()

    assert any(error["loc"] == (name.lower(),) for error in caught.value.errors())


def test_explicit_ip_limits_override_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ACCOUNT_PASSWORD_RECOVERY_IP_MAX_REQUESTS", "25")
    monkeypatch.setenv("ACCOUNT_PASSWORD_RECOVERY_IP_WINDOW_SECONDS", "900")

    settings = IsolatedPasswordRecoverySettings(
        account_password_recovery_ip_max_requests=5,
        account_password_recovery_ip_window_seconds=300,
    )

    assert settings.account_password_recovery_ip_max_requests == 5
    assert settings.account_password_recovery_ip_window_seconds == 300


def test_configuring_ip_limits_does_not_enable_recovery_or_reset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ACCOUNT_PASSWORD_RECOVERY_IP_MAX_REQUESTS", "25")
    monkeypatch.setenv("ACCOUNT_PASSWORD_RECOVERY_IP_WINDOW_SECONDS", "900")

    settings = IsolatedPasswordRecoverySettings()

    assert settings.account_password_recovery_api_enabled is False
    assert settings.account_password_reset_api_enabled is False
