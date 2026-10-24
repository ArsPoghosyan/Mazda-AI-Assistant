"""Password-reset settings without private configuration or live services."""

import pytest
from pydantic import ValidationError
from pydantic_settings import SettingsConfigDict

from app.config import Settings


class IsolatedPasswordResetSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


def test_reset_budget_is_independent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ACCOUNT_PASSWORD_RECOVERY_IP_MAX_REQUESTS", "42")
    monkeypatch.setenv("ACCOUNT_EMAIL_CONFIRMATION_IP_MAX_REQUESTS", "43")
    settings = IsolatedPasswordResetSettings()
    assert settings.account_password_reset_ip_max_requests == 10
    assert settings.account_password_recovery_ip_max_requests == 42
    assert settings.account_email_confirmation_ip_max_requests == 43


@pytest.fixture(autouse=True)
def clear_account_endpoint_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "ACCOUNT_PASSWORD_RESET_API_ENABLED",
        "ACCOUNT_PASSWORD_RESET_TIMEOUT_SECONDS",
        "ACCOUNT_PASSWORD_RESET_IP_MAX_REQUESTS",
        "ACCOUNT_PASSWORD_RESET_IP_WINDOW_SECONDS",
        "ACCOUNT_PASSWORD_RECOVERY_API_ENABLED",
        "ACCOUNT_SIGN_IN_API_ENABLED",
        "ACCOUNT_SIGN_OUT_API_ENABLED",
        "ACCOUNT_SESSION_API_ENABLED",
        "ACCOUNT_SIGN_UP_API_ENABLED",
        "ACCOUNT_EMAIL_CONFIRMATION_API_ENABLED",
    ):
        monkeypatch.delenv(name, raising=False)


def test_password_reset_defaults_are_disabled_and_bounded() -> None:
    settings = IsolatedPasswordResetSettings()

    assert settings.account_password_reset_api_enabled is False
    assert settings.account_password_reset_timeout_seconds == 15
    assert settings.account_password_reset_ip_max_requests == 10
    assert settings.account_password_reset_ip_window_seconds == 600


@pytest.mark.parametrize("timeout", [1, 15, 30])
def test_valid_password_reset_timeout_is_accepted(timeout: int) -> None:
    settings = IsolatedPasswordResetSettings.model_validate(
        {"account_password_reset_timeout_seconds": timeout}
    )

    assert settings.account_password_reset_timeout_seconds == timeout


@pytest.mark.parametrize("timeout", [0, -1, 31, 1.5, "invalid"])
def test_invalid_password_reset_timeout_is_rejected(timeout: object) -> None:
    with pytest.raises(ValidationError) as caught:
        IsolatedPasswordResetSettings.model_validate(
            {"account_password_reset_timeout_seconds": timeout}
        )

    assert any(
        error["loc"] == ("account_password_reset_timeout_seconds",)
        for error in caught.value.errors()
    )


def test_password_reset_settings_load_from_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ACCOUNT_PASSWORD_RESET_API_ENABLED", "true")
    monkeypatch.setenv("ACCOUNT_PASSWORD_RESET_TIMEOUT_SECONDS", "20")

    settings = IsolatedPasswordResetSettings()

    assert settings.account_password_reset_api_enabled is True
    assert settings.account_password_reset_timeout_seconds == 20


def test_enabling_reset_does_not_enable_other_account_endpoints() -> None:
    settings = IsolatedPasswordResetSettings.model_validate(
        {"account_password_reset_api_enabled": True}
    )

    assert settings.account_password_reset_api_enabled is True
    assert settings.account_password_recovery_api_enabled is False
    assert settings.account_sign_in_api_enabled is False
    assert settings.account_sign_out_api_enabled is False
    assert settings.account_session_api_enabled is False
    assert settings.account_sign_up_api_enabled is False
    assert settings.account_email_confirmation_api_enabled is False


def test_enabling_other_account_endpoints_does_not_enable_reset() -> None:
    settings = IsolatedPasswordResetSettings.model_validate(
        {
            "account_password_recovery_api_enabled": True,
            "account_sign_in_api_enabled": True,
            "account_sign_out_api_enabled": True,
            "account_session_api_enabled": True,
            "account_sign_up_api_enabled": True,
            "account_email_confirmation_api_enabled": True,
        }
    )

    assert settings.account_password_reset_api_enabled is False
    assert settings.account_password_reset_timeout_seconds == 15
    assert settings.account_password_reset_ip_max_requests == 10
    assert settings.account_password_reset_ip_window_seconds == 600


def test_empty_environment_values_keep_safe_reset_defaults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ACCOUNT_PASSWORD_RESET_API_ENABLED", "")
    monkeypatch.setenv("ACCOUNT_PASSWORD_RESET_TIMEOUT_SECONDS", "")
    monkeypatch.setenv("ACCOUNT_PASSWORD_RESET_IP_MAX_REQUESTS", "")
    monkeypatch.setenv("ACCOUNT_PASSWORD_RESET_IP_WINDOW_SECONDS", "")

    settings = IsolatedPasswordResetSettings()

    assert settings.account_password_reset_api_enabled is False
    assert settings.account_password_reset_timeout_seconds == 15
    assert settings.account_password_reset_ip_max_requests == 10
    assert settings.account_password_reset_ip_window_seconds == 600


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
def test_valid_password_reset_rate_limit_boundaries(field: str, value: int) -> None:
    settings = IsolatedPasswordResetSettings.model_validate(
        {f"account_password_reset_ip_{field}": value}
    )
    assert getattr(settings, f"account_password_reset_ip_{field}") == value
    assert not settings.account_password_reset_api_enabled


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
def test_invalid_password_reset_rate_limit_boundaries(field: str, value: object) -> None:
    with pytest.raises(ValidationError) as caught:
        IsolatedPasswordResetSettings.model_validate({f"account_password_reset_ip_{field}": value})
    assert any(
        error["loc"] == (f"account_password_reset_ip_{field}",)
        for error in caught.value.errors(include_input=False)
    )


def test_password_reset_rate_policy_environment_and_precedence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ACCOUNT_PASSWORD_RESET_IP_MAX_REQUESTS", "7")
    monkeypatch.setenv("ACCOUNT_PASSWORD_RESET_IP_WINDOW_SECONDS", "900")
    settings = IsolatedPasswordResetSettings()
    assert (
        settings.account_password_reset_ip_max_requests,
        settings.account_password_reset_ip_window_seconds,
    ) == (7, 900)
    overridden = IsolatedPasswordResetSettings(
        account_password_reset_ip_max_requests=2,
        account_password_reset_ip_window_seconds=60,
    )
    assert (
        overridden.account_password_reset_ip_max_requests,
        overridden.account_password_reset_ip_window_seconds,
    ) == (2, 60)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("ACCOUNT_PASSWORD_RESET_IP_MAX_REQUESTS", "0"),
        ("ACCOUNT_PASSWORD_RESET_IP_MAX_REQUESTS", "invalid"),
        ("ACCOUNT_PASSWORD_RESET_IP_WINDOW_SECONDS", "59"),
        ("ACCOUNT_PASSWORD_RESET_IP_WINDOW_SECONDS", "86401"),
    ],
)
def test_invalid_password_reset_rate_environment(
    monkeypatch: pytest.MonkeyPatch, name: str, value: str
) -> None:
    monkeypatch.setenv(name, value)
    with pytest.raises(ValidationError):
        IsolatedPasswordResetSettings()
