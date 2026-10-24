"""Email-confirmation configuration without private files or live services."""

import pytest
from pydantic import ValidationError
from pydantic_settings import SettingsConfigDict

from app.config import Settings


class IsolatedConfirmationSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


def test_confirmation_budget_is_independent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ACCOUNT_SIGN_UP_IP_MAX_REQUESTS", "42")
    monkeypatch.setenv("ACCOUNT_SIGN_IN_IP_MAX_REQUESTS", "43")
    monkeypatch.setenv("ACCOUNT_PASSWORD_RECOVERY_IP_MAX_REQUESTS", "44")
    settings = IsolatedConfirmationSettings()
    assert settings.account_email_confirmation_ip_max_requests == 10
    assert settings.account_sign_up_ip_max_requests == 42
    assert settings.account_sign_in_ip_max_requests == 43
    assert settings.account_password_recovery_ip_max_requests == 44


@pytest.fixture(autouse=True)
def clear_confirmation_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "ACCOUNT_EMAIL_CONFIRMATION_API_ENABLED",
        "ACCOUNT_EMAIL_CONFIRMATION_TIMEOUT_SECONDS",
        "ACCOUNT_EMAIL_CONFIRMATION_IP_MAX_REQUESTS",
        "ACCOUNT_EMAIL_CONFIRMATION_IP_WINDOW_SECONDS",
        "ACCOUNT_SIGN_UP_API_ENABLED",
        "ACCOUNT_SIGN_IN_API_ENABLED",
        "ACCOUNT_SIGN_OUT_API_ENABLED",
        "ACCOUNT_SESSION_API_ENABLED",
    ):
        monkeypatch.delenv(name, raising=False)


def test_confirmation_defaults_are_disabled_and_bounded() -> None:
    settings = IsolatedConfirmationSettings()

    assert settings.account_email_confirmation_api_enabled is False
    assert settings.account_email_confirmation_timeout_seconds == 15
    assert settings.account_email_confirmation_ip_max_requests == 10
    assert settings.account_email_confirmation_ip_window_seconds == 600


@pytest.mark.parametrize("timeout", [1, 15, 30])
def test_valid_confirmation_timeout_is_accepted(timeout: int) -> None:
    settings = IsolatedConfirmationSettings.model_validate(
        {"account_email_confirmation_timeout_seconds": timeout}
    )

    assert settings.account_email_confirmation_timeout_seconds == timeout


@pytest.mark.parametrize("timeout", [0, -1, 31, 1.5, "invalid"])
def test_invalid_confirmation_timeout_is_rejected(timeout: object) -> None:
    with pytest.raises(ValidationError) as caught:
        IsolatedConfirmationSettings.model_validate(
            {"account_email_confirmation_timeout_seconds": timeout}
        )

    assert any(
        error["loc"] == ("account_email_confirmation_timeout_seconds",)
        for error in caught.value.errors()
    )


def test_confirmation_settings_load_from_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ACCOUNT_EMAIL_CONFIRMATION_API_ENABLED", "true")
    monkeypatch.setenv("ACCOUNT_EMAIL_CONFIRMATION_TIMEOUT_SECONDS", "20")

    settings = IsolatedConfirmationSettings()

    assert settings.account_email_confirmation_api_enabled is True
    assert settings.account_email_confirmation_timeout_seconds == 20


def test_enabling_confirmation_does_not_enable_other_account_endpoints() -> None:
    settings = IsolatedConfirmationSettings.model_validate(
        {"account_email_confirmation_api_enabled": True}
    )

    assert settings.account_email_confirmation_api_enabled is True
    assert settings.account_sign_up_api_enabled is False
    assert settings.account_sign_in_api_enabled is False
    assert settings.account_sign_out_api_enabled is False
    assert settings.account_session_api_enabled is False


def test_empty_environment_values_keep_safe_defaults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ACCOUNT_EMAIL_CONFIRMATION_API_ENABLED", "")
    monkeypatch.setenv("ACCOUNT_EMAIL_CONFIRMATION_TIMEOUT_SECONDS", "")
    monkeypatch.setenv("ACCOUNT_EMAIL_CONFIRMATION_IP_MAX_REQUESTS", "")
    monkeypatch.setenv("ACCOUNT_EMAIL_CONFIRMATION_IP_WINDOW_SECONDS", "")

    settings = IsolatedConfirmationSettings()

    assert settings.account_email_confirmation_api_enabled is False
    assert settings.account_email_confirmation_timeout_seconds == 15
    assert settings.account_email_confirmation_ip_max_requests == 10
    assert settings.account_email_confirmation_ip_window_seconds == 600


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
def test_valid_email_confirmation_rate_limit_boundaries(field: str, value: int) -> None:
    settings = IsolatedConfirmationSettings.model_validate(
        {f"account_email_confirmation_ip_{field}": value}
    )
    assert getattr(settings, f"account_email_confirmation_ip_{field}") == value
    assert not settings.account_email_confirmation_api_enabled


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
def test_invalid_email_confirmation_rate_limit_boundaries(field: str, value: object) -> None:
    with pytest.raises(ValidationError) as caught:
        IsolatedConfirmationSettings.model_validate(
            {f"account_email_confirmation_ip_{field}": value}
        )
    assert any(
        error["loc"] == (f"account_email_confirmation_ip_{field}",)
        for error in caught.value.errors(include_input=False)
    )


def test_email_confirmation_rate_policy_environment_and_precedence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ACCOUNT_EMAIL_CONFIRMATION_IP_MAX_REQUESTS", "7")
    monkeypatch.setenv("ACCOUNT_EMAIL_CONFIRMATION_IP_WINDOW_SECONDS", "900")
    settings = IsolatedConfirmationSettings()
    assert (
        settings.account_email_confirmation_ip_max_requests,
        settings.account_email_confirmation_ip_window_seconds,
    ) == (7, 900)
    overridden = IsolatedConfirmationSettings(
        account_email_confirmation_ip_max_requests=2,
        account_email_confirmation_ip_window_seconds=60,
    )
    assert (
        overridden.account_email_confirmation_ip_max_requests,
        overridden.account_email_confirmation_ip_window_seconds,
    ) == (2, 60)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("ACCOUNT_EMAIL_CONFIRMATION_IP_MAX_REQUESTS", "0"),
        ("ACCOUNT_EMAIL_CONFIRMATION_IP_MAX_REQUESTS", "invalid"),
        ("ACCOUNT_EMAIL_CONFIRMATION_IP_WINDOW_SECONDS", "59"),
        ("ACCOUNT_EMAIL_CONFIRMATION_IP_WINDOW_SECONDS", "86401"),
    ],
)
def test_invalid_email_confirmation_rate_environment(
    monkeypatch: pytest.MonkeyPatch, name: str, value: str
) -> None:
    monkeypatch.setenv(name, value)
    with pytest.raises(ValidationError):
        IsolatedConfirmationSettings()
