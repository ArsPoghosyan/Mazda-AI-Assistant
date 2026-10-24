"""Sign-in limit configuration without private files or live services."""

import pytest
from pydantic import ValidationError
from pydantic_settings import SettingsConfigDict

from app.config import Settings


class IsolatedSignInSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@pytest.fixture(autouse=True)
def clear_sign_in_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "ACCOUNT_SIGN_IN_API_ENABLED",
        "ACCOUNT_SIGN_IN_TIMEOUT_SECONDS",
        "ACCOUNT_SIGN_IN_IP_MAX_REQUESTS",
        "ACCOUNT_SIGN_IN_IP_WINDOW_SECONDS",
        "ACCOUNT_PASSWORD_RECOVERY_API_ENABLED",
        "ACCOUNT_PASSWORD_RECOVERY_IP_MAX_REQUESTS",
        "ACCOUNT_PASSWORD_RECOVERY_IP_WINDOW_SECONDS",
        "ACCOUNT_PASSWORD_RESET_API_ENABLED",
        "ACCOUNT_SIGN_OUT_API_ENABLED",
        "ACCOUNT_SESSION_API_ENABLED",
        "ACCOUNT_SIGN_UP_API_ENABLED",
        "ACCOUNT_EMAIL_CONFIRMATION_API_ENABLED",
        "ACCOUNT_GOOGLE_OAUTH_API_ENABLED",
        "AUTH_RATE_LIMIT_HMAC_SECRET",
    ):
        monkeypatch.delenv(name, raising=False)


def test_sign_in_policy_defaults_do_not_enable_endpoints() -> None:
    settings = IsolatedSignInSettings()

    assert settings.account_sign_in_ip_max_requests == 30
    assert settings.account_sign_in_ip_window_seconds == 600
    assert settings.account_sign_in_timeout_seconds == 15
    assert settings.auth_rate_limit_hmac_secret is None
    assert not any(
        getattr(settings, name)
        for name in (
            "account_sign_in_api_enabled",
            "account_sign_out_api_enabled",
            "account_session_api_enabled",
            "account_sign_up_api_enabled",
            "account_email_confirmation_api_enabled",
            "account_password_recovery_api_enabled",
            "account_password_reset_api_enabled",
            "account_google_oauth_api_enabled",
        )
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("account_sign_in_ip_max_requests", 1),
        ("account_sign_in_ip_max_requests", 30),
        ("account_sign_in_ip_max_requests", 1000),
        ("account_sign_in_ip_window_seconds", 60),
        ("account_sign_in_ip_window_seconds", 600),
        ("account_sign_in_ip_window_seconds", 86400),
    ],
)
def test_valid_sign_in_limits_are_accepted(field: str, value: int) -> None:
    settings = IsolatedSignInSettings.model_validate({field: value})

    assert getattr(settings, field) == value


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("account_sign_in_ip_max_requests", 0),
        ("account_sign_in_ip_max_requests", -1),
        ("account_sign_in_ip_max_requests", 1001),
        ("account_sign_in_ip_max_requests", 1.5),
        ("account_sign_in_ip_max_requests", "invalid"),
        ("account_sign_in_ip_max_requests", None),
        ("account_sign_in_ip_window_seconds", 59),
        ("account_sign_in_ip_window_seconds", -1),
        ("account_sign_in_ip_window_seconds", 86401),
        ("account_sign_in_ip_window_seconds", 60.5),
        ("account_sign_in_ip_window_seconds", "invalid"),
        ("account_sign_in_ip_window_seconds", None),
    ],
)
def test_invalid_sign_in_limits_are_rejected(field: str, value: object) -> None:
    with pytest.raises(ValidationError) as caught:
        IsolatedSignInSettings.model_validate({field: value})

    assert any(error["loc"] == (field,) for error in caught.value.errors(include_input=False))


def test_sign_in_limits_load_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ACCOUNT_SIGN_IN_IP_MAX_REQUESTS", "45")
    monkeypatch.setenv("ACCOUNT_SIGN_IN_IP_WINDOW_SECONDS", "900")

    settings = IsolatedSignInSettings()

    assert settings.account_sign_in_ip_max_requests == 45
    assert settings.account_sign_in_ip_window_seconds == 900
    assert settings.account_sign_in_api_enabled is False


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("ACCOUNT_SIGN_IN_IP_MAX_REQUESTS", "0"),
        ("ACCOUNT_SIGN_IN_IP_MAX_REQUESTS", "1001"),
        ("ACCOUNT_SIGN_IN_IP_MAX_REQUESTS", "1.5"),
        ("ACCOUNT_SIGN_IN_IP_WINDOW_SECONDS", "59"),
        ("ACCOUNT_SIGN_IN_IP_WINDOW_SECONDS", "86401"),
        ("ACCOUNT_SIGN_IN_IP_WINDOW_SECONDS", "invalid"),
    ],
)
def test_invalid_environment_limits_fail_validation(
    monkeypatch: pytest.MonkeyPatch, name: str, value: str
) -> None:
    monkeypatch.setenv(name, value)

    with pytest.raises(ValidationError) as caught:
        IsolatedSignInSettings()

    assert any(
        error["loc"] == (name.lower(),) for error in caught.value.errors(include_input=False)
    )


def test_empty_environment_values_keep_policy_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ACCOUNT_SIGN_IN_IP_MAX_REQUESTS", "")
    monkeypatch.setenv("ACCOUNT_SIGN_IN_IP_WINDOW_SECONDS", "")

    settings = IsolatedSignInSettings()

    assert settings.account_sign_in_ip_max_requests == 30
    assert settings.account_sign_in_ip_window_seconds == 600


def test_explicit_limits_override_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ACCOUNT_SIGN_IN_IP_MAX_REQUESTS", "45")
    monkeypatch.setenv("ACCOUNT_SIGN_IN_IP_WINDOW_SECONDS", "900")

    settings = IsolatedSignInSettings(
        account_sign_in_ip_max_requests=5,
        account_sign_in_ip_window_seconds=300,
    )

    assert settings.account_sign_in_ip_max_requests == 5
    assert settings.account_sign_in_ip_window_seconds == 300


@pytest.mark.parametrize("configured", ["sign_in", "password_recovery"])
def test_sign_in_and_recovery_policies_are_independent(
    monkeypatch: pytest.MonkeyPatch, configured: str
) -> None:
    prefix = f"ACCOUNT_{configured.upper()}_IP"
    monkeypatch.setenv(f"{prefix}_MAX_REQUESTS", "7")
    monkeypatch.setenv(f"{prefix}_WINDOW_SECONDS", "300")

    settings = IsolatedSignInSettings()

    if configured == "sign_in":
        assert settings.account_sign_in_ip_max_requests == 7
        assert settings.account_sign_in_ip_window_seconds == 300
        assert settings.account_password_recovery_ip_max_requests == 10
        assert settings.account_password_recovery_ip_window_seconds == 600
    else:
        assert settings.account_password_recovery_ip_max_requests == 7
        assert settings.account_password_recovery_ip_window_seconds == 300
        assert settings.account_sign_in_ip_max_requests == 30
        assert settings.account_sign_in_ip_window_seconds == 600


def test_enabling_sign_in_does_not_enable_recovery(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ACCOUNT_SIGN_IN_API_ENABLED", "true")

    settings = IsolatedSignInSettings()

    assert settings.account_sign_in_api_enabled is True
    assert settings.account_password_recovery_api_enabled is False
    assert settings.account_sign_in_ip_max_requests == 30
    assert settings.account_sign_in_ip_window_seconds == 600
