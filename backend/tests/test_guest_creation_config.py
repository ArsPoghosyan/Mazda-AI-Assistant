"""Guest-creation limits use bounded, independent environment policies."""

import pytest
from pydantic import ValidationError
from pydantic_settings import SettingsConfigDict

from app.config import Settings


class IsolatedGuestSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@pytest.fixture(autouse=True)
def clear_guest_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "GUEST_CREATION_IP_MAX_REQUESTS",
        "GUEST_CREATION_IP_WINDOW_SECONDS",
        "GUEST_SESSION_API_ENABLED",
    ):
        monkeypatch.delenv(name, raising=False)


def test_defaults_preserve_other_endpoint_budgets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ACCOUNT_SIGN_IN_IP_MAX_REQUESTS", "42")
    settings = IsolatedGuestSettings()
    assert settings.guest_creation_ip_max_requests == 10
    assert settings.guest_creation_ip_window_seconds == 600
    assert not settings.guest_session_api_enabled
    assert settings.account_sign_in_ip_max_requests == 42


def test_empty_values_keep_safe_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GUEST_CREATION_IP_MAX_REQUESTS", "")
    monkeypatch.setenv("GUEST_CREATION_IP_WINDOW_SECONDS", "")
    settings = IsolatedGuestSettings()
    assert settings.guest_creation_ip_max_requests == 10
    assert settings.guest_creation_ip_window_seconds == 600


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
def test_valid_guest_creation_rate_limit_boundaries(field: str, value: int) -> None:
    settings = IsolatedGuestSettings.model_validate({f"guest_creation_ip_{field}": value})
    assert getattr(settings, f"guest_creation_ip_{field}") == value
    assert not settings.guest_session_api_enabled


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
def test_invalid_guest_creation_rate_limit_boundaries(field: str, value: object) -> None:
    with pytest.raises(ValidationError) as caught:
        IsolatedGuestSettings.model_validate({f"guest_creation_ip_{field}": value})
    assert any(
        error["loc"] == (f"guest_creation_ip_{field}",)
        for error in caught.value.errors(include_input=False)
    )


def test_guest_creation_rate_policy_environment_and_precedence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GUEST_CREATION_IP_MAX_REQUESTS", "7")
    monkeypatch.setenv("GUEST_CREATION_IP_WINDOW_SECONDS", "900")
    settings = IsolatedGuestSettings()
    assert (
        settings.guest_creation_ip_max_requests,
        settings.guest_creation_ip_window_seconds,
    ) == (7, 900)
    overridden = IsolatedGuestSettings(
        guest_creation_ip_max_requests=2,
        guest_creation_ip_window_seconds=60,
    )
    assert (
        overridden.guest_creation_ip_max_requests,
        overridden.guest_creation_ip_window_seconds,
    ) == (2, 60)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("GUEST_CREATION_IP_MAX_REQUESTS", "0"),
        ("GUEST_CREATION_IP_MAX_REQUESTS", "invalid"),
        ("GUEST_CREATION_IP_WINDOW_SECONDS", "59"),
        ("GUEST_CREATION_IP_WINDOW_SECONDS", "86401"),
    ],
)
def test_invalid_guest_creation_rate_environment(
    monkeypatch: pytest.MonkeyPatch, name: str, value: str
) -> None:
    monkeypatch.setenv(name, value)
    with pytest.raises(ValidationError):
        IsolatedGuestSettings()
