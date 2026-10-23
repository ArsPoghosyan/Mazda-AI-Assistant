"""Fixed callback validation without private files, services or redirect requests."""

import pytest
from pydantic import ValidationError
from pydantic_settings import SettingsConfigDict

from app.config import Settings

PATH = "/api/v1/account/google/callback"


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@pytest.fixture(autouse=True)
def clear_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("ACCOUNT_GOOGLE_OAUTH_CALLBACK_URL", "ACCOUNT_COOKIE_SECURE"):
        monkeypatch.delenv(name, raising=False)


@pytest.mark.parametrize("origin", ["https://askm6.com", "https://api.example.com:8443"])
def test_https_fixed_callback_is_accepted(origin: str) -> None:
    settings = IsolatedSettings.model_validate({"account_google_oauth_callback_url": origin + PATH})
    assert str(settings.account_google_oauth_callback_url) == origin + PATH
    assert settings.account_cookie_secure is True


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "[::1]"])
def test_loopback_http_requires_explicit_insecure_development_cookies(host: str) -> None:
    callback = f"http://{host}:5173{PATH}"
    with pytest.raises(ValidationError):
        IsolatedSettings.model_validate({"account_google_oauth_callback_url": callback})

    settings = IsolatedSettings.model_validate(
        {"account_google_oauth_callback_url": callback, "account_cookie_secure": False}
    )
    assert str(settings.account_google_oauth_callback_url) == callback


@pytest.mark.parametrize(
    "host", ["example.com", "localhost.example.com", "127.0.0.2", "2130706433", "0x7f000001"]
)
def test_nonliteral_loopback_or_remote_http_is_rejected(host: str) -> None:
    with pytest.raises(ValidationError):
        IsolatedSettings.model_validate(
            {
                "account_google_oauth_callback_url": f"http://{host}:5173{PATH}",
                "account_cookie_secure": False,
            }
        )


@pytest.mark.parametrize(
    "callback",
    [
        pytest.param(PATH, id="relative"),
        pytest.param(f"//example.com{PATH}", id="scheme-relative"),
        pytest.param(f"ftp://example.com{PATH}", id="unsupported-scheme"),
        pytest.param(f"https://user:synthetic-password@example.com{PATH}", id="credentials"),
        pytest.param(f"https://@example.com{PATH}", id="empty-userinfo"),
        pytest.param(f"https://example.com{PATH}?next=https://other.example", id="query"),
        pytest.param(f"https://example.com{PATH}?", id="empty-query"),
        pytest.param(f"https://example.com{PATH}#fragment", id="fragment"),
        pytest.param(f"https://example.com{PATH}#", id="empty-fragment"),
        pytest.param("https://example.com/other", id="wrong-path"),
        pytest.param(f"https://example.com{PATH}/", id="trailing-slash"),
        pytest.param(f"https://example.com/old/..{PATH}", id="dot-segments"),
        pytest.param(f"https://example.com/%2e%2e{PATH}", id="encoded-dot-segments"),
        pytest.param("https://example.com/api/v1/account/google/%63allback", id="encoded-path"),
        pytest.param(f"https://example.com\\other{PATH}", id="backslash"),
        pytest.param(f" https://example.com{PATH}", id="leading-space"),
        pytest.param(f"https://example.com{PATH} ", id="trailing-space"),
        pytest.param(f"https://example.com{PATH}\n", id="newline"),
        pytest.param(f"https://exam\tple.com{PATH}", id="embedded-tab"),
        pytest.param(f"https://example.com{PATH}\x00", id="nul"),
        pytest.param(f"https://*.example.com{PATH}", id="wildcard"),
        pytest.param(f"https://[invalid]{PATH}", id="invalid-ipv6"),
        pytest.param(f"https://example.com:bad{PATH}", id="invalid-port"),
        pytest.param(f"https://{'a' * 2050}.example{PATH}", id="oversized"),
    ],
)
def test_ambiguous_or_unapproved_callback_shapes_are_rejected(callback: str) -> None:
    with pytest.raises(ValidationError) as caught:
        IsolatedSettings.model_validate({"account_google_oauth_callback_url": callback})
    assert any(
        error["loc"] == ("account_google_oauth_callback_url",) for error in caught.value.errors()
    )
    assert "synthetic-password" not in str(caught.value)


def test_callback_loads_from_environment_with_development_cookie_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    callback = f"http://127.0.0.1:5173{PATH}"
    monkeypatch.setenv("ACCOUNT_GOOGLE_OAUTH_CALLBACK_URL", callback)
    monkeypatch.setenv("ACCOUNT_COOKIE_SECURE", "false")
    assert str(IsolatedSettings().account_google_oauth_callback_url) == callback
