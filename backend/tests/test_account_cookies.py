"""Account cookie policy, validation, and in-memory HTTP lifecycle."""

from datetime import UTC, datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from http.cookies import Morsel, SimpleCookie

import pytest
from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict

from app.account_cookies import (
    account_cookie_name,
    clear_account_cookie,
    read_account_cookie,
    set_account_cookie,
)
from app.config import Settings

TOKEN = "Ab9_-" * 8 + "Ab9"
EXPIRY = datetime(2030, 1, 1, 12, tzinfo=UTC)
INVALID_TOKENS = [
    "",
    "A" * 42,
    "A" * 44,
    "A" * 21 + " " + "A" * 21,
    "A" * 42 + "é",
    "A" * 42 + ";",
    "A" * 21 + "\n" + "A" * 21,
]


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


def settings_for(secure: bool = True) -> Settings:
    return IsolatedSettings.model_validate(
        {
            "database_url": None,
            "migration_database_url": None,
            "account_cookie_secure": secure,
            # Account policy must remain independent of guest policy.
            "guest_cookie_secure": not secure,
        }
    )


def request_for(cookie_header: str | None = None) -> Request:
    headers = [] if cookie_header is None else [(b"cookie", cookie_header.encode("latin-1"))]
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": headers,
        }
    )


def cookie_from(response: Response, name: str) -> Morsel[str]:
    cookies: SimpleCookie = SimpleCookie()
    cookies.load(response.headers["set-cookie"])
    return cookies[name]


@pytest.mark.parametrize(
    ("secure", "name"),
    [
        (True, "__Host-askm6_account"),
        (False, "askm6_account"),
    ],
)
def test_cookie_security_attributes(secure: bool, name: str) -> None:
    response = Response(content="ok")

    set_account_cookie(
        response,
        SecretStr(TOKEN),
        EXPIRY,
        settings_for(secure),
    )

    cookie = cookie_from(response, name)
    assert cookie.value == TOKEN
    assert bool(cookie["secure"]) is secure
    assert bool(cookie["httponly"])
    assert cookie["samesite"] == "lax"
    assert cookie["path"] == "/"
    assert cookie["domain"] == ""
    assert parsedate_to_datetime(cookie["expires"]) == EXPIRY
    assert cookie["expires"].endswith("GMT")
    assert response.headers["Cache-Control"] == "no-store"
    assert response.body == b"ok"


@pytest.mark.parametrize("secure", [True, False])
def test_clear_cookie_uses_matching_scope(secure: bool) -> None:
    settings = settings_for(secure)
    response = Response()

    clear_account_cookie(response, settings)

    cookie = cookie_from(response, account_cookie_name(settings))
    assert cookie.value == ""
    assert cookie["max-age"] == "0"
    assert bool(cookie["secure"]) is secure
    assert bool(cookie["httponly"])
    assert cookie["samesite"] == "lax"
    assert cookie["path"] == "/"
    assert cookie["domain"] == ""
    assert response.headers["Cache-Control"] == "no-store"


@pytest.mark.parametrize("raw_token", INVALID_TOKENS)
def test_invalid_token_is_rejected_before_cookie_is_set(
    raw_token: str,
) -> None:
    response = Response()

    with pytest.raises(ValueError, match="Invalid account cookie token"):
        set_account_cookie(
            response,
            SecretStr(raw_token),
            EXPIRY,
            settings_for(),
        )

    assert "set-cookie" not in response.headers
    assert "cache-control" not in response.headers


def test_naive_expiry_is_rejected_before_cookie_is_set() -> None:
    response = Response()

    with pytest.raises(
        ValueError,
        match="Account cookie expiry must include a timezone",
    ):
        set_account_cookie(
            response,
            SecretStr(TOKEN),
            datetime(2030, 1, 1, 12),
            settings_for(),
        )

    assert "set-cookie" not in response.headers


def test_expiry_is_converted_to_utc() -> None:
    settings = settings_for()
    response = Response()
    expiry = datetime(
        2030,
        1,
        1,
        16,
        tzinfo=timezone(timedelta(hours=4)),
    )

    set_account_cookie(response, SecretStr(TOKEN), expiry, settings)

    cookie = cookie_from(response, account_cookie_name(settings))
    assert parsedate_to_datetime(cookie["expires"]) == EXPIRY
    assert cookie["expires"].endswith("GMT")


@pytest.mark.parametrize("secure", [True, False])
def test_reader_returns_masked_token(secure: bool) -> None:
    settings = settings_for(secure)
    request = request_for(f"{account_cookie_name(settings)}={TOKEN}")

    token = read_account_cookie(request, settings)

    assert isinstance(token, SecretStr)
    assert token.get_secret_value() == TOKEN
    assert TOKEN not in repr(token)


def test_reader_returns_none_when_cookie_is_missing() -> None:
    assert read_account_cookie(request_for(), settings_for()) is None


@pytest.mark.parametrize("raw_token", INVALID_TOKENS)
def test_reader_rejects_malformed_tokens(raw_token: str) -> None:
    settings = settings_for()
    request = request_for(f"{account_cookie_name(settings)}={raw_token}")

    assert read_account_cookie(request, settings) is None


@pytest.mark.parametrize("secure", [True, False])
def test_reader_ignores_other_cookie_names(secure: bool) -> None:
    settings = settings_for(secure)
    other_name = "askm6_account" if secure else "__Host-askm6_account"
    request = request_for(f"{other_name}={TOKEN}; askm6_guest={TOKEN}; __Host-askm6_guest={TOKEN}")

    assert read_account_cookie(request, settings) is None


@pytest.mark.parametrize(
    ("secure", "base_url"),
    [
        (True, "https://example.test"),
        (False, "http://example.test"),
    ],
)
def test_client_receives_reads_and_clears_cookie(
    secure: bool,
    base_url: str,
) -> None:
    app = FastAPI()
    settings = settings_for(secure)

    @app.post("/session")
    def issue_cookie(response: Response) -> dict[str, str]:
        set_account_cookie(
            response,
            SecretStr(TOKEN),
            datetime.now(UTC) + timedelta(days=1),
            settings,
        )
        return {"status": "ok"}

    @app.get("/session")
    def check_cookie(request: Request) -> dict[str, bool]:
        token = read_account_cookie(request, settings)
        return {"has_token": (token is not None and token.get_secret_value() == TOKEN)}

    @app.delete("/session")
    def remove_cookie(response: Response) -> dict[str, str]:
        clear_account_cookie(response, settings)
        return {"status": "ok"}

    with TestClient(app, base_url=base_url) as client:
        assert client.get("/session").json() == {"has_token": False}

        issued = client.post("/session")
        assert issued.status_code == 200
        assert TOKEN not in issued.text
        assert client.get("/session").json() == {"has_token": True}

        cleared = client.delete("/session")
        assert cleared.status_code == 200
        assert TOKEN not in cleared.text
        assert client.get("/session").json() == {"has_token": False}
