"""Guest cookie headers and an in-memory HTTP cookie lifecycle."""

from datetime import UTC, datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from http.cookies import Morsel, SimpleCookie

import pytest
from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict

from app.config import Settings
from app.guest_cookies import (
    clear_guest_cookie,
    guest_cookie_name,
    set_guest_cookie,
)


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


def settings_for(secure: bool = True) -> Settings:
    return IsolatedSettings(
        database_url=None,
        migration_database_url=None,
        guest_cookie_secure=secure,
    )


def read_cookie(response: Response, name: str) -> Morsel[str]:
    cookies: SimpleCookie = SimpleCookie()
    cookies.load(response.headers["set-cookie"])
    return cookies[name]


@pytest.mark.parametrize(
    ("secure", "expected_name"),
    [
        (True, "__Host-askm6_guest"),
        (False, "askm6_guest"),
    ],
)
def test_cookie_has_expected_security_attributes(
    secure: bool,
    expected_name: str,
) -> None:
    settings = settings_for(secure)
    token = SecretStr("A" * 43)
    expiry = datetime(2030, 1, 1, 12, tzinfo=UTC)
    response = Response(content="ok")

    set_guest_cookie(response, token, expiry, settings)

    cookie = read_cookie(response, expected_name)

    assert cookie.value == token.get_secret_value()
    assert bool(cookie["secure"]) is secure
    assert bool(cookie["httponly"])
    assert cookie["samesite"] == "lax"
    assert cookie["path"] == "/"
    assert cookie["domain"] == ""
    assert parsedate_to_datetime(cookie["expires"]) == expiry
    assert cookie["expires"].endswith("GMT")
    assert response.headers["Cache-Control"] == "no-store"
    assert response.body == b"ok"


@pytest.mark.parametrize(
    ("secure", "expected_name"),
    [
        (True, "__Host-askm6_guest"),
        (False, "askm6_guest"),
    ],
)
def test_cookie_deletion_uses_matching_scope(
    secure: bool,
    expected_name: str,
) -> None:
    response = Response()

    clear_guest_cookie(response, settings_for(secure))

    cookie = read_cookie(response, expected_name)

    assert cookie.value == ""
    assert cookie["max-age"] == "0"
    assert cookie["path"] == "/"
    assert cookie["domain"] == ""
    assert bool(cookie["secure"]) is secure
    assert bool(cookie["httponly"])
    assert cookie["samesite"] == "lax"
    assert response.headers["Cache-Control"] == "no-store"


def test_timezone_naive_expiry_is_rejected_before_setting_cookie() -> None:
    response = Response()

    with pytest.raises(
        ValueError,
        match="Guest cookie expiry must include a timezone",
    ):
        set_guest_cookie(
            response,
            SecretStr("A" * 43),
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

    set_guest_cookie(response, SecretStr("A" * 43), expiry, settings)

    cookie = read_cookie(response, guest_cookie_name(settings))

    assert parsedate_to_datetime(cookie["expires"]) == datetime(2030, 1, 1, 12, tzinfo=UTC)
    assert cookie["expires"].endswith("GMT")


def test_https_client_receives_and_then_clears_cookie() -> None:
    app = FastAPI()
    settings = settings_for()
    token = SecretStr("A" * 43)

    @app.post("/session")
    def issue_cookie(response: Response) -> dict[str, str]:
        set_guest_cookie(
            response,
            token,
            datetime.now(UTC) + timedelta(days=1),
            settings,
        )
        return {"status": "ok"}

    @app.get("/session")
    def check_cookie(request: Request) -> dict[str, bool]:
        return {
            "has_cookie": request.cookies.get(guest_cookie_name(settings))
            == token.get_secret_value()
        }

    @app.delete("/session")
    def remove_cookie(response: Response) -> dict[str, str]:
        clear_guest_cookie(response, settings)
        return {"status": "ok"}

    with TestClient(app, base_url="https://example.test") as client:
        response = client.post("/session")

        assert response.status_code == 200
        assert token.get_secret_value() not in response.text
        assert client.get("/session").json() == {"has_cookie": True}

        assert client.delete("/session").status_code == 200
        assert client.get("/session").json() == {"has_cookie": False}
