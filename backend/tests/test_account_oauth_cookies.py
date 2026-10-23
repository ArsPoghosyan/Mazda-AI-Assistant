"""Pending-login cookie attributes, strict reads and matching deletion scope."""

from datetime import UTC, datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from http.cookies import Morsel, SimpleCookie

import pytest
from fastapi import Request, Response
from pydantic import SecretStr

from app.account_oauth_cookies import (
    clear_oauth_cookie,
    oauth_cookie_name,
    read_oauth_cookie,
    set_oauth_cookie,
)
from app.account_oauth_material import InvalidOAuthLoginMaterial
from app.config import Settings

TOKEN = "aB9_-" * 8 + "Ab9"
EXPIRY = datetime(2030, 1, 1, 12, tzinfo=UTC)
INVALID = ["", "a" * 42, "a" * 44, "a" * 42 + " ", "a" * 42 + "+", '"' + TOKEN + '"']


def settings_for(secure: bool = True) -> Settings:
    return Settings.model_construct(account_cookie_secure=secure, guest_cookie_secure=not secure)


def request_for(*headers: str) -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [(b"cookie", value.encode("latin-1")) for value in headers],
        }
    )


def issued_cookie(response: Response, settings: Settings) -> Morsel[str]:
    cookies: SimpleCookie = SimpleCookie()
    cookies.load(response.headers["set-cookie"])
    assert list(cookies) == [oauth_cookie_name(settings)]
    return cookies[oauth_cookie_name(settings)]


@pytest.mark.parametrize(
    ("secure", "name"),
    [
        (True, "__Host-askm6_oauth"),
        (False, "askm6_oauth"),
    ],
)
def test_issuance_uses_account_security_policy_and_short_expiry(secure: bool, name: str) -> None:
    settings = settings_for(secure)
    response = Response("ok")
    set_oauth_cookie(response, SecretStr(TOKEN), EXPIRY, settings)
    assert oauth_cookie_name(settings) == name
    cookie = issued_cookie(response, settings)
    assert cookie.value == TOKEN
    assert bool(cookie["secure"]) is secure
    assert bool(cookie["httponly"])
    assert cookie["samesite"] == "lax"
    assert cookie["path"] == "/"
    assert cookie["domain"] == ""
    assert parsedate_to_datetime(cookie["expires"]) == EXPIRY
    assert response.headers["Cache-Control"] == "no-store"
    assert response.body == b"ok"


@pytest.mark.parametrize("secure", [True, False])
def test_clearing_matches_issuance_scope_without_other_cookie_changes(secure: bool) -> None:
    settings = settings_for(secure)
    response = Response()
    clear_oauth_cookie(response, settings)
    cookie = issued_cookie(response, settings)
    assert cookie.value == ""
    assert cookie["max-age"] == "0"
    assert bool(cookie["secure"]) is secure
    assert bool(cookie["httponly"])
    assert cookie["samesite"] == "lax"
    assert cookie["path"] == "/"
    assert cookie["domain"] == ""
    assert response.headers["Cache-Control"] == "no-store"


@pytest.mark.parametrize("secure", [True, False])
def test_read_returns_masked_unchanged_binding(secure: bool) -> None:
    settings = settings_for(secure)
    request = request_for(f"unrelated=x; {oauth_cookie_name(settings)}={TOKEN}; guest=y")
    token = read_oauth_cookie(request, settings)
    assert token is not None
    assert token.get_secret_value() == TOKEN
    assert TOKEN not in repr(token)


@pytest.mark.parametrize("header", [None, "other=x", f"askm6_oauth={TOKEN}"])
def test_missing_selected_cookie_returns_none(header: str | None) -> None:
    request = request_for() if header is None else request_for(header)
    assert read_oauth_cookie(request, settings_for()) is None


@pytest.mark.parametrize("token", INVALID)
def test_malformed_binding_is_not_treated_as_a_fresh_start(token: str) -> None:
    with pytest.raises(InvalidOAuthLoginMaterial, match="^Invalid OAuth login material\\.$"):
        read_oauth_cookie(request_for(f"__Host-askm6_oauth={token}"), settings_for())


@pytest.mark.parametrize(
    "headers",
    [
        [f"__Host-askm6_oauth={TOKEN}; __Host-askm6_oauth={TOKEN}"],
        [f"__Host-askm6_oauth={TOKEN}", f"__Host-askm6_oauth={'b' * 43}"],
        ["__Host-askm6_oauth"],
    ],
)
def test_duplicate_or_valueless_cookie_is_rejected(headers: list[str]) -> None:
    with pytest.raises(InvalidOAuthLoginMaterial):
        read_oauth_cookie(request_for(*headers), settings_for())


@pytest.mark.parametrize("token", INVALID)
def test_invalid_issued_token_never_sets_cookie(token: str) -> None:
    response = Response()
    with pytest.raises(ValueError, match="Invalid OAuth cookie token"):
        set_oauth_cookie(response, SecretStr(token), EXPIRY, settings_for())
    assert "set-cookie" not in response.headers


def test_naive_expiry_is_rejected_before_issuance() -> None:
    response = Response()
    with pytest.raises(ValueError, match="timezone"):
        set_oauth_cookie(response, SecretStr(TOKEN), EXPIRY.replace(tzinfo=None), settings_for())
    assert "set-cookie" not in response.headers


def test_expiry_is_normalized_to_utc() -> None:
    response = Response()
    expiry = EXPIRY.astimezone(timezone(timedelta(hours=4)))
    set_oauth_cookie(response, SecretStr(TOKEN), expiry, settings_for())
    assert parsedate_to_datetime(issued_cookie(response, settings_for())["expires"]) == EXPIRY
