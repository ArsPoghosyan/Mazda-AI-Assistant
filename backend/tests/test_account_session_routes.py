"""Account-session HTTP guards without database or provider requests."""

import asyncio
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from http.cookies import SimpleCookie
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock, MagicMock, Mock
from uuid import uuid4

import httpx2
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine

from app.account_auth import AccountAuthenticationUnavailable
from app.account_key_cache import AccountKeyCache
from app.account_refresh import AccountRefreshRejected, AccountRefreshUnavailable
from app.account_session_auth import AuthenticatedAccountSession
from app.account_tokens import VerifiedAccount
from app.config import Settings
from app.main import create_app

PATH = "/api/v1/account/session"
ORIGIN = "https://app.example.test"
TOKEN = "A" * 43
COOKIE_NAME = "__Host-askm6_account"


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


def make_settings(enabled: bool = True) -> Settings:
    return IsolatedSettings.model_validate(
        {
            "database_url": None,
            "migration_database_url": None,
            "supabase_auth_issuer": None,
            "supabase_auth_publishable_key": None,
            "account_session_encryption_key": None,
            "account_cookie_secure": True,
            "account_session_api_enabled": enabled,
            "csrf_trusted_origins": (ORIGIN,),
        }
    )


@pytest.fixture
def authenticate(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    verifier = AsyncMock()
    monkeypatch.setattr(
        "app.account_session_routes.authenticate_account_session_transaction",
        verifier,
    )
    return verifier


def test_disabled_endpoint_stops_before_authentication(
    authenticate: AsyncMock,
) -> None:
    application = create_app(make_settings(enabled=False))

    with TestClient(
        application,
        base_url="https://api.example.test",
    ) as client:
        response = client.post(
            PATH,
            headers={
                "Origin": ORIGIN,
                "Cookie": f"{COOKIE_NAME}={TOKEN}",
            },
        )

    assert response.status_code == 503
    assert response.json() == {"detail": "Account sessions are temporarily unavailable."}
    assert response.headers["Cache-Control"] == "no-store"
    assert "set-cookie" not in response.headers
    authenticate.assert_not_awaited()


@pytest.mark.parametrize(
    "origin_headers",
    [
        [],
        [("Origin", "")],
        [("Origin", "null")],
        [("Origin", "https://untrusted.example.test")],
        [("Origin", ORIGIN + "/")],
        [("Origin", ORIGIN), ("Origin", ORIGIN)],
        [
            ("Origin", ORIGIN),
            ("Origin", "https://untrusted.example.test"),
        ],
    ],
    ids=[
        "missing",
        "empty",
        "null",
        "untrusted",
        "trailing-slash",
        "duplicate",
        "conflicting",
    ],
)
def test_invalid_origin_stops_before_authentication(
    authenticate: AsyncMock,
    origin_headers: list[tuple[str, str]],
) -> None:
    headers = [
        *origin_headers,
        ("Cookie", f"{COOKIE_NAME}={TOKEN}"),
    ]

    with TestClient(
        create_app(make_settings()),
        base_url="https://api.example.test",
    ) as client:
        response = client.post(PATH, headers=headers)

    assert response.status_code == 403
    assert response.json() == {"detail": "Request origin is not allowed."}
    assert response.headers["Cache-Control"] == "no-store"
    assert "set-cookie" not in response.headers
    authenticate.assert_not_awaited()


@pytest.mark.parametrize(
    "cookie_header",
    [
        None,
        f"{COOKIE_NAME}=",
        f"{COOKIE_NAME}={'A' * 42}",
        f"{COOKIE_NAME}={'A' * 44}",
        f"{COOKIE_NAME}={'A' * 42}!",
        f"askm6_account={TOKEN}",
        f"__Host-askm6_guest={TOKEN}",
    ],
    ids=[
        "missing",
        "empty",
        "short",
        "long",
        "invalid-character",
        "development-name",
        "guest-cookie",
    ],
)
def test_invalid_cookie_is_cleared_before_authentication(
    authenticate: AsyncMock,
    cookie_header: str | None,
) -> None:
    headers = {"Origin": ORIGIN}
    if cookie_header is not None:
        headers["Cookie"] = cookie_header

    with TestClient(
        create_app(make_settings()),
        base_url="https://api.example.test",
    ) as client:
        response = client.post(PATH, headers=headers)

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid or expired account session."}
    assert response.headers["Cache-Control"] == "no-store"
    assert TOKEN not in response.text

    cookies: SimpleCookie = SimpleCookie()
    cookies.load(response.headers["set-cookie"])
    cookie = cookies[COOKIE_NAME]
    assert cookie.value == ""
    assert cookie["max-age"] == "0"
    assert cookie["path"] == "/"

    authenticate.assert_not_awaited()


@dataclass
class SessionAPI:
    application: FastAPI
    client: TestClient
    settings: Settings
    engine: MagicMock
    http_client: httpx2.AsyncClient
    cache: AccountKeyCache
    authenticate: AsyncMock
    authenticated: AuthenticatedAccountSession


@pytest.fixture
def api(
    monkeypatch: pytest.MonkeyPatch,
    authenticate: AsyncMock,
) -> Iterator[SessionAPI]:
    settings = IsolatedSettings.model_validate(
        {
            **make_settings().model_dump(),
            "supabase_auth_issuer": "https://auth.example.test/auth/v1",
        }
    )

    engine = MagicMock(spec=AsyncEngine)
    monkeypatch.setattr(
        "app.main.create_database_engine",
        Mock(return_value=engine),
    )

    def reject_network(request: httpx2.Request) -> httpx2.Response:
        raise AssertionError("HTTP tests must not make network requests.")

    http_client = httpx2.AsyncClient(
        transport=httpx2.MockTransport(reject_network),
        trust_env=False,
    )
    monkeypatch.setattr(
        "app.main.httpx2",
        SimpleNamespace(
            AsyncClient=Mock(return_value=http_client),
            Limits=httpx2.Limits,
        ),
    )

    now = datetime.now(UTC).replace(microsecond=0)
    authenticated = AuthenticatedAccountSession(
        session_id=uuid4(),
        account=VerifiedAccount(
            user_id=uuid4(),
            session_id=uuid4(),
            assurance_level="aal1",
            access_token_expires_at=now + timedelta(minutes=5),
        ),
        idle_expires_at=now + timedelta(days=7),
        absolute_expires_at=now + timedelta(days=30),
    )
    authenticate.return_value = authenticated

    application = create_app(settings)

    with TestClient(
        application,
        base_url="https://api.example.test",
    ) as client:
        yield SessionAPI(
            application=application,
            client=client,
            settings=settings,
            engine=engine,
            http_client=http_client,
            cache=cast(AccountKeyCache, application.state.account_key_cache),
            authenticate=authenticate,
            authenticated=authenticated,
        )


def request_session(api: SessionAPI) -> httpx2.Response:
    return api.client.post(
        PATH,
        headers={
            "Origin": ORIGIN,
            "Cookie": f"{COOKIE_NAME}={TOKEN}",
        },
    )


def assert_cookie_cleared(response: httpx2.Response) -> None:
    cookies: SimpleCookie = SimpleCookie()
    cookies.load(response.headers["set-cookie"])
    cookie = cookies[COOKIE_NAME]
    assert cookie.value == ""
    assert cookie["max-age"] == "0"


def test_success_renews_cookie_and_returns_identity(api: SessionAPI) -> None:
    response = request_session(api)

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    assert TOKEN not in response.text

    body = response.json()
    assert set(body) == {
        "user_id",
        "expires_at",
        "absolute_expires_at",
    }
    assert body["user_id"] == str(api.authenticated.account.user_id)
    assert datetime.fromisoformat(body["expires_at"]) == api.authenticated.idle_expires_at
    assert (
        datetime.fromisoformat(body["absolute_expires_at"]) == api.authenticated.absolute_expires_at
    )

    cookies: SimpleCookie = SimpleCookie()
    cookies.load(response.headers["set-cookie"])
    cookie = cookies[COOKIE_NAME]
    assert cookie.value == TOKEN
    assert parsedate_to_datetime(cookie["expires"]) == api.authenticated.idle_expires_at
    assert bool(cookie["secure"])
    assert bool(cookie["httponly"])
    assert cookie["samesite"] == "lax"

    api.authenticate.assert_awaited_once_with(
        api.engine,
        SecretStr(TOKEN),
        settings=api.settings,
        client=api.http_client,
        key_cache=api.cache,
    )


def test_unknown_or_expired_session_clears_cookie(api: SessionAPI) -> None:
    api.authenticate.return_value = None

    response = request_session(api)

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid or expired account session."}
    assert response.headers["Cache-Control"] == "no-store"
    assert_cookie_cleared(response)
    api.authenticate.assert_awaited_once()


def test_provider_rejection_clears_cookie_without_retry(api: SessionAPI) -> None:
    api.authenticate.side_effect = AccountRefreshRejected("Synthetic private rejection detail")

    response = request_session(api)

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid or expired account session."}
    assert response.headers["Cache-Control"] == "no-store"
    assert_cookie_cleared(response)
    api.authenticate.assert_awaited_once()


@pytest.mark.parametrize(
    "failure",
    [
        AccountAuthenticationUnavailable("Synthetic private verification error"),
        AccountRefreshUnavailable("Synthetic private provider error"),
        SQLAlchemyError("Synthetic private database or commit error"),
        TimeoutError("Synthetic private timeout detail"),
    ],
    ids=["verification", "provider", "database", "timeout"],
)
def test_temporary_failure_preserves_cookie_without_retry(
    api: SessionAPI,
    failure: Exception,
) -> None:
    api.authenticate.side_effect = failure

    response = request_session(api)

    assert response.status_code == 503
    assert response.json() == {"detail": "Account sessions are temporarily unavailable."}
    assert response.headers["Cache-Control"] == "no-store"
    assert "set-cookie" not in response.headers
    api.authenticate.assert_awaited_once()


@pytest.mark.parametrize(
    "state_name",
    [
        "database_engine",
        "account_auth_client",
        "account_key_cache",
    ],
)
def test_missing_resources_stop_before_authentication(
    api: SessionAPI,
    state_name: str,
) -> None:
    setattr(api.application.state, state_name, None)

    response = request_session(api)

    assert response.status_code == 503
    assert response.json() == {"detail": "Account sessions are temporarily unavailable."}
    assert response.headers["Cache-Control"] == "no-store"
    assert "set-cookie" not in response.headers
    api.authenticate.assert_not_awaited()


def test_deadline_cancels_stalled_authentication(api: SessionAPI) -> None:
    api.settings.account_session_auth_timeout_seconds = 1
    was_cancelled = False

    async def stalled(
        *args: object,
        **kwargs: object,
    ) -> AuthenticatedAccountSession | None:
        nonlocal was_cancelled
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            was_cancelled = True
            raise

        raise AssertionError("Stalled authentication unexpectedly resumed.")

    api.authenticate.side_effect = stalled

    response = request_session(api)

    assert response.status_code == 503
    assert response.json() == {"detail": "Account sessions are temporarily unavailable."}
    assert response.headers["Cache-Control"] == "no-store"
    assert "set-cookie" not in response.headers
    assert was_cancelled
    api.authenticate.assert_awaited_once()
