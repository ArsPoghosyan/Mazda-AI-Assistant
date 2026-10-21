"""Sign-out HTTP guards and cookie cleanup without database requests."""

import asyncio
from collections.abc import Iterator
from dataclasses import dataclass
from http.cookies import SimpleCookie
from typing import cast
from unittest.mock import AsyncMock, Mock

import httpx2
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine

from app.config import Settings
from app.main import create_app

PATH = "/api/v1/account/sign-out"
ORIGIN = "https://app.example.test"
TOKEN = "A" * 43
COOKIE_NAME = "__Host-askm6_account"


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


def make_settings(
    enabled: bool = True,
    secure: bool = True,
) -> Settings:
    return IsolatedSettings.model_validate(
        {
            "database_url": None,
            "migration_database_url": None,
            "supabase_auth_issuer": None,
            "supabase_auth_publishable_key": None,
            "account_session_encryption_key": None,
            "account_cookie_secure": secure,
            "account_sign_out_api_enabled": enabled,
            "csrf_trusted_origins": (ORIGIN,),
        }
    )


@pytest.fixture
def deletion(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    operation = AsyncMock(return_value=True)
    monkeypatch.setattr(
        "app.account_sign_out_routes.delete_account_session_transaction",
        operation,
    )
    return operation


def assert_cookie_cleared(
    response: httpx2.Response,
    *,
    secure: bool = True,
) -> None:
    assert response.status_code == 204
    assert response.content == b""
    assert response.headers["Cache-Control"] == "no-store"

    cookies: SimpleCookie = SimpleCookie()
    cookies.load(response.headers["set-cookie"])

    name = COOKIE_NAME if secure else "askm6_account"
    assert set(cookies) == {name}
    cookie = cookies[name]

    assert cookie.value == ""
    assert cookie["max-age"] == "0"
    assert cookie["expires"]
    assert cookie["path"] == "/"
    assert cookie["domain"] == ""
    assert bool(cookie["httponly"])
    assert bool(cookie["secure"]) is secure
    assert cookie["samesite"] == "lax"


def test_disabled_sign_out_preserves_cookie_without_database_work(
    deletion: AsyncMock,
) -> None:
    with TestClient(
        create_app(make_settings(enabled=False)),
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
    assert response.json() == {"detail": "Account sign-out is temporarily unavailable."}
    assert response.headers["Cache-Control"] == "no-store"
    assert "set-cookie" not in response.headers
    deletion.assert_not_awaited()


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
def test_invalid_origin_preserves_cookie_without_database_work(
    deletion: AsyncMock,
    origin_headers: list[tuple[str, str]],
) -> None:
    with TestClient(
        create_app(make_settings()),
        base_url="https://api.example.test",
    ) as client:
        response = client.post(
            PATH,
            headers=[
                *origin_headers,
                ("Cookie", f"{COOKIE_NAME}={TOKEN}"),
            ],
        )

    assert response.status_code == 403
    assert response.json() == {"detail": "Request origin is not allowed."}
    assert response.headers["Cache-Control"] == "no-store"
    assert "set-cookie" not in response.headers
    deletion.assert_not_awaited()


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
def test_missing_or_malformed_account_cookie_is_cleared_without_database(
    deletion: AsyncMock,
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

    assert_cookie_cleared(response)
    deletion.assert_not_awaited()


@dataclass
class SignOutAPI:
    application: FastAPI
    client: TestClient
    settings: Settings
    engine: AsyncEngine
    deletion: AsyncMock


@pytest.fixture
def api(deletion: AsyncMock) -> Iterator[SignOutAPI]:
    settings = make_settings()
    application = create_app(settings)

    with TestClient(application, base_url="https://api.example.test") as client:
        engine = cast(AsyncEngine, Mock(spec=AsyncEngine))
        application.state.database_engine = engine

        yield SignOutAPI(
            application=application,
            client=client,
            settings=settings,
            engine=engine,
            deletion=deletion,
        )


def request_sign_out(api: SignOutAPI) -> httpx2.Response:
    name = COOKIE_NAME if api.settings.account_cookie_secure else "askm6_account"

    return api.client.post(
        PATH,
        headers={
            "Origin": ORIGIN,
            "Cookie": f"{name}={TOKEN}",
        },
    )


def assert_unavailable(response: httpx2.Response) -> None:
    assert response.status_code == 503
    assert response.json() == {"detail": "Account sign-out is temporarily unavailable."}
    assert response.headers["Cache-Control"] == "no-store"
    assert "set-cookie" not in response.headers
    assert TOKEN not in response.text
    assert "synthetic-private-detail" not in response.text


@pytest.mark.parametrize("secure", [True, False], ids=["https", "development"])
@pytest.mark.parametrize("deleted", [True, False], ids=["deleted", "unknown"])
def test_completed_deletion_clears_cookie_without_provider_resources(
    api: SignOutAPI,
    secure: bool,
    deleted: bool,
) -> None:
    api.settings.account_cookie_secure = secure
    api.deletion.return_value = deleted

    assert api.application.state.account_auth_client is None
    assert api.application.state.account_key_cache is None
    assert api.settings.account_session_encryption_key is None

    response = request_sign_out(api)

    assert_cookie_cleared(response, secure=secure)
    api.deletion.assert_awaited_once_with(api.engine, SecretStr(TOKEN))


def test_valid_cookie_requires_database_engine(api: SignOutAPI) -> None:
    api.application.state.database_engine = None

    response = request_sign_out(api)

    assert_unavailable(response)
    api.deletion.assert_not_awaited()


@pytest.mark.parametrize(
    "failure",
    [
        SQLAlchemyError("synthetic-private-detail"),
        TimeoutError("synthetic-private-detail"),
    ],
    ids=["database-error", "timeout"],
)
def test_deletion_failure_preserves_cookie_without_retry(
    api: SignOutAPI,
    failure: Exception,
) -> None:
    api.deletion.side_effect = failure

    response = request_sign_out(api)

    assert_unavailable(response)
    api.deletion.assert_awaited_once_with(api.engine, SecretStr(TOKEN))


def test_deadline_cancels_stalled_deletion_and_preserves_cookie(
    api: SignOutAPI,
) -> None:
    api.settings.account_sign_out_timeout_seconds = 1
    was_cancelled = False

    async def stalled(
        *args: object,
        **kwargs: object,
    ) -> bool:
        nonlocal was_cancelled
        try:
            await asyncio.sleep(3)
        except asyncio.CancelledError:
            was_cancelled = True
            raise

        raise AssertionError("Stalled deletion unexpectedly completed.")

    api.deletion.side_effect = stalled

    response = request_sign_out(api)

    assert_unavailable(response)
    assert was_cancelled
    api.deletion.assert_awaited_once_with(api.engine, SecretStr(TOKEN))
