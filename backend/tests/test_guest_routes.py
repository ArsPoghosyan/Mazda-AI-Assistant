"""Guest HTTP behavior using mocked database transactions."""

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import cast
from unittest.mock import AsyncMock, MagicMock, Mock
from uuid import uuid4

import pytest
from fastapi import FastAPI, Response
from fastapi.testclient import TestClient
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from app.config import Settings
from app.guest_cookies import set_guest_cookie
from app.guest_sessions import ActiveGuestSession, CreatedGuestSession
from app.main import create_app

TOKEN = "A" * 43
EXPIRY = datetime(2030, 1, 1, 12, tzinfo=UTC)
ORIGIN = "https://askm6.com"


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@dataclass
class GuestAPI:
    client: TestClient
    settings: Settings
    engine: MagicMock
    transaction: MagicMock
    create: AsyncMock
    refresh: AsyncMock
    events: list[str]


@pytest.fixture
def api(monkeypatch: pytest.MonkeyPatch) -> Iterator[GuestAPI]:
    settings = IsolatedSettings(
        database_url=None,
        migration_database_url=None,
        guest_session_api_enabled=True,
        guest_cookie_secure=True,
        csrf_trusted_origins=(ORIGIN,),
    )
    events: list[str] = []
    connection = MagicMock(spec=AsyncConnection)
    transaction = MagicMock()
    transaction.__aenter__ = AsyncMock(return_value=connection)

    async def finish_transaction(
        exception_type: object,
        exception: object,
        traceback: object,
    ) -> bool:
        events.append("commit" if exception_type is None else "rollback")
        return False

    transaction.__aexit__ = AsyncMock(side_effect=finish_transaction)

    engine = MagicMock(spec=AsyncEngine)
    engine.begin.return_value = transaction

    create = AsyncMock(
        return_value=CreatedGuestSession(
            session_id=uuid4(),
            token=SecretStr(TOKEN),
            expires_at=EXPIRY,
        )
    )
    refresh = AsyncMock(return_value=None)

    def record_cookie(
        response: Response,
        token: SecretStr,
        expires_at: datetime,
        configuration: Settings,
    ) -> None:
        events.append("cookie")
        set_guest_cookie(response, token, expires_at, configuration)

    monkeypatch.setattr(
        "app.main.create_database_engine",
        Mock(return_value=engine),
    )
    monkeypatch.setattr("app.guest_routes.create_guest_session", create)
    monkeypatch.setattr("app.guest_routes.refresh_guest_session", refresh)
    monkeypatch.setattr("app.guest_routes.set_guest_cookie", record_cookie)

    with TestClient(create_app(settings), base_url=ORIGIN) as client:
        yield GuestAPI(
            client=client,
            settings=settings,
            engine=engine,
            transaction=transaction,
            create=create,
            refresh=refresh,
            events=events,
        )


def test_creation_sets_cookie_after_commit(api: GuestAPI) -> None:
    response = api.client.post(
        "/api/v1/guest/session",
        headers={"Origin": ORIGIN},
    )

    assert response.status_code == 200
    assert set(response.json()) == {"status", "expires_at"}
    assert response.json()["status"] == "ok"
    assert datetime.fromisoformat(response.json()["expires_at"]) == EXPIRY
    assert TOKEN not in response.text
    assert response.cookies.get("__Host-askm6_guest") == TOKEN
    assert response.headers["Cache-Control"] == "no-store"
    assert api.events == ["commit", "cookie"]

    api.create.assert_awaited_once()
    api.refresh.assert_awaited_once_with(
        api.transaction.__aenter__.return_value,
        "",
        api.settings,
    )


def test_existing_session_is_reused(api: GuestAPI) -> None:
    existing_token = "B" * 43
    api.client.cookies.set("__Host-askm6_guest", existing_token)
    api.refresh.return_value = ActiveGuestSession(
        session_id=uuid4(),
        expires_at=EXPIRY,
    )

    response = api.client.post(
        "/api/v1/guest/session",
        headers={"Origin": ORIGIN},
    )

    assert response.status_code == 200
    assert response.cookies.get("__Host-askm6_guest") == existing_token
    assert existing_token not in response.text
    assert api.events == ["commit", "cookie"]

    api.create.assert_not_awaited()
    api.refresh.assert_awaited_once_with(
        api.transaction.__aenter__.return_value,
        existing_token,
        api.settings,
    )


@pytest.mark.parametrize(
    "origin",
    [None, "null", "https://evil.test"],
)
def test_origin_rejection_prevents_database_work(
    api: GuestAPI,
    origin: str | None,
) -> None:
    headers = {} if origin is None else {"Origin": origin}

    response = api.client.post(
        "/api/v1/guest/session",
        headers=headers,
    )

    assert response.status_code == 403
    assert "set-cookie" not in response.headers
    assert api.events == []

    api.engine.begin.assert_not_called()
    api.create.assert_not_awaited()
    api.refresh.assert_not_awaited()


@pytest.mark.parametrize("reason", ["disabled", "missing_database"])
def test_unavailable_configuration_does_not_start_transaction(
    api: GuestAPI,
    reason: str,
) -> None:
    if reason == "disabled":
        api.settings.guest_session_api_enabled = False
    else:
        cast(FastAPI, api.client.app).state.database_engine = None

    response = api.client.post(
        "/api/v1/guest/session",
        headers={"Origin": ORIGIN},
    )

    assert response.status_code == 503
    assert response.headers["Cache-Control"] == "no-store"
    assert "set-cookie" not in response.headers
    assert api.events == []

    api.engine.begin.assert_not_called()
    api.create.assert_not_awaited()
    api.refresh.assert_not_awaited()


@pytest.mark.parametrize(
    "failure_stage",
    ["connect", "refresh", "create", "commit"],
)
def test_database_failure_never_issues_cookie(
    api: GuestAPI,
    failure_stage: str,
) -> None:
    error = SQLAlchemyError("Private database failure details")

    if failure_stage == "connect":
        api.engine.begin.side_effect = error
    elif failure_stage == "refresh":
        api.refresh.side_effect = error
    elif failure_stage == "create":
        api.create.side_effect = error
    else:
        api.transaction.__aexit__.side_effect = error

    response = api.client.post(
        "/api/v1/guest/session",
        headers={"Origin": ORIGIN},
    )

    assert response.status_code == 503
    assert response.json() == {"detail": "Guest sessions are temporarily unavailable."}
    assert response.headers["Cache-Control"] == "no-store"
    assert "set-cookie" not in response.headers
    assert "Private database failure details" not in response.text
    assert TOKEN not in response.text
    assert "cookie" not in api.events

    if failure_stage in {"refresh", "create"}:
        assert api.events == ["rollback"]

    if failure_stage == "commit":
        api.create.assert_awaited_once()
