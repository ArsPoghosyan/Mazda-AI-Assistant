"""Guest HTTP verification and cookie behavior using mocked services."""

import asyncio
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import cast
from unittest.mock import AsyncMock, MagicMock, Mock
from uuid import uuid4

import httpx2
import pytest
from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from app.auth_rate_limits import AuthRateLimitDecision
from app.client_ip import ClientIPUnavailable
from app.config import Settings
from app.guest_cookies import set_guest_cookie
from app.guest_sessions import ActiveGuestSession, CreatedGuestSession
from app.main import create_app
from app.turnstile import TurnstileRejected, TurnstileUnavailable

TOKEN = "A" * 43
EXPIRY = datetime(2030, 1, 1, 12, tzinfo=UTC)
ORIGIN = "https://askm6.com"
CHALLENGE = "synthetic-guest-challenge"


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
    verify: AsyncMock
    limit: AsyncMock
    events: list[str]


@pytest.fixture
def api(monkeypatch: pytest.MonkeyPatch) -> Iterator[GuestAPI]:
    settings = IsolatedSettings(
        database_url=None,
        migration_database_url=None,
        guest_session_api_enabled=True,
        auth_rate_limit_hmac_secret=SecretStr("ab" * 32),
        guest_cookie_secure=True,
        csrf_trusted_origins=(ORIGIN,),
        supabase_auth_issuer=None,
        supabase_auth_publishable_key=None,
        account_session_encryption_key=None,
        turnstile_secret_key=SecretStr("synthetic-secret"),
        turnstile_allowed_hostnames=("askm6.com",),
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
    verify = AsyncMock()
    limit = AsyncMock(return_value=AuthRateLimitDecision(True, datetime.now(UTC), 0, None))
    monkeypatch.setattr("app.guest_session_service.commit_guest_creation_attempt", limit)

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
    monkeypatch.setattr("app.guest_session_service.create_guest_session", create)
    monkeypatch.setattr("app.guest_session_service.refresh_guest_session", refresh)
    monkeypatch.setattr("app.guest_session_service.verify_turnstile_token", verify)
    monkeypatch.setattr("app.guest_routes.set_guest_cookie", record_cookie)

    with TestClient(create_app(settings), base_url=ORIGIN, client=("192.0.2.12", 12345)) as client:
        cast(FastAPI, client.app).state.turnstile_client = Mock(spec=httpx2.AsyncClient)
        yield GuestAPI(
            client=client,
            settings=settings,
            engine=engine,
            transaction=transaction,
            create=create,
            refresh=refresh,
            verify=verify,
            limit=limit,
            events=events,
        )


def test_creation_sets_cookie_after_commit(api: GuestAPI) -> None:
    response = api.client.post(
        "/api/v1/guest/session",
        headers={"Origin": ORIGIN},
        json={"turnstile_token": CHALLENGE},
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
    api.refresh.assert_not_awaited()
    api.verify.assert_awaited_once_with(
        SecretStr(CHALLENGE),
        expected_action="guest_start",
        settings=api.settings,
        client=cast(FastAPI, api.client.app).state.turnstile_client,
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
    api.verify.assert_not_awaited()
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
    assert response.headers.get("X-Guest-Verification") is None

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
        api.client.cookies.set("__Host-askm6_guest", "B" * 43)
        api.refresh.side_effect = error
    elif failure_stage == "create":
        api.create.side_effect = error
    else:
        api.transaction.__aexit__.side_effect = error

    response = api.client.post(
        "/api/v1/guest/session",
        headers={"Origin": ORIGIN},
        json={"turnstile_token": CHALLENGE},
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


def test_missing_challenge_prevents_creation(api: GuestAPI) -> None:
    response = api.client.post(
        "/api/v1/guest/session",
        headers={"Origin": ORIGIN},
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "Human verification is required or was rejected."}
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers.get("X-Guest-Verification") == "required"
    assert "set-cookie" not in response.headers
    api.engine.begin.assert_not_called()
    api.verify.assert_not_awaited()
    api.create.assert_not_awaited()


@pytest.mark.parametrize(
    ("failure", "status_code"),
    [
        (TurnstileRejected("Private verification details"), 403),
        (TurnstileUnavailable("Private verification details"), 503),
        (TimeoutError("Private verification details"), 503),
    ],
    ids=["rejected", "unavailable", "timeout"],
)
def test_verification_failure_preserves_cookie_and_prevents_creation(
    api: GuestAPI,
    failure: Exception,
    status_code: int,
) -> None:
    api.verify.side_effect = failure
    api.client.cookies.set("__Host-askm6_guest", "B" * 43)
    response = api.client.post(
        "/api/v1/guest/session",
        headers={"Origin": ORIGIN},
        json={"turnstile_token": CHALLENGE},
    )

    detail = (
        "Human verification is required or was rejected."
        if status_code == 403
        else "Guest sessions are temporarily unavailable."
    )
    assert response.status_code == status_code
    assert response.json() == {"detail": detail}
    assert response.headers["Cache-Control"] == "no-store"
    assert "set-cookie" not in response.headers
    assert api.client.cookies.get("__Host-askm6_guest") == "B" * 43
    assert "Private verification details" not in response.text
    api.verify.assert_awaited_once()
    api.create.assert_not_awaited()
    assert api.engine.begin.call_count == 1


@pytest.mark.parametrize("phase", ["body", "service"])
def test_deadline_cancels_stalled_operation(
    api: GuestAPI,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
) -> None:
    api.settings.guest_session_timeout_seconds = 1
    was_cancelled = False

    async def wait_until_cancelled() -> None:
        nonlocal was_cancelled
        try:
            await asyncio.sleep(3)
        except asyncio.CancelledError:
            was_cancelled = True
            raise
        raise AssertionError("Stalled operation unexpectedly completed.")

    async def stalled_stream(request: Request) -> AsyncIterator[bytes]:
        yield b" "
        await wait_until_cancelled()

    async def stalled_verifier(*args: object, **kwargs: object) -> None:
        await wait_until_cancelled()

    if phase == "body":
        monkeypatch.setattr(Request, "stream", stalled_stream)
    else:
        api.verify.side_effect = stalled_verifier

    response = api.client.post(
        "/api/v1/guest/session",
        headers={"Origin": ORIGIN},
        json={"turnstile_token": CHALLENGE},
    )

    assert response.status_code == 503
    assert response.json() == {"detail": "Guest sessions are temporarily unavailable."}
    assert response.headers["Cache-Control"] == "no-store"
    assert "set-cookie" not in response.headers
    assert was_cancelled
    api.create.assert_not_awaited()
    api.engine.begin.assert_not_called()
    if phase == "body":
        api.verify.assert_not_awaited()
    else:
        api.verify.assert_awaited_once()


def test_creation_limit_returns_retry_without_verification_or_cookie(api: GuestAPI) -> None:
    api.limit.return_value = AuthRateLimitDecision(False, datetime.now(UTC), 127, None)
    response = api.client.post(
        "/api/v1/guest/session",
        headers={"Origin": ORIGIN},
        json={"turnstile_token": CHALLENGE},
    )
    assert response.status_code == 429
    assert response.json() == {"detail": "Guest session creation is temporarily rate limited."}
    assert response.headers["Retry-After"] == "127"
    assert response.headers["Cache-Control"] == "no-store"
    assert "set-cookie" not in response.headers
    assert "X-Guest-Verification" not in response.headers
    api.verify.assert_not_awaited()
    api.create.assert_not_awaited()
    api.engine.begin.assert_not_called()


def test_active_guest_bypasses_cap_and_missing_key(api: GuestAPI) -> None:
    api.settings.auth_rate_limit_hmac_secret = None
    api.limit.return_value = AuthRateLimitDecision(False, datetime.now(UTC), 127, None)
    api.client.cookies.set("__Host-askm6_guest", "B" * 43)
    api.refresh.return_value = ActiveGuestSession(session_id=uuid4(), expires_at=EXPIRY)
    response = api.client.post("/api/v1/guest/session", headers={"Origin": ORIGIN})
    assert response.status_code == 200
    assert "Retry-After" not in response.headers
    api.limit.assert_not_awaited()
    api.verify.assert_not_awaited()


@pytest.mark.parametrize("reason", ["secret", "peer", "accounting"])
def test_unavailable_creation_protection_fails_closed(
    api: GuestAPI,
    reason: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if reason == "secret":
        api.settings.auth_rate_limit_hmac_secret = None
    elif reason == "peer":
        monkeypatch.setattr(
            "app.guest_routes.get_guest_creation_ip_key",
            Mock(side_effect=ClientIPUnavailable("Client address is unavailable.")),
        )
    else:
        api.limit.side_effect = SQLAlchemyError("private-database-detail")
    response = api.client.post(
        "/api/v1/guest/session",
        headers={"Origin": ORIGIN},
        json={"turnstile_token": CHALLENGE},
    )
    assert response.status_code == 503
    assert response.json() == {"detail": "Guest sessions are temporarily unavailable."}
    assert response.headers["Cache-Control"] == "no-store"
    assert "set-cookie" not in response.headers
    assert "Retry-After" not in response.headers
    api.verify.assert_not_awaited()
    api.create.assert_not_awaited()


def test_creation_limiter_obeys_total_deadline(api: GuestAPI) -> None:
    api.settings.guest_session_timeout_seconds = 1
    cancelled = False

    async def stall(*args: object, **kwargs: object) -> None:
        nonlocal cancelled
        try:
            await asyncio.sleep(3)
        except asyncio.CancelledError:
            cancelled = True
            raise

    api.limit.side_effect = stall
    response = api.client.post("/api/v1/guest/session", headers={"Origin": ORIGIN})
    assert response.status_code == 503
    assert cancelled
    assert "set-cookie" not in response.headers
    api.verify.assert_not_awaited()
    api.create.assert_not_awaited()
