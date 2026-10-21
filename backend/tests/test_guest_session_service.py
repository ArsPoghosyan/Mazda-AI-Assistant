"""Guest-session orchestration without live HTTP or PostgreSQL."""

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import cast
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import httpx2
import pytest
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

import app.guest_session_service as service
from app.config import Settings
from app.guest_sessions import ActiveGuestSession, CreatedGuestSession
from app.turnstile import TurnstileRejected, TurnstileUnavailable

pytestmark = pytest.mark.anyio

BROWSER_TOKEN = SecretStr("B" * 43)
CHALLENGE_TOKEN = SecretStr("synthetic-challenge")


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@dataclass
class GuestMaterial:
    engine: Mock
    connection: AsyncConnection
    settings: Settings
    client: httpx2.AsyncClient | None
    created: CreatedGuestSession
    refresh: AsyncMock
    verify: AsyncMock
    create: AsyncMock
    commit: AsyncMock
    events: list[str]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def material(monkeypatch: pytest.MonkeyPatch) -> GuestMaterial:
    settings = IsolatedSettings.model_validate(
        {
            "database_url": None,
            "migration_database_url": None,
            "supabase_auth_issuer": None,
            "supabase_auth_publishable_key": None,
            "account_session_encryption_key": None,
            "turnstile_secret_key": "synthetic-secret",
            "turnstile_allowed_hostnames": ("example.test",),
        }
    )
    connection = cast(AsyncConnection, Mock(spec=AsyncConnection))
    client = cast(httpx2.AsyncClient, Mock(spec=httpx2.AsyncClient))
    created = CreatedGuestSession(
        session_id=uuid4(),
        token=SecretStr("C" * 43),
        expires_at=datetime(2030, 1, 1, tzinfo=UTC),
    )
    events: list[str] = []
    transaction_open = False
    commit = AsyncMock()
    refresh = AsyncMock(return_value=None)

    async def verify(
        *args: object,
        **kwargs: object,
    ) -> None:
        assert not transaction_open
        events.append("verify")

    async def create(
        *args: object,
        **kwargs: object,
    ) -> CreatedGuestSession:
        assert transaction_open
        events.append("create")
        return created

    verify_mock = AsyncMock(side_effect=verify)
    create_mock = AsyncMock(side_effect=create)

    @asynccontextmanager
    async def transaction() -> AsyncIterator[AsyncConnection]:
        nonlocal transaction_open
        assert not transaction_open
        transaction_open = True
        events.append("begin")
        try:
            yield connection
        except BaseException:
            events.append("rollback")
            raise
        else:
            events.append("commit")
            await commit()
        finally:
            transaction_open = False
            events.append("release")

    engine = Mock(spec=AsyncEngine)
    engine.begin.side_effect = transaction

    monkeypatch.setattr(service, "refresh_guest_session", refresh)
    monkeypatch.setattr(service, "verify_turnstile_token", verify_mock)
    monkeypatch.setattr(service, "create_guest_session", create_mock)

    return GuestMaterial(
        engine=engine,
        connection=connection,
        settings=settings,
        client=client,
        created=created,
        refresh=refresh,
        verify=verify_mock,
        create=create_mock,
        commit=commit,
        events=events,
    )


async def invoke(
    material: GuestMaterial,
    *,
    browser_token: SecretStr | None = BROWSER_TOKEN,
    challenge_token: SecretStr | None = CHALLENGE_TOKEN,
) -> service.EstablishedGuestSession:
    return await service.establish_guest_session(
        cast(AsyncEngine, material.engine),
        browser_token=browser_token,
        challenge_token=challenge_token,
        settings=material.settings,
        client=material.client,
    )


async def test_active_session_refreshes_without_turnstile(
    material: GuestMaterial,
) -> None:
    active = ActiveGuestSession(
        session_id=uuid4(),
        expires_at=material.created.expires_at,
    )
    material.refresh.return_value = active
    material.client = None

    result = await invoke(material, challenge_token=None)
    material.events.append("returned")

    assert result.token is BROWSER_TOKEN
    assert result.expires_at == active.expires_at
    assert BROWSER_TOKEN.get_secret_value() not in repr(result)
    assert material.events == ["begin", "commit", "release", "returned"]
    material.refresh.assert_awaited_once_with(
        material.connection,
        BROWSER_TOKEN.get_secret_value(),
        material.settings,
    )
    material.verify.assert_not_awaited()
    material.create.assert_not_awaited()
    material.engine.begin.assert_called_once_with()
    material.commit.assert_awaited_once_with()


async def test_new_session_verifies_before_opening_transaction(
    material: GuestMaterial,
) -> None:
    result = await invoke(material, browser_token=None)
    material.events.append("returned")

    assert result.token is material.created.token
    assert result.expires_at == material.created.expires_at
    assert material.created.token.get_secret_value() not in repr(result)
    assert material.events == [
        "verify",
        "begin",
        "create",
        "commit",
        "release",
        "returned",
    ]
    material.refresh.assert_not_awaited()
    material.verify.assert_awaited_once_with(
        CHALLENGE_TOKEN,
        expected_action="guest_start",
        settings=material.settings,
        client=material.client,
    )
    material.create.assert_awaited_once_with(
        material.connection,
        material.settings,
    )
    material.engine.begin.assert_called_once_with()


@pytest.mark.parametrize("raw_token", ["", "bad-token", "B" * 43])
async def test_unusable_browser_session_requires_verification(
    material: GuestMaterial,
    raw_token: str,
) -> None:
    result = await invoke(material, browser_token=SecretStr(raw_token))
    material.events.append("returned")

    assert result.token is material.created.token
    assert material.events == [
        "begin",
        "commit",
        "release",
        "verify",
        "begin",
        "create",
        "commit",
        "release",
        "returned",
    ]
    material.refresh.assert_awaited_once_with(
        material.connection,
        raw_token,
        material.settings,
    )
    material.verify.assert_awaited_once()
    material.create.assert_awaited_once()
    assert material.engine.begin.call_count == 2
    assert material.commit.await_count == 2


@pytest.mark.parametrize("missing", ["client", "challenge"])
async def test_missing_verification_input_prevents_creation(
    material: GuestMaterial,
    missing: str,
) -> None:
    expected_error: type[TurnstileUnavailable] | type[TurnstileRejected]
    if missing == "client":
        material.client = None
        expected_error = TurnstileUnavailable
        challenge = CHALLENGE_TOKEN
    else:
        expected_error = TurnstileRejected
        challenge = None

    with pytest.raises(expected_error):
        await invoke(
            material,
            browser_token=None,
            challenge_token=challenge,
        )

    assert material.events == []
    material.engine.begin.assert_not_called()
    material.refresh.assert_not_awaited()
    material.verify.assert_not_awaited()
    material.create.assert_not_awaited()


@pytest.mark.parametrize(
    "failure",
    [
        TurnstileRejected("Rejected."),
        TurnstileUnavailable("Unavailable."),
        asyncio.CancelledError(),
    ],
    ids=["rejected", "unavailable", "cancelled"],
)
async def test_verification_failure_prevents_database_creation(
    material: GuestMaterial,
    failure: BaseException,
) -> None:
    material.verify.side_effect = failure

    with pytest.raises(type(failure)) as caught:
        await invoke(material, browser_token=None)

    assert caught.value is failure
    assert material.events == []
    material.verify.assert_awaited_once()
    material.engine.begin.assert_not_called()
    material.create.assert_not_awaited()


@pytest.mark.parametrize(
    "failure",
    [SQLAlchemyError("Synthetic database failure"), asyncio.CancelledError()],
    ids=["database-error", "cancelled"],
)
async def test_refresh_failure_does_not_fall_back_to_creation(
    material: GuestMaterial,
    failure: BaseException,
) -> None:
    material.refresh.side_effect = failure

    with pytest.raises(type(failure)) as caught:
        await invoke(material)

    assert caught.value is failure
    assert material.events == ["begin", "rollback", "release"]
    material.verify.assert_not_awaited()
    material.create.assert_not_awaited()
    material.commit.assert_not_awaited()


@pytest.mark.parametrize(
    "failure",
    [SQLAlchemyError("Synthetic database failure"), asyncio.CancelledError()],
    ids=["database-error", "cancelled"],
)
async def test_creation_failure_rolls_back_without_retry(
    material: GuestMaterial,
    failure: BaseException,
) -> None:
    material.create.side_effect = failure

    with pytest.raises(type(failure)) as caught:
        await invoke(material, browser_token=None)

    assert caught.value is failure
    assert material.events == ["verify", "begin", "rollback", "release"]
    material.verify.assert_awaited_once()
    material.create.assert_awaited_once()
    material.engine.begin.assert_called_once_with()
    material.commit.assert_not_awaited()


@pytest.mark.parametrize("operation", ["refresh", "create"])
@pytest.mark.parametrize(
    "failure",
    [SQLAlchemyError("Synthetic commit failure"), asyncio.CancelledError()],
    ids=["commit-error", "cancelled"],
)
async def test_commit_failure_never_returns_cookie_material(
    material: GuestMaterial,
    operation: str,
    failure: BaseException,
) -> None:
    material.commit.side_effect = failure

    if operation == "refresh":
        material.refresh.return_value = ActiveGuestSession(
            session_id=uuid4(),
            expires_at=material.created.expires_at,
        )
        browser_token = BROWSER_TOKEN
    else:
        browser_token = None

    with pytest.raises(type(failure)) as caught:
        await invoke(material, browser_token=browser_token)

    assert caught.value is failure
    material.engine.begin.assert_called_once_with()
    material.commit.assert_awaited_once_with()

    if operation == "refresh":
        assert material.events == ["begin", "commit", "release"]
        material.verify.assert_not_awaited()
        material.create.assert_not_awaited()
    else:
        assert material.events == [
            "verify",
            "begin",
            "create",
            "commit",
            "release",
        ]
        material.verify.assert_awaited_once()
        material.create.assert_awaited_once()
