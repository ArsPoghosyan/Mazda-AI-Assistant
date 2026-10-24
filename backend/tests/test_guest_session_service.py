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
from app.auth_rate_limits import AuthRateLimitDecision
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
    limit: AsyncMock
    key: Mock
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
    limit = AsyncMock(return_value=AuthRateLimitDecision(True, datetime.now(UTC), 0, None))
    key = Mock(return_value=b"k" * 32)
    monkeypatch.setattr(service, "commit_guest_creation_attempt", limit)
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
        limit=limit,
        key=key,
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
        creation_ip_key=material.key,
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
    material.limit.assert_not_awaited()
    material.key.assert_not_called()


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


async def test_creation_commits_limit_before_verification(material: GuestMaterial) -> None:
    async def counted(*args: object, **kwargs: object) -> AuthRateLimitDecision:
        assert material.events == ["begin", "commit", "release"]
        material.events.append("limit-released")
        return AuthRateLimitDecision(True, datetime.now(UTC), 0, None)

    material.limit.side_effect = counted
    await invoke(material)
    assert material.events == [
        "begin",
        "commit",
        "release",
        "limit-released",
        "verify",
        "begin",
        "create",
        "commit",
        "release",
    ]
    material.limit.assert_awaited_once_with(
        material.engine,
        b"k" * 32,
        max_requests=10,
        window_seconds=600,
    )
    material.key.assert_called_once_with()


async def test_denial_never_verifies_or_creates(material: GuestMaterial) -> None:
    material.limit.return_value = AuthRateLimitDecision(False, datetime.now(UTC), 127, None)
    with pytest.raises(service.GuestCreationRateLimited) as caught:
        await invoke(material, browser_token=None)
    assert caught.value.retry_after_seconds == 127
    material.verify.assert_not_awaited()
    material.create.assert_not_awaited()
    material.engine.begin.assert_not_called()


@pytest.mark.parametrize("missing", ["client", "secret", "hostnames"])
async def test_missing_verification_configuration_does_not_charge_creation(
    material: GuestMaterial,
    missing: str,
) -> None:
    if missing == "client":
        material.client = None
    elif missing == "secret":
        material.settings.turnstile_secret_key = None
    else:
        material.settings.turnstile_allowed_hostnames = ()
    with pytest.raises(TurnstileUnavailable):
        await invoke(material, browser_token=None)
    material.limit.assert_not_awaited()
    material.key.assert_not_called()
    material.verify.assert_not_awaited()


@pytest.mark.parametrize("failure", [SQLAlchemyError("private"), asyncio.CancelledError()])
async def test_limiter_failure_propagates_without_provider_or_retry(
    material: GuestMaterial,
    failure: BaseException,
) -> None:
    material.limit.side_effect = failure
    with pytest.raises(type(failure)):
        await invoke(material, browser_token=None)
    material.limit.assert_awaited_once()
    material.verify.assert_not_awaited()
    material.create.assert_not_awaited()


async def test_missing_challenge_is_still_a_counted_attempt(material: GuestMaterial) -> None:
    with pytest.raises(TurnstileRejected):
        await invoke(material, browser_token=None, challenge_token=None)
    material.limit.assert_awaited_once()
    material.verify.assert_not_awaited()
