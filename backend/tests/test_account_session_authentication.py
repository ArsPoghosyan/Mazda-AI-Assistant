"""Stored-session authentication orchestration without live services."""

import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict
from sqlalchemy.ext.asyncio import AsyncConnection

import app.account_session_auth as session_auth
from app.account_auth import AccountAuthenticationUnavailable
from app.account_session_auth import LockedAccountSession
from app.account_tokens import VerifiedAccount
from app.config import Settings

pytestmark = pytest.mark.anyio


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def settings() -> Settings:
    return IsolatedSettings.model_validate(
        {
            "database_url": None,
            "migration_database_url": None,
            "account_session_inactivity_days": 7,
        }
    )


@pytest.fixture
def auth_mocks(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[AsyncMock, AsyncMock, AsyncMock]:
    connection = AsyncMock(spec=AsyncConnection)

    # These tests isolate orchestration. Existing tests exercise the real
    # loader, encryption, and JWT verification.
    snapshot = Mock(
        spec=LockedAccountSession,
        session_id=uuid4(),
    )
    account = VerifiedAccount(
        user_id=uuid4(),
        session_id=uuid4(),
        assurance_level="aal1",
        access_token_expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    loader = AsyncMock(return_value=snapshot)
    verifier = AsyncMock(return_value=account)

    monkeypatch.setattr(session_auth, "load_locked_account_session", loader)
    monkeypatch.setattr(session_auth, "verify_locked_account_access", verifier)

    return connection, loader, verifier


async def test_missing_session_does_not_verify_or_update(
    settings: Settings,
    auth_mocks: tuple[AsyncMock, AsyncMock, AsyncMock],
) -> None:
    connection, loader, verifier = auth_mocks
    loader.return_value = None

    result = await session_auth.authenticate_stored_account_session(
        cast(AsyncConnection, connection),
        SecretStr("A" * 43),
        settings=settings,
        key_cache=None,
    )

    assert result is None
    loader.assert_awaited_once()
    verifier.assert_not_awaited()
    connection.execute.assert_not_awaited()


@pytest.mark.parametrize(
    "failure",
    [
        AccountAuthenticationUnavailable("Account authentication is unavailable."),
        asyncio.CancelledError(),
    ],
    ids=["verification-unavailable", "verification-cancelled"],
)
async def test_verification_failure_prevents_activity_update(
    settings: Settings,
    auth_mocks: tuple[AsyncMock, AsyncMock, AsyncMock],
    failure: BaseException,
) -> None:
    connection, _, verifier = auth_mocks
    verifier.side_effect = failure

    with pytest.raises(type(failure)):
        await session_auth.authenticate_stored_account_session(
            cast(AsyncConnection, connection),
            SecretStr("A" * 43),
            settings=settings,
            key_cache=None,
        )

    verifier.assert_awaited_once()
    connection.execute.assert_not_awaited()
    connection.commit.assert_not_awaited()
    connection.rollback.assert_not_awaited()


async def test_guarded_update_without_matching_row_returns_none(
    settings: Settings,
    auth_mocks: tuple[AsyncMock, AsyncMock, AsyncMock],
) -> None:
    connection, _, verifier = auth_mocks
    query_result = Mock()
    query_result.one_or_none.return_value = None
    connection.execute.return_value = query_result

    result = await session_auth.authenticate_stored_account_session(
        cast(AsyncConnection, connection),
        SecretStr("A" * 43),
        settings=settings,
        key_cache=None,
    )

    assert result is None
    verifier.assert_awaited_once()
    connection.execute.assert_awaited_once()
    query_result.one_or_none.assert_called_once_with()


async def test_success_returns_verified_identity_and_database_deadlines(
    settings: Settings,
    auth_mocks: tuple[AsyncMock, AsyncMock, AsyncMock],
) -> None:
    connection, loader, verifier = auth_mocks
    now = datetime.now(UTC)
    row = SimpleNamespace(
        id=loader.return_value.session_id,
        idle_expires_at=now + timedelta(days=7),
        absolute_expires_at=now + timedelta(days=30),
    )
    query_result = Mock()
    query_result.one_or_none.return_value = row
    connection.execute.return_value = query_result

    result = await session_auth.authenticate_stored_account_session(
        cast(AsyncConnection, connection),
        SecretStr("A" * 43),
        settings=settings,
        key_cache=None,
    )

    assert result is not None
    assert result.session_id == row.id
    assert result.account is verifier.return_value
    assert result.idle_expires_at == row.idle_expires_at
    assert result.absolute_expires_at == row.absolute_expires_at

    verifier.assert_awaited_once_with(
        loader.return_value,
        settings=settings,
        key_cache=None,
    )
    connection.execute.assert_awaited_once()
    connection.commit.assert_not_awaited()
    connection.rollback.assert_not_awaited()
