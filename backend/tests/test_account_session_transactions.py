"""Account authentication returns only after successful transaction completion."""

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import cast
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import httpx2
import pytest
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

import app.account_session_transactions as transactions
from app.account_auth import AccountAuthenticationUnavailable
from app.account_refresh import AccountRefreshRejected
from app.account_session_auth import AuthenticatedAccountSession
from app.account_tokens import VerifiedAccount
from app.config import Settings

pytestmark = pytest.mark.anyio

TOKEN = SecretStr("A" * 43)


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@dataclass
class TransactionMaterial:
    engine: Mock
    connection: AsyncConnection
    settings: Settings
    client: httpx2.AsyncClient
    authenticated: AuthenticatedAccountSession
    authenticate: AsyncMock
    commit: AsyncMock
    events: list[str]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def material(monkeypatch: pytest.MonkeyPatch) -> TransactionMaterial:
    now = datetime.now(UTC)
    connection = cast(AsyncConnection, Mock(spec=AsyncConnection))
    client = cast(httpx2.AsyncClient, Mock(spec=httpx2.AsyncClient))
    settings = IsolatedSettings.model_validate(
        {
            "database_url": None,
            "migration_database_url": None,
            "supabase_auth_issuer": None,
            "supabase_auth_publishable_key": None,
            "account_session_encryption_key": None,
        }
    )

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

    authenticate = AsyncMock(return_value=authenticated)
    commit = AsyncMock()
    events: list[str] = []

    # Model the engine context manager without contacting PostgreSQL.
    @asynccontextmanager
    async def transaction() -> AsyncIterator[AsyncConnection]:
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
            events.append("release")

    engine = Mock(spec=AsyncEngine)
    engine.begin.side_effect = transaction
    monkeypatch.setattr(
        transactions,
        "authenticate_account_session",
        authenticate,
    )

    return TransactionMaterial(
        engine=engine,
        connection=connection,
        settings=settings,
        client=client,
        authenticated=authenticated,
        authenticate=authenticate,
        commit=commit,
        events=events,
    )


async def invoke(
    material: TransactionMaterial,
) -> AuthenticatedAccountSession | None:
    return await transactions.authenticate_account_session_transaction(
        cast(AsyncEngine, material.engine),
        TOKEN,
        settings=material.settings,
        client=material.client,
        key_cache=None,
    )


@pytest.mark.parametrize("accepted", [True, False])
async def test_returns_result_after_commit_and_connection_release(
    material: TransactionMaterial,
    accepted: bool,
) -> None:
    expected = material.authenticated if accepted else None
    material.authenticate.return_value = expected

    result = await invoke(material)
    material.events.append("returned")

    assert result is expected
    assert material.events == ["begin", "commit", "release", "returned"]
    material.engine.begin.assert_called_once_with()
    material.commit.assert_awaited_once_with()
    material.authenticate.assert_awaited_once_with(
        material.connection,
        TOKEN,
        settings=material.settings,
        client=material.client,
        key_cache=None,
    )


async def test_commit_failure_prevents_returning_authenticated_identity(
    material: TransactionMaterial,
) -> None:
    failure = SQLAlchemyError("Synthetic commit failure")
    material.commit.side_effect = failure

    with pytest.raises(SQLAlchemyError) as caught:
        await invoke(material)

    assert caught.value is failure
    assert material.events == ["begin", "commit", "release"]
    material.engine.begin.assert_called_once_with()
    material.authenticate.assert_awaited_once()
    material.commit.assert_awaited_once_with()


@pytest.mark.parametrize(
    "failure",
    [
        AccountRefreshRejected("Account credentials were rejected."),
        AccountAuthenticationUnavailable("Account authentication is unavailable."),
        SQLAlchemyError("Synthetic authentication database failure"),
        asyncio.CancelledError(),
    ],
    ids=["rejected", "unavailable", "database-error", "cancelled"],
)
async def test_authentication_failure_rolls_back_without_commit_or_retry(
    material: TransactionMaterial,
    failure: BaseException,
) -> None:
    material.authenticate.side_effect = failure

    with pytest.raises(type(failure)) as caught:
        await invoke(material)

    assert caught.value is failure
    assert material.events == ["begin", "rollback", "release"]
    material.engine.begin.assert_called_once_with()
    material.authenticate.assert_awaited_once()
    material.commit.assert_not_awaited()
