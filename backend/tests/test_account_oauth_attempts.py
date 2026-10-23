"""Pending OAuth creation guards and failures without live services."""

import asyncio
from datetime import UTC, datetime, timedelta, timezone
from typing import cast
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncConnection
from sqlalchemy.sql.dml import Insert

from app.account_oauth_attempts import (
    OAuthLoginAttemptUnavailable,
    create_oauth_login_attempt,
)
from app.account_oauth_material import hash_oauth_browser_token, recover_oauth_pkce_verifier
from app.account_token_encryption import AccountTokenCipher
from app.config import Settings

pytestmark = pytest.mark.anyio
DATABASE_TIME = datetime(2026, 10, 23, 12, tzinfo=timezone(timedelta(hours=4)))


class IsolatedAttemptSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def settings() -> Settings:
    return IsolatedAttemptSettings(
        account_session_encryption_key=SecretStr(Fernet.generate_key().decode("ascii")),
        account_google_oauth_api_enabled=False,
        account_google_oauth_attempt_lifetime_seconds=600,
    )


@pytest.fixture
def connection() -> Mock:
    database = Mock(spec=AsyncConnection)
    database.in_transaction.return_value = True
    database.scalar = AsyncMock(side_effect=[DATABASE_TIME, uuid4()])
    return database


def assert_transaction_is_caller_owned(connection: Mock) -> None:
    connection.begin.assert_not_called()
    connection.commit.assert_not_awaited()
    connection.rollback.assert_not_awaited()


async def test_creation_stores_protected_values_using_database_time(
    connection: Mock, settings: Settings
) -> None:
    created = await create_oauth_login_attempt(cast(AsyncConnection, connection), settings)

    assert created.expires_at == DATABASE_TIME.astimezone(UTC) + timedelta(seconds=600)
    assert created.expires_at.utcoffset() == timedelta(0)
    assert created.browser_token.get_secret_value() not in repr(created)
    assert connection.scalar.await_count == 2
    statement = connection.scalar.await_args_list[1].args[0]
    assert isinstance(statement, Insert)
    parameters = statement.compile().params
    assert parameters["created_at"] == DATABASE_TIME.astimezone(UTC)
    assert parameters["expires_at"] == created.expires_at
    assert parameters["browser_token_hash"] == hash_oauth_browser_token(
        created.browser_token.get_secret_value()
    )
    key = settings.account_session_encryption_key
    assert key is not None
    verifier = recover_oauth_pkce_verifier(
        parameters["pkce_verifier_ciphertext"], cipher=AccountTokenCipher(key)
    )
    assert verifier != created.browser_token
    assert_transaction_is_caller_owned(connection)


async def test_creation_requires_active_transaction(connection: Mock, settings: Settings) -> None:
    connection.in_transaction.return_value = False

    with pytest.raises(RuntimeError, match="requires an active transaction"):
        await create_oauth_login_attempt(cast(AsyncConnection, connection), settings)

    connection.scalar.assert_not_awaited()
    assert_transaction_is_caller_owned(connection)


async def test_missing_encryption_key_does_not_query_database(
    connection: Mock, settings: Settings
) -> None:
    settings = settings.model_copy(update={"account_session_encryption_key": None})

    with pytest.raises(OAuthLoginAttemptUnavailable, match="^OAuth login is unavailable\\.$"):
        await create_oauth_login_attempt(cast(AsyncConnection, connection), settings)

    connection.scalar.assert_not_awaited()
    assert_transaction_is_caller_owned(connection)


@pytest.mark.parametrize("clock", [None, "invalid", datetime(2026, 10, 23)])
async def test_invalid_database_time_does_not_insert(
    connection: Mock, settings: Settings, clock: object
) -> None:
    connection.scalar.side_effect = [clock]

    with pytest.raises(OAuthLoginAttemptUnavailable, match="^OAuth login is unavailable\\.$"):
        await create_oauth_login_attempt(cast(AsyncConnection, connection), settings)

    connection.scalar.assert_awaited_once()
    assert_transaction_is_caller_owned(connection)


@pytest.mark.parametrize("attempt_id", [None, "not-a-uuid"])
async def test_invalid_insert_result_is_rejected(
    connection: Mock, settings: Settings, attempt_id: object
) -> None:
    connection.scalar.side_effect = [DATABASE_TIME, attempt_id]

    with pytest.raises(OAuthLoginAttemptUnavailable, match="^OAuth login is unavailable\\.$"):
        await create_oauth_login_attempt(cast(AsyncConnection, connection), settings)

    assert connection.scalar.await_count == 2
    assert_transaction_is_caller_owned(connection)


@pytest.mark.parametrize("stage", ["clock", "insert"])
@pytest.mark.parametrize("cancelled", [False, True], ids=["database-error", "cancelled"])
async def test_failures_propagate_without_retry_or_transaction_control(
    connection: Mock, settings: Settings, stage: str, cancelled: bool
) -> None:
    failure = asyncio.CancelledError() if cancelled else SQLAlchemyError("Synthetic DB failure.")
    connection.scalar.side_effect = [failure] if stage == "clock" else [DATABASE_TIME, failure]

    with pytest.raises(type(failure)) as caught:
        await create_oauth_login_attempt(cast(AsyncConnection, connection), settings)

    assert caught.value is failure
    assert connection.scalar.await_count == (1 if stage == "clock" else 2)
    assert_transaction_is_caller_owned(connection)
