"""OAuth consumption guards, expiry boundaries and failure propagation."""

import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncConnection

from app.account_oauth_attempts import (
    OAuthLoginAttemptUnavailable,
    consume_oauth_login_attempt,
    replace_oauth_login_attempt,
)
from app.account_oauth_material import InvalidOAuthLoginMaterial, hash_oauth_browser_token
from app.config import Settings

pytestmark = pytest.mark.anyio
TOKEN = "a" * 43
NOW = datetime(2026, 10, 23, tzinfo=UTC)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def connection() -> Mock:
    database = Mock(spec=AsyncConnection)
    database.in_transaction.return_value = True
    row = SimpleNamespace(
        id=uuid4(),
        pkce_verifier_ciphertext=b"synthetic-encrypted-verifier",
        expires_at=NOW + timedelta(minutes=10),
    )
    result = Mock()
    result.one_or_none.return_value = row
    database.execute = AsyncMock(return_value=result)
    database.scalar = AsyncMock(return_value=NOW)
    return database


def assert_no_transaction_control(connection: Mock) -> None:
    connection.begin.assert_not_called()
    connection.commit.assert_not_awaited()
    connection.rollback.assert_not_awaited()


async def test_consumption_returns_only_provisional_protected_material(connection: Mock) -> None:
    consumed = await consume_oauth_login_attempt(cast(AsyncConnection, connection), TOKEN)

    assert consumed.pkce_verifier_ciphertext == b"synthetic-encrypted-verifier"
    assert consumed.expires_at == NOW + timedelta(minutes=10)
    assert "synthetic-encrypted-verifier" not in repr(consumed)
    statement = connection.execute.await_args.args[0]
    compiled = statement.compile()
    assert set(compiled.params.values()) == {hash_oauth_browser_token(TOKEN), "google", "sign_in"}
    assert TOKEN not in str(compiled)
    assert "clock_timestamp" in str(connection.scalar.await_args.args[0])
    assert_no_transaction_control(connection)


@pytest.mark.parametrize("token", [None, "malformed"])
async def test_invalid_token_never_contacts_database(connection: Mock, token: str | None) -> None:
    with pytest.raises(InvalidOAuthLoginMaterial, match="^Invalid OAuth login material\\.$"):
        await consume_oauth_login_attempt(cast(AsyncConnection, connection), token)

    connection.execute.assert_not_awaited()
    connection.scalar.assert_not_awaited()
    assert_no_transaction_control(connection)


@pytest.mark.parametrize("operation", ["consume", "replace"])
async def test_operations_require_active_transaction(connection: Mock, operation: str) -> None:
    connection.in_transaction.return_value = False
    with pytest.raises(RuntimeError, match="requires an active transaction"):
        if operation == "consume":
            await consume_oauth_login_attempt(cast(AsyncConnection, connection), TOKEN)
        else:
            # Only the transaction guard is exercised; no configuration is read.
            await replace_oauth_login_attempt(
                cast(AsyncConnection, connection), Settings.model_construct(), TOKEN
            )

    connection.execute.assert_not_awaited()
    connection.scalar.assert_not_awaited()
    connection.begin_nested.assert_not_called()


async def test_unknown_or_replayed_attempt_does_not_read_clock(connection: Mock) -> None:
    connection.execute.return_value.one_or_none.return_value = None
    with pytest.raises(InvalidOAuthLoginMaterial):
        await consume_oauth_login_attempt(cast(AsyncConnection, connection), TOKEN)

    connection.execute.assert_awaited_once()
    connection.scalar.assert_not_awaited()
    assert_no_transaction_control(connection)


@pytest.mark.parametrize("offset", [-1, 0, 1], ids=["expired", "exact-deadline", "active"])
async def test_expiry_boundary_uses_fresh_clock_after_deletion(
    connection: Mock, offset: int
) -> None:
    row = connection.execute.return_value.one_or_none.return_value
    row.expires_at = NOW + timedelta(microseconds=offset)
    if offset <= 0:
        with pytest.raises(InvalidOAuthLoginMaterial):
            await consume_oauth_login_attempt(cast(AsyncConnection, connection), TOKEN)
    else:
        assert (
            await consume_oauth_login_attempt(cast(AsyncConnection, connection), TOKEN)
        ).expires_at == row.expires_at

    assert_no_transaction_control(connection)


@pytest.mark.parametrize("clock", [None, "invalid", datetime(2026, 10, 23)])
async def test_invalid_fresh_database_time_fails_closed(connection: Mock, clock: object) -> None:
    connection.scalar.return_value = clock
    with pytest.raises(OAuthLoginAttemptUnavailable):
        await consume_oauth_login_attempt(cast(AsyncConnection, connection), TOKEN)

    assert_no_transaction_control(connection)


@pytest.mark.parametrize("stage", ["delete", "clock"])
@pytest.mark.parametrize("cancelled", [False, True], ids=["database-error", "cancelled"])
async def test_failures_propagate_without_retry_or_commit(
    connection: Mock, stage: str, cancelled: bool
) -> None:
    failure = asyncio.CancelledError() if cancelled else SQLAlchemyError("Synthetic DB failure.")
    if stage == "delete":
        connection.execute.side_effect = failure
    else:
        connection.scalar.side_effect = failure

    with pytest.raises(type(failure)) as caught:
        await consume_oauth_login_attempt(cast(AsyncConnection, connection), TOKEN)

    assert caught.value is failure
    connection.execute.assert_awaited_once()
    assert connection.scalar.await_count == (0 if stage == "delete" else 1)
    assert_no_transaction_control(connection)
