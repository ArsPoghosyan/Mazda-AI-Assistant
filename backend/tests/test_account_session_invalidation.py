"""Account-wide session invalidation guards without PostgreSQL."""

import asyncio
from datetime import UTC, datetime, timedelta
from typing import cast
from unittest.mock import AsyncMock, Mock
from uuid import UUID, uuid4

import pytest
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncConnection
from sqlalchemy.sql.dml import Delete

from app.account_session_invalidation import invalidate_account_sessions
from app.account_tokens import VerifiedAccount

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def account() -> VerifiedAccount:
    return VerifiedAccount(
        user_id=UUID("11111111-1111-4111-8111-111111111111"),
        session_id=UUID("22222222-2222-4222-8222-222222222222"),
        assurance_level="aal1",
        access_token_expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


@pytest.fixture
def connection() -> Mock:
    database = Mock(spec=AsyncConnection)
    database.in_transaction.return_value = True

    result = Mock()
    result.scalars.return_value.all.return_value = []
    database.execute = AsyncMock(return_value=result)

    return database


def assert_caller_owns_transaction(connection: Mock) -> None:
    connection.begin.assert_not_called()
    connection.begin_nested.assert_not_called()
    connection.commit.assert_not_awaited()
    connection.rollback.assert_not_awaited()


async def test_requires_active_transaction(
    connection: Mock,
    account: VerifiedAccount,
) -> None:
    connection.in_transaction.return_value = False

    with pytest.raises(RuntimeError, match="requires an active transaction"):
        await invalidate_account_sessions(
            cast(AsyncConnection, connection),
            account,
        )

    connection.execute.assert_not_awaited()
    assert_caller_owns_transaction(connection)


@pytest.mark.parametrize("count", [0, 1, 3])
async def test_targets_verified_account_and_returns_deleted_count(
    connection: Mock,
    account: VerifiedAccount,
    count: int,
) -> None:
    deleted_ids = [uuid4() for _ in range(count)]
    result = connection.execute.return_value
    result.scalars.return_value.all.return_value = deleted_ids

    deleted_count = await invalidate_account_sessions(
        cast(AsyncConnection, connection),
        account,
    )

    assert deleted_count == count
    connection.execute.assert_awaited_once()

    statement = connection.execute.await_args.args[0]
    assert isinstance(statement, Delete)

    compiled = statement.compile()
    sql = str(compiled)

    assert sql.startswith("DELETE FROM app.account_sessions WHERE ")
    assert "app.account_sessions.user_id =" in sql
    assert "RETURNING app.account_sessions.id" in sql
    assert list(compiled.params.values()) == [account.user_id]
    assert str(account.user_id) not in sql

    result.scalars.assert_called_once_with()
    result.scalars.return_value.all.assert_called_once_with()
    assert_caller_owns_transaction(connection)


@pytest.mark.parametrize(
    "failure",
    [
        SQLAlchemyError("Synthetic invalidation failure"),
        asyncio.CancelledError(),
    ],
    ids=["database-error", "cancelled"],
)
async def test_failures_propagate_without_retry(
    connection: Mock,
    account: VerifiedAccount,
    failure: BaseException,
) -> None:
    connection.execute.side_effect = failure

    with pytest.raises(type(failure)) as caught:
        await invalidate_account_sessions(
            cast(AsyncConnection, connection),
            account,
        )

    assert caught.value is failure
    connection.execute.assert_awaited_once()
    assert_caller_owns_transaction(connection)


async def test_result_read_failure_propagates_without_committing(
    connection: Mock,
    account: VerifiedAccount,
) -> None:
    failure = SQLAlchemyError("Synthetic result-read failure")
    result = connection.execute.return_value
    result.scalars.return_value.all.side_effect = failure

    with pytest.raises(SQLAlchemyError) as caught:
        await invalidate_account_sessions(
            cast(AsyncConnection, connection),
            account,
        )

    assert caught.value is failure
    connection.execute.assert_awaited_once()
    assert_caller_owns_transaction(connection)
