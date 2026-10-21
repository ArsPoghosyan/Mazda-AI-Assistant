"""Account-session deletion guards and query targeting without PostgreSQL."""

import asyncio
from hashlib import sha256
from typing import cast
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest
from pydantic import SecretStr
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncConnection
from sqlalchemy.sql.dml import Delete

from app.account_session_deletion import delete_account_session

pytestmark = pytest.mark.anyio

TOKEN = SecretStr("A" * 41 + "-_")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def connection() -> Mock:
    database = Mock(spec=AsyncConnection)
    database.in_transaction.return_value = True
    database.scalar = AsyncMock(return_value=None)
    return database


@pytest.mark.parametrize(
    "raw_token",
    [
        None,
        "",
        "invalid",
        "A" * 42,
        "A" * 44,
        "A" * 43 + "\n",
        "A" * 42 + "!",
        "\N{SNOWMAN}" * 43,
        " " + "A" * 42,
    ],
)
async def test_invalid_credentials_do_not_touch_database(
    connection: Mock,
    raw_token: str | None,
) -> None:
    token = None if raw_token is None else SecretStr(raw_token)

    result = await delete_account_session(
        cast(AsyncConnection, connection),
        token,
    )

    assert result is False
    assert connection.mock_calls == []


async def test_valid_credential_requires_active_transaction(
    connection: Mock,
) -> None:
    connection.in_transaction.return_value = False

    with pytest.raises(RuntimeError, match="requires an active transaction"):
        await delete_account_session(
            cast(AsyncConnection, connection),
            TOKEN,
        )

    connection.scalar.assert_not_awaited()
    connection.commit.assert_not_awaited()
    connection.rollback.assert_not_awaited()


@pytest.mark.parametrize("matched", [True, False], ids=["deleted", "unknown"])
async def test_deletion_targets_only_the_cookie_hash(
    connection: Mock,
    matched: bool,
) -> None:
    connection.scalar.return_value = uuid4() if matched else None

    result = await delete_account_session(
        cast(AsyncConnection, connection),
        TOKEN,
    )

    assert result is matched
    connection.scalar.assert_awaited_once()

    statement = connection.scalar.await_args.args[0]
    assert isinstance(statement, Delete)

    compiled = statement.compile()
    sql = str(compiled)
    expected_hash = sha256(TOKEN.get_secret_value().encode("ascii")).digest()

    assert sql.startswith("DELETE FROM app.account_sessions WHERE ")
    assert "app.account_sessions.token_hash =" in sql
    assert "RETURNING app.account_sessions.id" in sql
    assert list(compiled.params.values()) == [expected_hash]
    assert TOKEN.get_secret_value() not in sql

    connection.begin.assert_not_called()
    connection.commit.assert_not_awaited()
    connection.rollback.assert_not_awaited()


@pytest.mark.parametrize(
    "failure",
    [
        SQLAlchemyError("Synthetic deletion failure"),
        asyncio.CancelledError(),
    ],
    ids=["database-error", "cancelled"],
)
async def test_failures_propagate_without_retry_or_transaction_control(
    connection: Mock,
    failure: BaseException,
) -> None:
    connection.scalar.side_effect = failure

    with pytest.raises(type(failure)) as caught:
        await delete_account_session(
            cast(AsyncConnection, connection),
            TOKEN,
        )

    assert caught.value is failure
    connection.scalar.assert_awaited_once()
    connection.begin.assert_not_called()
    connection.commit.assert_not_awaited()
    connection.rollback.assert_not_awaited()
