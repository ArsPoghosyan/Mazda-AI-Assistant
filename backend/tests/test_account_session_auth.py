"""Locked-session loader guards without database or provider access."""

from typing import cast
from unittest.mock import AsyncMock, Mock

import pytest
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncConnection

from app.account_session_auth import load_locked_account_session

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


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
async def test_invalid_tokens_do_not_touch_the_database(
    raw_token: str | None,
) -> None:
    connection = AsyncMock(spec=AsyncConnection)
    token = None if raw_token is None else SecretStr(raw_token)

    result = await load_locked_account_session(
        cast(AsyncConnection, connection),
        token,
    )

    assert result is None
    assert connection.mock_calls == []


async def test_loading_requires_an_active_transaction() -> None:
    connection = AsyncMock(spec=AsyncConnection)
    connection.in_transaction.return_value = False

    with pytest.raises(RuntimeError, match="requires an active transaction"):
        await load_locked_account_session(
            cast(AsyncConnection, connection),
            SecretStr("A" * 43),
        )

    connection.execute.assert_not_awaited()
    connection.scalar.assert_not_awaited()


async def test_unknown_token_returns_none_without_a_clock_query() -> None:
    connection = AsyncMock(spec=AsyncConnection)
    connection.in_transaction.return_value = True

    query_result = Mock()
    query_result.one_or_none.return_value = None
    connection.execute.return_value = query_result

    result = await load_locked_account_session(
        cast(AsyncConnection, connection),
        SecretStr("A" * 43),
    )

    assert result is None
    connection.execute.assert_awaited_once()
    query_result.one_or_none.assert_called_once_with()
    connection.scalar.assert_not_awaited()
