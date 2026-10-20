"""Account-session lookup guards without database or provider access."""

from typing import cast
from unittest.mock import AsyncMock

import pytest
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict
from sqlalchemy.ext.asyncio import AsyncConnection

from app.account_sessions import touch_account_session
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
            "supabase_auth_issuer": None,
            "account_session_encryption_key": None,
            "account_session_inactivity_days": 7,
            "account_session_absolute_lifetime_days": 30,
        }
    )


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
async def test_invalid_tokens_are_rejected_before_database_work(
    settings: Settings,
    raw_token: str | None,
) -> None:
    connection = AsyncMock(spec=AsyncConnection)
    token = None if raw_token is None else SecretStr(raw_token)

    result = await touch_account_session(
        cast(AsyncConnection, connection),
        token,
        settings,
    )

    assert result is None
    assert connection.mock_calls == []


async def test_valid_token_requires_an_active_transaction(
    settings: Settings,
) -> None:
    connection = AsyncMock(spec=AsyncConnection)
    connection.in_transaction.return_value = False

    with pytest.raises(RuntimeError, match="requires an active transaction"):
        await touch_account_session(
            cast(AsyncConnection, connection),
            SecretStr("A" * 43),
            settings,
        )

    connection.scalar.assert_not_awaited()
    connection.execute.assert_not_awaited()


async def test_unknown_token_returns_none_without_updating(
    settings: Settings,
) -> None:
    connection = AsyncMock(spec=AsyncConnection)
    connection.in_transaction.return_value = True
    connection.scalar.return_value = None

    result = await touch_account_session(
        cast(AsyncConnection, connection),
        SecretStr("A" * 43),
        settings,
    )

    assert result is None
    connection.scalar.assert_awaited_once()
    connection.execute.assert_not_awaited()
