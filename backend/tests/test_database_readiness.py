"""Readiness tests using simulated database connections."""

import asyncio
from typing import cast
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine

from app.database import database_is_ready


def fake_database() -> tuple[MagicMock, AsyncMock]:
    connection = AsyncMock()
    engine = MagicMock(spec=AsyncEngine)
    engine.connect.return_value.__aenter__.return_value = connection
    return engine, connection


def test_missing_engine_is_not_ready() -> None:
    assert not asyncio.run(database_is_ready(None, 1))


def test_successful_query_is_ready() -> None:
    engine, connection = fake_database()

    assert asyncio.run(database_is_ready(cast(AsyncEngine, engine), 1))

    connection.execute.assert_awaited_once()
    engine.connect.return_value.__aexit__.assert_awaited_once()


@pytest.mark.parametrize("stage", ["connect", "query"])
def test_database_failure_is_not_ready(stage: str) -> None:
    engine, connection = fake_database()
    error = SQLAlchemyError("Private connection details")

    if stage == "connect":
        engine.connect.return_value.__aenter__.side_effect = error
    else:
        connection.execute.side_effect = error

    assert not asyncio.run(database_is_ready(cast(AsyncEngine, engine), 1))


def test_slow_query_times_out() -> None:
    engine, connection = fake_database()

    async def slow_query(*args: object, **kwargs: object) -> None:
        await asyncio.sleep(1)

    connection.execute.side_effect = slow_query

    assert not asyncio.run(database_is_ready(cast(AsyncEngine, engine), 0.01))
    engine.connect.return_value.__aexit__.assert_awaited_once()
