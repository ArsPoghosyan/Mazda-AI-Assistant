"""Failure boundaries for authentication rate-limit accounting."""

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from app import auth_rate_limits as limiter


@pytest.fixture(params=["password_recovery", "sign_in", "sign_up"])
def purpose(request: pytest.FixtureRequest) -> str:
    return str(request.param)


@pytest.mark.parametrize(
    ("key", "maximum", "window"),
    [
        (b"k" * 31, 10, 600),
        (b"k" * 33, 10, 600),
        (b"k" * 32, 0, 600),
        (b"k" * 32, 1001, 600),
        (b"k" * 32, True, 600),
        (b"k" * 32, 10, 59),
        (b"k" * 32, 10, 86401),
        (b"k" * 32, 10, True),
    ],
)
def test_invalid_parameters_fail_before_database_access(
    purpose: str, key: bytes, maximum: int, window: int
) -> None:
    connection = MagicMock(spec=AsyncConnection)
    counter = {
        "password_recovery": limiter.count_password_recovery_attempt,
        "sign_in": limiter.count_sign_in_attempt,
        "sign_up": limiter.count_sign_up_attempt,
    }[purpose]
    with pytest.raises(ValueError, match="^Invalid authentication rate-limit parameters\\.$"):
        asyncio.run(counter(connection, key, max_requests=maximum, window_seconds=window))
    connection.in_transaction.assert_not_called()
    connection.execute.assert_not_called()


def test_connection_must_already_have_a_transaction(purpose: str) -> None:
    connection = MagicMock(spec=AsyncConnection)
    connection.in_transaction.return_value = False
    counter = {
        "password_recovery": limiter.count_password_recovery_attempt,
        "sign_in": limiter.count_sign_in_attempt,
        "sign_up": limiter.count_sign_up_attempt,
    }[purpose]
    with pytest.raises(RuntimeError, match="requires an active transaction"):
        asyncio.run(counter(connection, b"k" * 32, max_requests=10, window_seconds=600))
    connection.execute.assert_not_called()


@pytest.mark.parametrize("value", [None, "not-a-date", datetime(2026, 10, 24)])
def test_unusable_database_time_fails_closed(value: object) -> None:
    connection = MagicMock(spec=AsyncConnection)
    connection.scalar = AsyncMock(return_value=value)
    with pytest.raises(limiter.AuthRateLimitUnavailable):
        asyncio.run(limiter._database_now(connection))
    connection.scalar.assert_awaited_once()


def test_row_removed_before_lock_fails_closed_without_a_time_read_or_update(purpose: str) -> None:
    connection = MagicMock(spec=AsyncConnection)
    connection.in_transaction.return_value = True
    missing = MagicMock()
    missing.one_or_none.return_value = None
    connection.execute = AsyncMock(side_effect=[MagicMock(), missing])
    counter = {
        "password_recovery": limiter.count_password_recovery_attempt,
        "sign_in": limiter.count_sign_in_attempt,
        "sign_up": limiter.count_sign_up_attempt,
    }[purpose]
    with pytest.raises(limiter.AuthRateLimitUnavailable):
        asyncio.run(counter(connection, b"k" * 32, max_requests=10, window_seconds=600))
    assert connection.execute.await_count == 2
    connection.scalar.assert_not_called()


@pytest.mark.parametrize("failure", ["none", "commit", "database", "cancel"])
def test_wrapper_commits_before_return_and_never_retries_on_failure(
    monkeypatch: pytest.MonkeyPatch, purpose: str, failure: str
) -> None:
    events: list[str] = []
    connection = MagicMock(spec=AsyncConnection)
    engine = MagicMock(spec=AsyncEngine)
    decision = limiter.AuthRateLimitDecision(True, datetime.now(UTC), 0, None)

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
            if failure == "commit":
                raise RuntimeError("Synthetic commit failure.")

    engine.begin.return_value = transaction()

    async def count(*args: object, **kwargs: object) -> limiter.AuthRateLimitDecision:
        events.append("count")
        if failure == "database":
            raise SQLAlchemyError("Synthetic database failure.")
        if failure == "cancel":
            raise asyncio.CancelledError
        return decision

    counter = AsyncMock(side_effect=count)
    monkeypatch.setattr(limiter, f"count_{purpose}_attempt", counter)

    async def run() -> limiter.AuthRateLimitDecision:
        commit = {
            "password_recovery": limiter.commit_password_recovery_attempt,
            "sign_in": limiter.commit_sign_in_attempt,
            "sign_up": limiter.commit_sign_up_attempt,
        }[purpose]
        return await commit(engine, b"k" * 32, max_requests=10, window_seconds=600)

    if failure == "none":
        assert asyncio.run(run()) is decision
        assert events == ["begin", "count", "commit"]
    elif failure == "commit":
        with pytest.raises(RuntimeError, match="Synthetic commit failure"):
            asyncio.run(run())
        assert events == ["begin", "count", "commit"]
    else:
        error = SQLAlchemyError if failure == "database" else asyncio.CancelledError
        with pytest.raises(error):
            asyncio.run(run())
        assert events == ["begin", "count", "rollback"]
    engine.begin.assert_called_once()
    counter.assert_awaited_once_with(connection, b"k" * 32, max_requests=10, window_seconds=600)
