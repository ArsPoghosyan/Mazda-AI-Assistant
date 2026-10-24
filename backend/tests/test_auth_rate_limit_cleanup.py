"""Validation and failure boundaries for limiter cleanup."""

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import cast
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from app import auth_rate_limit_cleanup as cleanup
from app.auth_rate_limit_cleanup import delete_expired_password_recovery_limits


@pytest.mark.parametrize("batch", [0, -1, 1001, True, False, 1.5, "100", None])
def test_invalid_batch_fails_before_database_access(batch: object) -> None:
    connection = MagicMock(spec=AsyncConnection)
    with pytest.raises(ValueError, match="Cleanup batch size"):
        asyncio.run(
            delete_expired_password_recovery_limits(connection, batch_size=cast(int, batch))
        )
    connection.in_transaction.assert_not_called()
    connection.execute.assert_not_called()


def test_cleanup_requires_a_caller_transaction() -> None:
    connection = MagicMock(spec=AsyncConnection)
    connection.in_transaction.return_value = False
    with pytest.raises(RuntimeError, match="requires an active transaction"):
        asyncio.run(delete_expired_password_recovery_limits(connection))
    connection.execute.assert_not_called()


@pytest.mark.parametrize("failure", ["database", "cancel"])
def test_failure_propagates_without_commit_or_retry(failure: str) -> None:
    connection = MagicMock(spec=AsyncConnection)
    connection.in_transaction.return_value = True
    error = SQLAlchemyError if failure == "database" else asyncio.CancelledError
    connection.execute = AsyncMock(side_effect=error)
    with pytest.raises(error):
        asyncio.run(delete_expired_password_recovery_limits(connection))
    connection.execute.assert_awaited_once()
    connection.commit.assert_not_called()
    connection.rollback.assert_not_called()


@pytest.mark.parametrize("batch", [0, -1, 1001, True, False, 1.5, "100", None])
def test_wrapper_rejects_invalid_batch_before_acquiring_a_connection(batch: object) -> None:
    engine = MagicMock(spec=AsyncEngine)
    with pytest.raises(ValueError, match="Cleanup batch size"):
        asyncio.run(
            cleanup.commit_expired_password_recovery_cleanup(
                engine, timeout_seconds=1, batch_size=cast(int, batch)
            )
        )
    engine.begin.assert_not_called()


@pytest.mark.parametrize(
    "timeout",
    [0, -1, 30.001, float("nan"), float("inf"), float("-inf"), True, False, "5", None, 10**400],
)
def test_wrapper_rejects_invalid_deadline_before_acquiring_a_connection(timeout: object) -> None:
    engine = MagicMock(spec=AsyncEngine)
    with pytest.raises(ValueError, match="Cleanup timeout"):
        asyncio.run(
            cleanup.commit_expired_password_recovery_cleanup(
                engine, timeout_seconds=cast(float, timeout)
            )
        )
    engine.begin.assert_not_called()


@pytest.mark.parametrize("failure", ["none", "acquire", "delete", "commit", "cancel"])
def test_wrapper_returns_only_after_commit_and_release_without_retry(
    monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    events: list[str] = []
    connection = MagicMock(spec=AsyncConnection)
    engine = MagicMock(spec=AsyncEngine)

    @asynccontextmanager
    async def transaction() -> AsyncIterator[AsyncConnection]:
        events.append("acquire")
        if failure == "acquire":
            raise SQLAlchemyError("Synthetic acquisition failure.")
        try:
            try:
                yield connection
            except BaseException:
                events.append("rollback")
                raise
            else:
                events.append("commit")
                if failure == "commit":
                    raise SQLAlchemyError("Synthetic commit failure.")
        finally:
            events.append("release")

    async def delete_batch(*args: object, **kwargs: object) -> int:
        events.append("delete")
        if failure == "delete":
            raise SQLAlchemyError("Synthetic deletion failure.")
        if failure == "cancel":
            raise asyncio.CancelledError
        return 7

    engine.begin.return_value = transaction()
    deleter = AsyncMock(side_effect=delete_batch)
    monkeypatch.setattr(cleanup, "delete_expired_password_recovery_limits", deleter)

    async def run() -> int:
        deleted = await cleanup.commit_expired_password_recovery_cleanup(
            engine, timeout_seconds=30, batch_size=1000
        )
        events.append("return")
        return deleted

    if failure == "none":
        assert asyncio.run(run()) == 7
        assert events == ["acquire", "delete", "commit", "release", "return"]
    else:
        error = asyncio.CancelledError if failure == "cancel" else SQLAlchemyError
        with pytest.raises(error):
            asyncio.run(run())
        if failure == "acquire":
            assert events == ["acquire"]
        elif failure == "commit":
            assert events == ["acquire", "delete", "commit", "release"]
        else:
            assert events == ["acquire", "delete", "rollback", "release"]
    engine.begin.assert_called_once()
    if failure == "acquire":
        deleter.assert_not_called()
    else:
        deleter.assert_awaited_once_with(connection, batch_size=1000)


@pytest.mark.parametrize("phase", ["acquire", "delete", "commit", "release"])
def test_wrapper_real_deadline_cancels_every_awaited_phase(
    monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    async def check() -> None:
        engine = MagicMock(spec=AsyncEngine)
        connection = MagicMock(spec=AsyncConnection)
        entered = asyncio.Event()
        cancelled = asyncio.Event()
        rolled_back = False

        async def block() -> None:
            entered.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                cancelled.set()
                raise

        @asynccontextmanager
        async def transaction() -> AsyncIterator[AsyncConnection]:
            nonlocal rolled_back
            if phase == "acquire":
                await block()
            try:
                try:
                    yield connection
                except BaseException:
                    rolled_back = True
                    raise
                else:
                    if phase == "commit":
                        await block()
            finally:
                if phase == "release":
                    await block()

        async def delete_batch(*args: object, **kwargs: object) -> int:
            if phase == "delete":
                await block()
            return 1

        engine.begin.return_value = transaction()
        deleter = AsyncMock(side_effect=delete_batch)
        monkeypatch.setattr(cleanup, "delete_expired_password_recovery_limits", deleter)
        async with asyncio.timeout(2):
            with pytest.raises(TimeoutError):
                await cleanup.commit_expired_password_recovery_cleanup(engine, timeout_seconds=0.03)
        assert entered.is_set() and cancelled.is_set()
        assert rolled_back is (phase == "delete")
        engine.begin.assert_called_once()
        assert deleter.await_count == (0 if phase == "acquire" else 1)

    asyncio.run(check())


def test_wrapper_preserves_external_cancellation_and_unwinds_transaction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def check() -> None:
        engine = MagicMock(spec=AsyncEngine)
        connection = MagicMock(spec=AsyncConnection)
        entered = asyncio.Event()
        events: list[str] = []

        @asynccontextmanager
        async def transaction() -> AsyncIterator[AsyncConnection]:
            try:
                yield connection
            except asyncio.CancelledError:
                events.append("rollback")
                raise
            finally:
                events.append("release")

        async def delete_batch(*args: object, **kwargs: object) -> int:
            entered.set()
            await asyncio.Event().wait()
            return 1

        engine.begin.return_value = transaction()
        deleter = AsyncMock(side_effect=delete_batch)
        monkeypatch.setattr(cleanup, "delete_expired_password_recovery_limits", deleter)
        task = asyncio.create_task(
            cleanup.commit_expired_password_recovery_cleanup(engine, timeout_seconds=30)
        )
        try:
            async with asyncio.timeout(2):
                await entered.wait()
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
            assert events == ["rollback", "release"]
            deleter.assert_awaited_once_with(connection, batch_size=100)
            engine.begin.assert_called_once()
        finally:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    asyncio.run(check())
