"""Guest/account session cleanup validation, completion and cancellation boundaries."""

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Protocol, cast
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from app import session_cleanup as cleanup


class DeleteBatch(Protocol):
    async def __call__(self, connection: AsyncConnection, *, batch_size: int = 100) -> int: ...


class CommitBatch(Protocol):
    async def __call__(
        self, engine: AsyncEngine, *, timeout_seconds: float, batch_size: int = 100
    ) -> int: ...


@dataclass(frozen=True)
class CleanupFunctions:
    delete_name: str
    delete: DeleteBatch
    commit: CommitBatch


@pytest.fixture(params=["guest", "account"])
def case(request: pytest.FixtureRequest) -> CleanupFunctions:
    if request.param == "guest":
        return CleanupFunctions(
            "delete_expired_guest_sessions",
            cleanup.delete_expired_guest_sessions,
            cleanup.commit_expired_guest_session_cleanup,
        )
    return CleanupFunctions(
        "delete_expired_account_sessions",
        cleanup.delete_expired_account_sessions,
        cleanup.commit_expired_account_session_cleanup,
    )


@pytest.mark.parametrize("batch", [0, -1, 1001, True, False, 1.5, "100", None])
def test_invalid_batch_is_rejected_before_connection_access(
    case: CleanupFunctions, batch: object
) -> None:
    connection = MagicMock(spec=AsyncConnection)
    with pytest.raises(ValueError, match="Session cleanup batch size"):
        asyncio.run(case.delete(connection, batch_size=cast(int, batch)))
    connection.in_transaction.assert_not_called()
    connection.execute.assert_not_called()

    engine = MagicMock(spec=AsyncEngine)
    with pytest.raises(ValueError, match="Session cleanup batch size"):
        asyncio.run(case.commit(engine, batch_size=cast(int, batch), timeout_seconds=5))
    engine.begin.assert_not_called()


def test_caller_transaction_is_required(
    case: CleanupFunctions,
) -> None:
    connection = MagicMock(spec=AsyncConnection)
    connection.in_transaction.return_value = False
    with pytest.raises(RuntimeError, match="requires an active transaction"):
        asyncio.run(case.delete(connection))
    connection.execute.assert_not_called()


@pytest.mark.parametrize(
    "timeout",
    [
        0,
        -1,
        30.001,
        float("nan"),
        float("inf"),
        float("-inf"),
        True,
        False,
        "5",
        None,
        10**400,
    ],
)
def test_invalid_timeout_is_rejected_before_acquisition(
    case: CleanupFunctions, timeout: object
) -> None:
    engine = MagicMock(spec=AsyncEngine)
    with pytest.raises(ValueError, match="Session cleanup timeout"):
        asyncio.run(case.commit(engine, timeout_seconds=cast(float, timeout)))
    engine.begin.assert_not_called()


@pytest.mark.parametrize("failure", ["none", "acquire", "delete", "commit", "cancel"])
def test_only_committed_counts_escape_and_failures_never_retry(
    case: CleanupFunctions, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    events: list[str] = []
    connection = MagicMock(spec=AsyncConnection)
    engine = MagicMock(spec=AsyncEngine)

    @asynccontextmanager
    async def transaction() -> AsyncIterator[AsyncConnection]:
        events.append("acquire")
        if failure == "acquire":
            raise SQLAlchemyError("synthetic-private")
        try:
            try:
                yield connection
            except BaseException:
                events.append("rollback")
                raise
            else:
                events.append("commit")
                if failure == "commit":
                    raise SQLAlchemyError("synthetic-private")
        finally:
            events.append("release")

    async def delete(*args: object, **kwargs: object) -> int:
        events.append("delete")
        if failure == "delete":
            raise SQLAlchemyError("synthetic-private")
        if failure == "cancel":
            raise asyncio.CancelledError
        return 7

    deleter = AsyncMock(side_effect=delete)
    monkeypatch.setattr(cleanup, case.delete_name, deleter)
    engine.begin.return_value = transaction()

    async def run() -> int:
        count = await case.commit(engine, timeout_seconds=30, batch_size=1000)
        events.append("return")
        return count

    if failure == "none":
        assert asyncio.run(run()) == 7
        assert events == ["acquire", "delete", "commit", "release", "return"]
    else:
        error = asyncio.CancelledError if failure == "cancel" else SQLAlchemyError
        with pytest.raises(error):
            asyncio.run(run())
        assert "return" not in events
        if failure == "acquire":
            assert events == ["acquire"]
        elif failure == "commit":
            assert events == ["acquire", "delete", "commit", "release"]
        else:
            assert events == ["acquire", "delete", "rollback", "release"]
    engine.begin.assert_called_once()
    if failure == "acquire":
        deleter.assert_not_awaited()
    else:
        deleter.assert_awaited_once_with(connection, batch_size=1000)


@pytest.mark.parametrize("phase", ["acquire", "delete", "commit", "release"])
def test_deadline_includes_every_awaited_phase(
    case: CleanupFunctions, monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    async def check() -> None:
        entered, cancelled = asyncio.Event(), asyncio.Event()
        engine, connection = MagicMock(spec=AsyncEngine), MagicMock(spec=AsyncConnection)

        async def block() -> None:
            entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()

        @asynccontextmanager
        async def transaction() -> AsyncIterator[AsyncConnection]:
            if phase == "acquire":
                await block()
            try:
                yield connection
                if phase == "commit":
                    await block()
            finally:
                if phase == "release":
                    await block()

        async def delete(*args: object, **kwargs: object) -> int:
            if phase == "delete":
                await block()
            return 1

        engine.begin.return_value = transaction()
        deleter = AsyncMock(side_effect=delete)
        monkeypatch.setattr(cleanup, case.delete_name, deleter)
        async with asyncio.timeout(2):
            with pytest.raises(TimeoutError):
                await case.commit(engine, timeout_seconds=0.03)
        assert entered.is_set() and cancelled.is_set()
        assert deleter.await_count == (0 if phase == "acquire" else 1)

    asyncio.run(check())


def test_external_cancellation_propagates_and_releases_connection(
    case: CleanupFunctions,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def check() -> None:
        engine, connection = MagicMock(spec=AsyncEngine), MagicMock(spec=AsyncConnection)
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

        async def delete(*args: object, **kwargs: object) -> int:
            entered.set()
            await asyncio.Event().wait()
            return 1

        engine.begin.return_value = transaction()
        monkeypatch.setattr(cleanup, case.delete_name, AsyncMock(side_effect=delete))
        task = asyncio.create_task(case.commit(engine, timeout_seconds=30))
        try:
            async with asyncio.timeout(2):
                await entered.wait()
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
            assert events == ["rollback", "release"]
        finally:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    asyncio.run(check())
