"""Deterministic scheduling, failure isolation and cancellation without a database."""

import asyncio
import logging
from dataclasses import dataclass, field
from typing import cast
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest
from pydantic_settings import SettingsConfigDict
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine

from app import auth_rate_limit_scheduler as scheduler
from app.config import Settings

WARNINGS = {
    "limiter": "Authentication limiter cleanup failed; waiting for the next interval.",
    "oauth": "Pending Google login-attempt cleanup failed; waiting for the next interval.",
    "guest": "Guest-session cleanup failed; waiting for the next interval.",
    "account": "Account-session cleanup failed; waiting for the next interval.",
}
SUCCESS = {
    "limiter": "authentication limiter records",
    "oauth": "pending Google login attempts",
    "guest": "guest sessions",
    "account": "account sessions",
}


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


def settings(*, enabled: bool = True) -> Settings:
    return IsolatedSettings(
        auth_rate_limit_cleanup_enabled=enabled,
        auth_rate_limit_cleanup_interval_seconds=60,
        auth_rate_limit_cleanup_batch_size=2,
        auth_rate_limit_cleanup_timeout_seconds=3,
    )


@dataclass
class Ticks:
    waiting: asyncio.Queue[asyncio.Future[None]] = field(default_factory=asyncio.Queue)
    intervals: list[int] = field(default_factory=list)

    async def sleep(self, interval: int) -> None:
        self.intervals.append(interval)
        gate: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        self.waiting.put_nowait(gate)
        await gate

    async def next(self) -> asyncio.Future[None]:
        return await asyncio.wait_for(self.waiting.get(), 2)


@pytest.fixture(autouse=True)
def oauth_cleanup(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    cleanup = AsyncMock(return_value=0)
    monkeypatch.setattr(scheduler, "commit_expired_oauth_login_attempt_cleanup", cleanup)
    return cleanup


@pytest.fixture(autouse=True)
def session_cleanups(monkeypatch: pytest.MonkeyPatch) -> dict[str, AsyncMock]:
    helpers = {name: AsyncMock(return_value=0) for name in ("guest", "account")}
    for name, helper in helpers.items():
        monkeypatch.setattr(scheduler, f"commit_expired_{name}_session_cleanup", helper)
    return helpers


@pytest.mark.parametrize(("enabled", "has_engine"), [(False, False), (False, True), (True, False)])
def test_disabled_or_missing_engine_creates_no_task(
    monkeypatch: pytest.MonkeyPatch, enabled: bool, has_engine: bool
) -> None:
    create = Mock(side_effect=AssertionError("No housekeeping task should start."))
    monkeypatch.setattr(scheduler, "create_task", create)

    async def check() -> None:
        engine = MagicMock(spec=AsyncEngine) if has_engine else None
        async with scheduler.auth_rate_limit_cleanup_lifespan(engine, settings(enabled=enabled)):
            pass

    asyncio.run(check())
    create.assert_not_called()


@pytest.mark.parametrize("deleted", [0, 1, 2])
@pytest.mark.parametrize("operation", ["limiter", "oauth", "guest", "account"])
def test_waits_before_first_batch_and_never_drains_or_catches_up(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    deleted: int,
    oauth_cleanup: AsyncMock,
    session_cleanups: dict[str, AsyncMock],
    operation: str,
) -> None:
    cleanup = AsyncMock(return_value=0)
    helpers = {"limiter": cleanup, "oauth": oauth_cleanup, **session_cleanups}
    helpers[operation].return_value = deleted
    monkeypatch.setattr(scheduler, "commit_expired_auth_rate_limit_cleanup", cleanup)
    caplog.set_level(logging.INFO, logger=scheduler.__name__)

    async def check() -> None:
        ticks = Ticks()
        engine = MagicMock(spec=AsyncEngine)
        monkeypatch.setattr(scheduler, "sleep", ticks.sleep)
        async with scheduler.auth_rate_limit_cleanup_lifespan(engine, settings()):
            first = await ticks.next()
            for helper in helpers.values():
                helper.assert_not_awaited()
            first.set_result(None)
            second = await ticks.next()
            for helper in helpers.values():
                helper.assert_awaited_once_with(engine, batch_size=2, timeout_seconds=3)
            assert not second.done()
            assert ticks.intervals == [60, 60]
        assert second.cancelled()
        assert not any(task.get_name() == "auth-rate-limit-cleanup" for task in asyncio.all_tasks())

    asyncio.run(check())
    assert len(caplog.records) == (1 if deleted else 0)
    if deleted:
        assert caplog.records[0].getMessage() == (
            f"Deleted {deleted} expired {SUCCESS[operation]}."
        )


@pytest.mark.parametrize(
    "failure",
    [
        SQLAlchemyError("private-database-url"),
        TimeoutError("private-query"),
        RuntimeError("private-unexpected-failure"),
    ],
)
@pytest.mark.parametrize("operation", ["limiter", "oauth", "guest", "account"])
def test_failure_is_private_and_waits_for_next_interval_without_immediate_retry(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    failure: Exception,
    operation: str,
    oauth_cleanup: AsyncMock,
    session_cleanups: dict[str, AsyncMock],
) -> None:
    cleanup = AsyncMock(return_value=0)
    monkeypatch.setattr(scheduler, "commit_expired_auth_rate_limit_cleanup", cleanup)
    helpers = {"limiter": cleanup, "oauth": oauth_cleanup, **session_cleanups}
    failed = helpers[operation]
    failed.side_effect = [failure, 0]

    async def check() -> None:
        ticks = Ticks()
        monkeypatch.setattr(scheduler, "sleep", ticks.sleep)
        async with scheduler.auth_rate_limit_cleanup_lifespan(
            MagicMock(spec=AsyncEngine), settings()
        ):
            (await ticks.next()).set_result(None)
            second = await ticks.next()
            for helper in helpers.values():
                helper.assert_awaited_once()
            second.set_result(None)
            await ticks.next()
            assert all(helper.await_count == 2 for helper in helpers.values())

    asyncio.run(check())
    assert [record.getMessage() for record in caplog.records] == [WARNINGS[operation]]
    assert all(record.exc_info is None for record in caplog.records)
    assert "private" not in caplog.text


@pytest.mark.parametrize("operation", ["limiter", "oauth", "guest", "account"])
def test_slow_batch_cannot_overlap_and_shutdown_waits_for_its_cancellation(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    operation: str,
    oauth_cleanup: AsyncMock,
    session_cleanups: dict[str, AsyncMock],
) -> None:
    async def check() -> None:
        ticks, entered, released = Ticks(), asyncio.Event(), asyncio.Event()
        monkeypatch.setattr(scheduler, "sleep", ticks.sleep)

        async def pending(*args: object, **kwargs: object) -> int:
            entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                # Model awaited database rollback/release during cancellation.
                await asyncio.sleep(0)
                released.set()
            return 0

        cleanup = AsyncMock(return_value=0)
        helpers = {"limiter": cleanup, "oauth": oauth_cleanup, **session_cleanups}
        failed = helpers[operation]
        failed.side_effect = pending
        monkeypatch.setattr(scheduler, "commit_expired_auth_rate_limit_cleanup", cleanup)
        async with scheduler.auth_rate_limit_cleanup_lifespan(
            MagicMock(spec=AsyncEngine), settings()
        ):
            (await ticks.next()).set_result(None)
            await asyncio.wait_for(entered.wait(), 2)
            for _ in range(3):
                await asyncio.sleep(0)
            cleanup.assert_awaited_once()
            assert ticks.waiting.empty()
            assert ticks.intervals == [60]
        assert released.is_set()
        cleanup.assert_awaited_once()
        names = list(helpers)
        for name, helper in helpers.items():
            assert helper.await_count == (1 if names.index(name) <= names.index(operation) else 0)

    asyncio.run(check())
    assert not caplog.records


def test_operations_are_serial_and_success_counts_stay_separate(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    oauth_cleanup: AsyncMock,
    session_cleanups: dict[str, AsyncMock],
) -> None:
    caplog.set_level(logging.INFO, logger=scheduler.__name__)

    async def check() -> None:
        ticks = Ticks()
        events: list[str] = []
        monkeypatch.setattr(scheduler, "sleep", ticks.sleep)

        async def limiter(*args: object, **kwargs: object) -> int:
            events.append("limiter-started")
            await asyncio.sleep(0)
            events.append("limiter-committed")
            return 2

        async def oauth(*args: object, **kwargs: object) -> int:
            assert events == ["limiter-started", "limiter-committed"]
            events.append("oauth-committed")
            return 2

        async def guest(*args: object, **kwargs: object) -> int:
            assert events == ["limiter-started", "limiter-committed", "oauth-committed"]
            events.append("guest-committed")
            return 2

        async def account(*args: object, **kwargs: object) -> int:
            assert events == [
                "limiter-started",
                "limiter-committed",
                "oauth-committed",
                "guest-committed",
            ]
            events.append("account-committed")
            return 2

        monkeypatch.setattr(scheduler, "commit_expired_auth_rate_limit_cleanup", limiter)
        oauth_cleanup.side_effect = oauth
        session_cleanups["guest"].side_effect = guest
        session_cleanups["account"].side_effect = account
        async with scheduler.auth_rate_limit_cleanup_lifespan(
            MagicMock(spec=AsyncEngine), settings()
        ):
            (await ticks.next()).set_result(None)
            await ticks.next()
            assert events == [
                "limiter-started",
                "limiter-committed",
                "oauth-committed",
                "guest-committed",
                "account-committed",
            ]
            oauth_cleanup.assert_awaited_once()

    asyncio.run(check())
    assert [record.getMessage() for record in caplog.records] == [
        "Deleted 2 expired authentication limiter records.",
        "Deleted 2 expired pending Google login attempts.",
        "Deleted 2 expired guest sessions.",
        "Deleted 2 expired account sessions.",
    ]


def test_caller_error_still_cancels_the_waiting_task(monkeypatch: pytest.MonkeyPatch) -> None:
    async def check() -> None:
        ticks = Ticks()
        monkeypatch.setattr(scheduler, "sleep", ticks.sleep)
        gate: asyncio.Future[None] | None = None
        with pytest.raises(RuntimeError, match="caller-failed"):
            async with scheduler.auth_rate_limit_cleanup_lifespan(
                cast(AsyncEngine, MagicMock(spec=AsyncEngine)), settings()
            ):
                gate = await ticks.next()
                raise RuntimeError("caller-failed")
        assert gate is not None and gate.cancelled()

    asyncio.run(check())


def test_all_failed_operations_still_allow_the_next_pass(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    oauth_cleanup: AsyncMock,
    session_cleanups: dict[str, AsyncMock],
) -> None:
    limiter = AsyncMock()
    monkeypatch.setattr(scheduler, "commit_expired_auth_rate_limit_cleanup", limiter)
    helpers = {"limiter": limiter, "oauth": oauth_cleanup, **session_cleanups}
    for helper in helpers.values():
        helper.side_effect = [TimeoutError("private-detail"), 0]

    async def check() -> None:
        ticks = Ticks()
        monkeypatch.setattr(scheduler, "sleep", ticks.sleep)
        async with scheduler.auth_rate_limit_cleanup_lifespan(
            MagicMock(spec=AsyncEngine), settings()
        ):
            (await ticks.next()).set_result(None)
            second = await ticks.next()
            assert all(helper.await_count == 1 for helper in helpers.values())
            second.set_result(None)
            await ticks.next()
            assert all(helper.await_count == 2 for helper in helpers.values())

    asyncio.run(check())
    assert [record.getMessage() for record in caplog.records] == list(WARNINGS.values())
    assert "private" not in caplog.text
