"""Bounded cleanup and accounting overlap on guarded local PostgreSQL."""

import asyncio
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from secrets import token_bytes
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from pydantic import SecretStr
from sqlalchemy import DateTime, delete, event, func, insert, literal, select, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine
from sqlalchemy.pool import NullPool
from sqlalchemy.sql.elements import ColumnElement

from app import auth_rate_limit_cleanup as cleanup
from app import auth_rate_limit_maintenance as maintenance
from app.auth_rate_limits import commit_password_recovery_attempt, count_password_recovery_attempt
from app.config import Settings
from app.models import AuthRateLimit

pytestmark = pytest.mark.integration


@dataclass
class CleanupCase:
    engine: AsyncEngine
    observer: AsyncEngine
    name: str
    keys: list[bytes] = field(default_factory=list, repr=False)


type CaseFactory = Callable[[], AbstractAsyncContextManager[CleanupCase]]


@pytest.fixture
def case_factory(integration_engine: Engine) -> CaseFactory:
    @asynccontextmanager
    async def connect() -> AsyncIterator[CleanupCase]:
        name = f"limit-cleanup-test-{token_bytes(8).hex()}"
        engine = create_async_engine(
            integration_engine.url,
            poolclass=NullPool,
            hide_parameters=True,
            connect_args={
                "connect_timeout": 5,
                "hostaddr": "127.0.0.1",
                "options": (
                    "-c role=askm6_app -c timezone=UTC -c statement_timeout=5000 "
                    f"-c application_name={name}"
                ),
            },
        )
        observer = create_async_engine(
            integration_engine.url,
            poolclass=NullPool,
            isolation_level="AUTOCOMMIT",
            hide_parameters=True,
            connect_args={"connect_timeout": 5, "hostaddr": "127.0.0.1"},
        )
        case = CleanupCase(engine, observer, name)
        try:
            async with engine.connect() as guard:
                async with guard.begin():
                    assert tuple(
                        (await guard.execute(text("SELECT current_database(), current_user"))).one()
                    ) == ("askm6_test", "askm6_app")
                    assert (
                        await guard.scalar(
                            text(
                                "SELECT NOT rolsuper AND NOT rolbypassrls "
                                "FROM pg_roles WHERE rolname = current_user"
                            )
                        )
                        is True
                    )
                    # Protect pre-existing records: the real cleanup must skip
                    # these locks, so committed tests can delete only their own
                    # synthetic rows. Never clear a shared table for test setup.
                    existing = (
                        await guard.execute(
                            select(AuthRateLimit.key_hash).limit(1001).with_for_update(nowait=True)
                        )
                    ).all()
                    assert len(existing) <= 1000, (
                        "Too many existing rows for isolated cleanup tests."
                    )
                    yield case
        finally:
            try:
                if case.keys:
                    async with engine.begin() as connection:
                        await connection.execute(
                            delete(AuthRateLimit).where(
                                AuthRateLimit.purpose == "password_recovery",
                                AuthRateLimit.key_hash.in_(case.keys),
                            )
                        )
            finally:
                await engine.dispose()
                await observer.dispose()

    return connect


async def seed(case: CleanupCase, expiries: list[datetime]) -> list[bytes]:
    keys = [token_bytes(32) for _ in expiries]
    case.keys.extend(keys)
    async with case.engine.begin() as connection:
        await connection.execute(
            insert(AuthRateLimit),
            [
                {
                    "purpose": "password_recovery",
                    "key_hash": key,
                    "request_times": [expiry - timedelta(seconds=600)],
                    "expires_at": expiry,
                }
                for key, expiry in zip(keys, expiries, strict=True)
            ],
        )
    return keys


async def state(
    case: CleanupCase, connection: AsyncConnection | None = None
) -> dict[bytes, tuple[list[datetime], datetime]]:
    if connection is None:
        async with case.engine.connect() as reader:
            return await state(case, reader)
    rows = (
        await connection.execute(select(AuthRateLimit).where(AuthRateLimit.key_hash.in_(case.keys)))
    ).all()
    return {row.key_hash: (list(row.request_times), row.expires_at) for row in rows}


async def wait_for_counter_lock(case: CleanupCase) -> None:
    async with asyncio.timeout(4):
        async with case.observer.connect() as connection:
            while not await connection.scalar(
                text(
                    "SELECT EXISTS (SELECT 1 FROM pg_stat_activity "
                    "WHERE application_name = :name AND wait_event_type = 'Lock')"
                ),
                {"name": case.name},
            ):
                await asyncio.sleep(0.01)


def test_no_expired_rows_leaves_active_state_unchanged(case_factory: CaseFactory) -> None:
    async def check() -> None:
        async with case_factory() as case:
            await seed(case, [datetime.now(UTC) + timedelta(hours=1)])
            before = await state(case)
            async with case.engine.begin() as connection:
                assert await cleanup.delete_expired_password_recovery_limits(connection) == 0
            assert await state(case) == before

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


@pytest.mark.parametrize("offset", [-1, 0, 1])
def test_exact_expiry_boundary(
    case_factory: CaseFactory, monkeypatch: pytest.MonkeyPatch, offset: int
) -> None:
    now = datetime(2026, 10, 24, 12, tzinfo=UTC)

    def cutoff() -> ColumnElement[datetime]:
        return literal(now, type_=DateTime(timezone=True))

    monkeypatch.setattr(cleanup, "func", SimpleNamespace(statement_timestamp=cutoff))

    async def check() -> None:
        async with case_factory() as case:
            await seed(case, [now + timedelta(microseconds=offset)])
            before = await state(case)
            async with case.engine.begin() as connection:
                count = await cleanup.delete_expired_password_recovery_limits(connection)
                assert count == (1 if offset <= 0 else 0)
            assert await state(case) == ({} if offset <= 0 else before)

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


@pytest.mark.parametrize("batch", [1, 2, 1000])
def test_batch_bound_and_deterministic_tie_order(case_factory: CaseFactory, batch: int) -> None:
    async def check() -> None:
        async with case_factory() as case:
            keys = await seed(case, [datetime.now(UTC) - timedelta(hours=1)] * (batch + 1))
            async with case.engine.begin() as connection:
                assert (
                    await cleanup.delete_expired_password_recovery_limits(
                        connection, batch_size=batch
                    )
                    == batch
                )
            assert set(await state(case)) == set(sorted(keys)[batch:])

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_default_batch_repeats_until_no_more_expired_rows(case_factory: CaseFactory) -> None:
    async def check() -> None:
        async with case_factory() as case:
            await seed(case, [datetime.now(UTC) - timedelta(hours=1)] * 105)
            for expected in (100, 5, 0):
                async with case.engine.begin() as connection:
                    assert (
                        await cleanup.delete_expired_password_recovery_limits(connection)
                        == expected
                    )
            assert await state(case) == {}

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_oldest_expiry_is_removed_first(case_factory: CaseFactory) -> None:
    async def check() -> None:
        async with case_factory() as case:
            now = datetime.now(UTC)
            newest, oldest = await seed(case, [now - timedelta(minutes=1), now - timedelta(days=1)])
            async with case.engine.begin() as connection:
                assert (
                    await cleanup.delete_expired_password_recovery_limits(connection, batch_size=1)
                    == 1
                )
            assert set(await state(case)) == {newest}
            assert oldest not in await state(case)

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


@pytest.mark.parametrize("cancel", [False, True])
def test_rollback_or_cancellation_restores_deleted_rows(
    case_factory: CaseFactory, cancel: bool
) -> None:
    async def check() -> None:
        async with case_factory() as case:
            await seed(case, [datetime.now(UTC) - timedelta(hours=1)] * 3)
            before = await state(case)
            error = asyncio.CancelledError if cancel else RuntimeError
            with pytest.raises(error):
                async with case.engine.begin() as connection:
                    assert await cleanup.delete_expired_password_recovery_limits(connection) == 3
                    assert await state(case, connection) == {}
                    assert await state(case) == before
                    raise error
            assert await state(case) == before

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_locked_oldest_row_is_skipped_and_can_be_deleted_later(case_factory: CaseFactory) -> None:
    async def check() -> None:
        async with case_factory() as case:
            now = datetime.now(UTC)
            locked, *_ = await seed(case, [now - timedelta(hours=n) for n in (3, 2, 1)])
            async with case.engine.begin() as holder:
                await holder.execute(
                    select(AuthRateLimit).where(AuthRateLimit.key_hash == locked).with_for_update()
                )
                async with asyncio.timeout(2):
                    async with case.engine.begin() as connection:
                        assert (
                            await cleanup.delete_expired_password_recovery_limits(connection) == 2
                        )
                assert set(await state(case)) == {locked}
            async with case.engine.begin() as connection:
                assert await cleanup.delete_expired_password_recovery_limits(connection) == 1
            assert await state(case) == {}

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_overlapping_cleanup_transactions_delete_disjoint_batches(
    case_factory: CaseFactory,
) -> None:
    async def check() -> None:
        async with case_factory() as case:
            keys = set(await seed(case, [datetime.now(UTC) - timedelta(hours=1)] * 5))
            async with case.engine.begin() as first, case.engine.begin() as second:
                first_count, second_count = await asyncio.gather(
                    cleanup.delete_expired_password_recovery_limits(first, batch_size=2),
                    cleanup.delete_expired_password_recovery_limits(second, batch_size=2),
                )
                assert first_count == second_count == 2
                deleted_first = keys - set(await state(case, first))
                deleted_second = keys - set(await state(case, second))
                assert len(deleted_first) == len(deleted_second) == 2
                assert deleted_first.isdisjoint(deleted_second)
                assert set(await state(case)) == keys
            assert len(await state(case)) == 1

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_cleanup_skips_a_counter_extending_an_expired_row(case_factory: CaseFactory) -> None:
    async def check() -> None:
        async with case_factory() as case:
            (key,) = await seed(case, [datetime.now(UTC) - timedelta(hours=1)])
            async with case.engine.begin() as counter:
                assert (
                    await count_password_recovery_attempt(
                        counter, key, max_requests=1, window_seconds=600
                    )
                ).allowed
                async with asyncio.timeout(2):
                    async with case.engine.begin() as connection:
                        assert (
                            await cleanup.delete_expired_password_recovery_limits(connection) == 0
                        )
            row = (await state(case))[key]
            assert len(row[0]) == 1 and row[1] > datetime.now(UTC)

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_counter_waits_for_cleanup_then_creates_a_fresh_row(case_factory: CaseFactory) -> None:
    async def check() -> None:
        async with case_factory() as case:
            (key,) = await seed(case, [datetime.now(UTC) - timedelta(hours=1)])
            task = None
            try:
                async with case.engine.begin() as connection:
                    assert await cleanup.delete_expired_password_recovery_limits(connection) == 1
                    task = asyncio.create_task(
                        commit_password_recovery_attempt(
                            case.engine, key, max_requests=1, window_seconds=600
                        )
                    )
                    await wait_for_counter_lock(case)
                    assert not task.done()
                async with asyncio.timeout(3):
                    assert (await task).allowed
                assert len((await state(case))[key][0]) == 1
            finally:
                if task is not None:
                    if not task.done():
                        task.cancel()
                    await asyncio.gather(task, return_exceptions=True)

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_cutoff_uses_current_statement_not_transaction_start(case_factory: CaseFactory) -> None:
    async def check() -> None:
        async with case_factory() as case:
            async with case.engine.begin() as connection:
                started = await connection.scalar(select(func.clock_timestamp()))
                assert isinstance(started, datetime)
                (key,) = await seed(case, [started + timedelta(milliseconds=100)])
                await connection.execute(text("SELECT pg_sleep(0.2)"))
                assert await cleanup.delete_expired_password_recovery_limits(connection) == 1
            assert key not in await state(case)

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_wrapper_returns_a_committed_batch_and_preserves_active_rows(
    case_factory: CaseFactory,
) -> None:
    async def check() -> None:
        async with case_factory() as case:
            now = datetime.now(UTC)
            *expired, active = await seed(
                case, [now - timedelta(hours=1)] * 2 + [now + timedelta(minutes=5)]
            )
            before = await state(case)
            assert (
                await cleanup.commit_expired_password_recovery_cleanup(
                    case.engine, timeout_seconds=3, batch_size=1
                )
                == 1
            )
            after = await state(case)
            assert len(after) == 2 and after[active] == before[active]
            assert sum(key in after for key in expired) == 1
            assert (
                await cleanup.commit_expired_password_recovery_cleanup(
                    case.engine, timeout_seconds=3
                )
                == 1
            )
            assert await state(case) == {active: before[active]}

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_wrapper_database_error_at_commit_rolls_back_deletion(case_factory: CaseFactory) -> None:
    async def check() -> None:
        async with case_factory() as case:
            await seed(case, [datetime.now(UTC) - timedelta(hours=1)] * 2)
            before = await state(case)
            commits = 0

            def fail_commit(connection: Connection) -> None:
                nonlocal commits
                commits += 1
                connection.exec_driver_sql("SELECT 1 / 0")

            event.listen(case.engine.sync_engine, "commit", fail_commit)
            try:
                with pytest.raises(SQLAlchemyError):
                    await cleanup.commit_expired_password_recovery_cleanup(
                        case.engine, timeout_seconds=3
                    )
                assert commits == 1
            finally:
                event.remove(case.engine.sync_engine, "commit", fail_commit)
            assert await state(case) == before
            assert (
                await cleanup.commit_expired_password_recovery_cleanup(
                    case.engine, timeout_seconds=3
                )
                == 2
            )

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


@pytest.mark.parametrize("cancel", [False, True])
def test_wrapper_cancels_real_database_lock_wait_and_recovers(
    case_factory: CaseFactory, cancel: bool
) -> None:
    async def check() -> None:
        async with case_factory() as case:
            await seed(case, [datetime.now(UTC) - timedelta(hours=1)])
            before = await state(case)
            task = None
            try:
                async with case.engine.begin() as holder:
                    # SKIP LOCKED skips row locks, not conflicting table locks.
                    # This mode permits the fixture's existing ROW SHARE lock.
                    await holder.execute(
                        text("LOCK TABLE app.auth_rate_limits IN SHARE ROW EXCLUSIVE MODE")
                    )
                    task = asyncio.create_task(
                        cleanup.commit_expired_password_recovery_cleanup(
                            case.engine, timeout_seconds=2 if cancel else 1
                        )
                    )
                    await wait_for_counter_lock(case)
                    assert not task.done()
                    if cancel:
                        task.cancel()
                    error = asyncio.CancelledError if cancel else TimeoutError
                    with pytest.raises(error):
                        await task
                    assert await state(case) == before
                assert (
                    await cleanup.commit_expired_password_recovery_cleanup(
                        case.engine, timeout_seconds=3
                    )
                    == 1
                )
            finally:
                if task is not None:
                    if not task.done():
                        task.cancel()
                    await asyncio.gather(task, return_exceptions=True)

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_wrapper_deadline_covers_real_connection_pool_wait(case_factory: CaseFactory) -> None:
    async def check() -> None:
        async with case_factory() as case:
            await seed(case, [datetime.now(UTC) - timedelta(hours=1)])
            before = await state(case)
            engine = create_async_engine(
                case.engine.url,
                pool_size=1,
                max_overflow=0,
                pool_timeout=2,
                hide_parameters=True,
                connect_args={
                    "connect_timeout": 5,
                    "hostaddr": "127.0.0.1",
                    "options": "-c role=askm6_app -c timezone=UTC -c statement_timeout=5000",
                },
            )
            try:
                async with engine.connect():
                    with pytest.raises(TimeoutError):
                        await cleanup.commit_expired_password_recovery_cleanup(
                            engine, timeout_seconds=0.1
                        )
                    assert await state(case) == before
                assert (
                    await cleanup.commit_expired_password_recovery_cleanup(
                        engine, timeout_seconds=3
                    )
                    == 1
                )
            finally:
                await engine.dispose()

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_wrapper_timeout_after_delete_rolls_back_real_rows(
    case_factory: CaseFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def check() -> None:
        async with case_factory() as case:
            await seed(case, [datetime.now(UTC) - timedelta(hours=1)] * 2)
            before = await state(case)
            original = cleanup.delete_expired_password_recovery_limits
            deleted = asyncio.Event()

            async def pause_after_delete(connection: AsyncConnection, *, batch_size: int) -> int:
                result = await original(connection, batch_size=batch_size)
                assert result == 2
                deleted.set()
                await asyncio.Event().wait()
                return result

            monkeypatch.setattr(
                cleanup, "delete_expired_password_recovery_limits", pause_after_delete
            )
            with pytest.raises(TimeoutError):
                await cleanup.commit_expired_password_recovery_cleanup(
                    case.engine, timeout_seconds=0.3
                )
            assert deleted.is_set()
            assert await state(case) == before
            monkeypatch.setattr(cleanup, "delete_expired_password_recovery_limits", original)
            assert (
                await cleanup.commit_expired_password_recovery_cleanup(
                    case.engine, timeout_seconds=3
                )
                == 2
            )

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def maintenance_settings(database: str = "askm6_test") -> Settings:
    # Real connections still use the guarded fixture, never this synthetic
    # password. Unit tests separately check pinned engine-creation arguments.
    return Settings.model_construct(
        database_url=SecretStr(
            f"postgresql+psycopg://askm6_app:synthetic-password@127.0.0.1:15432/{database}"
        )
    )


def test_maintenance_checks_real_identity_and_commits_one_batch(
    case_factory: CaseFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def check() -> None:
        async with case_factory() as case:
            now = datetime.now(UTC)
            *expired, active = await seed(
                case, [now - timedelta(hours=1)] * 2 + [now + timedelta(minutes=5)]
            )
            before = await state(case)
            factory = MagicMock(return_value=case.engine)
            monkeypatch.setattr(maintenance, "create_async_engine", factory)
            assert (
                await maintenance.cleanup_local(
                    maintenance_settings(), batch_size=1, timeout_seconds=3
                )
                == 1
            )
            after = await state(case)
            assert len(after) == 2 and after[active] == before[active]
            assert sum(key in after for key in expired) == 1
            factory.assert_called_once()

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


@pytest.mark.parametrize("mismatch", ["database", "administrator"])
def test_maintenance_rejects_real_identity_mismatch_without_deleting(
    case_factory: CaseFactory, monkeypatch: pytest.MonkeyPatch, mismatch: str
) -> None:
    async def check() -> None:
        async with case_factory() as case:
            await seed(case, [datetime.now(UTC) - timedelta(hours=1)])
            before = await state(case)
            engine = case.observer if mismatch == "administrator" else case.engine
            settings = maintenance_settings("mazda6" if mismatch == "database" else "askm6_test")
            monkeypatch.setattr(maintenance, "create_async_engine", MagicMock(return_value=engine))
            deleter = AsyncMock()
            monkeypatch.setattr(maintenance, "commit_expired_password_recovery_cleanup", deleter)
            with pytest.raises(ValueError, match="Unexpected database identity"):
                await maintenance.cleanup_local(settings, batch_size=1, timeout_seconds=3)
            deleter.assert_not_called()
            assert await state(case) == before

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)
