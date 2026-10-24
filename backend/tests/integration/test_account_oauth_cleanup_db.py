"""Expired pending-attempt cleanup and callback overlap on guarded PostgreSQL."""

import asyncio
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, AsyncExitStack, asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from secrets import token_bytes, token_urlsafe
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr
from sqlalchemy import DateTime, delete, event, func, insert, literal, select, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine
from sqlalchemy.pool import NullPool

from app import account_oauth_cleanup as cleanup
from app import auth_rate_limit_scheduler as scheduler
from app.account_oauth_attempts import consume_oauth_login_attempt, replace_oauth_login_attempt
from app.account_oauth_material import InvalidOAuthLoginMaterial, hash_oauth_browser_token
from app.config import Settings
from app.models import AuthRateLimit, OAuthLoginAttempt

pytestmark = pytest.mark.integration


@dataclass
class CleanupCase:
    engine: AsyncEngine
    ids: list[UUID] = field(default_factory=list)
    tokens: dict[UUID, str] = field(default_factory=dict, repr=False)


type CaseFactory = Callable[[], AbstractAsyncContextManager[CleanupCase]]
type State = dict[UUID, tuple[datetime, bytes, bytes]]


@pytest.fixture(autouse=True)
def isolate_session_scheduling(monkeypatch: pytest.MonkeyPatch) -> None:
    # OAuth/limiter tests do not own session rows. Four-table scheduling is
    # exercised separately with guards for all tables in test_session_cleanup_db.
    for mode in ("guest", "account"):
        monkeypatch.setattr(
            scheduler, f"commit_expired_{mode}_session_cleanup", AsyncMock(return_value=0)
        )


@pytest.fixture
def case_factory(integration_engine: Engine) -> CaseFactory:
    @asynccontextmanager
    async def connect() -> AsyncIterator[CleanupCase]:
        engine = create_async_engine(
            integration_engine.url,
            poolclass=NullPool,
            hide_parameters=True,
            connect_args={
                "connect_timeout": 5,
                "hostaddr": "127.0.0.1",
                "options": "-c role=askm6_app -c timezone=UTC -c statement_timeout=5000",
            },
        )

        @event.listens_for(engine.sync_engine, "begin")
        def restricted(connection: Connection) -> None:
            assert tuple(
                connection.execute(text("SELECT current_database(), current_user")).one()
            ) == (
                "askm6_test",
                "askm6_app",
            )
            assert (
                connection.scalar(
                    text(
                        "SELECT NOT rolsuper AND NOT rolbypassrls "
                        "FROM pg_roles WHERE rolname=current_user"
                    )
                )
                is True
            )

        case = CleanupCase(engine)
        try:
            async with engine.begin() as guard:
                # These committed global-cleanup tests require an unused test
                # table. Preserve pre-existing attempts; never clear it to start.
                if await guard.scalar(select(OAuthLoginAttempt.id).limit(1)) is not None:
                    pytest.skip("Existing OAuth attempts prevent isolated cleanup testing.")
            yield case
        finally:
            try:
                if case.ids:
                    async with engine.begin() as connection:
                        await connection.execute(
                            delete(OAuthLoginAttempt).where(OAuthLoginAttempt.id.in_(case.ids))
                        )
            finally:
                await engine.dispose()

    return connect


async def seed(
    case: CleanupCase, expiries: list[datetime], connection: AsyncConnection | None = None
) -> list[UUID]:
    if connection is None:
        async with case.engine.begin() as writer:
            return await seed(case, expiries, writer)
    ids = [uuid4() for _ in expiries]
    case.ids.extend(ids)
    for attempt_id in ids:
        case.tokens[attempt_id] = token_urlsafe(32)
    await connection.execute(
        insert(OAuthLoginAttempt),
        [
            {
                "id": attempt_id,
                "browser_token_hash": hash_oauth_browser_token(case.tokens[attempt_id]),
                # Deliberately not decryptable; cleanup needs no encryption key.
                "pkce_verifier_ciphertext": b"synthetic-opaque-ciphertext",
                "created_at": expiry - timedelta(days=2),
                "expires_at": expiry,
            }
            for attempt_id, expiry in zip(ids, expiries, strict=True)
        ],
    )
    return ids


async def state(case: CleanupCase, connection: AsyncConnection | None = None) -> State:
    if connection is None:
        async with case.engine.connect() as reader:
            return await state(case, reader)
    return {
        row.id: (row.expires_at, row.browser_token_hash, row.pkce_verifier_ciphertext)
        for row in (
            await connection.execute(
                select(OAuthLoginAttempt).where(OAuthLoginAttempt.id.in_(case.ids))
            )
        ).all()
    }


async def commit(case: CleanupCase, batch_size: int = 100) -> int:
    return await cleanup.commit_expired_oauth_login_attempt_cleanup(
        case.engine, batch_size=batch_size, timeout_seconds=3
    )


async def wait_for_block(case: CleanupCase, locker: int, worker: int) -> None:
    async with asyncio.timeout(3):
        async with case.engine.connect() as observer:
            while not await observer.scalar(
                text("SELECT :locker = ANY(pg_blocking_pids(:worker))"),
                {"locker": locker, "worker": worker},
            ):
                await asyncio.sleep(0.01)


def test_only_expired_rows_are_removed_and_active_attempt_remains_consumable(
    case_factory: CaseFactory,
) -> None:
    async def check() -> None:
        async with case_factory() as case:
            now = datetime.now(UTC)
            expired, active = await seed(case, [now - timedelta(hours=1), now + timedelta(hours=1)])
            before = await state(case)
            assert await commit(case) == 1
            assert await state(case) == {active: before[active]}
            assert await commit(case) == 0
            async with case.engine.begin() as connection:
                assert (
                    await consume_oauth_login_attempt(connection, case.tokens[active])
                ).attempt_id == active
            assert await state(case) == {}
            async with case.engine.begin() as connection:
                with pytest.raises(InvalidOAuthLoginMaterial):
                    await consume_oauth_login_attempt(connection, case.tokens[expired])

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_default_batch_is_bounded_and_callers_choose_whether_to_continue(
    case_factory: CaseFactory,
) -> None:
    async def check() -> None:
        async with case_factory() as case:
            now = datetime.now(UTC)
            await seed(case, [now - timedelta(hours=1)] * 101 + [now + timedelta(hours=1)])
            assert (
                await cleanup.commit_expired_oauth_login_attempt_cleanup(
                    case.engine, timeout_seconds=3
                )
                == 100
            )
            assert len(await state(case)) == 2
            assert await commit(case) == 1
            assert len(await state(case)) == 1
            assert await commit(case) == 0

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_batch_order_is_expiry_then_id(case_factory: CaseFactory) -> None:
    async def check() -> None:
        async with case_factory() as case:
            now = datetime.now(UTC)
            ids = await seed(case, [now - timedelta(hours=1)] * 3)
            oldest = (await seed(case, [now - timedelta(hours=2)]))[0]
            assert await commit(case, 2) == 2
            assert set(await state(case)) == set(ids) - {min(ids)}
            assert oldest not in await state(case)

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_expiry_boundary_is_inclusive(
    case_factory: CaseFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    cutoff = datetime.now(UTC)
    monkeypatch.setattr(
        cleanup,
        "func",
        SimpleNamespace(statement_timestamp=lambda: literal(cutoff, type_=DateTime(timezone=True))),
    )

    async def check() -> None:
        async with case_factory() as case:
            ids = await seed(
                case,
                [cutoff - timedelta(microseconds=1), cutoff, cutoff + timedelta(microseconds=1)],
            )
            assert await commit(case) == 2
            assert set(await state(case)) == {ids[2]}

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_long_transaction_uses_fresh_statement_time(case_factory: CaseFactory) -> None:
    async def check() -> None:
        async with case_factory() as case:
            async with case.engine.begin() as connection:
                now = await connection.scalar(select(func.clock_timestamp()))
                assert isinstance(now, datetime)
                await seed(case, [now + timedelta(seconds=0.1)], connection)
                await connection.execute(select(func.pg_sleep(0.2)))
                assert await cleanup.delete_expired_oauth_login_attempts(connection) == 1
            assert await state(case) == {}

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_lock_wait_deadline_rolls_back_without_broadening_permissions(
    case_factory: CaseFactory,
) -> None:
    async def check() -> None:
        async with case_factory() as case:
            now = datetime.now(UTC)
            first, other, active = await seed(
                case, [now - timedelta(hours=2), now - timedelta(hours=1), now + timedelta(hours=1)]
            )
            before = await state(case)
            async with case.engine.connect() as holder:
                transaction = await holder.begin()
                try:
                    await holder.execute(
                        delete(OAuthLoginAttempt).where(OAuthLoginAttempt.id == first)
                    )
                    with pytest.raises(TimeoutError):
                        await cleanup.commit_expired_oauth_login_attempt_cleanup(
                            case.engine, batch_size=1, timeout_seconds=0.1
                        )
                    assert await state(case) == before
                finally:
                    await transaction.rollback()
            assert await commit(case, 1) == 1
            assert await state(case) == {other: before[other], active: before[active]}
            assert await commit(case, 1) == 1
            assert await state(case) == {active: before[active]}

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_overlapping_cleaners_do_not_double_count_or_exceed_batch(
    case_factory: CaseFactory,
) -> None:
    async def check() -> None:
        async with case_factory() as case:
            await seed(case, [datetime.now(UTC) - timedelta(hours=1)] * 4)
            async with case.engine.connect() as first:
                transaction = await first.begin()
                locker = await first.scalar(text("SELECT pg_backend_pid()"))
                assert isinstance(locker, int)
                assert await cleanup.delete_expired_oauth_login_attempts(first, batch_size=2) == 2
                async with case.engine.begin() as second:
                    worker = await second.scalar(text("SELECT pg_backend_pid()"))
                    assert isinstance(worker, int)
                    task = asyncio.create_task(
                        cleanup.delete_expired_oauth_login_attempts(second, batch_size=2)
                    )
                    try:
                        await wait_for_block(case, locker, worker)
                        assert len(await state(case)) == 4
                        await transaction.commit()
                        assert await asyncio.wait_for(task, 3) == 0
                    finally:
                        if not task.done():
                            task.cancel()
                        await asyncio.gather(task, return_exceptions=True)
                        if transaction.is_active:
                            await transaction.rollback()
            assert len(await state(case)) == 2
            assert await commit(case, 2) == 2
            assert await state(case) == {}

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_failed_commit_restores_rows(case_factory: CaseFactory) -> None:
    async def check() -> None:
        async with case_factory() as case:
            await seed(case, [datetime.now(UTC) - timedelta(hours=1)])
            before = await state(case)

            def fail(connection: Connection) -> None:
                connection.exec_driver_sql("SELECT 1 / 0")

            event.listen(case.engine.sync_engine, "commit", fail)
            try:
                with pytest.raises(SQLAlchemyError):
                    await commit(case)
            finally:
                event.remove(case.engine.sync_engine, "commit", fail)
            assert await state(case) == before
            assert await commit(case) == 1

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


@pytest.mark.parametrize("outcome", ["cancel", "timeout"])
def test_interruption_after_delete_rolls_back_before_connection_release(
    case_factory: CaseFactory, monkeypatch: pytest.MonkeyPatch, outcome: str
) -> None:
    async def check() -> None:
        async with case_factory() as case:
            await seed(case, [datetime.now(UTC) - timedelta(hours=1)])
            before = await state(case)
            entered = asyncio.Event()
            original = cleanup.delete_expired_oauth_login_attempts

            async def pending(connection: AsyncConnection, *, batch_size: int) -> int:
                deleted = await original(connection, batch_size=batch_size)
                entered.set()
                await asyncio.Event().wait()
                return deleted

            monkeypatch.setattr(cleanup, "delete_expired_oauth_login_attempts", pending)
            task = asyncio.create_task(
                cleanup.commit_expired_oauth_login_attempt_cleanup(
                    case.engine, timeout_seconds=0.1 if outcome == "timeout" else 30
                )
            )
            try:
                async with asyncio.timeout(3):
                    await entered.wait()
                    assert await state(case) == before
                    if outcome == "cancel":
                        task.cancel()
                    error = asyncio.CancelledError if outcome == "cancel" else TimeoutError
                    with pytest.raises(error):
                        await task
                assert await state(case) == before
            finally:
                if not task.done():
                    task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                monkeypatch.setattr(cleanup, "delete_expired_oauth_login_attempts", original)
            assert await commit(case) == 1

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_pending_replacement_and_its_new_binding_are_preserved(case_factory: CaseFactory) -> None:
    async def check() -> None:
        async with case_factory() as case:
            old = (await seed(case, [datetime.now(UTC) - timedelta(hours=1)]))[0]
            settings = Settings.model_construct(
                account_session_encryption_key=SecretStr(Fernet.generate_key().decode("ascii"))
            )
            async with case.engine.begin() as connection:
                new = await replace_oauth_login_attempt(connection, settings, case.tokens[old])
                case.ids.append(new.attempt_id)
                with pytest.raises(TimeoutError):
                    await cleanup.commit_expired_oauth_login_attempt_cleanup(
                        case.engine, timeout_seconds=0.1
                    )
            assert set(await state(case)) == {new.attempt_id}
            assert await commit(case) == 0
            async with case.engine.begin() as connection:
                consumed = await consume_oauth_login_attempt(
                    connection, new.browser_token.get_secret_value()
                )
                assert consumed.attempt_id == new.attempt_id

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_cleanup_uses_existing_immutable_runtime_grants(case_factory: CaseFactory) -> None:
    async def check() -> None:
        async with case_factory() as case:
            async with case.engine.connect() as connection:
                assert (
                    await connection.execute(
                        text(
                            "SELECT has_table_privilege(current_user, "
                            "'app.oauth_login_attempts', 'SELECT'), "
                            "has_table_privilege(current_user, "
                            "'app.oauth_login_attempts', 'DELETE'), "
                            "has_any_column_privilege(current_user, "
                            "'app.oauth_login_attempts', 'UPDATE')"
                        )
                    )
                ).one() == (True, True, False)
            assert await commit(case) == 0

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_cleanup_winner_makes_waiting_callback_reject_the_consumed_binding(
    case_factory: CaseFactory,
) -> None:
    async def check() -> None:
        async with case_factory() as case:
            attempt = (await seed(case, [datetime.now(UTC) - timedelta(hours=1)]))[0]
            pid: asyncio.Future[int] = asyncio.get_running_loop().create_future()

            async def callback() -> None:
                async with case.engine.begin() as connection:
                    worker = await connection.scalar(text("SELECT pg_backend_pid()"))
                    assert isinstance(worker, int)
                    pid.set_result(worker)
                    await consume_oauth_login_attempt(connection, case.tokens[attempt])

            async with case.engine.begin() as holder:
                locker = await holder.scalar(text("SELECT pg_backend_pid()"))
                assert isinstance(locker, int)
                assert await cleanup.delete_expired_oauth_login_attempts(holder) == 1
                task = asyncio.create_task(callback())
                try:
                    worker = await asyncio.wait_for(pid, 3)
                    await wait_for_block(case, locker, worker)
                    assert not task.done()
                except BaseException:
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                    raise
            try:
                with pytest.raises(InvalidOAuthLoginMaterial):
                    await asyncio.wait_for(task, 3)
            finally:
                if not task.done():
                    task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            assert await state(case) == {}

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


@pytest.mark.parametrize("locked_oauth", [False, True])
def test_scheduled_passes_commit_both_tables_with_independent_lock_deadlines(
    case_factory: CaseFactory,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    locked_oauth: bool,
) -> None:
    async def check() -> None:
        async with case_factory() as case:
            now = datetime.now(UTC)
            expiries = [
                now - timedelta(hours=2),
                now - timedelta(hours=1),
                now + timedelta(hours=1),
            ]
            oauth_ids = await seed(case, expiries)
            oauth_before = await state(case)
            keys = [token_bytes(32) for _ in expiries]
            waiting: asyncio.Queue[asyncio.Future[None]] = asyncio.Queue()

            async def wait(interval: int) -> None:
                assert interval == 60
                gate: asyncio.Future[None] = asyncio.get_running_loop().create_future()
                waiting.put_nowait(gate)
                await gate

            async def next_tick() -> asyncio.Future[None]:
                return await asyncio.wait_for(waiting.get(), 4)

            async def limiter_state() -> set[bytes]:
                async with case.engine.connect() as connection:
                    return set(
                        (
                            await connection.scalars(
                                select(AuthRateLimit.key_hash).where(
                                    AuthRateLimit.purpose == "google_start",
                                    AuthRateLimit.key_hash.in_(keys),
                                )
                            )
                        ).all()
                    )

            monkeypatch.setattr(scheduler, "sleep", wait)
            settings = Settings.model_construct(
                auth_rate_limit_cleanup_enabled=True,
                auth_rate_limit_cleanup_interval_seconds=60,
                auth_rate_limit_cleanup_batch_size=1,
                auth_rate_limit_cleanup_timeout_seconds=1,
            )
            try:
                async with AsyncExitStack() as locks:
                    # Global limiter cleanup skips these locks. Preserve every
                    # pre-existing limiter row, then insert only tracked keys.
                    guard = await locks.enter_async_context(case.engine.begin())
                    existing = (
                        await guard.execute(
                            select(AuthRateLimit.key_hash).limit(1001).with_for_update(nowait=True)
                        )
                    ).all()
                    assert len(existing) <= 1000, (
                        "Too many existing rows for isolated cleanup tests."
                    )
                    async with case.engine.begin() as connection:
                        await connection.execute(
                            insert(AuthRateLimit),
                            [
                                {
                                    "purpose": "google_start",
                                    "key_hash": key,
                                    "request_times": [expiry - timedelta(minutes=1)],
                                    "expires_at": expiry,
                                }
                                for key, expiry in zip(keys, expiries, strict=True)
                            ],
                        )
                    async with case.engine.connect() as holder:
                        transaction = await holder.begin()
                        try:
                            if locked_oauth:
                                await holder.execute(
                                    delete(OAuthLoginAttempt).where(
                                        OAuthLoginAttempt.id == oauth_ids[0]
                                    )
                                )
                            async with scheduler.auth_rate_limit_cleanup_lifespan(
                                case.engine, settings
                            ):
                                first = await next_tick()
                                assert await limiter_state() == set(keys)
                                assert await state(case) == oauth_before
                                first.set_result(None)
                                second = await next_tick()
                                assert await limiter_state() == set(keys[1:])
                                remaining = oauth_ids if locked_oauth else oauth_ids[1:]
                                assert await state(case) == {
                                    attempt_id: oauth_before[attempt_id] for attempt_id in remaining
                                }
                                await transaction.rollback()
                                second.set_result(None)
                                third = await next_tick()
                                assert await limiter_state() == {keys[2]}
                                remaining = oauth_ids[1:] if locked_oauth else oauth_ids[2:]
                                assert await state(case) == {
                                    attempt_id: oauth_before[attempt_id] for attempt_id in remaining
                                }
                                if locked_oauth:
                                    third.set_result(None)
                                    third = await next_tick()
                                    assert await state(case) == {
                                        oauth_ids[2]: oauth_before[oauth_ids[2]]
                                    }
                            assert third.cancelled()
                        finally:
                            if transaction.is_active:
                                await transaction.rollback()
            finally:
                async with case.engine.begin() as connection:
                    await connection.execute(
                        delete(AuthRateLimit).where(
                            AuthRateLimit.purpose == "google_start",
                            AuthRateLimit.key_hash.in_(keys),
                        )
                    )

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)
    assert [record.getMessage() for record in caplog.records] == (
        ["Pending Google login-attempt cleanup failed; waiting for the next interval."]
        if locked_oauth
        else []
    )
    assert all(record.exc_info is None for record in caplog.records)
