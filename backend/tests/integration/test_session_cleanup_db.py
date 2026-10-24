"""Bounded session deletion and activity races on guarded local PostgreSQL."""

import asyncio
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, AsyncExitStack, asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from secrets import token_urlsafe
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from pydantic import SecretStr
from sqlalchemy import DateTime, delete, event, func, insert, literal, select, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine
from sqlalchemy.pool import NullPool

from app import auth_rate_limit_scheduler as scheduler
from app import session_cleanup as cleanup
from app.account_session_auth import load_locked_account_session
from app.account_sessions import touch_account_session
from app.config import Settings
from app.guest_sessions import refresh_guest_session
from app.models import AccountSession, AuthRateLimit, GuestSession, OAuthLoginAttempt, UserProfile

pytestmark = pytest.mark.integration


@dataclass
class CleanupCase:
    engine: AsyncEngine
    guest: bool
    ids: dict[bool, list[UUID]] = field(default_factory=lambda: {True: [], False: []})
    tokens: dict[UUID, str] = field(default_factory=dict, repr=False)
    profiles: list[UUID] = field(default_factory=list)

    @property
    def model(self) -> type[GuestSession] | type[AccountSession]:
        return GuestSession if self.guest else AccountSession

    async def delete(self, connection: AsyncConnection, batch_size: int = 100) -> int:
        helper = (
            cleanup.delete_expired_guest_sessions
            if self.guest
            else cleanup.delete_expired_account_sessions
        )
        return await helper(connection, batch_size=batch_size)

    async def commit(self, batch_size: int = 100, timeout_seconds: float = 3) -> int:
        helper = (
            cleanup.commit_expired_guest_session_cleanup
            if self.guest
            else cleanup.commit_expired_account_session_cleanup
        )
        return await helper(self.engine, batch_size=batch_size, timeout_seconds=timeout_seconds)


type CaseFactory = Callable[[], AbstractAsyncContextManager[CleanupCase]]
type State = dict[UUID, tuple[object, ...]]


@pytest.fixture(params=[True, False], ids=["guest", "account"])
def case_factory(integration_engine: Engine, request: pytest.FixtureRequest) -> CaseFactory:
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
            ) == ("askm6_test", "askm6_app")
            assert (
                connection.scalar(
                    text(
                        "SELECT NOT rolsuper AND NOT rolbypassrls "
                        "FROM pg_roles WHERE rolname=current_user"
                    )
                )
                is True
            )

        case = CleanupCase(engine, bool(request.param))
        try:
            async with engine.begin() as guard:
                # Preserve pre-existing sessions in either table. These global
                # cleanup tests skip their locks; never clear tables for setup.
                for model in (GuestSession, AccountSession):
                    existing = (
                        await guard.execute(
                            select(model.id).limit(1001).with_for_update(nowait=True)
                        )
                    ).all()
                    assert len(existing) <= 1000, "Too many existing sessions for isolated tests."
                yield case
        finally:
            try:
                async with engine.begin() as connection:
                    for guest, ids in case.ids.items():
                        model = GuestSession if guest else AccountSession
                        if ids:
                            await connection.execute(delete(model).where(model.id.in_(ids)))
                    if case.profiles:
                        await connection.execute(
                            delete(UserProfile).where(UserProfile.id.in_(case.profiles))
                        )
            finally:
                await engine.dispose()

    return connect


async def seed(
    case: CleanupCase,
    expiries: list[datetime],
    *,
    guest: bool | None = None,
    absolute_expired: bool = False,
    connection: AsyncConnection | None = None,
) -> list[UUID]:
    if connection is None:
        async with case.engine.begin() as writer:
            return await seed(
                case, expiries, guest=guest, absolute_expired=absolute_expired, connection=writer
            )
    mode = case.guest if guest is None else guest
    ids = [uuid4() for _ in expiries]
    case.ids[mode].extend(ids)
    for session_id, expiry in zip(ids, expiries, strict=True):
        token = token_urlsafe(32)
        case.tokens[session_id] = token
        values: dict[str, object] = {
            "id": session_id,
            "token_hash": sha256(token.encode("ascii")).digest(),
            "created_at": expiry - timedelta(days=40),
            "last_seen_at": expiry - timedelta(days=1),
        }
        if mode:
            values["expires_at"] = expiry
            await connection.execute(insert(GuestSession).values(**values))
        else:
            owner = uuid4()
            case.profiles.append(owner)
            await connection.execute(insert(UserProfile).values(id=owner))
            values.update(
                {
                    "user_id": owner,
                    "provider_session_id": uuid4(),
                    # Cleanup must work without a key or decrypting credentials.
                    "access_token_ciphertext": b"synthetic-opaque-access",
                    "refresh_token_ciphertext": b"synthetic-opaque-refresh",
                    "access_token_expires_at": datetime.now(UTC) - timedelta(hours=1),
                    "idle_expires_at": expiry,
                    "absolute_expires_at": expiry
                    if absolute_expired
                    else expiry + timedelta(days=60),
                }
            )
            await connection.execute(insert(AccountSession).values(**values))
    return ids


async def state(case: CleanupCase, *, guest: bool | None = None) -> State:
    mode = case.guest if guest is None else guest
    model = GuestSession if mode else AccountSession
    async with case.engine.connect() as reader:
        rows = (await reader.execute(select(model).where(model.id.in_(case.ids[mode])))).all()
        return {row.id: tuple(row) for row in rows}


async def activity(case: CleanupCase, connection: AsyncConnection, session_id: UUID) -> object:
    settings = Settings.model_construct(
        guest_session_inactivity_days=30, account_session_inactivity_days=7
    )
    if case.guest:
        return await refresh_guest_session(connection, case.tokens[session_id], settings)
    return await touch_account_session(connection, SecretStr(case.tokens[session_id]), settings)


def test_only_expired_local_sessions_are_deleted_and_profiles_other_mode_survive(
    case_factory: CaseFactory,
) -> None:
    async def check() -> None:
        async with case_factory() as case:
            now = datetime.now(UTC)
            expired, active = await seed(case, [now - timedelta(hours=1), now + timedelta(days=1)])
            before = await state(case)
            await seed(
                case, [now - timedelta(hours=1), now + timedelta(days=1)], guest=not case.guest
            )
            other_before = await state(case, guest=not case.guest)
            assert await case.commit() == 1
            assert await state(case) == {active: before[active]}
            assert await state(case, guest=not case.guest) == other_before
            assert await case.commit() == 0
            async with case.engine.begin() as connection:
                assert set(
                    (
                        await connection.scalars(
                            select(UserProfile.id).where(UserProfile.id.in_(case.profiles))
                        )
                    ).all()
                ) == set(case.profiles)
                assert await activity(case, connection, active) is not None
                assert await activity(case, connection, expired) is None

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_default_batch_cap_and_stable_expiry_id_order(case_factory: CaseFactory) -> None:
    async def check() -> None:
        async with case_factory() as case:
            now = datetime.now(UTC)
            tied = await seed(case, [now - timedelta(hours=1)] * 101)
            oldest = (await seed(case, [now - timedelta(hours=2)]))[0]
            active = (await seed(case, [now + timedelta(days=1)]))[0]
            assert await case.commit() == 100
            assert set(await state(case)) == set(sorted(tied)[99:]) | {active}
            assert oldest not in await state(case)
            assert await case.commit() == 2
            assert set(await state(case)) == {active}
            assert await case.commit() == 0

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


@pytest.mark.parametrize("absolute_expired", [False, True])
def test_inclusive_expiry_boundary(
    case_factory: CaseFactory, monkeypatch: pytest.MonkeyPatch, absolute_expired: bool
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
                absolute_expired=absolute_expired,
            )
            assert await case.commit() == 2
            assert set(await state(case)) == {ids[2]}

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_statement_time_is_fresh_in_a_long_transaction(case_factory: CaseFactory) -> None:
    async def check() -> None:
        async with case_factory() as case:
            async with case.engine.begin() as connection:
                now = await connection.scalar(select(func.clock_timestamp()))
                assert isinstance(now, datetime)
                await seed(case, [now + timedelta(seconds=0.1)], connection=connection)
                await connection.execute(select(func.pg_sleep(0.2)))
                assert await case.delete(connection) == 1
            assert await state(case) == {}

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_locked_expired_row_is_skipped_until_a_later_pass(case_factory: CaseFactory) -> None:
    async def check() -> None:
        async with case_factory() as case:
            now = datetime.now(UTC)
            first, second, active = await seed(
                case, [now - timedelta(hours=2), now - timedelta(hours=1), now + timedelta(days=1)]
            )
            before = await state(case)
            async with case.engine.begin() as holder:
                await holder.execute(
                    select(case.model.id).where(case.model.id == first).with_for_update()
                )
                assert await case.commit(1) == 1
                assert await state(case) == {first: before[first], active: before[active]}
                assert second not in await state(case)
            assert await case.commit(1) == 1
            assert await state(case) == {active: before[active]}

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_overlapping_cleaners_take_disjoint_bounded_batches(case_factory: CaseFactory) -> None:
    async def check() -> None:
        async with case_factory() as case:
            await seed(case, [datetime.now(UTC) - timedelta(hours=1)] * 4)
            async with case.engine.begin() as holder:
                assert await case.delete(holder, 2) == 2
                assert await case.commit(2) == 2
                assert len(await state(case)) == 2  # First batch is still uncommitted.
            assert await state(case) == {}

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_activity_winner_is_skipped_and_its_committed_extension_survives(
    case_factory: CaseFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A fixed cleanup cutoff lies after the old expiry but before the extension.
    cutoff = datetime.now(UTC) + timedelta(hours=2)
    monkeypatch.setattr(
        cleanup,
        "func",
        SimpleNamespace(statement_timestamp=lambda: literal(cutoff, type_=DateTime(timezone=True))),
    )

    async def check() -> None:
        async with case_factory() as case:
            session = (await seed(case, [cutoff - timedelta(hours=1)]))[0]
            async with case.engine.begin() as holder:
                assert await activity(case, holder, session) is not None
                assert await case.commit() == 0
            assert await case.commit() == 0
            assert set(await state(case)) == {session}

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_cleanup_winner_prevents_waiting_session_lookup_from_reviving_identity(
    case_factory: CaseFactory,
) -> None:
    async def check() -> None:
        async with case_factory() as case:
            session = (await seed(case, [datetime.now(UTC) - timedelta(hours=1)]))[0]
            pid: asyncio.Future[int] = asyncio.get_running_loop().create_future()

            async def lookup() -> object:
                async with case.engine.begin() as connection:
                    worker = await connection.scalar(text("SELECT pg_backend_pid()"))
                    assert isinstance(worker, int)
                    pid.set_result(worker)
                    if case.guest:
                        return await activity(case, connection, session)
                    return await load_locked_account_session(
                        connection, SecretStr(case.tokens[session])
                    )

            async with case.engine.begin() as holder:
                locker = await holder.scalar(text("SELECT pg_backend_pid()"))
                assert isinstance(locker, int)
                assert await case.delete(holder) == 1
                task = asyncio.create_task(lookup())
                try:
                    worker = await asyncio.wait_for(pid, 3)
                    async with asyncio.timeout(3):
                        async with case.engine.connect() as observer:
                            while not await observer.scalar(
                                text("SELECT :locker = ANY(pg_blocking_pids(:worker))"),
                                {"locker": locker, "worker": worker},
                            ):
                                await asyncio.sleep(0.01)
                    assert not task.done()
                except BaseException:
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                    raise
            try:
                assert await asyncio.wait_for(task, 3) is None
            finally:
                if not task.done():
                    task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            assert await state(case) == {}

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_failed_commit_restores_sessions(case_factory: CaseFactory) -> None:
    async def check() -> None:
        async with case_factory() as case:
            await seed(case, [datetime.now(UTC) - timedelta(hours=1)])
            before = await state(case)

            def fail(connection: Connection) -> None:
                connection.exec_driver_sql("SELECT 1 / 0")

            event.listen(case.engine.sync_engine, "commit", fail)
            try:
                with pytest.raises(SQLAlchemyError):
                    await case.commit()
            finally:
                event.remove(case.engine.sync_engine, "commit", fail)
            assert await state(case) == before
            assert await case.commit() == 1

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


@pytest.mark.parametrize("outcome", ["cancel", "timeout"])
def test_interrupted_delete_rolls_back_before_release(
    case_factory: CaseFactory, monkeypatch: pytest.MonkeyPatch, outcome: str
) -> None:
    async def check() -> None:
        async with case_factory() as case:
            await seed(case, [datetime.now(UTC) - timedelta(hours=1)])
            before = await state(case)
            entered = asyncio.Event()
            deadline: asyncio.Timeout | None = None

            def tracked_timeout(seconds: float) -> asyncio.Timeout:
                nonlocal deadline
                deadline = asyncio.timeout(seconds)
                return deadline

            if outcome == "timeout":
                # Keep acquisition bounded, then expire the real helper deadline
                # only once deletion has happened. Connection latency must not
                # turn this rollback test into an acquisition-timeout test.
                monkeypatch.setattr(cleanup, "asyncio", SimpleNamespace(timeout=tracked_timeout))
            name = (
                "delete_expired_guest_sessions" if case.guest else "delete_expired_account_sessions"
            )
            original = (
                cleanup.delete_expired_guest_sessions
                if case.guest
                else cleanup.delete_expired_account_sessions
            )

            async def pending(connection: AsyncConnection, *, batch_size: int) -> int:
                count = await original(connection, batch_size=batch_size)
                entered.set()
                if outcome == "timeout":
                    assert deadline is not None
                    deadline.reschedule(asyncio.get_running_loop().time())
                await asyncio.Event().wait()
                return count

            monkeypatch.setattr(cleanup, name, pending)
            task = asyncio.create_task(
                case.commit(timeout_seconds=5 if outcome == "timeout" else 30)
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
                monkeypatch.setattr(cleanup, name, original)
            assert await case.commit() == 1

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_existing_grants_allow_cleanup_and_no_owned_history_can_cascade(
    case_factory: CaseFactory,
) -> None:
    async def check() -> None:
        async with case_factory() as case:
            async with case.engine.connect() as connection:
                assert (
                    await connection.execute(
                        text(
                            "SELECT has_table_privilege(current_user, :table, 'SELECT'), "
                            "has_table_privilege(current_user, :table, 'DELETE'), "
                            "has_any_column_privilege(current_user, :table, 'UPDATE')"
                        ),
                        {"table": f"app.{case.model.__tablename__}"},
                    )
                ).one() == (True, True, True)
                assert (
                    await connection.scalar(
                        text(
                            "SELECT count(*) FROM pg_constraint WHERE contype='f' AND "
                            "confrelid IN ('app.guest_sessions'::regclass, "
                            "'app.account_sessions'::regclass)"
                        )
                    )
                    == 0
                ), "Review cleanup and retention when session-owned tables are introduced."
            assert await case.commit() == 0

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


@pytest.mark.parametrize("outcome", ["success", "commit-failure", "timeout", "locked"])
def test_scheduled_four_table_pass_is_bounded_and_isolates_session_failures(
    case_factory: CaseFactory,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    outcome: str,
) -> None:
    expected_messages: list[str] = []

    async def check() -> None:
        async with case_factory() as case:
            if outcome in ("commit-failure", "timeout"):
                mode_name = "Guest" if case.guest else "Account"
                expected_messages.append(
                    f"{mode_name}-session cleanup failed; waiting for the next interval."
                )
            oauth_ids: list[UUID] = []
            keys: list[bytes] = []
            session_ids: dict[bool, list[UUID]] = {}
            before: dict[bool, State] = {}
            waiting: asyncio.Queue[asyncio.Future[None]] = asyncio.Queue()

            async def wait(interval: int) -> None:
                assert interval == 60
                gate: asyncio.Future[None] = asyncio.get_running_loop().create_future()
                waiting.put_nowait(gate)
                await gate

            async def next_tick() -> asyncio.Future[None]:
                return await asyncio.wait_for(waiting.get(), 5)

            async def remaining_auxiliary() -> tuple[set[bytes], set[UUID]]:
                async with case.engine.connect() as connection:
                    limiter = set(
                        (
                            await connection.scalars(
                                select(AuthRateLimit.key_hash).where(
                                    AuthRateLimit.purpose == "google_start",
                                    AuthRateLimit.key_hash.in_(keys),
                                )
                            )
                        ).all()
                    )
                    oauth = set(
                        (
                            await connection.scalars(
                                select(OAuthLoginAttempt.id).where(
                                    OAuthLoginAttempt.id.in_(oauth_ids)
                                )
                            )
                        ).all()
                    )
                    return limiter, oauth

            def fail_marked_commit(connection: Connection) -> None:
                if connection.info.pop("fail_session_cleanup_commit", False):
                    connection.exec_driver_sql("SELECT 1 / 0")

            event.listen(case.engine.sync_engine, "commit", fail_marked_commit)
            try:
                async with AsyncExitStack() as locks:
                    # Session fixture protects both session tables. Limiter rows
                    # can also be protected with skip-locked guards. OAuth has
                    # no UPDATE grant, so require an otherwise unused test table.
                    guard = await locks.enter_async_context(case.engine.begin())
                    existing = (
                        await guard.execute(
                            select(AuthRateLimit.key_hash).limit(1001).with_for_update(nowait=True)
                        )
                    ).all()
                    assert len(existing) <= 1000, "Too many limiter rows for isolated tests."
                    if await guard.scalar(select(OAuthLoginAttempt.id).limit(1)) is not None:
                        pytest.skip("Existing OAuth attempts prevent isolated scheduling tests.")
                    now = datetime.now(UTC)
                    expiries = [
                        now - timedelta(hours=2),
                        now - timedelta(hours=1),
                        now + timedelta(days=1),
                    ]
                    for mode in (True, False):
                        session_ids[mode] = await seed(case, expiries, guest=mode)
                        before[mode] = await state(case, guest=mode)
                    keys = [sha256(token_urlsafe(32).encode("ascii")).digest() for _ in expiries]
                    oauth_ids = [uuid4() for _ in expiries]
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
                        await connection.execute(
                            insert(OAuthLoginAttempt),
                            [
                                {
                                    "id": attempt_id,
                                    "browser_token_hash": sha256(
                                        token_urlsafe(32).encode("ascii")
                                    ).digest(),
                                    "pkce_verifier_ciphertext": b"synthetic-opaque-pkce",
                                    "created_at": expiry - timedelta(days=2),
                                    "expires_at": expiry,
                                }
                                for attempt_id, expiry in zip(oauth_ids, expiries, strict=True)
                            ],
                        )

                    session_locks = await locks.enter_async_context(AsyncExitStack())
                    if outcome == "locked":
                        holder = await session_locks.enter_async_context(case.engine.begin())
                        await holder.execute(
                            select(case.model.id)
                            .where(case.model.id == session_ids[case.guest][0])
                            .with_for_update()
                        )

                    if outcome in ("commit-failure", "timeout"):
                        name = (
                            "delete_expired_guest_sessions"
                            if case.guest
                            else "delete_expired_account_sessions"
                        )
                        original = (
                            cleanup.delete_expired_guest_sessions
                            if case.guest
                            else cleanup.delete_expired_account_sessions
                        )
                        first_call = True

                        async def fail_once(connection: AsyncConnection, *, batch_size: int) -> int:
                            nonlocal first_call
                            count = await original(connection, batch_size=batch_size)
                            if first_call:
                                first_call = False
                                assert count == 1
                                if outcome == "timeout":
                                    await asyncio.Event().wait()
                                else:
                                    assert connection.sync_connection is not None
                                    connection.sync_connection.info[
                                        "fail_session_cleanup_commit"
                                    ] = True
                            return count

                        monkeypatch.setattr(cleanup, name, fail_once)

                    monkeypatch.setattr(scheduler, "sleep", wait)
                    settings = Settings.model_construct(
                        auth_rate_limit_cleanup_enabled=True,
                        auth_rate_limit_cleanup_interval_seconds=60,
                        auth_rate_limit_cleanup_batch_size=1,
                        auth_rate_limit_cleanup_timeout_seconds=1,
                    )
                    async with scheduler.auth_rate_limit_cleanup_lifespan(case.engine, settings):
                        first = await next_tick()
                        for mode in (True, False):
                            assert await state(case, guest=mode) == before[mode]
                        assert await remaining_auxiliary() == (set(keys), set(oauth_ids))
                        first.set_result(None)
                        second = await next_tick()
                        assert await remaining_auxiliary() == (set(keys[1:]), set(oauth_ids[1:]))
                        for mode in (True, False):
                            expected = dict(before[mode])
                            if mode != case.guest or outcome not in ("commit-failure", "timeout"):
                                removed = session_ids[mode][
                                    1 if mode == case.guest and outcome == "locked" else 0
                                ]
                                expected.pop(removed)
                            assert await state(case, guest=mode) == expected
                        await session_locks.aclose()
                        second.set_result(None)
                        third = await next_tick()
                        assert await remaining_auxiliary() == ({keys[2]}, {oauth_ids[2]})
                        for mode in (True, False):
                            remaining = (
                                session_ids[mode][1:]
                                if mode == case.guest and outcome in ("commit-failure", "timeout")
                                else session_ids[mode][2:]
                            )
                            assert await state(case, guest=mode) == {
                                sid: before[mode][sid] for sid in remaining
                            }
                        if outcome in ("commit-failure", "timeout"):
                            third.set_result(None)
                            third = await next_tick()
                        for mode in (True, False):
                            active = session_ids[mode][2]
                            assert await state(case, guest=mode) == {active: before[mode][active]}
                        async with case.engine.connect() as connection:
                            assert set(
                                (
                                    await connection.scalars(
                                        select(UserProfile.id).where(
                                            UserProfile.id.in_(case.profiles)
                                        )
                                    )
                                ).all()
                            ) == set(case.profiles)
                    assert third.cancelled()
            finally:
                event.remove(case.engine.sync_engine, "commit", fail_marked_commit)
                async with case.engine.begin() as connection:
                    await connection.execute(
                        delete(AuthRateLimit).where(
                            AuthRateLimit.purpose == "google_start",
                            AuthRateLimit.key_hash.in_(keys),
                        )
                    )
                    await connection.execute(
                        delete(OAuthLoginAttempt).where(OAuthLoginAttempt.id.in_(oauth_ids))
                    )

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)
    assert [record.getMessage() for record in caplog.records] == expected_messages
    assert all(record.exc_info is None for record in caplog.records)
