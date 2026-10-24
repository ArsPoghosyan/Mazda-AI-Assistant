"""Atomic rolling-window counting on the guarded local test database."""

import asyncio
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from secrets import token_bytes

import pytest
from sqlalchemy import delete, func, insert, select, text, update
from sqlalchemy.engine import Engine
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine
from sqlalchemy.pool import NullPool

from app import auth_rate_limits as limiter
from app.models import AuthRateLimit

pytestmark = pytest.mark.integration


@dataclass(frozen=True)
class LimitCase:
    engine: AsyncEngine
    observer: AsyncEngine
    application_name: str
    purpose: str
    key: bytes = field(repr=False)
    other_key: bytes = field(repr=False)


type CaseFactory = Callable[[], AbstractAsyncContextManager[LimitCase]]


@pytest.fixture(params=["password_recovery", "sign_in", "sign_up", "email_confirmation"])
def case_factory(integration_engine: Engine, request: pytest.FixtureRequest) -> CaseFactory:
    purpose = str(request.param)

    @asynccontextmanager
    async def connect() -> AsyncIterator[LimitCase]:
        key, other_key = token_bytes(32), token_bytes(32)
        name = f"auth-limit-test-{key.hex()[:12]}"
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
        try:
            async with engine.connect() as connection:
                identity = (
                    await connection.execute(text("SELECT current_database(), current_user"))
                ).one()
                assert tuple(identity) == ("askm6_test", "askm6_app")
                assert (
                    await connection.scalar(
                        text(
                            "SELECT NOT rolsuper AND NOT rolbypassrls "
                            "FROM pg_roles WHERE rolname = current_user"
                        )
                    )
                    is True
                )
            yield LimitCase(engine, observer, name, purpose, key, other_key)
        finally:
            # Real commits are needed to test visibility and concurrent callers.
            # Remove only this test's two synthetic keys, even after failures.
            try:
                async with engine.begin() as connection:
                    await connection.execute(
                        delete(AuthRateLimit).where(
                            AuthRateLimit.purpose.in_(
                                ["password_recovery", "sign_in", "sign_up", "email_confirmation"]
                            ),
                            AuthRateLimit.key_hash.in_([key, other_key]),
                        )
                    )
            finally:
                await engine.dispose()
                await observer.dispose()

    return connect


async def seed(case: LimitCase, times: list[datetime], *, purpose: str | None = None) -> None:
    async with case.engine.begin() as connection:
        await connection.execute(
            insert(AuthRateLimit).values(
                purpose=purpose if purpose is not None else case.purpose,
                key_hash=case.key,
                request_times=times,
                expires_at=max(times) + timedelta(seconds=600),
            )
        )


async def read_state(
    case: LimitCase, *, purpose: str | None = None
) -> tuple[list[datetime], datetime] | None:
    async with case.engine.connect() as connection:
        row = (
            await connection.execute(
                select(AuthRateLimit).where(
                    AuthRateLimit.purpose == (purpose if purpose is not None else case.purpose),
                    AuthRateLimit.key_hash == case.key,
                )
            )
        ).one_or_none()
        return None if row is None else (list(row.request_times), row.expires_at)


def fix_time(monkeypatch: pytest.MonkeyPatch, now: datetime) -> None:
    async def fixed(_connection: AsyncConnection) -> datetime:
        return now

    monkeypatch.setattr(limiter, "_database_now", fixed)


async def count(
    case: LimitCase,
    maximum: int = 3,
    window: int = 600,
    *,
    key: bytes | None = None,
    purpose: str | None = None,
) -> limiter.AuthRateLimitDecision:
    selected = purpose if purpose is not None else case.purpose
    commit = {
        "password_recovery": limiter.commit_password_recovery_attempt,
        "sign_in": limiter.commit_sign_in_attempt,
        "sign_up": limiter.commit_sign_up_attempt,
        "email_confirmation": limiter.commit_email_confirmation_attempt,
    }[selected]
    return await commit(
        case.engine,
        key if key is not None else case.key,
        max_requests=maximum,
        window_seconds=window,
    )


async def wait_for_lock(case: LimitCase) -> None:
    async with asyncio.timeout(4):
        async with case.observer.connect() as connection:
            while not await connection.scalar(
                text(
                    "SELECT EXISTS (SELECT 1 FROM pg_stat_activity "
                    "WHERE application_name = :name AND wait_event_type = 'Lock')"
                ),
                {"name": case.application_name},
            ):
                await asyncio.sleep(0.01)


def test_committed_attempts_are_visible_and_denial_does_not_change_state(
    case_factory: CaseFactory,
) -> None:
    async def check() -> None:
        async with case_factory() as case:
            for _ in range(3):
                result = await count(case)
                assert result.allowed and result.retry_at is None
                assert result.retry_after_seconds == 0
                assert result.checked_at.utcoffset() == timedelta(0)
            before = await read_state(case)
            assert before is not None and len(before[0]) == 3
            denied = await count(case)
            assert not denied.allowed and 1 <= denied.retry_after_seconds <= 600
            assert denied.retry_at == before[0][0] + timedelta(seconds=600)
            assert await read_state(case) == before

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


@pytest.mark.parametrize("microseconds", [-1, 0, 1])
def test_exact_expiry_boundary(
    case_factory: CaseFactory, monkeypatch: pytest.MonkeyPatch, microseconds: int
) -> None:
    now = datetime(2026, 10, 24, 12, tzinfo=UTC)
    fix_time(monkeypatch, now)

    async def check() -> None:
        async with case_factory() as case:
            old = now - timedelta(seconds=600) + timedelta(microseconds=microseconds)
            await seed(case, [old])
            result = await count(case, maximum=1)
            assert result.allowed is (microseconds <= 0)
            state = await read_state(case)
            assert state is not None
            assert state[0] == ([now] if result.allowed else [old])
            if not result.allowed:
                assert result.retry_after_seconds == 1

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_expiry_is_individual_and_retry_time_is_rounded_up(
    case_factory: CaseFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = datetime(2026, 10, 24, 12, tzinfo=UTC)
    fix_time(monkeypatch, now)

    async def check() -> None:
        async with case_factory() as case:
            times = [now - timedelta(seconds=n) for n in (599.2, 300, 1)]
            await seed(case, times)
            before = await read_state(case)
            denied = await count(case)
            assert not denied.allowed and denied.retry_after_seconds == 1
            assert await read_state(case) == before
            fix_time(monkeypatch, now + timedelta(seconds=1))
            assert (await count(case)).allowed
            state = await read_state(case)
            assert state is not None
            assert state[0] == [*times[1:], now + timedelta(seconds=1)]
            assert state[1] == now + timedelta(seconds=601)

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_expired_entries_are_pruned_when_counting(
    case_factory: CaseFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = datetime(2026, 10, 24, 12, tzinfo=UTC)
    fix_time(monkeypatch, now)

    async def check() -> None:
        async with case_factory() as case:
            await seed(case, [now - timedelta(seconds=601), now - timedelta(seconds=30)])
            assert (await count(case)).allowed
            state = await read_state(case)
            assert state == ([now - timedelta(seconds=30), now], now + timedelta(seconds=600))

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_lowered_cap_waits_for_enough_entries_to_expire(
    case_factory: CaseFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = datetime(2026, 10, 24, 12, tzinfo=UTC)
    fix_time(monkeypatch, now)

    async def check() -> None:
        async with case_factory() as case:
            await seed(case, [now - timedelta(seconds=n) for n in (500, 400, 300, 200, 100)])
            before = await read_state(case)
            result = await count(case, maximum=2)
            assert not result.allowed
            assert result.retry_after_seconds == 400
            assert result.retry_at == now + timedelta(seconds=400)
            fix_time(monkeypatch, now + timedelta(seconds=1))
            assert (await count(case, maximum=2)).retry_after_seconds == 399
            assert await read_state(case) == before

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_distinct_fingerprints_have_independent_limits(case_factory: CaseFactory) -> None:
    async def check() -> None:
        async with case_factory() as case:
            assert (await count(case, maximum=1)).allowed
            before = await read_state(case)
            other = await count(case, maximum=1, key=case.other_key)
            assert other.allowed
            assert not (await count(case, maximum=1)).allowed
            assert await read_state(case) == before

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


@pytest.mark.parametrize("existing", [False, True])
def test_concurrent_callers_cannot_exceed_the_cap(
    case_factory: CaseFactory, existing: bool
) -> None:
    async def check() -> None:
        async with case_factory() as case:
            if existing:
                assert (await count(case)).allowed
            async with asyncio.timeout(10):
                decisions = await asyncio.gather(*(count(case) for _ in range(12)))
            assert sum(result.allowed for result in decisions) == (2 if existing else 3)
            assert all(
                result.retry_after_seconds >= 1 for result in decisions if not result.allowed
            )
            state = await read_state(case)
            assert state is not None and len(state[0]) == 3

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


@pytest.mark.parametrize("existing", [False, True])
def test_rollback_restores_previous_window(case_factory: CaseFactory, existing: bool) -> None:
    async def check() -> None:
        async with case_factory() as case:
            if existing:
                assert (await count(case)).allowed
            before = await read_state(case)
            async with case.engine.connect() as connection:
                transaction = await connection.begin()
                counter = {
                    "password_recovery": limiter.count_password_recovery_attempt,
                    "sign_in": limiter.count_sign_in_attempt,
                    "sign_up": limiter.count_sign_up_attempt,
                    "email_confirmation": limiter.count_email_confirmation_attempt,
                }[case.purpose]
                decision = await counter(connection, case.key, max_requests=3, window_seconds=600)
                assert decision.allowed
                await transaction.rollback()
            assert await read_state(case) == before

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_time_is_read_after_a_real_row_lock_wait(case_factory: CaseFactory) -> None:
    async def check() -> None:
        async with case_factory() as case:
            await seed(case, [datetime.now(UTC)])
            async with case.engine.connect() as locker:
                transaction = await locker.begin()
                await locker.execute(
                    select(AuthRateLimit)
                    .where(
                        AuthRateLimit.purpose == case.purpose, AuthRateLimit.key_hash == case.key
                    )
                    .with_for_update()
                )
                task = asyncio.create_task(count(case, maximum=1, window=60))
                try:
                    await wait_for_lock(case)
                    now = await locker.scalar(select(func.clock_timestamp()))
                    assert isinstance(now, datetime)
                    expiry = now + timedelta(seconds=0.15)
                    await locker.execute(
                        update(AuthRateLimit)
                        .where(
                            AuthRateLimit.purpose == case.purpose,
                            AuthRateLimit.key_hash == case.key,
                        )
                        .values(request_times=[expiry - timedelta(seconds=60)], expires_at=expiry)
                    )
                    await locker.execute(select(func.pg_sleep(0.25)))
                    await transaction.commit()
                    result = await asyncio.wait_for(task, 5)
                    assert result.allowed
                    assert result.checked_at >= expiry
                    state = await read_state(case)
                    assert state is not None and state[0] == [result.checked_at]
                finally:
                    if transaction.is_active:
                        await transaction.rollback()
                    if not task.done():
                        task.cancel()
                    await asyncio.gather(task, return_exceptions=True)

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_cancelling_a_blocked_transaction_preserves_state(case_factory: CaseFactory) -> None:
    async def check() -> None:
        async with case_factory() as case:
            assert (await count(case)).allowed
            before = await read_state(case)
            async with case.engine.connect() as locker:
                transaction = await locker.begin()
                await locker.execute(
                    select(AuthRateLimit)
                    .where(
                        AuthRateLimit.purpose == case.purpose, AuthRateLimit.key_hash == case.key
                    )
                    .with_for_update()
                )
                task = asyncio.create_task(count(case))
                try:
                    await wait_for_lock(case)
                    task.cancel()
                    with pytest.raises(asyncio.CancelledError):
                        await task
                finally:
                    if transaction.is_active:
                        await transaction.rollback()
                    if not task.done():
                        task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
            assert await read_state(case) == before
            assert (await count(case)).allowed

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_same_fingerprint_has_independent_operation_caps_and_windows(
    case_factory: CaseFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = datetime(2026, 10, 24, 12, tzinfo=UTC)
    fix_time(monkeypatch, now)

    async def check() -> None:
        async with case_factory() as case:
            other = "sign_in" if case.purpose == "password_recovery" else "password_recovery"
            assert (await count(case, maximum=1, window=60)).allowed
            own_before = await read_state(case)
            for _ in range(2):
                assert (await count(case, maximum=2, window=600, purpose=other)).allowed
            other_before = await read_state(case, purpose=other)
            assert own_before == ([now], now + timedelta(seconds=60))
            assert other_before == ([now, now], now + timedelta(seconds=600))
            own_denied = await count(case, maximum=1, window=60)
            other_denied = await count(case, maximum=2, window=600, purpose=other)
            assert not own_denied.allowed and own_denied.retry_after_seconds == 60
            assert not other_denied.allowed and other_denied.retry_after_seconds == 600
            assert own_denied.retry_at == now + timedelta(seconds=60)
            assert other_denied.retry_at == now + timedelta(seconds=600)
            assert await read_state(case) == own_before
            assert await read_state(case, purpose=other) == other_before

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_other_operation_does_not_wait_for_same_fingerprint_row_lock(
    case_factory: CaseFactory,
) -> None:
    async def check() -> None:
        async with case_factory() as case:
            other = "sign_in" if case.purpose == "password_recovery" else "password_recovery"
            now = datetime.now(UTC)
            await seed(case, [now])
            await seed(case, [now], purpose=other)
            own_before = await read_state(case)
            async with case.engine.connect() as locker:
                transaction = await locker.begin()
                try:
                    await locker.execute(
                        select(AuthRateLimit)
                        .where(
                            AuthRateLimit.purpose == case.purpose,
                            AuthRateLimit.key_hash == case.key,
                        )
                        .with_for_update()
                    )
                    # This must finish while the other purpose's lock is held.
                    result = await asyncio.wait_for(count(case, purpose=other), timeout=4)
                    assert result.allowed
                    assert await read_state(case) == own_before
                    other_state = await read_state(case, purpose=other)
                    assert other_state is not None and len(other_state[0]) == 2
                finally:
                    await transaction.rollback()

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_concurrent_operations_enforce_separate_caps_for_same_fingerprint(
    case_factory: CaseFactory,
) -> None:
    async def check() -> None:
        async with case_factory() as case:
            other = "sign_in" if case.purpose == "password_recovery" else "password_recovery"
            async with asyncio.timeout(10):
                decisions = await asyncio.gather(
                    *(count(case, maximum=3) for _ in range(12)),
                    *(count(case, maximum=2, purpose=other) for _ in range(12)),
                )
            assert sum(result.allowed for result in decisions[:12]) == 3
            assert sum(result.allowed for result in decisions[12:]) == 2
            assert all(
                result.retry_after_seconds >= 1 for result in decisions if not result.allowed
            )
            own_state = await read_state(case)
            other_state = await read_state(case, purpose=other)
            assert own_state is not None and len(own_state[0]) == 3
            assert other_state is not None and len(other_state[0]) == 2

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)
