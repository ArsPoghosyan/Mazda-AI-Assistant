"""Regression test for expiry while a guest refresh waits on a row lock."""

import asyncio
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from datetime import datetime, timedelta
from uuid import uuid4

import pytest
from pydantic_settings import SettingsConfigDict
from sqlalchemy import delete, func, insert, select, text, update
from sqlalchemy.engine import Engine
from sqlalchemy.ext.asyncio import AsyncConnection, create_async_engine
from sqlalchemy.pool import NullPool

from app.config import Settings
from app.guest_sessions import ActiveGuestSession, refresh_guest_session
from app.guest_tokens import generate_guest_token, hash_guest_token
from app.models import GuestSession

pytestmark = pytest.mark.integration

type ConnectionFactory = Callable[[], AbstractAsyncContextManager[AsyncConnection]]


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


def test_session_expiring_during_lock_wait_is_not_revived(
    integration_engine: Engine,
    async_app_connection_factory: ConnectionFactory,
) -> None:
    session_id = uuid4()
    token = generate_guest_token()
    settings = IsolatedSettings(
        database_url=None,
        migration_database_url=None,
        guest_session_inactivity_days=30,
    )

    old_activity = func.statement_timestamp() - timedelta(days=31)

    with integration_engine.begin() as connection:
        connection.execute(
            insert(GuestSession).values(
                id=session_id,
                token_hash=hash_guest_token(token),
                created_at=old_activity,
                last_seen_at=old_activity,
                expires_at=func.statement_timestamp() + timedelta(days=30),
            )
        )

    async def check() -> None:
        locker_engine = create_async_engine(
            integration_engine.url,
            poolclass=NullPool,
            connect_args={"connect_timeout": 5, "hostaddr": "127.0.0.1"},
            echo=False,
            hide_parameters=True,
        )

        try:
            async with asyncio.timeout(10):
                async with async_app_connection_factory() as observer:
                    ready: asyncio.Future[int] = asyncio.get_running_loop().create_future()

                    async def attempt_refresh() -> ActiveGuestSession | None:
                        async with async_app_connection_factory() as worker:
                            worker_pid = await worker.scalar(text("SELECT pg_backend_pid()"))
                            assert isinstance(worker_pid, int)
                            ready.set_result(worker_pid)

                            return await refresh_guest_session(
                                worker,
                                token,
                                settings,
                            )

                    async with asyncio.TaskGroup() as group:
                        async with locker_engine.begin() as locker:
                            await locker.execute(text("SET LOCAL ROLE askm6_app"))
                            locker_pid = await locker.scalar(text("SELECT pg_backend_pid()"))
                            assert isinstance(locker_pid, int)

                            locked_id = await locker.scalar(
                                select(GuestSession.id)
                                .where(GuestSession.id == session_id)
                                .with_for_update()
                            )
                            assert locked_id == session_id

                            task = group.create_task(attempt_refresh())
                            worker_pid = await ready

                            while True:
                                blocked = await observer.scalar(
                                    text("SELECT :locker = ANY(pg_blocking_pids(:worker))"),
                                    {
                                        "locker": locker_pid,
                                        "worker": worker_pid,
                                    },
                                )
                                if blocked:
                                    break
                                await asyncio.sleep(0.01)

                            still_active = await observer.scalar(
                                select(GuestSession.expires_at > func.clock_timestamp()).where(
                                    GuestSession.id == session_id
                                )
                            )
                            assert still_active is True

                            expired_at = await locker.scalar(
                                update(GuestSession)
                                .where(GuestSession.id == session_id)
                                .values(expires_at=func.statement_timestamp())
                                .returning(GuestSession.expires_at)
                            )
                            assert isinstance(expired_at, datetime)

                        # Leaving locker_engine.begin() commits and releases
                        # the row lock. The waiting refresh can now continue.
                        assert await task is None

                    stored_expiry = await observer.scalar(
                        select(GuestSession.expires_at).where(GuestSession.id == session_id)
                    )
                    assert stored_expiry == expired_at
        finally:
            await locker_engine.dispose()

    try:
        asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)
    finally:
        with integration_engine.begin() as connection:
            connection.execute(delete(GuestSession).where(GuestSession.id == session_id))
