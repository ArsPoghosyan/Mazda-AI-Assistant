"""Locked loading must observe expiry and credential changes after waiting."""

import asyncio
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from datetime import timedelta
from hashlib import sha256
from secrets import token_urlsafe
from uuid import uuid4

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr
from sqlalchemy import delete, func, insert, select, text, update
from sqlalchemy.engine import Engine
from sqlalchemy.ext.asyncio import AsyncConnection, create_async_engine
from sqlalchemy.pool import NullPool

from app.account_session_auth import (
    LockedAccountSession,
    load_locked_account_session,
)
from app.account_token_encryption import AccountTokenCipher
from app.models import AccountSession, UserProfile

pytestmark = pytest.mark.integration

type ConnectionFactory = Callable[[], AbstractAsyncContextManager[AsyncConnection]]


@pytest.mark.parametrize(
    "change",
    ["idle_expiry", "absolute_expiry", "credentials"],
)
def test_loading_observes_changes_committed_during_lock_wait(
    integration_engine: Engine,
    async_app_connection_factory: ConnectionFactory,
    change: str,
) -> None:
    session_id = uuid4()
    user_id = uuid4()
    token = SecretStr(token_urlsafe(32))
    cipher = AccountTokenCipher(SecretStr(Fernet.generate_key().decode("ascii")))

    with integration_engine.begin() as connection:
        connection.execute(insert(UserProfile).values(id=user_id))
        connection.execute(
            insert(AccountSession).values(
                id=session_id,
                user_id=user_id,
                provider_session_id=uuid4(),
                token_hash=sha256(token.get_secret_value().encode("ascii")).digest(),
                access_token_ciphertext=cipher.encrypt(SecretStr("original-access")),
                refresh_token_ciphertext=cipher.encrypt(SecretStr("original-refresh")),
                access_token_expires_at=(func.statement_timestamp() + timedelta(hours=1)),
                created_at=(func.statement_timestamp() - timedelta(days=10)),
                last_seen_at=(func.statement_timestamp() - timedelta(days=8)),
                idle_expires_at=(func.statement_timestamp() + timedelta(days=7)),
                absolute_expires_at=(func.statement_timestamp() + timedelta(days=30)),
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

                    async def attempt_load() -> LockedAccountSession | None:
                        async with async_app_connection_factory() as worker:
                            pid = await worker.scalar(text("SELECT pg_backend_pid()"))
                            assert isinstance(pid, int)
                            ready.set_result(pid)
                            return await load_locked_account_session(worker, token)

                    async with asyncio.TaskGroup() as group:
                        # Local test admin can change the absolute deadline.
                        # The loader itself uses the restricted application role.
                        async with locker_engine.begin() as locker:
                            locker_pid = await locker.scalar(text("SELECT pg_backend_pid()"))
                            assert isinstance(locker_pid, int)

                            locked_id = await locker.scalar(
                                select(AccountSession.id)
                                .where(AccountSession.id == session_id)
                                .with_for_update()
                            )
                            assert locked_id == session_id

                            task = group.create_task(attempt_load())
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
                                select(
                                    (AccountSession.idle_expires_at > func.clock_timestamp())
                                    & (AccountSession.absolute_expires_at > func.clock_timestamp())
                                ).where(AccountSession.id == session_id)
                            )
                            assert still_active is True

                            values: dict[str, object]
                            if change == "credentials":
                                values = {
                                    "access_token_ciphertext": cipher.encrypt(
                                        SecretStr("replacement-access")
                                    ),
                                    "refresh_token_ciphertext": cipher.encrypt(
                                        SecretStr("replacement-refresh")
                                    ),
                                    "access_token_expires_at": (
                                        func.statement_timestamp() + timedelta(hours=2)
                                    ),
                                }
                            else:
                                values = {
                                    "idle_expires_at": func.statement_timestamp(),
                                }
                                if change == "absolute_expiry":
                                    values["absolute_expires_at"] = func.statement_timestamp()

                            expected = (
                                await locker.execute(
                                    update(AccountSession)
                                    .where(AccountSession.id == session_id)
                                    .values(**values)
                                    .returning(*AccountSession.__table__.c)
                                )
                            ).one()

                        # Exiting the locker transaction commits and releases it.
                        loaded = await task

                    stored = (
                        await observer.execute(
                            select(AccountSession).where(AccountSession.id == session_id)
                        )
                    ).one()

                    # Loading must not modify anything the locker committed.
                    assert stored == expected

                    if change == "credentials":
                        assert loaded is not None
                        assert loaded.session_id == session_id
                        assert loaded.user_id == user_id
                        assert loaded.provider_session_id == expected.provider_session_id
                        assert loaded.access_token_ciphertext == expected.access_token_ciphertext
                        assert loaded.refresh_token_ciphertext == expected.refresh_token_ciphertext
                        assert loaded.access_token_expires_at == expected.access_token_expires_at
                        assert loaded.last_seen_at == expected.last_seen_at
                        assert loaded.idle_expires_at == expected.idle_expires_at
                        assert loaded.absolute_expires_at == expected.absolute_expires_at
                        assert cipher.decrypt(loaded.access_token_ciphertext) == SecretStr(
                            "replacement-access"
                        )
                        assert cipher.decrypt(loaded.refresh_token_ciphertext) == SecretStr(
                            "replacement-refresh"
                        )
                    else:
                        assert loaded is None
        finally:
            await locker_engine.dispose()

    try:
        asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)
    finally:
        with integration_engine.begin() as connection:
            connection.execute(delete(AccountSession).where(AccountSession.id == session_id))
            connection.execute(delete(UserProfile).where(UserProfile.id == user_id))
