"""Account sessions must not revive after expiring during a row-lock wait."""

import asyncio
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from datetime import datetime, timedelta
from hashlib import sha256
from secrets import token_urlsafe
from uuid import uuid4

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict
from sqlalchemy import delete, func, insert, select, text, update
from sqlalchemy.engine import Engine
from sqlalchemy.ext.asyncio import AsyncConnection, create_async_engine
from sqlalchemy.pool import NullPool

from app.account_sessions import ActiveAccountSession, touch_account_session
from app.account_token_encryption import AccountTokenCipher
from app.config import Settings
from app.models import AccountSession, UserProfile

pytestmark = pytest.mark.integration

type ConnectionFactory = Callable[[], AbstractAsyncContextManager[AsyncConnection]]


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@pytest.mark.parametrize("deadline", ["idle", "absolute"])
def test_session_expiring_during_lock_wait_is_not_revived(
    integration_engine: Engine,
    async_app_connection_factory: ConnectionFactory,
    deadline: str,
) -> None:
    session_id = uuid4()
    user_id = uuid4()
    token = SecretStr(token_urlsafe(32))
    cipher = AccountTokenCipher(SecretStr(Fernet.generate_key().decode("ascii")))
    settings = IsolatedSettings.model_validate(
        {
            "database_url": None,
            "migration_database_url": None,
            "supabase_auth_issuer": None,
            "account_session_encryption_key": None,
            "account_session_inactivity_days": 7,
            "account_session_absolute_lifetime_days": 30,
        }
    )

    # Commit synthetic rows so separate test connections can see them.
    with integration_engine.begin() as connection:
        connection.execute(insert(UserProfile).values(id=user_id))
        original_activity, original_absolute_expiry = connection.execute(
            insert(AccountSession)
            .values(
                id=session_id,
                user_id=user_id,
                token_hash=sha256(token.get_secret_value().encode("ascii")).digest(),
                provider_session_id=uuid4(),
                access_token_ciphertext=cipher.encrypt(SecretStr("synthetic-access")),
                refresh_token_ciphertext=cipher.encrypt(SecretStr("synthetic-refresh")),
                access_token_expires_at=(func.statement_timestamp() + timedelta(hours=1)),
                created_at=func.statement_timestamp() - timedelta(days=10),
                last_seen_at=func.statement_timestamp() - timedelta(days=8),
                idle_expires_at=func.statement_timestamp() + timedelta(days=7),
                absolute_expires_at=(func.statement_timestamp() + timedelta(days=30)),
            )
            .returning(
                AccountSession.last_seen_at,
                AccountSession.absolute_expires_at,
            )
        ).one()

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

                    async def attempt_lookup() -> ActiveAccountSession | None:
                        async with async_app_connection_factory() as worker:
                            worker_pid = await worker.scalar(text("SELECT pg_backend_pid()"))
                            assert isinstance(worker_pid, int)
                            ready.set_result(worker_pid)
                            return await touch_account_session(
                                worker,
                                token,
                                settings,
                            )

                    async with asyncio.TaskGroup() as group:
                        # This local admin connection controls the test's expiry.
                        # The lookup worker uses the restricted application role.
                        async with locker_engine.begin() as locker:
                            locker_pid = await locker.scalar(text("SELECT pg_backend_pid()"))
                            assert isinstance(locker_pid, int)

                            locked_id = await locker.scalar(
                                select(AccountSession.id)
                                .where(AccountSession.id == session_id)
                                .with_for_update()
                            )
                            assert locked_id == session_id

                            task = group.create_task(attempt_lookup())
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

                            values: dict[str, object] = {
                                "idle_expires_at": func.statement_timestamp(),
                            }
                            if deadline == "absolute":
                                values["absolute_expires_at"] = func.statement_timestamp()

                            expired_at = await locker.scalar(
                                update(AccountSession)
                                .where(AccountSession.id == session_id)
                                .values(**values)
                                .returning(AccountSession.idle_expires_at)
                            )
                            assert isinstance(expired_at, datetime)

                        # Commit releases the row lock. Lookup must now reject it.
                        assert await task is None

                    stored = (
                        await observer.execute(
                            select(
                                AccountSession.last_seen_at,
                                AccountSession.idle_expires_at,
                                AccountSession.absolute_expires_at,
                            ).where(AccountSession.id == session_id)
                        )
                    ).one()

                    assert stored.last_seen_at == original_activity
                    assert stored.idle_expires_at == expired_at
                    if deadline == "absolute":
                        assert stored.absolute_expires_at == expired_at
                    else:
                        assert stored.absolute_expires_at == original_absolute_expiry
        finally:
            await locker_engine.dispose()

    try:
        asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)
    finally:
        with integration_engine.begin() as connection:
            connection.execute(delete(AccountSession).where(AccountSession.id == session_id))
            connection.execute(delete(UserProfile).where(UserProfile.id == user_id))
