"""Account-session activity and expiry checks on guarded local PostgreSQL."""

import asyncio
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from datetime import timedelta
from hashlib import sha256
from secrets import token_urlsafe
from uuid import UUID, uuid4

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict
from sqlalchemy import func, insert, select
from sqlalchemy.ext.asyncio import AsyncConnection

from app.account_sessions import touch_account_session
from app.account_token_encryption import AccountTokenCipher
from app.config import Settings
from app.models import AccountSession, UserProfile

pytestmark = pytest.mark.integration

type ConnectionFactory = Callable[[], AbstractAsyncContextManager[AsyncConnection]]


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


def settings_for(inactivity_days: int = 7) -> Settings:
    return IsolatedSettings.model_validate(
        {
            "database_url": None,
            "migration_database_url": None,
            "supabase_auth_issuer": None,
            "account_session_encryption_key": None,
            "account_session_inactivity_days": inactivity_days,
            "account_session_absolute_lifetime_days": 30,
        }
    )


@dataclass(frozen=True)
class SeededSession:
    session_id: UUID
    user_id: UUID
    provider_session_id: UUID
    token: SecretStr


async def seed_session(
    connection: AsyncConnection,
    **overrides: object,
) -> SeededSession:
    session = SeededSession(
        session_id=uuid4(),
        user_id=uuid4(),
        provider_session_id=uuid4(),
        token=SecretStr(token_urlsafe(32)),
    )
    cipher = AccountTokenCipher(SecretStr(Fernet.generate_key().decode("ascii")))
    now = func.statement_timestamp()

    await connection.execute(insert(UserProfile).values(id=session.user_id))

    values: dict[str, object] = {
        "id": session.session_id,
        "user_id": session.user_id,
        "provider_session_id": session.provider_session_id,
        "token_hash": sha256(session.token.get_secret_value().encode("ascii")).digest(),
        "access_token_ciphertext": cipher.encrypt(SecretStr("synthetic-access")),
        "refresh_token_ciphertext": cipher.encrypt(SecretStr("synthetic-refresh")),
        "access_token_expires_at": now + timedelta(hours=1),
        "created_at": now - timedelta(days=10),
        "last_seen_at": now - timedelta(days=1),
        "idle_expires_at": now + timedelta(days=6),
        "absolute_expires_at": now + timedelta(days=20),
    }
    values.update(overrides)
    await connection.execute(insert(AccountSession).values(**values))
    return session


@pytest.mark.parametrize("inactivity_days", [1, 7, 60])
def test_activity_updates_only_the_matching_session_and_caps_expiry(
    async_app_connection_factory: ConnectionFactory,
    inactivity_days: int,
) -> None:
    async def check() -> None:
        async with async_app_connection_factory() as connection:
            session = await seed_session(connection)
            other = await seed_session(connection)

            statement = select(AccountSession).where(AccountSession.id == session.session_id)
            other_statement = select(AccountSession).where(AccountSession.id == other.session_id)
            before = (await connection.execute(statement)).one()
            other_before = (await connection.execute(other_statement)).one()

            active = await touch_account_session(
                connection,
                session.token,
                settings_for(inactivity_days),
            )
            after = (await connection.execute(statement)).one()

            assert active is not None
            assert active.session_id == session.session_id
            assert active.user_id == session.user_id
            assert active.provider_session_id == session.provider_session_id
            assert active.access_token_expires_at == before.access_token_expires_at
            assert active.idle_expires_at == after.idle_expires_at
            assert active.absolute_expires_at == before.absolute_expires_at

            assert after.last_seen_at > before.last_seen_at
            assert after.idle_expires_at == min(
                after.last_seen_at + timedelta(days=inactivity_days),
                before.absolute_expires_at,
            )

            for column in (
                "user_id",
                "provider_session_id",
                "token_hash",
                "created_at",
                "access_token_ciphertext",
                "refresh_token_ciphertext",
                "access_token_expires_at",
                "absolute_expires_at",
            ):
                assert getattr(after, column) == getattr(before, column)

            assert (await connection.execute(other_statement)).one() == other_before

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


@pytest.mark.parametrize("deadline", ["idle", "absolute"])
@pytest.mark.parametrize("expiry_seconds", [0, -1])
def test_expired_session_is_rejected_without_modifying_it(
    async_app_connection_factory: ConnectionFactory,
    deadline: str,
    expiry_seconds: int,
) -> None:
    async def check() -> None:
        async with async_app_connection_factory() as connection:
            expiry = func.statement_timestamp() + timedelta(seconds=expiry_seconds)
            overrides: dict[str, object] = {
                "last_seen_at": func.statement_timestamp() - timedelta(days=8),
                "idle_expires_at": expiry,
            }
            if deadline == "absolute":
                overrides["absolute_expires_at"] = expiry

            session = await seed_session(connection, **overrides)
            statement = select(AccountSession).where(AccountSession.id == session.session_id)
            before = (await connection.execute(statement)).one()

            active = await touch_account_session(
                connection,
                session.token,
                settings_for(),
            )

            assert active is None
            assert (await connection.execute(statement)).one() == before

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_unknown_token_leaves_existing_session_unchanged(
    async_app_connection_factory: ConnectionFactory,
) -> None:
    async def check() -> None:
        async with async_app_connection_factory() as connection:
            session = await seed_session(connection)
            statement = select(AccountSession).where(AccountSession.id == session.session_id)
            before = (await connection.execute(statement)).one()

            unknown_token = SecretStr(token_urlsafe(32))
            assert unknown_token != session.token

            active = await touch_account_session(
                connection,
                unknown_token,
                settings_for(),
            )

            assert active is None
            assert (await connection.execute(statement)).one() == before

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_activity_update_rolls_back_with_callers_savepoint(
    async_app_connection_factory: ConnectionFactory,
) -> None:
    async def check() -> None:
        async with async_app_connection_factory() as connection:
            session = await seed_session(connection)
            statement = select(AccountSession).where(AccountSession.id == session.session_id)
            before = (await connection.execute(statement)).one()

            savepoint = await connection.begin_nested()
            try:
                active = await touch_account_session(
                    connection,
                    session.token,
                    settings_for(),
                )
                assert active is not None

                updated = (await connection.execute(statement)).one()
                assert updated.last_seen_at > before.last_seen_at
                assert updated.idle_expires_at > before.idle_expires_at
            finally:
                await savepoint.rollback()

            assert (await connection.execute(statement)).one() == before

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_expired_provider_token_does_not_hide_active_session_metadata(
    async_app_connection_factory: ConnectionFactory,
) -> None:
    async def check() -> None:
        async with async_app_connection_factory() as connection:
            session = await seed_session(
                connection,
                access_token_expires_at=(func.statement_timestamp() - timedelta(seconds=1)),
            )
            original_expiry = await connection.scalar(
                select(AccountSession.access_token_expires_at).where(
                    AccountSession.id == session.session_id
                )
            )

            active = await touch_account_session(
                connection,
                session.token,
                settings_for(),
            )

            assert active is not None
            assert active.access_token_expires_at == original_expiry
            assert (
                await connection.scalar(
                    select(
                        AccountSession.access_token_expires_at < func.statement_timestamp()
                    ).where(AccountSession.id == session.session_id)
                )
                is True
            )

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)
