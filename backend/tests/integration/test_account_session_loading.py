"""Locked account-session loading on guarded local PostgreSQL."""

import asyncio
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from datetime import datetime, timedelta
from hashlib import sha256
from secrets import token_urlsafe
from uuid import UUID, uuid4

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr
from sqlalchemy import func, insert, select
from sqlalchemy.ext.asyncio import AsyncConnection

from app.account_session_auth import load_locked_account_session
from app.account_token_encryption import AccountTokenCipher
from app.models import AccountSession, UserProfile

pytestmark = pytest.mark.integration

type ConnectionFactory = Callable[[], AbstractAsyncContextManager[AsyncConnection]]


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


def test_loading_returns_matching_snapshot_without_changing_rows(
    async_app_connection_factory: ConnectionFactory,
) -> None:
    async def check() -> None:
        async with async_app_connection_factory() as connection:
            session = await seed_session(connection)
            other = await seed_session(connection)

            statement = select(AccountSession).where(AccountSession.id == session.session_id)
            other_statement = select(AccountSession).where(AccountSession.id == other.session_id)
            before = (await connection.execute(statement)).one()
            other_before = (await connection.execute(other_statement)).one()

            started_at = await connection.scalar(select(func.clock_timestamp()))
            loaded = await load_locked_account_session(connection, session.token)
            finished_at = await connection.scalar(select(func.clock_timestamp()))

            assert loaded is not None
            assert loaded.session_id == session.session_id
            assert loaded.user_id == session.user_id
            assert loaded.provider_session_id == session.provider_session_id
            assert loaded.access_token_ciphertext == before.access_token_ciphertext
            assert loaded.refresh_token_ciphertext == before.refresh_token_ciphertext
            assert loaded.access_token_expires_at == before.access_token_expires_at
            assert loaded.last_seen_at == before.last_seen_at
            assert loaded.idle_expires_at == before.idle_expires_at
            assert loaded.absolute_expires_at == before.absolute_expires_at
            assert isinstance(started_at, datetime)
            assert isinstance(finished_at, datetime)
            assert started_at <= loaded.checked_at <= finished_at
            assert loaded.checked_at.utcoffset() == timedelta(0)

            representation = repr(loaded)
            assert before.access_token_ciphertext.decode("ascii") not in representation
            assert before.refresh_token_ciphertext.decode("ascii") not in representation

            assert (await connection.execute(statement)).one() == before
            assert (await connection.execute(other_statement)).one() == other_before

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


@pytest.mark.parametrize("deadline", ["idle", "absolute"])
@pytest.mark.parametrize("expiry_seconds", [0, -1])
def test_expired_application_session_is_not_loaded_or_changed(
    async_app_connection_factory: ConnectionFactory,
    deadline: str,
    expiry_seconds: int,
) -> None:
    async def check() -> None:
        async with async_app_connection_factory() as connection:
            expiry = func.statement_timestamp() + timedelta(seconds=expiry_seconds)
            overrides: dict[str, object] = {
                "last_seen_at": (func.statement_timestamp() - timedelta(days=8)),
                "idle_expires_at": expiry,
            }
            if deadline == "absolute":
                overrides["absolute_expires_at"] = expiry

            session = await seed_session(connection, **overrides)
            statement = select(AccountSession).where(AccountSession.id == session.session_id)
            before = (await connection.execute(statement)).one()

            loaded = await load_locked_account_session(connection, session.token)

            assert loaded is None
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
            unknown = SecretStr(token_urlsafe(32))
            assert unknown != session.token

            loaded = await load_locked_account_session(connection, unknown)

            assert loaded is None
            assert (await connection.execute(statement)).one() == before

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_expired_provider_token_still_allows_loading_for_refresh(
    async_app_connection_factory: ConnectionFactory,
) -> None:
    async def check() -> None:
        async with async_app_connection_factory() as connection:
            session = await seed_session(
                connection,
                access_token_expires_at=(func.statement_timestamp() - timedelta(seconds=1)),
            )
            statement = select(AccountSession).where(AccountSession.id == session.session_id)
            before = (await connection.execute(statement)).one()

            loaded = await load_locked_account_session(connection, session.token)

            assert loaded is not None
            assert loaded.access_token_expires_at < loaded.checked_at
            assert (await connection.execute(statement)).one() == before

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)
