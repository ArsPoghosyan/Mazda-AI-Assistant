"""Session deletion and isolation on guarded local PostgreSQL."""

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
from sqlalchemy import func, insert, select
from sqlalchemy.ext.asyncio import AsyncConnection

from app.account_session_deletion import delete_account_session
from app.account_token_encryption import AccountTokenCipher
from app.models import AccountSession, UserProfile

pytestmark = pytest.mark.integration

type ConnectionFactory = Callable[[], AbstractAsyncContextManager[AsyncConnection]]


@dataclass(frozen=True)
class SeededSession:
    session_id: UUID
    token: SecretStr


async def seed_session(
    connection: AsyncConnection,
    user_id: UUID,
    *,
    expiry: str = "active",
) -> SeededSession:
    session = SeededSession(
        session_id=uuid4(),
        token=SecretStr(token_urlsafe(32)),
    )
    cipher = AccountTokenCipher(SecretStr(Fernet.generate_key().decode("ascii")))
    now = func.statement_timestamp()

    values: dict[str, object] = {
        "id": session.session_id,
        "user_id": user_id,
        "provider_session_id": uuid4(),
        "token_hash": sha256(session.token.get_secret_value().encode("ascii")).digest(),
        "access_token_ciphertext": cipher.encrypt(SecretStr("synthetic-access")),
        "refresh_token_ciphertext": cipher.encrypt(SecretStr("synthetic-refresh")),
        "access_token_expires_at": now + timedelta(hours=1),
        "created_at": now - timedelta(days=40),
        "last_seen_at": now - timedelta(days=10),
        "idle_expires_at": now + timedelta(days=6),
        "absolute_expires_at": now + timedelta(days=20),
    }

    if expiry == "idle":
        values["idle_expires_at"] = now - timedelta(days=1)
    elif expiry == "absolute":
        values["idle_expires_at"] = now - timedelta(days=2)
        values["absolute_expires_at"] = now - timedelta(days=1)

    await connection.execute(insert(AccountSession).values(**values))
    return session


@pytest.mark.parametrize("expiry", ["active", "idle", "absolute"])
def test_deletes_only_matching_session_and_preserves_accounts(
    async_app_connection_factory: ConnectionFactory,
    expiry: str,
) -> None:
    async def check() -> None:
        async with async_app_connection_factory() as connection:
            owner_id = uuid4()
            other_owner_id = uuid4()
            await connection.execute(
                insert(UserProfile).values([{"id": owner_id}, {"id": other_owner_id}])
            )

            target = await seed_session(connection, owner_id, expiry=expiry)
            sibling = await seed_session(connection, owner_id)
            other = await seed_session(connection, other_owner_id)

            target_statement = select(AccountSession).where(AccountSession.id == target.session_id)
            sibling_statement = select(AccountSession).where(
                AccountSession.id == sibling.session_id
            )
            other_statement = select(AccountSession).where(AccountSession.id == other.session_id)

            sibling_before = (await connection.execute(sibling_statement)).one()
            other_before = (await connection.execute(other_statement)).one()

            assert await delete_account_session(connection, target.token) is True
            assert (await connection.execute(target_statement)).one_or_none() is None

            # A repeated request is a harmless no-op.
            assert await delete_account_session(connection, target.token) is False

            assert (await connection.execute(sibling_statement)).one() == sibling_before
            assert (await connection.execute(other_statement)).one() == other_before

            for user_id in (owner_id, other_owner_id):
                assert (
                    await connection.scalar(select(UserProfile.id).where(UserProfile.id == user_id))
                    == user_id
                )

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_unknown_cookie_leaves_existing_session_unchanged(
    async_app_connection_factory: ConnectionFactory,
) -> None:
    async def check() -> None:
        async with async_app_connection_factory() as connection:
            user_id = uuid4()
            await connection.execute(insert(UserProfile).values(id=user_id))
            session = await seed_session(connection, user_id)

            statement = select(AccountSession).where(AccountSession.id == session.session_id)
            before = (await connection.execute(statement)).one()

            unknown = SecretStr(token_urlsafe(32))
            assert unknown != session.token

            assert await delete_account_session(connection, unknown) is False
            assert (await connection.execute(statement)).one() == before
            assert (
                await connection.scalar(select(UserProfile.id).where(UserProfile.id == user_id))
                == user_id
            )

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_caller_rollback_restores_deleted_session(
    async_app_connection_factory: ConnectionFactory,
) -> None:
    async def check() -> None:
        async with async_app_connection_factory() as connection:
            user_id = uuid4()
            await connection.execute(insert(UserProfile).values(id=user_id))
            target = await seed_session(connection, user_id)
            sibling = await seed_session(connection, user_id)

            target_statement = select(AccountSession).where(AccountSession.id == target.session_id)
            sibling_statement = select(AccountSession).where(
                AccountSession.id == sibling.session_id
            )
            target_before = (await connection.execute(target_statement)).one()
            sibling_before = (await connection.execute(sibling_statement)).one()

            savepoint = await connection.begin_nested()
            try:
                assert await delete_account_session(connection, target.token) is True
                assert (await connection.execute(target_statement)).one_or_none() is None
            finally:
                await savepoint.rollback()

            assert (await connection.execute(target_statement)).one() == target_before
            assert (await connection.execute(sibling_statement)).one() == sibling_before
            assert (
                await connection.scalar(select(UserProfile.id).where(UserProfile.id == user_id))
                == user_id
            )

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)
