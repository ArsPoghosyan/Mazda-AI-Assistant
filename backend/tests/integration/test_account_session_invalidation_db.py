"""Account-session invalidation on guarded local PostgreSQL."""

import asyncio
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from secrets import token_urlsafe
from uuid import UUID, uuid4

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr
from sqlalchemy import func, insert, select
from sqlalchemy.ext.asyncio import AsyncConnection

from app.account_session_invalidation import invalidate_account_sessions
from app.account_token_encryption import AccountTokenCipher
from app.account_tokens import VerifiedAccount
from app.models import AccountSession, GuestSession, UserProfile

pytestmark = pytest.mark.integration

type ConnectionFactory = Callable[[], AbstractAsyncContextManager[AsyncConnection]]


def verified_account(user_id: UUID) -> VerifiedAccount:
    return VerifiedAccount(
        user_id=user_id,
        session_id=uuid4(),
        assurance_level="aal1",
        access_token_expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


async def seed_session(
    connection: AsyncConnection,
    user_id: UUID,
    *,
    expiry: str = "active",
) -> UUID:
    session_id = uuid4()
    cipher = AccountTokenCipher(SecretStr(Fernet.generate_key().decode("ascii")))
    now = func.statement_timestamp()

    values: dict[str, object] = {
        "id": session_id,
        "user_id": user_id,
        "provider_session_id": uuid4(),
        "token_hash": sha256(token_urlsafe(32).encode("ascii")).digest(),
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
    return session_id


def test_invalidates_only_target_accounts_sessions(
    async_app_connection_factory: ConnectionFactory,
) -> None:
    async def check() -> None:
        async with async_app_connection_factory() as connection:
            owner_id = uuid4()
            other_id = uuid4()
            guest_id = uuid4()

            await connection.execute(
                insert(UserProfile).values([{"id": owner_id}, {"id": other_id}])
            )

            for expiry in ("active", "idle", "absolute"):
                await seed_session(connection, owner_id, expiry=expiry)

            await seed_session(connection, other_id)
            await seed_session(connection, other_id, expiry="idle")

            now = func.statement_timestamp()
            await connection.execute(
                insert(GuestSession).values(
                    id=guest_id,
                    token_hash=sha256(token_urlsafe(32).encode("ascii")).digest(),
                    created_at=now,
                    last_seen_at=now,
                    expires_at=now + timedelta(days=30),
                )
            )

            target_statement = select(AccountSession).where(AccountSession.user_id == owner_id)
            other_statement = (
                select(AccountSession)
                .where(AccountSession.user_id == other_id)
                .order_by(AccountSession.id)
            )
            profiles_statement = (
                select(UserProfile)
                .where(UserProfile.id.in_([owner_id, other_id]))
                .order_by(UserProfile.id)
            )
            guest_statement = select(GuestSession).where(GuestSession.id == guest_id)

            other_before = (await connection.execute(other_statement)).all()
            profiles_before = (await connection.execute(profiles_statement)).all()
            guest_before = (await connection.execute(guest_statement)).one()

            account = verified_account(owner_id)
            assert await invalidate_account_sessions(connection, account) == 3
            assert (await connection.execute(target_statement)).all() == []

            assert (await connection.execute(other_statement)).all() == other_before
            assert (await connection.execute(profiles_statement)).all() == profiles_before
            assert (await connection.execute(guest_statement)).one() == guest_before

            assert await invalidate_account_sessions(connection, account) == 0

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


@pytest.mark.parametrize("profile_exists", [True, False])
def test_account_without_sessions_is_a_noop(
    async_app_connection_factory: ConnectionFactory,
    profile_exists: bool,
) -> None:
    async def check() -> None:
        async with async_app_connection_factory() as connection:
            owner_id = uuid4()
            other_id = uuid4()

            await connection.execute(insert(UserProfile).values(id=other_id))
            if profile_exists:
                await connection.execute(insert(UserProfile).values(id=owner_id))

            other_session_id = await seed_session(connection, other_id)
            other_statement = select(AccountSession).where(AccountSession.id == other_session_id)
            other_before = (await connection.execute(other_statement)).one()

            assert (
                await invalidate_account_sessions(
                    connection,
                    verified_account(owner_id),
                )
                == 0
            )

            assert (await connection.execute(other_statement)).one() == other_before
            stored_profile_id = await connection.scalar(
                select(UserProfile.id).where(UserProfile.id == owner_id)
            )
            assert stored_profile_id == (owner_id if profile_exists else None)

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_caller_rollback_restores_invalidated_sessions(
    async_app_connection_factory: ConnectionFactory,
) -> None:
    async def check() -> None:
        async with async_app_connection_factory() as connection:
            owner_id = uuid4()
            other_id = uuid4()
            await connection.execute(
                insert(UserProfile).values([{"id": owner_id}, {"id": other_id}])
            )

            await seed_session(connection, owner_id)
            await seed_session(connection, owner_id, expiry="absolute")
            await seed_session(connection, other_id)

            all_statement = (
                select(AccountSession)
                .where(AccountSession.user_id.in_([owner_id, other_id]))
                .order_by(AccountSession.id)
            )
            target_statement = select(AccountSession.id).where(AccountSession.user_id == owner_id)
            before = (await connection.execute(all_statement)).all()

            savepoint = await connection.begin_nested()
            try:
                assert (
                    await invalidate_account_sessions(
                        connection,
                        verified_account(owner_id),
                    )
                    == 2
                )
                assert (await connection.execute(target_statement)).all() == []
            finally:
                await savepoint.rollback()

            assert (await connection.execute(all_statement)).all() == before

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)
