"""PostgreSQL tests for guest-session lookup and refresh."""

import asyncio
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from datetime import timedelta

import pytest
from pydantic_settings import SettingsConfigDict
from sqlalchemy import func, insert, select
from sqlalchemy.ext.asyncio import AsyncConnection

from app.config import Settings
from app.guest_sessions import create_guest_session, refresh_guest_session
from app.guest_tokens import generate_guest_token, hash_guest_token
from app.models import GuestSession

pytestmark = pytest.mark.integration

type ConnectionFactory = Callable[[], AbstractAsyncContextManager[AsyncConnection]]


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


def settings_for(days: int = 30) -> Settings:
    return IsolatedSettings(
        database_url=None,
        migration_database_url=None,
        guest_session_inactivity_days=days,
    )


@pytest.mark.parametrize("days", [1, 30, 90])
def test_valid_session_refresh_preserves_identity_and_uses_configured_expiry(
    async_app_connection_factory: ConnectionFactory,
    days: int,
) -> None:
    async def check() -> None:
        async with async_app_connection_factory() as connection:
            created = await create_guest_session(connection, settings_for())

            statement = select(
                GuestSession.token_hash,
                GuestSession.created_at,
                GuestSession.last_seen_at,
                GuestSession.expires_at,
            ).where(GuestSession.id == created.session_id)

            before = (await connection.execute(statement)).one()

            active = await refresh_guest_session(
                connection,
                created.token.get_secret_value(),
                settings_for(days),
            )
            after = (await connection.execute(statement)).one()

            assert active is not None
            assert active.session_id == created.session_id
            assert active.expires_at == after.expires_at
            assert after.token_hash == before.token_hash
            assert after.created_at == before.created_at
            assert after.last_seen_at >= before.last_seen_at
            assert after.expires_at - after.last_seen_at == timedelta(days=days)

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


@pytest.mark.parametrize(
    "token",
    [
        None,
        "",
        "invalid",
        "A" * 43,
        "A" * 43 + "\n",
    ],
)
def test_missing_malformed_and_unknown_tokens_do_not_refresh_another_session(
    async_app_connection_factory: ConnectionFactory,
    token: str | None,
) -> None:
    async def check() -> None:
        async with async_app_connection_factory() as connection:
            created = await create_guest_session(connection, settings_for())
            statement = select(
                GuestSession.last_seen_at,
                GuestSession.expires_at,
            ).where(GuestSession.id == created.session_id)

            before = (await connection.execute(statement)).one()

            active = await refresh_guest_session(
                connection,
                token,
                settings_for(),
            )

            assert active is None
            assert (await connection.execute(statement)).one() == before

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_expired_session_is_rejected_without_changing_its_timestamps(
    async_app_connection_factory: ConnectionFactory,
) -> None:
    async def check() -> None:
        async with async_app_connection_factory() as connection:
            token = generate_guest_token()
            old_activity = func.statement_timestamp() - timedelta(days=31)

            result = await connection.execute(
                insert(GuestSession)
                .values(
                    token_hash=hash_guest_token(token),
                    created_at=old_activity,
                    last_seen_at=old_activity,
                    expires_at=func.statement_timestamp() - timedelta(seconds=1),
                )
                .returning(
                    GuestSession.id,
                    GuestSession.last_seen_at,
                    GuestSession.expires_at,
                )
            )
            session_id, original_activity, original_expiry = result.one()

            active = await refresh_guest_session(
                connection,
                token,
                settings_for(),
            )

            assert active is None

            stored = (
                await connection.execute(
                    select(
                        GuestSession.last_seen_at,
                        GuestSession.expires_at,
                    ).where(GuestSession.id == session_id)
                )
            ).one()

            assert tuple(stored) == (original_activity, original_expiry)

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)
