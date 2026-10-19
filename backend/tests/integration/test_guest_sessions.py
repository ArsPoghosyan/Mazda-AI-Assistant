"""PostgreSQL tests for guest-session creation."""

import asyncio
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from datetime import timedelta

import pytest
from pydantic_settings import SettingsConfigDict
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncConnection

from app.config import Settings
from app.guest_sessions import create_guest_session
from app.guest_tokens import hash_guest_token
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


def test_creation_stores_only_the_token_hash(
    async_app_connection_factory: ConnectionFactory,
) -> None:
    async def check() -> None:
        async with async_app_connection_factory() as connection:
            created = await create_guest_session(connection, settings_for())
            token = created.token.get_secret_value()

            stored = (
                await connection.execute(
                    select(
                        GuestSession.token_hash,
                        GuestSession.expires_at,
                    ).where(GuestSession.id == created.session_id)
                )
            ).one()

            assert stored.token_hash == hash_guest_token(token)
            assert stored.token_hash != token.encode("ascii")
            assert stored.expires_at == created.expires_at
            assert token not in repr(created)

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


@pytest.mark.parametrize("days", [1, 30, 90])
def test_creation_respects_configurable_expiry(
    async_app_connection_factory: ConnectionFactory,
    days: int,
) -> None:
    async def check() -> None:
        async with async_app_connection_factory() as connection:
            created = await create_guest_session(
                connection,
                settings_for(days),
            )
            created_at = await connection.scalar(
                select(GuestSession.created_at).where(GuestSession.id == created.session_id)
            )

            assert created_at is not None
            assert created.expires_at - created_at == timedelta(days=days)

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_creation_is_rolled_back_with_the_callers_transaction(
    async_app_connection_factory: ConnectionFactory,
) -> None:
    async def check() -> None:
        async with async_app_connection_factory() as connection:
            created = await create_guest_session(connection, settings_for())

        async with async_app_connection_factory() as connection:
            remaining = await connection.scalar(
                select(GuestSession.id).where(GuestSession.id == created.session_id)
            )
            assert remaining is None

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)
