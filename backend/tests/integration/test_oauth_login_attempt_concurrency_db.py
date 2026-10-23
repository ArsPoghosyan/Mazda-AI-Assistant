"""Committed OAuth consumption/replacement races on guarded local PostgreSQL."""

import asyncio
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import timedelta
from secrets import token_urlsafe
from uuid import UUID, uuid4

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict
from sqlalchemy import delete, func, insert, select, text, update
from sqlalchemy.engine import Engine
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine
from sqlalchemy.pool import NullPool

from app.account_oauth_attempts import (
    ConsumedOAuthLoginAttempt,
    CreatedOAuthLoginAttempt,
    consume_oauth_login_attempt,
    replace_oauth_login_attempt,
)
from app.account_oauth_material import InvalidOAuthLoginMaterial, hash_oauth_browser_token
from app.account_token_encryption import AccountTokenCipher
from app.config import Settings
from app.models import OAuthLoginAttempt

pytestmark = pytest.mark.integration
type Outcome = CreatedOAuthLoginAttempt | ConsumedOAuthLoginAttempt


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@dataclass
class SeededAttempt:
    token: str
    attempt_id: UUID
    settings: Settings
    cleanup_ids: list[UUID]


@pytest.fixture
def seeded(integration_engine: Engine) -> Iterator[SeededAttempt]:
    attempt_id = uuid4()
    token = token_urlsafe(32)
    key = SecretStr(Fernet.generate_key().decode("ascii"))
    settings = IsolatedSettings(
        account_session_encryption_key=key,
        account_google_oauth_attempt_lifetime_seconds=600,
        account_google_oauth_api_enabled=False,
    )
    cleanup_ids = [attempt_id]
    try:
        with integration_engine.begin() as connection:
            connection.execute(
                insert(OAuthLoginAttempt).values(
                    id=attempt_id,
                    browser_token_hash=hash_oauth_browser_token(token),
                    pkce_verifier_ciphertext=AccountTokenCipher(key).encrypt(SecretStr("v" * 43)),
                    created_at=func.clock_timestamp() - timedelta(minutes=1),
                    expires_at=func.clock_timestamp() + timedelta(minutes=10),
                )
            )
        yield SeededAttempt(token, attempt_id, settings, cleanup_ids)
    finally:
        with integration_engine.begin() as connection:
            connection.execute(
                delete(OAuthLoginAttempt).where(OAuthLoginAttempt.id.in_(cleanup_ids))
            )


def async_engine(integration_engine: Engine) -> AsyncEngine:
    # The shared integration_engine fixture already guards URL, role and revision.
    return create_async_engine(
        integration_engine.url,
        poolclass=NullPool,
        connect_args={"connect_timeout": 5, "hostaddr": "127.0.0.1"},
        echo=False,
        hide_parameters=True,
    )


@asynccontextmanager
async def app_transaction(engine: AsyncEngine) -> AsyncIterator[AsyncConnection]:
    async with engine.begin() as connection:
        await connection.execute(text("SET LOCAL ROLE askm6_app"))
        await connection.execute(text("SET LOCAL TIME ZONE 'UTC'"))
        await connection.execute(text("SET LOCAL statement_timeout = '5s'"))
        yield connection


async def operate(connection: AsyncConnection, seeded: SeededAttempt, operation: str) -> Outcome:
    if operation == "consume":
        return await consume_oauth_login_attempt(connection, seeded.token)
    created = await replace_oauth_login_attempt(connection, seeded.settings, seeded.token)
    seeded.cleanup_ids.append(created.attempt_id)
    return created


async def contender(
    engine: AsyncEngine, seeded: SeededAttempt, operation: str, ready: asyncio.Future[int]
) -> Outcome | None:
    try:
        async with app_transaction(engine) as connection:
            pid = await connection.scalar(text("SELECT pg_backend_pid()"))
            assert isinstance(pid, int)
            ready.set_result(pid)
            return await operate(connection, seeded, operation)
    except InvalidOAuthLoginMaterial:
        return None


async def wait_for_block(engine: AsyncEngine, locker: int, worker: int) -> None:
    async with engine.connect() as observer:
        while not await observer.scalar(
            text("SELECT :locker = ANY(pg_blocking_pids(:worker))"),
            {"locker": locker, "worker": worker},
        ):
            await asyncio.sleep(0.01)


@pytest.mark.parametrize(
    ("winner", "loser"),
    [
        ("consume", "consume"),
        ("replace", "replace"),
        ("replace", "consume"),
        ("consume", "replace"),
    ],
)
def test_competing_requests_have_only_one_committed_winner(
    integration_engine: Engine, seeded: SeededAttempt, winner: str, loser: str
) -> None:
    async def check() -> None:
        engine = async_engine(integration_engine)
        try:
            async with asyncio.timeout(10):
                ready: asyncio.Future[int] = asyncio.get_running_loop().create_future()
                async with asyncio.TaskGroup() as group:
                    async with app_transaction(engine) as connection:
                        winner_pid = await connection.scalar(text("SELECT pg_backend_pid()"))
                        assert isinstance(winner_pid, int)
                        outcome = await operate(connection, seeded, winner)
                        task = group.create_task(contender(engine, seeded, loser, ready))
                        await wait_for_block(engine, winner_pid, await ready)
                    # The winner's transaction commits before the blocked request resumes.
                    assert await task is None

                async with app_transaction(engine) as observer:
                    assert (
                        await observer.scalar(
                            select(OAuthLoginAttempt.id).where(
                                OAuthLoginAttempt.id == seeded.attempt_id
                            )
                        )
                        is None
                    )
                    if isinstance(outcome, CreatedOAuthLoginAttempt):
                        assert (
                            await observer.scalar(
                                select(OAuthLoginAttempt.id).where(
                                    OAuthLoginAttempt.id == outcome.attempt_id
                                )
                            )
                            == outcome.attempt_id
                        )
                        consumed = await consume_oauth_login_attempt(
                            observer, outcome.browser_token.get_secret_value()
                        )
                        assert consumed.attempt_id == outcome.attempt_id
        finally:
            await engine.dispose()

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_expiry_is_checked_after_waiting_for_row_lock(
    integration_engine: Engine, seeded: SeededAttempt
) -> None:
    async def check() -> None:
        engine = async_engine(integration_engine)
        try:
            async with asyncio.timeout(10):
                ready: asyncio.Future[int] = asyncio.get_running_loop().create_future()
                async with asyncio.TaskGroup() as group:
                    # Only this guarded test-admin connection can update the deadline.
                    async with engine.begin() as locker:
                        locker_pid = await locker.scalar(text("SELECT pg_backend_pid()"))
                        assert isinstance(locker_pid, int)
                        assert (
                            await locker.scalar(
                                select(OAuthLoginAttempt.id)
                                .where(OAuthLoginAttempt.id == seeded.attempt_id)
                                .with_for_update()
                            )
                            == seeded.attempt_id
                        )
                        task = group.create_task(contender(engine, seeded, "consume", ready))
                        await wait_for_block(engine, locker_pid, await ready)
                        # Deadline is later than the blocked DELETE's statement start,
                        # but already expired when that DELETE can acquire the row.
                        await locker.execute(
                            update(OAuthLoginAttempt)
                            .where(OAuthLoginAttempt.id == seeded.attempt_id)
                            .values(expires_at=func.clock_timestamp())
                        )
                    assert await task is None

                async with app_transaction(engine) as observer:
                    # The rejection rolled back the DELETE; expiry is not data cleanup.
                    assert (
                        await observer.scalar(
                            select(OAuthLoginAttempt.id).where(
                                OAuthLoginAttempt.id == seeded.attempt_id
                            )
                        )
                        == seeded.attempt_id
                    )
        finally:
            await engine.dispose()

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)
