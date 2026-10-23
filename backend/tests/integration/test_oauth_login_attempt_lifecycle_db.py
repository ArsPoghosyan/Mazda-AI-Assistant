"""Replacement and provisional single-use consumption on guarded PostgreSQL."""

import asyncio
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from datetime import timedelta
from secrets import token_urlsafe

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict
from sqlalchemy import func, insert, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection

from app.account_oauth_attempts import (
    CreatedOAuthLoginAttempt,
    OAuthLoginAttemptUnavailable,
    consume_oauth_login_attempt,
    create_oauth_login_attempt,
    replace_oauth_login_attempt,
)
from app.account_oauth_material import (
    InvalidOAuthLoginMaterial,
    create_oauth_login_material,
    hash_oauth_browser_token,
)
from app.account_token_encryption import AccountTokenCipher
from app.config import Settings
from app.models import OAuthLoginAttempt

pytestmark = pytest.mark.integration
type ConnectionFactory = Callable[[], AbstractAsyncContextManager[AsyncConnection]]


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@pytest.fixture
def settings() -> Settings:
    return IsolatedSettings(
        account_session_encryption_key=SecretStr(Fernet.generate_key().decode("ascii")),
        account_google_oauth_attempt_lifetime_seconds=600,
        account_google_oauth_api_enabled=False,
    )


def test_consumption_targets_one_attempt_and_rejects_replay(
    async_app_connection_factory: ConnectionFactory, settings: Settings
) -> None:
    async def check() -> None:
        async with async_app_connection_factory() as connection:
            first = await create_oauth_login_attempt(connection, settings)
            other = await create_oauth_login_attempt(connection, settings)
            stored = (
                await connection.execute(
                    select(OAuthLoginAttempt).where(OAuthLoginAttempt.id == first.attempt_id)
                )
            ).one()
            consumed = await consume_oauth_login_attempt(
                connection, first.browser_token.get_secret_value()
            )
            assert consumed.attempt_id == first.attempt_id
            assert consumed.pkce_verifier_ciphertext == stored.pkce_verifier_ciphertext
            assert stored.pkce_verifier_ciphertext.decode("ascii") not in repr(consumed)
            assert (
                await connection.scalar(
                    select(OAuthLoginAttempt.id).where(OAuthLoginAttempt.id == other.attempt_id)
                )
                == other.attempt_id
            )
            with pytest.raises(InvalidOAuthLoginMaterial):
                await consume_oauth_login_attempt(
                    connection, first.browser_token.get_secret_value()
                )
            with pytest.raises(InvalidOAuthLoginMaterial):
                await consume_oauth_login_attempt(connection, token_urlsafe(32))

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_expired_attempt_is_rejected(
    async_app_connection_factory: ConnectionFactory, settings: Settings
) -> None:
    async def check() -> None:
        async with async_app_connection_factory() as connection:
            token = token_urlsafe(32)
            key = settings.account_session_encryption_key
            assert key is not None
            await connection.execute(
                insert(OAuthLoginAttempt).values(
                    browser_token_hash=hash_oauth_browser_token(token),
                    pkce_verifier_ciphertext=AccountTokenCipher(key).encrypt(SecretStr("v" * 43)),
                    created_at=func.clock_timestamp() - timedelta(minutes=2),
                    expires_at=func.clock_timestamp() - timedelta(minutes=1),
                )
            )
            with pytest.raises(InvalidOAuthLoginMaterial):
                await consume_oauth_login_attempt(connection, token)

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_consumption_rollback_restores_attempt(
    async_app_connection_factory: ConnectionFactory, settings: Settings
) -> None:
    async def check() -> None:
        async with async_app_connection_factory() as connection:
            created = await create_oauth_login_attempt(connection, settings)
            savepoint = await connection.begin_nested()
            consumed = await consume_oauth_login_attempt(
                connection, created.browser_token.get_secret_value()
            )
            assert consumed.attempt_id == created.attempt_id
            await savepoint.rollback()
            assert (
                await connection.scalar(
                    select(OAuthLoginAttempt.id).where(OAuthLoginAttempt.id == created.attempt_id)
                )
                == created.attempt_id
            )

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_replacement_invalidates_old_token_and_preserves_other_browser(
    async_app_connection_factory: ConnectionFactory, settings: Settings
) -> None:
    async def check() -> None:
        async with async_app_connection_factory() as connection:
            first = await create_oauth_login_attempt(connection, settings)
            other = await create_oauth_login_attempt(connection, settings)
            replacement = await replace_oauth_login_attempt(
                connection, settings, first.browser_token.get_secret_value()
            )
            assert replacement.browser_token != first.browser_token
            assert replacement.code_challenge != first.code_challenge
            with pytest.raises(InvalidOAuthLoginMaterial):
                await consume_oauth_login_attempt(
                    connection, first.browser_token.get_secret_value()
                )
            assert (
                await consume_oauth_login_attempt(
                    connection, replacement.browser_token.get_secret_value()
                )
            ).attempt_id == replacement.attempt_id
            assert (
                await consume_oauth_login_attempt(
                    connection, other.browser_token.get_secret_value()
                )
            ).attempt_id == other.attempt_id

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


@pytest.mark.parametrize("token", [None, "invalid", "a" * 43])
def test_unproven_replacement_creates_nothing(
    async_app_connection_factory: ConnectionFactory, settings: Settings, token: str | None
) -> None:
    async def check() -> None:
        async with async_app_connection_factory() as connection:
            before = (await connection.scalars(select(OAuthLoginAttempt.id))).all()
            with pytest.raises(InvalidOAuthLoginMaterial):
                await replace_oauth_login_attempt(connection, settings, token)
            assert (await connection.scalars(select(OAuthLoginAttempt.id))).all() == before

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_failed_replacement_restores_original_even_when_caught(
    async_app_connection_factory: ConnectionFactory, settings: Settings
) -> None:
    async def check() -> None:
        async with async_app_connection_factory() as connection:
            first = await create_oauth_login_attempt(connection, settings)
            statement = select(OAuthLoginAttempt).where(OAuthLoginAttempt.id == first.attempt_id)
            original = (await connection.execute(statement)).one()
            unavailable = settings.model_copy(update={"account_session_encryption_key": None})
            with pytest.raises(OAuthLoginAttemptUnavailable):
                await replace_oauth_login_attempt(
                    connection, unavailable, first.browser_token.get_secret_value()
                )
            assert (await connection.execute(statement)).one() == original
            assert connection.in_transaction()

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_outer_rollback_reverts_successful_replacement(
    async_app_connection_factory: ConnectionFactory, settings: Settings
) -> None:
    async def check() -> None:
        async with async_app_connection_factory() as connection:
            first = await create_oauth_login_attempt(connection, settings)
            savepoint = await connection.begin_nested()
            replacement = await replace_oauth_login_attempt(
                connection, settings, first.browser_token.get_secret_value()
            )
            await savepoint.rollback()
            assert (
                await connection.scalar(
                    select(OAuthLoginAttempt.id).where(OAuthLoginAttempt.id == first.attempt_id)
                )
                == first.attempt_id
            )
            assert (
                await connection.scalar(
                    select(OAuthLoginAttempt.id).where(
                        OAuthLoginAttempt.id == replacement.attempt_id
                    )
                )
                is None
            )

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_database_rejection_of_replacement_restores_old_and_other_rows(
    async_app_connection_factory: ConnectionFactory,
    settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def check() -> None:
        async with async_app_connection_factory() as connection:
            first = await create_oauth_login_attempt(connection, settings)
            key = settings.account_session_encryption_key
            assert key is not None
            material = create_oauth_login_material(AccountTokenCipher(key))
            monkeypatch.setattr(
                "app.account_oauth_attempts.create_oauth_login_material", lambda cipher: material
            )
            other = await create_oauth_login_attempt(connection, settings)
            statement = (
                select(OAuthLoginAttempt)
                .where(OAuthLoginAttempt.id.in_([first.attempt_id, other.attempt_id]))
                .order_by(OAuthLoginAttempt.id)
            )
            originals = (await connection.execute(statement)).all()
            with pytest.raises(IntegrityError):
                await replace_oauth_login_attempt(
                    connection, settings, first.browser_token.get_secret_value()
                )
            assert (await connection.execute(statement)).all() == originals
            assert connection.in_transaction()

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_cancelled_replacement_restores_original_and_propagates(
    async_app_connection_factory: ConnectionFactory,
    settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def check() -> None:
        async with async_app_connection_factory() as connection:
            first = await create_oauth_login_attempt(connection, settings)
            failure = asyncio.CancelledError()

            async def cancel_creation(
                connection: AsyncConnection, settings: Settings
            ) -> CreatedOAuthLoginAttempt:
                raise failure

            monkeypatch.setattr(
                "app.account_oauth_attempts.create_oauth_login_attempt", cancel_creation
            )
            with pytest.raises(asyncio.CancelledError) as caught:
                await replace_oauth_login_attempt(
                    connection, settings, first.browser_token.get_secret_value()
                )
            assert caught.value is failure
            assert (
                await connection.scalar(
                    select(OAuthLoginAttempt.id).where(OAuthLoginAttempt.id == first.attempt_id)
                )
                == first.attempt_id
            )

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)
