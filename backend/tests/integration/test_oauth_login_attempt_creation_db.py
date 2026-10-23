"""OAuth creation and rollback on the guarded local PostgreSQL database."""

import asyncio
from base64 import urlsafe_b64decode
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from datetime import datetime, timedelta
from hashlib import sha256

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncConnection

from app.account_oauth_attempts import create_oauth_login_attempt
from app.account_oauth_material import hash_oauth_browser_token, recover_oauth_pkce_verifier
from app.account_token_encryption import AccountTokenCipher
from app.config import Settings
from app.models import OAuthLoginAttempt

pytestmark = pytest.mark.integration
type ConnectionFactory = Callable[[], AbstractAsyncContextManager[AsyncConnection]]


class IsolatedAttemptSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@pytest.fixture
def settings() -> Settings:
    return IsolatedAttemptSettings(
        account_session_encryption_key=SecretStr(Fernet.generate_key().decode("ascii")),
        account_google_oauth_api_enabled=False,
        account_google_oauth_attempt_lifetime_seconds=600,
    )


@pytest.mark.parametrize("lifetime", [60, 600, 900])
def test_creation_stores_only_protected_material_with_database_expiry(
    async_app_connection_factory: ConnectionFactory, settings: Settings, lifetime: int
) -> None:
    settings = settings.model_copy(
        update={"account_google_oauth_attempt_lifetime_seconds": lifetime}
    )

    async def check() -> None:
        async with async_app_connection_factory() as connection:
            started_at = await connection.scalar(select(func.clock_timestamp()))
            created = await create_oauth_login_attempt(connection, settings)
            finished_at = await connection.scalar(select(func.clock_timestamp()))
            row = (
                await connection.execute(
                    select(OAuthLoginAttempt).where(OAuthLoginAttempt.id == created.attempt_id)
                )
            ).one()

            assert isinstance(started_at, datetime)
            assert isinstance(finished_at, datetime)
            assert started_at <= row.created_at <= finished_at
            assert row.created_at.utcoffset() == timedelta(0)
            assert row.expires_at == row.created_at + timedelta(seconds=lifetime)
            assert created.expires_at == row.expires_at
            assert (row.provider, row.purpose) == ("google", "sign_in")
            browser_token = created.browser_token.get_secret_value()
            assert row.browser_token_hash == hash_oauth_browser_token(browser_token)
            key = settings.account_session_encryption_key
            assert key is not None
            verifier = recover_oauth_pkce_verifier(
                row.pkce_verifier_ciphertext, cipher=AccountTokenCipher(key)
            ).get_secret_value()
            # Compare against SHA-256 bytes directly, independently of challenge encoding.
            assert (
                urlsafe_b64decode(created.code_challenge + "=")
                == sha256(verifier.encode("ascii")).digest()
            )
            assert verifier != browser_token
            assert verifier.encode("ascii") not in row.pkce_verifier_ciphertext
            assert browser_token not in repr(created)
            assert verifier not in repr(created)
            assert connection.in_transaction()

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_attempt_is_uncommitted_and_disappears_on_caller_rollback(
    async_app_connection_factory: ConnectionFactory, settings: Settings
) -> None:
    async def check() -> None:
        async with async_app_connection_factory() as writer:
            created = await create_oauth_login_attempt(writer, settings)
            statement = select(OAuthLoginAttempt.id).where(
                OAuthLoginAttempt.id == created.attempt_id
            )
            assert await writer.scalar(statement) == created.attempt_id
            async with async_app_connection_factory() as observer:
                assert await observer.scalar(statement) is None

        async with async_app_connection_factory() as observer:
            assert await observer.scalar(statement) is None

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_independent_attempts_preserve_each_others_records(
    async_app_connection_factory: ConnectionFactory, settings: Settings
) -> None:
    async def check() -> None:
        async with async_app_connection_factory() as connection:
            first = await create_oauth_login_attempt(connection, settings)
            first_statement = select(OAuthLoginAttempt).where(
                OAuthLoginAttempt.id == first.attempt_id
            )
            original = (await connection.execute(first_statement)).one()
            second = await create_oauth_login_attempt(connection, settings)

            assert first.attempt_id != second.attempt_id
            assert first.browser_token != second.browser_token
            assert first.code_challenge != second.code_challenge
            assert (await connection.execute(first_statement)).one() == original
            assert (
                await connection.scalar(
                    select(OAuthLoginAttempt.id).where(OAuthLoginAttempt.id == second.attempt_id)
                )
                == second.attempt_id
            )

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)
