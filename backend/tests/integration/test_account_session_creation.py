"""Account-session creation using generated credentials and local PostgreSQL."""

import asyncio
from base64 import urlsafe_b64decode
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import jwt
import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm
from psycopg.errors import UniqueViolation
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict
from sqlalchemy import insert, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection

from app.account_key_cache import AccountKeyCache
from app.account_sessions import AccountSessionUnavailable, create_account_session
from app.account_token_encryption import AccountTokenCipher
from app.account_tokens import InvalidAccountToken, VerifiedAccount
from app.config import Settings
from app.models import AccountSession, UserProfile

pytestmark = pytest.mark.integration

type ConnectionFactory = Callable[[], AbstractAsyncContextManager[AsyncConnection]]

ISSUER = "https://auth.example.test/auth/v1"


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@dataclass(frozen=True)
class AuthMaterial:
    settings: Settings
    access_token: SecretStr
    refresh_token: SecretStr
    user_id: UUID
    provider_session_id: UUID
    access_expires_at: datetime
    cache: AccountKeyCache
    download: AsyncMock


@pytest.fixture
def material() -> AuthMaterial:
    signing_key = ec.generate_private_key(ec.SECP256R1())
    user_id = uuid4()
    provider_session_id = uuid4()
    now = int(datetime.now(UTC).timestamp())
    expiry = now + 300

    claims = {
        "iss": ISSUER,
        "aud": "authenticated",
        "iat": now - 1,
        "exp": expiry,
        "sub": str(user_id),
        "session_id": str(provider_session_id),
        "role": "authenticated",
        "is_anonymous": False,
        "aal": "aal1",
    }
    access_token = SecretStr(
        jwt.encode(
            claims,
            signing_key,
            algorithm="ES256",
            headers={"kid": "test-key"},
        )
    )

    public_jwk = ECAlgorithm.to_jwk(signing_key.public_key(), as_dict=True)
    public_jwk.update(
        {
            "kid": "test-key",
            "alg": "ES256",
            "use": "sig",
            "key_ops": ["verify"],
        }
    )
    download = AsyncMock(return_value={"keys": [public_jwk]})

    settings = IsolatedSettings.model_validate(
        {
            "database_url": None,
            "migration_database_url": None,
            "supabase_auth_issuer": ISSUER,
            "supabase_auth_audience": "authenticated",
            "account_session_encryption_key": Fernet.generate_key().decode("ascii"),
            "account_session_inactivity_days": 7,
            "account_session_absolute_lifetime_days": 30,
        }
    )

    return AuthMaterial(
        settings=settings,
        access_token=access_token,
        refresh_token=SecretStr("synthetic-refresh-token"),
        user_id=user_id,
        provider_session_id=provider_session_id,
        access_expires_at=datetime.fromtimestamp(expiry, tz=UTC),
        cache=AccountKeyCache(download),
        download=download,
    )


def test_creation_stores_verified_identity_and_protected_credentials(
    async_app_connection_factory: ConnectionFactory,
    material: AuthMaterial,
) -> None:
    async def check() -> None:
        async with async_app_connection_factory() as connection:
            created = await create_account_session(
                connection,
                material.settings,
                access_token=material.access_token,
                refresh_token=material.refresh_token,
                key_cache=material.cache,
            )

            stored = (
                await connection.execute(
                    select(AccountSession).where(AccountSession.id == created.session_id)
                )
            ).one()

            browser_token = created.token.get_secret_value()
            assert len(browser_token) == 43
            assert len(urlsafe_b64decode(browser_token + "=")) == 32
            assert stored.token_hash == sha256(browser_token.encode("ascii")).digest()
            assert stored.token_hash != browser_token.encode("ascii")
            assert browser_token not in repr(created)

            assert created.user_id == material.user_id
            assert stored.user_id == material.user_id
            assert stored.provider_session_id == material.provider_session_id
            assert stored.access_token_expires_at == material.access_expires_at
            assert (
                await connection.scalar(
                    select(UserProfile.id).where(UserProfile.id == material.user_id)
                )
                == material.user_id
            )

            key = material.settings.account_session_encryption_key
            assert key is not None
            cipher = AccountTokenCipher(key)

            assert cipher.decrypt(stored.access_token_ciphertext) == material.access_token
            assert cipher.decrypt(stored.refresh_token_ciphertext) == material.refresh_token
            assert stored.access_token_ciphertext != (
                material.access_token.get_secret_value().encode("ascii")
            )
            assert stored.refresh_token_ciphertext != (
                material.refresh_token.get_secret_value().encode("ascii")
            )

            assert stored.created_at == stored.last_seen_at
            assert stored.created_at.tzinfo is not None
            assert stored.idle_expires_at == created.idle_expires_at
            assert stored.absolute_expires_at == created.absolute_expires_at
            material.download.assert_awaited_once()

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


@pytest.mark.parametrize(
    ("inactivity_days", "absolute_days"),
    [(7, 30), (1, 1), (60, 30)],
)
def test_creation_respects_both_expiry_settings(
    async_app_connection_factory: ConnectionFactory,
    material: AuthMaterial,
    inactivity_days: int,
    absolute_days: int,
) -> None:
    settings = material.settings.model_copy(
        update={
            "account_session_inactivity_days": inactivity_days,
            "account_session_absolute_lifetime_days": absolute_days,
        }
    )

    async def check() -> None:
        async with async_app_connection_factory() as connection:
            created = await create_account_session(
                connection,
                settings,
                access_token=material.access_token,
                refresh_token=material.refresh_token,
                key_cache=material.cache,
            )
            created_at = await connection.scalar(
                select(AccountSession.created_at).where(AccountSession.id == created.session_id)
            )

            assert created_at is not None
            assert created.idle_expires_at - created_at == timedelta(
                days=min(inactivity_days, absolute_days)
            )
            assert created.absolute_expires_at - created_at == timedelta(days=absolute_days)

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_outer_rollback_removes_session_and_new_profile(
    async_app_connection_factory: ConnectionFactory,
    material: AuthMaterial,
) -> None:
    async def check() -> None:
        async with async_app_connection_factory() as connection:
            created = await create_account_session(
                connection,
                material.settings,
                access_token=material.access_token,
                refresh_token=material.refresh_token,
                key_cache=material.cache,
            )

        async with async_app_connection_factory() as connection:
            assert (
                await connection.scalar(
                    select(AccountSession.id).where(AccountSession.id == created.session_id)
                )
                is None
            )
            assert (
                await connection.scalar(
                    select(UserProfile.id).where(UserProfile.id == material.user_id)
                )
                is None
            )

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


async def assert_no_account_rows(
    connection: AsyncConnection,
    user_id: UUID,
) -> None:
    assert await connection.scalar(select(UserProfile.id).where(UserProfile.id == user_id)) is None
    assert (
        await connection.scalar(select(AccountSession.id).where(AccountSession.user_id == user_id))
        is None
    )


def test_missing_encryption_key_rejects_creation(
    async_app_connection_factory: ConnectionFactory,
    material: AuthMaterial,
) -> None:
    settings = material.settings.model_copy(update={"account_session_encryption_key": None})

    async def check() -> None:
        async with async_app_connection_factory() as connection:
            with pytest.raises(AccountSessionUnavailable) as caught:
                await create_account_session(
                    connection,
                    settings,
                    access_token=material.access_token,
                    refresh_token=material.refresh_token,
                    key_cache=material.cache,
                )

            assert str(caught.value) == "Account sessions are unavailable."
            material.download.assert_not_awaited()
            await assert_no_account_rows(connection, material.user_id)

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


@pytest.mark.parametrize("raw_token", ["", "not-a-token"])
def test_invalid_access_token_rejects_creation(
    async_app_connection_factory: ConnectionFactory,
    material: AuthMaterial,
    raw_token: str,
) -> None:
    async def check() -> None:
        async with async_app_connection_factory() as connection:
            with pytest.raises(InvalidAccountToken) as caught:
                await create_account_session(
                    connection,
                    material.settings,
                    access_token=SecretStr(raw_token),
                    refresh_token=material.refresh_token,
                    key_cache=material.cache,
                )

            assert str(caught.value) == "Invalid account token."
            material.download.assert_not_awaited()
            await assert_no_account_rows(connection, material.user_id)

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


@pytest.mark.parametrize("raw_refresh", ["", "\N{SNOWMAN}", "x" * 8193])
def test_invalid_refresh_token_format_rejects_creation(
    async_app_connection_factory: ConnectionFactory,
    material: AuthMaterial,
    raw_refresh: str,
) -> None:
    async def check() -> None:
        async with async_app_connection_factory() as connection:
            with pytest.raises(InvalidAccountToken) as caught:
                await create_account_session(
                    connection,
                    material.settings,
                    access_token=material.access_token,
                    refresh_token=SecretStr(raw_refresh),
                    key_cache=material.cache,
                )

            assert str(caught.value) == "Invalid account token."
            material.download.assert_awaited_once()
            await assert_no_account_rows(connection, material.user_id)

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_failed_session_insert_rolls_back_only_its_savepoint(
    async_app_connection_factory: ConnectionFactory,
    material: AuthMaterial,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Force a collision with an existing session's token hash.
    browser_token = "A" * 43
    digest = sha256(browser_token.encode("ascii")).digest()
    existing_user_id = uuid4()
    existing_session_id = uuid4()

    def duplicate_browser_token(_size: int) -> str:
        return browser_token

    monkeypatch.setattr(
        "app.account_sessions.token_urlsafe",
        duplicate_browser_token,
    )

    async def check() -> None:
        async with async_app_connection_factory() as connection:
            key = material.settings.account_session_encryption_key
            assert key is not None
            cipher = AccountTokenCipher(key)
            access_ciphertext = cipher.encrypt(SecretStr("existing-access"))
            refresh_ciphertext = cipher.encrypt(SecretStr("existing-refresh"))
            now = datetime.now(UTC)

            await connection.execute(insert(UserProfile).values(id=existing_user_id))
            await connection.execute(
                insert(AccountSession).values(
                    id=existing_session_id,
                    user_id=existing_user_id,
                    token_hash=digest,
                    provider_session_id=uuid4(),
                    access_token_ciphertext=access_ciphertext,
                    refresh_token_ciphertext=refresh_ciphertext,
                    access_token_expires_at=now + timedelta(hours=1),
                    created_at=now,
                    last_seen_at=now,
                    idle_expires_at=now + timedelta(days=7),
                    absolute_expires_at=now + timedelta(days=30),
                )
            )

            with pytest.raises(IntegrityError) as caught:
                await create_account_session(
                    connection,
                    material.settings,
                    access_token=material.access_token,
                    refresh_token=material.refresh_token,
                    key_cache=material.cache,
                )

            assert isinstance(caught.value.orig, UniqueViolation)
            assert caught.value.orig.diag.constraint_name == "uq_account_sessions_token_hash"

            await assert_no_account_rows(connection, material.user_id)

            existing = (
                await connection.execute(
                    select(AccountSession).where(AccountSession.id == existing_session_id)
                )
            ).one()

            assert existing.user_id == existing_user_id
            assert existing.token_hash == digest
            assert existing.access_token_ciphertext == access_ciphertext
            assert existing.refresh_token_ciphertext == refresh_ciphertext
            assert (
                await connection.scalar(
                    select(UserProfile.id).where(UserProfile.id == existing_user_id)
                )
                == existing_user_id
            )

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_creation_reuses_existing_account_profile(
    async_app_connection_factory: ConnectionFactory,
    material: AuthMaterial,
) -> None:
    async def check() -> None:
        async with async_app_connection_factory() as connection:
            original_created_at = datetime.now(UTC) - timedelta(days=1)
            await connection.execute(
                insert(UserProfile).values(
                    id=material.user_id,
                    created_at=original_created_at,
                )
            )

            created = await create_account_session(
                connection,
                material.settings,
                access_token=material.access_token,
                refresh_token=material.refresh_token,
                key_cache=material.cache,
            )

            assert created.user_id == material.user_id
            assert (
                await connection.scalar(
                    select(UserProfile.created_at).where(UserProfile.id == material.user_id)
                )
                == original_created_at
            )
            assert (
                await connection.scalar(
                    select(AccountSession.user_id).where(AccountSession.id == created.session_id)
                )
                == material.user_id
            )

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_token_expired_after_verification_rolls_back_new_profile(
    async_app_connection_factory: ConnectionFactory,
    material: AuthMaterial,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Simulate verification succeeding before a delay makes the token expire.
    authenticate = AsyncMock(
        return_value=VerifiedAccount(
            user_id=material.user_id,
            session_id=material.provider_session_id,
            assurance_level="aal1",
            access_token_expires_at=datetime.now(UTC) - timedelta(seconds=1),
        )
    )
    monkeypatch.setattr(
        "app.account_sessions.authenticate_account_token",
        authenticate,
    )

    async def check() -> None:
        async with async_app_connection_factory() as connection:
            with pytest.raises(InvalidAccountToken) as caught:
                await create_account_session(
                    connection,
                    material.settings,
                    access_token=material.access_token,
                    refresh_token=material.refresh_token,
                    key_cache=material.cache,
                )

            assert str(caught.value) == "Invalid account token."
            await assert_no_account_rows(connection, material.user_id)

            authenticate.assert_awaited_once_with(
                material.access_token,
                settings=material.settings,
                key_cache=material.cache,
            )

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)
