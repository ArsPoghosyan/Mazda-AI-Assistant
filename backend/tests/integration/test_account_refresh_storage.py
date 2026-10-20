"""Verified refresh storage on guarded local PostgreSQL."""

import asyncio
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from secrets import token_urlsafe
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import jwt
import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict
from sqlalchemy import func, insert, literal, select, update
from sqlalchemy.ext.asyncio import AsyncConnection

import app.account_session_refresh as session_refresh
from app.account_key_cache import AccountKeyCache
from app.account_refresh import RefreshedAccountTokens
from app.account_refresh_verification import (
    VerifiedAccountRefresh,
    verify_refreshed_account_tokens,
)
from app.account_session_auth import load_locked_account_session
from app.account_session_refresh import store_verified_account_refresh
from app.account_token_encryption import AccountTokenCipher
from app.config import Settings
from app.models import AccountSession, UserProfile

pytestmark = pytest.mark.integration

type ConnectionFactory = Callable[[], AbstractAsyncContextManager[AsyncConnection]]

ISSUER = "https://auth.example.test/auth/v1"


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@dataclass(frozen=True)
class StorageMaterial:
    settings: Settings
    user_id: UUID
    provider_session_id: UUID
    tokens: RefreshedAccountTokens
    cipher: AccountTokenCipher
    cache: AccountKeyCache
    download: AsyncMock


@pytest.fixture
def material() -> StorageMaterial:
    signing_key = ec.generate_private_key(ec.SECP256R1())
    encryption_key = SecretStr(Fernet.generate_key().decode("ascii"))
    user_id = uuid4()
    provider_session_id = uuid4()
    now = int(datetime.now(UTC).timestamp())

    tokens = RefreshedAccountTokens(
        access_token=SecretStr(
            jwt.encode(
                {
                    "iss": ISSUER,
                    "aud": "authenticated",
                    "iat": now - 1,
                    "exp": now + 300,
                    "sub": str(user_id),
                    "session_id": str(provider_session_id),
                    "role": "authenticated",
                    "is_anonymous": False,
                    "aal": "aal1",
                },
                signing_key,
                algorithm="ES256",
                headers={"kid": "refresh-storage-test-key"},
            )
        ),
        refresh_token=SecretStr("synthetic-replacement-refresh"),
    )

    public_jwk = ECAlgorithm.to_jwk(
        signing_key.public_key(),
        as_dict=True,
    )
    public_jwk.update(
        {
            "kid": "refresh-storage-test-key",
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
            "supabase_auth_publishable_key": None,
            "account_session_encryption_key": encryption_key,
            "account_session_inactivity_days": 7,
            "account_session_absolute_lifetime_days": 30,
        }
    )

    return StorageMaterial(
        settings=settings,
        user_id=user_id,
        provider_session_id=provider_session_id,
        tokens=tokens,
        cipher=AccountTokenCipher(encryption_key),
        cache=AccountKeyCache(download),
        download=download,
    )


async def seed_session(
    connection: AsyncConnection,
    material: StorageMaterial,
    **overrides: object,
) -> tuple[UUID, SecretStr]:
    session_id = uuid4()
    token = SecretStr(token_urlsafe(32))
    now = func.statement_timestamp()

    values: dict[str, object] = {
        "id": session_id,
        "user_id": material.user_id,
        "provider_session_id": material.provider_session_id,
        "token_hash": sha256(token.get_secret_value().encode("ascii")).digest(),
        "access_token_ciphertext": material.cipher.encrypt(SecretStr("synthetic-old-access")),
        "refresh_token_ciphertext": material.cipher.encrypt(SecretStr("synthetic-old-refresh")),
        "access_token_expires_at": now - timedelta(seconds=1),
        "created_at": now - timedelta(days=10),
        "last_seen_at": now - timedelta(days=1),
        "idle_expires_at": now + timedelta(days=6),
        "absolute_expires_at": now + timedelta(days=20),
    }
    values.update(overrides)

    await connection.execute(insert(UserProfile).values(id=values["user_id"]))
    await connection.execute(insert(AccountSession).values(**values))
    return session_id, token


async def verify_material(
    material: StorageMaterial,
) -> VerifiedAccountRefresh:
    return await verify_refreshed_account_tokens(
        material.tokens,
        expected_user_id=material.user_id,
        expected_provider_session_id=material.provider_session_id,
        settings=material.settings,
        key_cache=material.cache,
    )


@pytest.mark.parametrize("inactivity_days", [1, 7, 60])
def test_replacement_encrypts_both_tokens_and_preserves_other_data(
    async_app_connection_factory: ConnectionFactory,
    material: StorageMaterial,
    inactivity_days: int,
) -> None:
    settings = material.settings.model_copy(
        update={"account_session_inactivity_days": inactivity_days}
    )

    async def check() -> None:
        async with async_app_connection_factory() as connection:
            session_id, token = await seed_session(connection, material)
            other_id, _ = await seed_session(
                connection,
                material,
                user_id=uuid4(),
                provider_session_id=uuid4(),
            )
            statement = select(AccountSession).where(AccountSession.id == session_id)
            other_statement = select(AccountSession).where(AccountSession.id == other_id)
            before = (await connection.execute(statement)).one()
            other_before = (await connection.execute(other_statement)).one()

            session = await load_locked_account_session(connection, token)
            assert session is not None
            refreshed = await verify_material(material)

            authenticated = await store_verified_account_refresh(
                connection,
                session,
                refreshed,
                settings=settings,
            )
            after = (await connection.execute(statement)).one()

            assert authenticated is not None
            assert authenticated.session_id == session_id
            assert authenticated.account == refreshed.account
            assert authenticated.idle_expires_at == after.idle_expires_at
            assert authenticated.absolute_expires_at == before.absolute_expires_at

            assert (
                material.cipher.decrypt(after.access_token_ciphertext)
                == material.tokens.access_token
            )
            assert (
                material.cipher.decrypt(after.refresh_token_ciphertext)
                == material.tokens.refresh_token
            )

            assert after.access_token_ciphertext != before.access_token_ciphertext
            assert after.refresh_token_ciphertext != before.refresh_token_ciphertext
            assert after.access_token_ciphertext != (
                material.tokens.access_token.get_secret_value().encode("ascii")
            )
            assert after.refresh_token_ciphertext != (
                material.tokens.refresh_token.get_secret_value().encode("ascii")
            )
            assert after.access_token_expires_at == refreshed.account.access_token_expires_at

            assert after.last_seen_at > before.last_seen_at
            assert after.idle_expires_at == min(
                after.last_seen_at + timedelta(days=inactivity_days),
                before.absolute_expires_at,
            )

            changed_columns = {
                "access_token_ciphertext",
                "refresh_token_ciphertext",
                "access_token_expires_at",
                "last_seen_at",
                "idle_expires_at",
            }
            for column in AccountSession.__table__.columns:
                if column.name not in changed_columns:
                    assert getattr(after, column.name) == getattr(before, column.name)

            assert (await connection.execute(other_statement)).one() == other_before
            assert connection.in_transaction()
            material.download.assert_awaited_once()

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_replacement_rolls_back_with_callers_savepoint(
    async_app_connection_factory: ConnectionFactory,
    material: StorageMaterial,
) -> None:
    async def check() -> None:
        async with async_app_connection_factory() as connection:
            session_id, token = await seed_session(connection, material)
            statement = select(AccountSession).where(AccountSession.id == session_id)
            before = (await connection.execute(statement)).one()

            session = await load_locked_account_session(connection, token)
            assert session is not None
            refreshed = await verify_material(material)

            savepoint = await connection.begin_nested()
            try:
                authenticated = await store_verified_account_refresh(
                    connection,
                    session,
                    refreshed,
                    settings=material.settings,
                )
                assert authenticated is not None

                during = (await connection.execute(statement)).one()
                assert during.access_token_ciphertext != before.access_token_ciphertext
                assert during.refresh_token_ciphertext != before.refresh_token_ciphertext
                assert during.last_seen_at > before.last_seen_at
            finally:
                await savepoint.rollback()

            assert (await connection.execute(statement)).one() == before

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


@pytest.mark.parametrize(
    "changed_column",
    [
        "access_token_ciphertext",
        "refresh_token_ciphertext",
        "access_token_expires_at",
    ],
)
def test_stale_snapshot_cannot_overwrite_newer_credentials(
    async_app_connection_factory: ConnectionFactory,
    material: StorageMaterial,
    changed_column: str,
) -> None:
    async def check() -> None:
        async with async_app_connection_factory() as connection:
            session_id, token = await seed_session(connection, material)
            statement = select(AccountSession).where(AccountSession.id == session_id)

            session = await load_locked_account_session(connection, token)
            assert session is not None
            refreshed = await verify_material(material)

            # Deliberately make the snapshot stale within this test transaction.
            # Real concurrent refresh coordination will be tested separately.
            values: dict[str, object]
            if changed_column == "access_token_expires_at":
                values = {changed_column: (func.statement_timestamp() + timedelta(hours=1))}
            else:
                values = {
                    changed_column: material.cipher.encrypt(SecretStr("synthetic-newer-credential"))
                }

            expected = (
                await connection.execute(
                    update(AccountSession)
                    .where(AccountSession.id == session_id)
                    .values(**values)
                    .returning(*AccountSession.__table__.c)
                )
            ).one()

            assert getattr(expected, changed_column) != getattr(session, changed_column)

            authenticated = await store_verified_account_refresh(
                connection,
                session,
                refreshed,
                settings=material.settings,
            )

            assert authenticated is None

            after = (await connection.execute(statement)).one()
            assert after == expected
            assert after.last_seen_at == session.last_seen_at
            assert after.idle_expires_at == session.idle_expires_at
            assert after.absolute_expires_at == session.absolute_expires_at
            material.download.assert_awaited_once()

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


@pytest.mark.parametrize("deadline", ["idle", "absolute", "access"])
@pytest.mark.parametrize("seconds_after_expiry", [0, 1])
def test_expiry_prevents_credential_replacement(
    async_app_connection_factory: ConnectionFactory,
    material: StorageMaterial,
    monkeypatch: pytest.MonkeyPatch,
    deadline: str,
    seconds_after_expiry: int,
) -> None:
    async def check() -> None:
        async with async_app_connection_factory() as connection:
            overrides: dict[str, object] = {}

            if deadline != "access":
                soon = func.statement_timestamp() + timedelta(minutes=1)
                overrides["idle_expires_at"] = soon
                if deadline == "absolute":
                    overrides["absolute_expires_at"] = soon

            session_id, token = await seed_session(
                connection,
                material,
                **overrides,
            )
            statement = select(AccountSession).where(AccountSession.id == session_id)
            before = (await connection.execute(statement)).one()

            session = await load_locked_account_session(connection, token)
            assert session is not None
            refreshed = await verify_material(material)

            if deadline == "access":
                expiry = refreshed.account.access_token_expires_at
            elif deadline == "idle":
                expiry = session.idle_expires_at
            else:
                expiry = session.absolute_expires_at

            checked_at = expiry + timedelta(seconds=seconds_after_expiry)

            if deadline == "access":
                assert session.idle_expires_at > checked_at
                assert session.absolute_expires_at > checked_at
            else:
                assert refreshed.account.access_token_expires_at > checked_at
                if deadline == "idle":
                    assert session.absolute_expires_at > checked_at
                else:
                    assert session.idle_expires_at == session.absolute_expires_at

            # Simulate time passing after verification while retaining the
            # real PostgreSQL comparisons and credential-update statement.
            monkeypatch.setattr(
                session_refresh,
                "func",
                SimpleNamespace(
                    statement_timestamp=lambda: literal(checked_at),
                    greatest=func.greatest,
                    least=func.least,
                ),
            )

            authenticated = await store_verified_account_refresh(
                connection,
                session,
                refreshed,
                settings=material.settings,
            )

            assert authenticated is None
            assert (await connection.execute(statement)).one() == before
            material.download.assert_awaited_once()

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)
