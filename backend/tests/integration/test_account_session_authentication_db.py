"""Stored-session authentication against guarded local PostgreSQL."""

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

import app.account_session_auth as session_auth
from app.account_auth import AccountAuthenticationUnavailable
from app.account_key_cache import AccountKeyCache
from app.account_key_fetch import AccountKeyFetchError
from app.account_session_auth import (
    LockedAccountSession,
    authenticate_stored_account_session,
)
from app.account_token_encryption import AccountTokenCipher
from app.account_tokens import VerifiedAccount
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
    user_id: UUID
    provider_session_id: UUID
    access_token: SecretStr
    access_expiry: datetime
    cipher: AccountTokenCipher
    cache: AccountKeyCache
    download: AsyncMock


@pytest.fixture
def material() -> AuthMaterial:
    signing_key = ec.generate_private_key(ec.SECP256R1())
    encryption_key = SecretStr(Fernet.generate_key().decode("ascii"))
    user_id = uuid4()
    provider_session_id = uuid4()
    now = int(datetime.now(UTC).timestamp())
    expiry = now + 300

    token = SecretStr(
        jwt.encode(
            {
                "iss": ISSUER,
                "aud": "authenticated",
                "iat": now - 1,
                "exp": expiry,
                "sub": str(user_id),
                "session_id": str(provider_session_id),
                "role": "authenticated",
                "is_anonymous": False,
                "aal": "aal1",
            },
            signing_key,
            algorithm="ES256",
            headers={"kid": "authentication-test-key"},
        )
    )

    public_jwk = ECAlgorithm.to_jwk(signing_key.public_key(), as_dict=True)
    public_jwk.update(
        {
            "kid": "authentication-test-key",
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
            "account_session_encryption_key": encryption_key,
            "account_session_inactivity_days": 7,
            "account_session_absolute_lifetime_days": 30,
        }
    )

    return AuthMaterial(
        settings=settings,
        user_id=user_id,
        provider_session_id=provider_session_id,
        access_token=token,
        access_expiry=datetime.fromtimestamp(expiry, tz=UTC),
        cipher=AccountTokenCipher(encryption_key),
        cache=AccountKeyCache(download),
        download=download,
    )


async def seed_session(
    connection: AsyncConnection,
    material: AuthMaterial,
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
        "access_token_ciphertext": material.cipher.encrypt(material.access_token),
        "refresh_token_ciphertext": material.cipher.encrypt(SecretStr("synthetic-refresh")),
        "access_token_expires_at": material.access_expiry,
        "created_at": now - timedelta(days=10),
        "last_seen_at": now - timedelta(days=1),
        "idle_expires_at": now + timedelta(days=6),
        "absolute_expires_at": now + timedelta(days=20),
    }
    values.update(overrides)

    await connection.execute(insert(UserProfile).values(id=values["user_id"]))
    await connection.execute(insert(AccountSession).values(**values))
    return session_id, token


@pytest.mark.parametrize("inactivity_days", [1, 7, 60])
def test_authentication_updates_only_matching_activity(
    async_app_connection_factory: ConnectionFactory,
    material: AuthMaterial,
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

            authenticated = await authenticate_stored_account_session(
                connection,
                token,
                settings=settings,
                key_cache=material.cache,
            )
            after = (await connection.execute(statement)).one()

            assert authenticated is not None
            assert authenticated.session_id == session_id
            assert authenticated.account.user_id == material.user_id
            assert authenticated.account.session_id == material.provider_session_id
            assert authenticated.account.access_token_expires_at == material.access_expiry
            assert authenticated.idle_expires_at == after.idle_expires_at
            assert authenticated.absolute_expires_at == before.absolute_expires_at

            assert after.last_seen_at > before.last_seen_at
            assert after.idle_expires_at == min(
                after.last_seen_at + timedelta(days=inactivity_days),
                before.absolute_expires_at,
            )

            for column in AccountSession.__table__.columns:
                if column.name not in {"last_seen_at", "idle_expires_at"}:
                    assert getattr(after, column.name) == getattr(before, column.name)

            assert (await connection.execute(other_statement)).one() == other_before
            assert connection.in_transaction()
            assert material.access_token.get_secret_value() not in repr(authenticated)
            material.download.assert_awaited_once()

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


@pytest.mark.parametrize(
    "failure",
    ["ciphertext", "identity", "signing-keys"],
)
def test_verification_failure_leaves_entire_row_unchanged(
    async_app_connection_factory: ConnectionFactory,
    material: AuthMaterial,
    failure: str,
) -> None:
    async def check() -> None:
        async with async_app_connection_factory() as connection:
            overrides: dict[str, object] = {}

            if failure == "ciphertext":
                overrides["access_token_ciphertext"] = b"unreadable"
            elif failure == "identity":
                overrides["provider_session_id"] = uuid4()
            else:
                material.download.side_effect = AccountKeyFetchError("Synthetic signing-key outage")

            session_id, token = await seed_session(
                connection,
                material,
                **overrides,
            )
            statement = select(AccountSession).where(AccountSession.id == session_id)
            before = (await connection.execute(statement)).one()

            with pytest.raises(AccountAuthenticationUnavailable):
                await authenticate_stored_account_session(
                    connection,
                    token,
                    settings=material.settings,
                    key_cache=material.cache,
                )

            assert (await connection.execute(statement)).one() == before
            assert connection.in_transaction()

            if failure == "ciphertext":
                material.download.assert_not_awaited()
            else:
                material.download.assert_awaited_once()

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_authenticated_activity_rolls_back_with_callers_savepoint(
    async_app_connection_factory: ConnectionFactory,
    material: AuthMaterial,
) -> None:
    async def check() -> None:
        async with async_app_connection_factory() as connection:
            session_id, token = await seed_session(connection, material)
            statement = select(AccountSession).where(AccountSession.id == session_id)
            before = (await connection.execute(statement)).one()

            savepoint = await connection.begin_nested()
            try:
                authenticated = await authenticate_stored_account_session(
                    connection,
                    token,
                    settings=material.settings,
                    key_cache=material.cache,
                )
                assert authenticated is not None

                updated = (await connection.execute(statement)).one()
                assert updated.last_seen_at > before.last_seen_at
                assert updated.idle_expires_at > before.idle_expires_at
            finally:
                await savepoint.rollback()

            assert (await connection.execute(statement)).one() == before

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_session_expiring_after_verification_is_not_extended(
    async_app_connection_factory: ConnectionFactory,
    material: AuthMaterial,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_verify = session_auth.verify_locked_account_access

    async def check() -> None:
        async with async_app_connection_factory() as connection:
            session_id, token = await seed_session(connection, material)
            statement = select(AccountSession).where(AccountSession.id == session_id)
            before = (await connection.execute(statement)).one()
            expected_rows: list[dict[str, object]] = []

            async def verify_then_expire(
                session: LockedAccountSession,
                *,
                settings: Settings,
                key_cache: AccountKeyCache | None,
            ) -> VerifiedAccount:
                account = await original_verify(
                    session,
                    settings=settings,
                    key_cache=key_cache,
                )

                # Deterministically simulate expiry between successful
                # verification and the final activity update.
                expired = (
                    await connection.execute(
                        update(AccountSession)
                        .where(AccountSession.id == session_id)
                        .values(
                            idle_expires_at=func.statement_timestamp(),
                        )
                        .returning(*AccountSession.__table__.c)
                    )
                ).one()
                expected_rows.append(dict(expired._mapping))
                return account

            monkeypatch.setattr(
                session_auth,
                "verify_locked_account_access",
                verify_then_expire,
            )

            authenticated = await authenticate_stored_account_session(
                connection,
                token,
                settings=material.settings,
                key_cache=material.cache,
            )

            assert authenticated is None
            assert len(expected_rows) == 1

            after = (await connection.execute(statement)).one()
            assert dict(after._mapping) == expected_rows[0]
            assert after.last_seen_at == before.last_seen_at
            assert after.absolute_expires_at == before.absolute_expires_at
            material.download.assert_awaited_once()

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


@pytest.mark.parametrize("seconds_after_expiry", [0, 1])
def test_access_expiry_is_rechecked_after_verification(
    async_app_connection_factory: ConnectionFactory,
    material: AuthMaterial,
    monkeypatch: pytest.MonkeyPatch,
    seconds_after_expiry: int,
) -> None:
    original_verify = session_auth.verify_locked_account_access

    async def check() -> None:
        async with async_app_connection_factory() as connection:
            session_id, token = await seed_session(connection, material)
            statement = select(AccountSession).where(AccountSession.id == session_id)
            before = (await connection.execute(statement)).one()
            verified_accounts: list[VerifiedAccount] = []

            async def verify_then_advance_check_time(
                session: LockedAccountSession,
                *,
                settings: Settings,
                key_cache: AccountKeyCache | None,
            ) -> VerifiedAccount:
                account = await original_verify(
                    session,
                    settings=settings,
                    key_cache=key_cache,
                )
                verified_accounts.append(account)

                checked_at = account.access_token_expires_at + timedelta(
                    seconds=seconds_after_expiry
                )

                # Application-session deadlines remain valid so the access
                # token's expiry is the reason authentication must fail.
                assert session.idle_expires_at > checked_at
                assert session.absolute_expires_at > checked_at

                # Simulate the final database check occurring later.
                # Keep the real SQL comparison and activity expressions.
                monkeypatch.setattr(
                    session_auth,
                    "func",
                    SimpleNamespace(
                        statement_timestamp=lambda: literal(checked_at),
                        greatest=func.greatest,
                        least=func.least,
                    ),
                )
                return account

            monkeypatch.setattr(
                session_auth,
                "verify_locked_account_access",
                verify_then_advance_check_time,
            )

            authenticated = await authenticate_stored_account_session(
                connection,
                token,
                settings=material.settings,
                key_cache=material.cache,
            )

            assert len(verified_accounts) == 1
            assert verified_accounts[0].access_token_expires_at == before.access_token_expires_at
            assert authenticated is None
            assert (await connection.execute(statement)).one() == before
            material.download.assert_awaited_once()

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


@pytest.mark.parametrize("seconds_after_expiry", [0, 1])
def test_absolute_expiry_is_rechecked_after_verification(
    async_app_connection_factory: ConnectionFactory,
    material: AuthMaterial,
    monkeypatch: pytest.MonkeyPatch,
    seconds_after_expiry: int,
) -> None:
    original_verify = session_auth.verify_locked_account_access

    async def check() -> None:
        async with async_app_connection_factory() as connection:
            deadline = func.statement_timestamp() + timedelta(minutes=1)
            session_id, token = await seed_session(
                connection,
                material,
                idle_expires_at=deadline,
                absolute_expires_at=deadline,
            )
            statement = select(AccountSession).where(AccountSession.id == session_id)
            before = (await connection.execute(statement)).one()
            verified_accounts: list[VerifiedAccount] = []

            async def verify_then_advance_check_time(
                session: LockedAccountSession,
                *,
                settings: Settings,
                key_cache: AccountKeyCache | None,
            ) -> VerifiedAccount:
                account = await original_verify(
                    session,
                    settings=settings,
                    key_cache=key_cache,
                )
                verified_accounts.append(account)

                checked_at = session.absolute_expires_at + timedelta(seconds=seconds_after_expiry)

                assert session.idle_expires_at == session.absolute_expires_at

                # The JWT remains valid at the simulated check time.
                assert account.access_token_expires_at > checked_at

                monkeypatch.setattr(
                    session_auth,
                    "func",
                    SimpleNamespace(
                        statement_timestamp=lambda: literal(checked_at),
                        greatest=func.greatest,
                        least=func.least,
                    ),
                )
                return account

            monkeypatch.setattr(
                session_auth,
                "verify_locked_account_access",
                verify_then_advance_check_time,
            )

            authenticated = await authenticate_stored_account_session(
                connection,
                token,
                settings=material.settings,
                key_cache=material.cache,
            )

            assert len(verified_accounts) == 1
            assert authenticated is None
            assert (await connection.execute(statement)).one() == before
            material.download.assert_awaited_once()

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)
