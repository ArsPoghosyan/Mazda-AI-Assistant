"""Refresh storage guards before database writes."""

from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import cast
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict
from sqlalchemy.ext.asyncio import AsyncConnection

from app.account_refresh import (
    AccountRefreshUnavailable,
    RefreshedAccountTokens,
)
from app.account_refresh_verification import VerifiedAccountRefresh
from app.account_session_auth import LockedAccountSession
from app.account_session_refresh import store_verified_account_refresh
from app.account_token_encryption import AccountTokenCipher
from app.account_tokens import VerifiedAccount
from app.config import Settings

pytestmark = pytest.mark.anyio


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@dataclass(frozen=True)
class GuardMaterial:
    settings: Settings
    session: LockedAccountSession
    refreshed: VerifiedAccountRefresh


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def material() -> GuardMaterial:
    encryption_key = SecretStr(Fernet.generate_key().decode("ascii"))
    cipher = AccountTokenCipher(encryption_key)
    now = datetime.now(UTC)
    user_id = uuid4()
    provider_session_id = uuid4()

    settings = IsolatedSettings.model_validate(
        {
            "database_url": None,
            "migration_database_url": None,
            "supabase_auth_issuer": None,
            "supabase_auth_publishable_key": None,
            "account_session_encryption_key": encryption_key,
            "account_session_inactivity_days": 7,
        }
    )
    session = LockedAccountSession(
        session_id=uuid4(),
        user_id=user_id,
        provider_session_id=provider_session_id,
        access_token_ciphertext=cipher.encrypt(SecretStr("synthetic-old-access")),
        refresh_token_ciphertext=cipher.encrypt(SecretStr("synthetic-old-refresh")),
        access_token_expires_at=now - timedelta(seconds=1),
        last_seen_at=now - timedelta(days=1),
        idle_expires_at=now + timedelta(days=7),
        absolute_expires_at=now + timedelta(days=30),
        checked_at=now,
    )

    # Construct internal results directly to isolate storage guards.
    # Other tests exercise real JWT verification.
    refreshed = VerifiedAccountRefresh(
        account=VerifiedAccount(
            user_id=user_id,
            session_id=provider_session_id,
            assurance_level="aal1",
            access_token_expires_at=now + timedelta(minutes=5),
        ),
        tokens=RefreshedAccountTokens(
            access_token=SecretStr("synthetic-new-access"),
            refresh_token=SecretStr("synthetic-new-refresh"),
        ),
    )
    return GuardMaterial(settings, session, refreshed)


async def assert_unavailable_before_sql(material: GuardMaterial) -> None:
    connection = AsyncMock(spec=AsyncConnection)
    connection.in_transaction.return_value = True

    with pytest.raises(AccountRefreshUnavailable) as caught:
        await store_verified_account_refresh(
            cast(AsyncConnection, connection),
            material.session,
            material.refreshed,
            settings=material.settings,
        )

    assert str(caught.value) == "Account refresh is unavailable."
    connection.execute.assert_not_awaited()
    connection.scalar.assert_not_awaited()
    connection.commit.assert_not_awaited()
    connection.rollback.assert_not_awaited()


async def test_storage_requires_an_active_transaction(
    material: GuardMaterial,
) -> None:
    connection = AsyncMock(spec=AsyncConnection)
    connection.in_transaction.return_value = False

    with pytest.raises(RuntimeError, match="requires an active transaction"):
        await store_verified_account_refresh(
            cast(AsyncConnection, connection),
            material.session,
            material.refreshed,
            settings=material.settings,
        )

    connection.execute.assert_not_awaited()
    connection.commit.assert_not_awaited()
    connection.rollback.assert_not_awaited()


@pytest.mark.parametrize("field", ["user_id", "session_id"])
async def test_identity_mismatch_prevents_database_write(
    material: GuardMaterial,
    field: str,
) -> None:
    if field == "user_id":
        account = replace(material.refreshed.account, user_id=uuid4())
    else:
        account = replace(material.refreshed.account, session_id=uuid4())

    refreshed = replace(material.refreshed, account=account)

    await assert_unavailable_before_sql(replace(material, refreshed=refreshed))


async def test_missing_encryption_key_prevents_database_write(
    material: GuardMaterial,
) -> None:
    settings = material.settings.model_copy(update={"account_session_encryption_key": None})

    await assert_unavailable_before_sql(replace(material, settings=settings))


@pytest.mark.parametrize("field", ["access", "refresh"])
@pytest.mark.parametrize("plaintext", ["", "\N{SNOWMAN}", "x" * 8193])
async def test_unencryptable_token_prevents_database_write(
    material: GuardMaterial,
    field: str,
    plaintext: str,
) -> None:
    if field == "access":
        tokens = replace(
            material.refreshed.tokens,
            access_token=SecretStr(plaintext),
        )
    else:
        tokens = replace(
            material.refreshed.tokens,
            refresh_token=SecretStr(plaintext),
        )

    refreshed = replace(material.refreshed, tokens=tokens)

    await assert_unavailable_before_sql(replace(material, refreshed=refreshed))


async def test_overflowing_inactivity_period_prevents_database_write(
    material: GuardMaterial,
) -> None:
    settings = material.settings.model_copy(update={"account_session_inactivity_days": 10**20})

    await assert_unavailable_before_sql(replace(material, settings=settings))
