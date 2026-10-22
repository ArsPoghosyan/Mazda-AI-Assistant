"""Recovery identity binding without live providers or database access."""

import asyncio
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock
from uuid import UUID

import pytest
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict

from app.account_auth import AccountAuthenticationUnavailable
from app.account_key_cache import AccountKeyCache
from app.account_recovery_identity import verify_recovery_identity
from app.account_recovery_verification import (
    AccountRecoveryVerificationUnavailable,
    RecoveryVerificationCredentials,
)
from app.account_tokens import InvalidAccountToken, VerifiedAccount
from app.config import Settings

pytestmark = pytest.mark.anyio

USER_ID = UUID("11111111-1111-4111-8111-111111111111")
OTHER_USER_ID = UUID("33333333-3333-4333-8333-333333333333")
SESSION_ID = UUID("22222222-2222-4222-8222-222222222222")
ACCESS_TOKEN = "synthetic-recovery-access-token"
PRIVATE_DETAIL = "private-verification-detail"


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def settings() -> Settings:
    return IsolatedSettings.model_validate(
        {
            "database_url": None,
            "migration_database_url": None,
            "supabase_auth_issuer": "https://auth.example.test/auth/v1",
            "supabase_auth_audience": "authenticated",
        }
    )


@pytest.fixture
def credentials() -> RecoveryVerificationCredentials:
    return RecoveryVerificationCredentials(
        user_id=USER_ID,
        access_token=SecretStr(ACCESS_TOKEN),
    )


@pytest.fixture
def account() -> VerifiedAccount:
    return VerifiedAccount(
        user_id=USER_ID,
        session_id=SESSION_ID,
        assurance_level="aal1",
        access_token_expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


@pytest.fixture
def cache() -> AccountKeyCache:
    download = AsyncMock(side_effect=AssertionError("These helper tests must not fetch keys."))
    return AccountKeyCache(download)


async def test_matching_identity_uses_existing_authentication(
    monkeypatch: pytest.MonkeyPatch,
    settings: Settings,
    credentials: RecoveryVerificationCredentials,
    account: VerifiedAccount,
    cache: AccountKeyCache,
) -> None:
    authenticate = AsyncMock(return_value=account)
    monkeypatch.setattr(
        "app.account_recovery_identity.authenticate_account_token",
        authenticate,
    )

    result = await verify_recovery_identity(
        credentials,
        settings=settings,
        key_cache=cache,
    )

    assert result is account
    authenticate.assert_awaited_once_with(
        credentials.access_token,
        settings=settings,
        key_cache=cache,
    )


async def test_mismatched_account_is_blocked(
    monkeypatch: pytest.MonkeyPatch,
    settings: Settings,
    account: VerifiedAccount,
    cache: AccountKeyCache,
) -> None:
    credentials = RecoveryVerificationCredentials(
        user_id=OTHER_USER_ID,
        access_token=SecretStr(ACCESS_TOKEN),
    )
    authenticate = AsyncMock(return_value=account)
    monkeypatch.setattr(
        "app.account_recovery_identity.authenticate_account_token",
        authenticate,
    )

    with pytest.raises(AccountRecoveryVerificationUnavailable) as caught:
        await verify_recovery_identity(
            credentials,
            settings=settings,
            key_cache=cache,
        )

    assert str(caught.value) == "Recovery verification is unavailable."
    assert ACCESS_TOKEN not in repr(caught.value)
    assert str(USER_ID) not in repr(caught.value)
    assert str(OTHER_USER_ID) not in repr(caught.value)
    authenticate.assert_awaited_once()


@pytest.mark.parametrize(
    "exception_type",
    [InvalidAccountToken, AccountAuthenticationUnavailable],
)
async def test_verification_failures_are_masked(
    monkeypatch: pytest.MonkeyPatch,
    settings: Settings,
    credentials: RecoveryVerificationCredentials,
    cache: AccountKeyCache,
    exception_type: type[Exception],
) -> None:
    authenticate = AsyncMock(side_effect=exception_type(PRIVATE_DETAIL))
    monkeypatch.setattr(
        "app.account_recovery_identity.authenticate_account_token",
        authenticate,
    )

    with pytest.raises(AccountRecoveryVerificationUnavailable) as caught:
        await verify_recovery_identity(
            credentials,
            settings=settings,
            key_cache=cache,
        )

    assert str(caught.value) == "Recovery verification is unavailable."
    assert PRIVATE_DETAIL not in repr(caught.value)
    assert ACCESS_TOKEN not in repr(caught.value)
    assert caught.value.__suppress_context__
    authenticate.assert_awaited_once()


async def test_cancellation_propagates(
    monkeypatch: pytest.MonkeyPatch,
    settings: Settings,
    credentials: RecoveryVerificationCredentials,
    cache: AccountKeyCache,
) -> None:
    authenticate = AsyncMock(side_effect=asyncio.CancelledError())
    monkeypatch.setattr(
        "app.account_recovery_identity.authenticate_account_token",
        authenticate,
    )

    with pytest.raises(asyncio.CancelledError):
        await verify_recovery_identity(
            credentials,
            settings=settings,
            key_cache=cache,
        )

    authenticate.assert_awaited_once()


@pytest.mark.parametrize("missing", ["issuer", "cache"])
async def test_missing_verification_resources_fail_closed(
    settings: Settings,
    credentials: RecoveryVerificationCredentials,
    cache: AccountKeyCache,
    missing: str,
) -> None:
    if missing == "issuer":
        settings = settings.model_copy(update={"supabase_auth_issuer": None})

    with pytest.raises(AccountRecoveryVerificationUnavailable) as caught:
        await verify_recovery_identity(
            credentials,
            settings=settings,
            key_cache=None if missing == "cache" else cache,
        )

    assert str(caught.value) == "Recovery verification is unavailable."
    assert ACCESS_TOKEN not in repr(caught.value)
