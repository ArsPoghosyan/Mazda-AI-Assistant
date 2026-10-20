"""Account-session coordination without database or provider requests."""

import asyncio
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import cast
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import httpx2
import pytest
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncConnection

import app.account_session_service as service
from app.account_auth import AccountAuthenticationUnavailable
from app.account_key_cache import AccountKeyCache
from app.account_refresh import (
    AccountRefreshRejected,
    AccountRefreshUnavailable,
    RefreshedAccountTokens,
)
from app.account_refresh_verification import VerifiedAccountRefresh
from app.account_session_auth import (
    AuthenticatedAccountSession,
    LockedAccountSession,
)
from app.account_tokens import VerifiedAccount
from app.config import Settings

pytestmark = pytest.mark.anyio

TOKEN = SecretStr("A" * 43)


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@dataclass(frozen=True)
class CoordinatorMaterial:
    connection: AsyncMock
    settings: Settings
    client: httpx2.AsyncClient
    cache: AccountKeyCache
    session: LockedAccountSession
    authenticated: AuthenticatedAccountSession
    refreshed: VerifiedAccountRefresh
    load: AsyncMock
    valid: AsyncMock
    refresh: AsyncMock
    store: AsyncMock


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def material(monkeypatch: pytest.MonkeyPatch) -> CoordinatorMaterial:
    now = datetime.now(UTC)
    user_id = uuid4()
    provider_session_id = uuid4()

    settings = IsolatedSettings.model_validate(
        {
            "database_url": None,
            "migration_database_url": None,
            "supabase_auth_issuer": None,
            "supabase_auth_publishable_key": None,
            "account_session_encryption_key": None,
            "account_session_inactivity_days": 7,
        }
    )

    # Internal values are constructed directly because these tests isolate
    # coordination. Separate tests exercise encryption and JWT verification.
    session = LockedAccountSession(
        session_id=uuid4(),
        user_id=user_id,
        provider_session_id=provider_session_id,
        access_token_ciphertext=b"synthetic-access",
        refresh_token_ciphertext=b"synthetic-refresh",
        access_token_expires_at=now + timedelta(minutes=5),
        last_seen_at=now - timedelta(days=1),
        idle_expires_at=now + timedelta(days=7),
        absolute_expires_at=now + timedelta(days=30),
        checked_at=now,
    )
    account = VerifiedAccount(
        user_id=user_id,
        session_id=provider_session_id,
        assurance_level="aal1",
        access_token_expires_at=now + timedelta(minutes=5),
    )
    authenticated = AuthenticatedAccountSession(
        session_id=session.session_id,
        account=account,
        idle_expires_at=session.idle_expires_at,
        absolute_expires_at=session.absolute_expires_at,
    )
    refreshed = VerifiedAccountRefresh(
        account=account,
        tokens=RefreshedAccountTokens(
            access_token=SecretStr("synthetic-new-access"),
            refresh_token=SecretStr("synthetic-new-refresh"),
        ),
    )

    connection = AsyncMock(spec=AsyncConnection)
    connection.in_transaction.return_value = True
    client = cast(httpx2.AsyncClient, Mock(spec=httpx2.AsyncClient))
    cache = AccountKeyCache(AsyncMock())

    load = AsyncMock(return_value=session)
    valid = AsyncMock(return_value=authenticated)
    refresh = AsyncMock(return_value=refreshed)
    store = AsyncMock(return_value=authenticated)

    monkeypatch.setattr(service, "load_locked_account_session", load)
    monkeypatch.setattr(service, "authenticate_stored_account_session", valid)
    monkeypatch.setattr(service, "refresh_locked_account_tokens", refresh)
    monkeypatch.setattr(service, "store_verified_account_refresh", store)

    return CoordinatorMaterial(
        connection=connection,
        settings=settings,
        client=client,
        cache=cache,
        session=session,
        authenticated=authenticated,
        refreshed=refreshed,
        load=load,
        valid=valid,
        refresh=refresh,
        store=store,
    )


async def invoke(
    material: CoordinatorMaterial,
) -> AuthenticatedAccountSession | None:
    try:
        return await service.authenticate_account_session(
            cast(AsyncConnection, material.connection),
            TOKEN,
            settings=material.settings,
            client=material.client,
            key_cache=material.cache,
        )
    finally:
        # Transaction completion belongs to the caller on every path.
        material.connection.commit.assert_not_awaited()
        material.connection.rollback.assert_not_awaited()


def use_expired_session(
    material: CoordinatorMaterial,
    offset_seconds: int = 0,
) -> LockedAccountSession:
    session = replace(
        material.session,
        access_token_expires_at=(material.session.checked_at + timedelta(seconds=offset_seconds)),
    )
    material.load.return_value = session
    return session


async def test_missing_session_stops_before_authentication(
    material: CoordinatorMaterial,
) -> None:
    material.load.return_value = None

    assert await invoke(material) is None

    material.load.assert_awaited_once_with(material.connection, TOKEN)
    material.valid.assert_not_awaited()
    material.refresh.assert_not_awaited()
    material.store.assert_not_awaited()


@pytest.mark.parametrize("accepted", [True, False])
async def test_current_access_uses_existing_verification_without_refresh(
    material: CoordinatorMaterial,
    accepted: bool,
) -> None:
    expected = material.authenticated if accepted else None
    material.valid.return_value = expected

    assert await invoke(material) is expected

    material.valid.assert_awaited_once_with(
        material.connection,
        TOKEN,
        settings=material.settings,
        key_cache=material.cache,
    )
    material.refresh.assert_not_awaited()
    material.store.assert_not_awaited()


@pytest.mark.parametrize("offset_seconds", [0, -1])
async def test_expired_access_refreshes_once_then_stores_verified_result(
    material: CoordinatorMaterial,
    offset_seconds: int,
) -> None:
    session = use_expired_session(material, offset_seconds)

    assert await invoke(material) is material.authenticated

    material.valid.assert_not_awaited()
    material.refresh.assert_awaited_once_with(
        session,
        settings=material.settings,
        client=material.client,
        key_cache=material.cache,
    )
    material.store.assert_awaited_once_with(
        material.connection,
        session,
        material.refreshed,
        settings=material.settings,
    )


async def test_verification_failure_does_not_fall_back_to_refresh(
    material: CoordinatorMaterial,
) -> None:
    failure = AccountAuthenticationUnavailable("Account authentication is unavailable.")
    material.valid.side_effect = failure

    with pytest.raises(AccountAuthenticationUnavailable) as caught:
        await invoke(material)

    assert caught.value is failure
    material.valid.assert_awaited_once()
    material.refresh.assert_not_awaited()
    material.store.assert_not_awaited()


@pytest.mark.parametrize(
    "failure",
    [
        AccountRefreshRejected("Account credentials were rejected."),
        AccountRefreshUnavailable("Account refresh is unavailable."),
        asyncio.CancelledError(),
    ],
    ids=["rejected", "unavailable", "cancelled"],
)
async def test_refresh_failure_propagates_without_storage_or_retry(
    material: CoordinatorMaterial,
    failure: BaseException,
) -> None:
    use_expired_session(material)
    material.refresh.side_effect = failure

    with pytest.raises(type(failure)) as caught:
        await invoke(material)

    assert caught.value is failure
    material.valid.assert_not_awaited()
    material.refresh.assert_awaited_once()
    material.store.assert_not_awaited()


async def test_storage_guard_failure_returns_no_authenticated_identity(
    material: CoordinatorMaterial,
) -> None:
    use_expired_session(material)
    material.store.return_value = None

    assert await invoke(material) is None

    material.valid.assert_not_awaited()
    material.refresh.assert_awaited_once()
    material.store.assert_awaited_once()


async def test_storage_database_failure_propagates_without_retry(
    material: CoordinatorMaterial,
) -> None:
    use_expired_session(material)
    failure = SQLAlchemyError("Synthetic storage failure")
    material.store.side_effect = failure

    with pytest.raises(SQLAlchemyError) as caught:
        await invoke(material)

    assert caught.value is failure
    material.valid.assert_not_awaited()
    material.refresh.assert_awaited_once()
    material.store.assert_awaited_once()


async def test_invalid_inactivity_period_stops_before_provider_exchange(
    material: CoordinatorMaterial,
) -> None:
    use_expired_session(material)
    settings = material.settings.model_copy(update={"account_session_inactivity_days": 10**20})

    with pytest.raises(AccountAuthenticationUnavailable):
        await invoke(replace(material, settings=settings))

    material.valid.assert_not_awaited()
    material.refresh.assert_not_awaited()
    material.store.assert_not_awaited()
