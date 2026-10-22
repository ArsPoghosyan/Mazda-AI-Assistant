"""Account-session coordination without database or provider requests."""

import asyncio
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import cast
from unittest.mock import AsyncMock, Mock, patch
from uuid import UUID, uuid4

import httpx2
import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncConnection

import app.account_session_service as service
from app.account_auth import AccountAuthenticationUnavailable
from app.account_key_cache import AccountKeyCache
from app.account_provider_session import (
    AccountProviderSessionRejected,
    AccountProviderSessionUnavailable,
)
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
from app.account_token_encryption import AccountTokenCipher
from app.account_tokens import InvalidAccountToken, VerifiedAccount
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
    active: AsyncMock


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
            "account_session_encryption_key": Fernet.generate_key().decode("ascii"),
            "account_session_inactivity_days": 7,
        }
    )

    # Internal values are constructed directly because these tests isolate
    # coordination. Separate tests exercise encryption and JWT verification.
    encryption_key = settings.account_session_encryption_key
    assert encryption_key is not None
    cipher = AccountTokenCipher(encryption_key)
    session = LockedAccountSession(
        session_id=uuid4(),
        user_id=user_id,
        provider_session_id=provider_session_id,
        access_token_ciphertext=cipher.encrypt(SecretStr("synthetic-current-access")),
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
        active=AsyncMock(return_value=account),
    )


async def invoke(
    material: CoordinatorMaterial,
) -> AuthenticatedAccountSession | None:
    try:
        with patch.object(service, "verify_active_account_session_token", material.active):
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
    material.active.assert_not_awaited()
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


@pytest.fixture
def verification_mocks(
    material: CoordinatorMaterial,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[AsyncMock, AsyncMock]:
    authenticate = AsyncMock(return_value=material.authenticated.account)
    check = AsyncMock()
    monkeypatch.setattr(service, "authenticate_account_token", authenticate)
    monkeypatch.setattr(service, "check_provider_session", check)
    return authenticate, check


async def verify_session_token(material: CoordinatorMaterial) -> VerifiedAccount:
    return await service.verify_active_account_session_token(
        SecretStr("synthetic-session-access-token"),
        material.session,
        settings=material.settings,
        client=material.client,
        key_cache=material.cache,
    )


async def test_active_session_token_verifies_jwt_before_matching_provider_request(
    material: CoordinatorMaterial,
    verification_mocks: tuple[AsyncMock, AsyncMock],
) -> None:
    authenticate, check = verification_mocks
    account = material.authenticated.account
    token = SecretStr("synthetic-session-access-token")

    async def provider_check(*args: object, **kwargs: object) -> None:
        authenticate.assert_awaited_once_with(
            token, settings=material.settings, key_cache=material.cache
        )
        assert kwargs["verified_account"] is account

    check.side_effect = provider_check

    assert await verify_session_token(material) is account

    check.assert_awaited_once_with(
        token, verified_account=account, settings=material.settings, client=material.client
    )
    material.connection.execute.assert_not_awaited()
    material.connection.commit.assert_not_awaited()
    material.connection.rollback.assert_not_awaited()


@pytest.mark.parametrize("mismatch", ["account", "provider-session", "nil-session"])
async def test_active_session_token_rejects_identity_mismatch_before_provider_request(
    material: CoordinatorMaterial,
    verification_mocks: tuple[AsyncMock, AsyncMock],
    mismatch: str,
) -> None:
    authenticate, check = verification_mocks
    account = material.authenticated.account
    if mismatch == "account":
        account = replace(account, user_id=uuid4())
    elif mismatch == "provider-session":
        account = replace(account, session_id=uuid4())
    else:
        account = replace(account, session_id=UUID(int=0))
        material = replace(
            material, session=replace(material.session, provider_session_id=UUID(int=0))
        )
    authenticate.return_value = account

    with pytest.raises(AccountAuthenticationUnavailable) as caught:
        await verify_session_token(material)

    assert str(caught.value) == "Account authentication is unavailable."
    authenticate.assert_awaited_once()
    check.assert_not_awaited()


async def test_active_session_token_masks_invalid_stored_jwt_before_provider_request(
    material: CoordinatorMaterial,
    verification_mocks: tuple[AsyncMock, AsyncMock],
) -> None:
    authenticate, check = verification_mocks
    authenticate.side_effect = InvalidAccountToken("private-token-detail")

    with pytest.raises(AccountAuthenticationUnavailable) as caught:
        await verify_session_token(material)

    assert str(caught.value) == "Account authentication is unavailable."
    assert caught.value.__suppress_context__
    authenticate.assert_awaited_once()
    check.assert_not_awaited()


async def test_active_session_token_propagates_unavailable_jwt_verification(
    material: CoordinatorMaterial,
    verification_mocks: tuple[AsyncMock, AsyncMock],
) -> None:
    authenticate, check = verification_mocks
    failure = AccountAuthenticationUnavailable("Account authentication is unavailable.")
    authenticate.side_effect = failure

    with pytest.raises(AccountAuthenticationUnavailable) as caught:
        await verify_session_token(material)

    assert caught.value is failure
    authenticate.assert_awaited_once()
    check.assert_not_awaited()


@pytest.mark.parametrize(
    ("provider_error", "expected_error", "message"),
    [
        (
            AccountProviderSessionRejected,
            AccountRefreshRejected,
            "Account credentials were rejected.",
        ),
        (
            AccountProviderSessionUnavailable,
            AccountAuthenticationUnavailable,
            "Account authentication is unavailable.",
        ),
    ],
)
async def test_active_session_token_maps_provider_failure_without_fallback(
    material: CoordinatorMaterial,
    verification_mocks: tuple[AsyncMock, AsyncMock],
    provider_error: type[Exception],
    expected_error: type[Exception],
    message: str,
) -> None:
    authenticate, check = verification_mocks
    check.side_effect = provider_error("private-provider-detail")

    with pytest.raises(expected_error) as caught:
        await verify_session_token(material)

    assert str(caught.value) == message
    assert caught.value.__suppress_context__
    authenticate.assert_awaited_once()
    check.assert_awaited_once()
    material.connection.execute.assert_not_awaited()
    material.store.assert_not_awaited()


@pytest.mark.parametrize("stage", ["jwt", "provider"])
async def test_active_session_token_propagates_cancellation(
    material: CoordinatorMaterial,
    verification_mocks: tuple[AsyncMock, AsyncMock],
    stage: str,
) -> None:
    authenticate, check = verification_mocks
    cancellation = asyncio.CancelledError()
    if stage == "jwt":
        authenticate.side_effect = cancellation
    else:
        check.side_effect = cancellation

    with pytest.raises(asyncio.CancelledError) as caught:
        await verify_session_token(material)

    assert caught.value is cancellation
    authenticate.assert_awaited_once()
    if stage == "jwt":
        check.assert_not_awaited()
    else:
        check.assert_awaited_once()


@pytest.mark.parametrize("access_expired", [False, True])
async def test_live_check_finishes_before_activity_or_credential_storage(
    material: CoordinatorMaterial,
    access_expired: bool,
) -> None:
    session = use_expired_session(material) if access_expired else material.session

    async def active_check(*args: object, **kwargs: object) -> VerifiedAccount:
        material.valid.assert_not_awaited()
        material.store.assert_not_awaited()

        if access_expired:
            material.refresh.assert_awaited_once()
        else:
            material.refresh.assert_not_awaited()

        return material.authenticated.account

    material.active.side_effect = active_check

    assert await invoke(material) is material.authenticated

    expected_token = (
        material.refreshed.tokens.access_token
        if access_expired
        else SecretStr("synthetic-current-access")
    )
    material.active.assert_awaited_once_with(
        expected_token,
        session,
        settings=material.settings,
        client=material.client,
        key_cache=material.cache,
    )


@pytest.mark.parametrize("access_expired", [False, True])
@pytest.mark.parametrize(
    "failure",
    [
        AccountRefreshRejected("Account credentials were rejected."),
        AccountAuthenticationUnavailable("Account authentication is unavailable."),
        asyncio.CancelledError(),
    ],
    ids=["rejected", "unavailable", "cancelled"],
)
async def test_live_check_failure_prevents_updates_and_fallback(
    material: CoordinatorMaterial,
    access_expired: bool,
    failure: BaseException,
) -> None:
    if access_expired:
        use_expired_session(material)

    material.active.side_effect = failure

    with pytest.raises(type(failure)) as caught:
        await invoke(material)

    assert caught.value is failure
    material.active.assert_awaited_once()
    material.valid.assert_not_awaited()
    material.store.assert_not_awaited()

    if access_expired:
        material.refresh.assert_awaited_once()
    else:
        material.refresh.assert_not_awaited()


@pytest.mark.parametrize("problem", ["missing-key", "corrupt-ciphertext"])
async def test_unreadable_current_credentials_stop_before_live_check(
    material: CoordinatorMaterial,
    problem: str,
) -> None:
    if problem == "missing-key":
        material = replace(
            material,
            settings=material.settings.model_copy(update={"account_session_encryption_key": None}),
        )
    else:
        material.load.return_value = replace(
            material.session, access_token_ciphertext=b"corrupt-ciphertext"
        )

    with pytest.raises(AccountAuthenticationUnavailable):
        await invoke(material)

    material.active.assert_not_awaited()
    material.valid.assert_not_awaited()
    material.refresh.assert_not_awaited()
    material.store.assert_not_awaited()
