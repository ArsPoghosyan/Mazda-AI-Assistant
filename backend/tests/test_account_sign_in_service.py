"""Sign-in orchestration without live provider or database calls."""

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import cast
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import httpx2
import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

import app.account_sign_in_service as service
from app.account_auth import AccountAuthenticationUnavailable
from app.account_key_cache import AccountKeyCache
from app.account_sessions import (
    AccountSessionAlreadyExists,
    AccountSessionUnavailable,
    CreatedAccountSession,
)
from app.account_sign_in import (
    AccountSignInCaptchaRejected,
    AccountSignInRejected,
    AccountSignInUnavailable,
    SignedInAccountTokens,
)
from app.account_tokens import InvalidAccountToken
from app.config import Settings

pytestmark = pytest.mark.anyio

EMAIL = SecretStr("owner@example.test")
PASSWORD = SecretStr("  synthetic-password-é  ")


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@dataclass
class SignInMaterial:
    engine: Mock
    connection: AsyncConnection
    settings: Settings
    client: httpx2.AsyncClient
    key_cache: AccountKeyCache | None
    tokens: SignedInAccountTokens
    created: CreatedAccountSession
    sign_in: AsyncMock
    create_session: AsyncMock
    commit: AsyncMock
    events: list[str]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def material(monkeypatch: pytest.MonkeyPatch) -> SignInMaterial:
    settings = IsolatedSettings.model_validate(
        {
            "database_url": None,
            "migration_database_url": None,
            "supabase_auth_issuer": "https://auth.example.test/auth/v1",
            "supabase_auth_publishable_key": "sb_publishable_synthetic_test_key",
            "account_session_encryption_key": Fernet.generate_key().decode("ascii"),
        }
    )

    connection = cast(AsyncConnection, Mock(spec=AsyncConnection))
    client = cast(httpx2.AsyncClient, Mock(spec=httpx2.AsyncClient))
    key_cache = cast(AccountKeyCache, Mock(spec=AccountKeyCache))

    tokens = SignedInAccountTokens(
        access_token=SecretStr("synthetic-access-token"),
        refresh_token=SecretStr("synthetic-refresh-token"),
    )

    now = datetime.now(UTC)
    created = CreatedAccountSession(
        session_id=uuid4(),
        user_id=uuid4(),
        token=SecretStr("A" * 43),
        idle_expires_at=now + timedelta(days=7),
        absolute_expires_at=now + timedelta(days=30),
    )

    events: list[str] = []
    commit = AsyncMock()

    async def provider_sign_in(
        *args: object,
        **kwargs: object,
    ) -> SignedInAccountTokens:
        events.append("provider")
        return tokens

    async def create_session(
        *args: object,
        **kwargs: object,
    ) -> CreatedAccountSession:
        events.append("create")
        return created

    sign_in = AsyncMock(side_effect=provider_sign_in)
    create = AsyncMock(side_effect=create_session)

    @asynccontextmanager
    async def transaction() -> AsyncIterator[AsyncConnection]:
        events.append("begin")
        try:
            yield connection
        except BaseException:
            events.append("rollback")
            raise
        else:
            events.append("commit")
            await commit()
        finally:
            events.append("release")

    engine = Mock(spec=AsyncEngine)
    engine.begin.side_effect = transaction

    monkeypatch.setattr(service, "sign_in_with_password", sign_in)
    monkeypatch.setattr(service, "create_account_session", create)

    return SignInMaterial(
        engine=engine,
        connection=connection,
        settings=settings,
        client=client,
        key_cache=key_cache,
        tokens=tokens,
        created=created,
        sign_in=sign_in,
        create_session=create,
        commit=commit,
        events=events,
    )


async def invoke(
    material: SignInMaterial,
    *,
    captcha_token: SecretStr | None = None,
) -> CreatedAccountSession:
    return await service.sign_in_account(
        cast(AsyncEngine, material.engine),
        EMAIL,
        PASSWORD,
        settings=material.settings,
        client=material.client,
        key_cache=material.key_cache,
        captcha_token=captcha_token,
    )


async def test_returns_session_after_commit_and_connection_release(
    material: SignInMaterial,
) -> None:
    result = await invoke(material)
    material.events.append("returned")

    assert result is material.created
    assert material.events == [
        "provider",
        "begin",
        "create",
        "commit",
        "release",
        "returned",
    ]

    material.sign_in.assert_awaited_once_with(
        EMAIL,
        PASSWORD,
        settings=material.settings,
        client=material.client,
        captcha_token=None,
    )
    material.create_session.assert_awaited_once_with(
        material.connection,
        material.settings,
        access_token=material.tokens.access_token,
        refresh_token=material.tokens.refresh_token,
        key_cache=material.key_cache,
    )
    material.engine.begin.assert_called_once_with()
    material.commit.assert_awaited_once_with()


@pytest.mark.parametrize(
    "missing",
    [
        "supabase_auth_issuer",
        "supabase_auth_publishable_key",
        "account_session_encryption_key",
        "key_cache",
    ],
)
async def test_missing_configuration_stops_before_provider_or_database(
    material: SignInMaterial,
    missing: str,
) -> None:
    if missing == "key_cache":
        material.key_cache = None
    else:
        material.settings = material.settings.model_copy(update={missing: None})

    with pytest.raises(
        AccountSignInUnavailable,
        match=r"^Account sign-in is not configured\.$",
    ):
        await invoke(material)

    assert material.events == []
    material.sign_in.assert_not_awaited()
    material.engine.begin.assert_not_called()
    material.create_session.assert_not_awaited()
    material.commit.assert_not_awaited()


@pytest.mark.parametrize(
    "failure",
    [
        AccountSignInRejected("Sign-in was rejected."),
        AccountSignInUnavailable("Account sign-in is unavailable."),
        asyncio.CancelledError(),
    ],
    ids=["rejected", "unavailable", "cancelled"],
)
async def test_provider_failure_does_not_open_database_transaction(
    material: SignInMaterial,
    failure: BaseException,
) -> None:
    material.sign_in.side_effect = failure

    with pytest.raises(type(failure)) as caught:
        await invoke(material)

    assert caught.value is failure
    assert material.events == []
    material.sign_in.assert_awaited_once()
    material.engine.begin.assert_not_called()
    material.create_session.assert_not_awaited()
    material.commit.assert_not_awaited()


@pytest.mark.parametrize(
    "failure",
    [
        InvalidAccountToken("Invalid account token."),
        AccountAuthenticationUnavailable("Account authentication is unavailable."),
        AccountSessionUnavailable("Account sessions are unavailable."),
        AccountSessionAlreadyExists("Account session already exists."),
        SQLAlchemyError("Synthetic session-creation failure"),
        asyncio.CancelledError(),
    ],
    ids=[
        "invalid-token",
        "verification-unavailable",
        "session-unavailable",
        "duplicate-session",
        "database-error",
        "cancelled",
    ],
)
async def test_session_creation_failure_exits_transaction_without_commit(
    material: SignInMaterial,
    failure: BaseException,
) -> None:
    material.create_session.side_effect = failure

    with pytest.raises(type(failure)) as caught:
        await invoke(material)

    assert caught.value is failure
    assert material.events == ["provider", "begin", "rollback", "release"]
    material.sign_in.assert_awaited_once()
    material.engine.begin.assert_called_once_with()
    material.create_session.assert_awaited_once()
    material.commit.assert_not_awaited()


@pytest.mark.parametrize(
    "failure",
    [
        SQLAlchemyError("Synthetic commit failure"),
        asyncio.CancelledError(),
    ],
    ids=["database-error", "cancelled"],
)
async def test_commit_failure_prevents_returning_session(
    material: SignInMaterial,
    failure: BaseException,
) -> None:
    material.commit.side_effect = failure

    with pytest.raises(type(failure)) as caught:
        await invoke(material)

    assert caught.value is failure
    assert material.events == ["provider", "begin", "create", "commit", "release"]
    material.sign_in.assert_awaited_once()
    material.engine.begin.assert_called_once_with()
    material.create_session.assert_awaited_once()
    material.commit.assert_awaited_once_with()


async def test_forwards_captcha_without_persisting_it(
    material: SignInMaterial,
) -> None:
    proof = SecretStr("synthetic-captcha-proof")

    result = await invoke(material, captcha_token=proof)

    assert result is material.created
    assert material.events == [
        "provider",
        "begin",
        "create",
        "commit",
        "release",
    ]

    material.sign_in.assert_awaited_once_with(
        EMAIL,
        PASSWORD,
        settings=material.settings,
        client=material.client,
        captcha_token=proof,
    )

    # Session storage receives provider credentials, not the CAPTCHA proof.
    material.create_session.assert_awaited_once_with(
        material.connection,
        material.settings,
        access_token=material.tokens.access_token,
        refresh_token=material.tokens.refresh_token,
        key_cache=material.key_cache,
    )
    material.commit.assert_awaited_once_with()
    assert proof.get_secret_value() not in repr(result)


@pytest.mark.parametrize(
    "captcha_token",
    [None, SecretStr("synthetic-captcha-proof")],
    ids=["missing-proof", "supplied-proof"],
)
async def test_captcha_rejection_prevents_database_work(
    material: SignInMaterial,
    captcha_token: SecretStr | None,
) -> None:
    failure = AccountSignInCaptchaRejected("Human verification was rejected.")
    material.sign_in.side_effect = failure

    with pytest.raises(AccountSignInCaptchaRejected) as caught:
        await invoke(material, captcha_token=captcha_token)

    assert caught.value is failure
    assert material.events == []

    material.sign_in.assert_awaited_once_with(
        EMAIL,
        PASSWORD,
        settings=material.settings,
        client=material.client,
        captcha_token=captcha_token,
    )
    material.engine.begin.assert_not_called()
    material.create_session.assert_not_awaited()
    material.commit.assert_not_awaited()
