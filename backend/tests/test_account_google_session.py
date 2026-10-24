"""Google-exchanged credentials reach a browser session only after verification/commit."""

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

import app.account_google_session as service
from app.account_auth import AccountAuthenticationUnavailable
from app.account_google_exchange import ExchangedGoogleTokens, GoogleCodeExchangeUnavailable
from app.account_key_cache import AccountKeyCache
from app.account_sessions import (
    AccountSessionAlreadyExists,
    AccountSessionUnavailable,
    CreatedAccountSession,
)
from app.account_tokens import InvalidAccountToken, VerifiedAccount
from app.config import Settings

pytestmark = pytest.mark.anyio


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@dataclass
class Material:
    engine: Mock
    connection: AsyncConnection
    client: httpx2.AsyncClient
    settings: Settings
    key_cache: AccountKeyCache | None
    tokens: ExchangedGoogleTokens
    created: CreatedAccountSession
    verify: AsyncMock
    persist: AsyncMock
    commit: AsyncMock
    events: list[str]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def material(monkeypatch: pytest.MonkeyPatch) -> Material:
    settings = IsolatedSettings.model_validate(
        {
            "database_url": None,
            "migration_database_url": None,
            "supabase_auth_issuer": "https://auth.example.test/auth/v1",
            "supabase_auth_publishable_key": "sb_publishable_synthetic",
            "account_session_encryption_key": Fernet.generate_key().decode("ascii"),
            "account_google_oauth_api_enabled": False,
            "account_google_oauth_callback_url": None,
        }
    )
    connection = cast(AsyncConnection, Mock(spec=AsyncConnection))
    client = cast(httpx2.AsyncClient, Mock(spec=httpx2.AsyncClient))
    key_cache = cast(AccountKeyCache, Mock(spec=AccountKeyCache))
    tokens = ExchangedGoogleTokens(SecretStr("synthetic-access"), SecretStr("synthetic-refresh"))
    now = datetime.now(UTC)
    account = VerifiedAccount(uuid4(), uuid4(), "aal1", now + timedelta(hours=1))
    created = CreatedAccountSession(
        uuid4(),
        account.user_id,
        SecretStr("synthetic-browser-cookie"),
        now + timedelta(days=7),
        now + timedelta(days=30),
    )
    events: list[str] = []

    async def verify(
        token: SecretStr,
        *,
        settings: Settings,
        key_cache: AccountKeyCache | None,
        client: httpx2.AsyncClient,
    ) -> VerifiedAccount:
        events.append("verify")
        return account

    async def persist(
        connection: AsyncConnection,
        settings: Settings,
        *,
        access_token: SecretStr,
        refresh_token: SecretStr,
        key_cache: AccountKeyCache | None,
    ) -> CreatedAccountSession:
        events.append("persist")
        return created

    verification = AsyncMock(side_effect=verify)
    persistence = AsyncMock(side_effect=persist)
    commit = AsyncMock()

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
    monkeypatch.setattr(service, "authenticate_active_account_token", verification)
    monkeypatch.setattr(service, "create_account_session", persistence)
    return Material(
        engine,
        connection,
        client,
        settings,
        key_cache,
        tokens,
        created,
        verification,
        persistence,
        commit,
        events,
    )


async def invoke(material: Material) -> CreatedAccountSession:
    return await service.create_google_account_session(
        cast(AsyncEngine, material.engine),
        material.tokens,
        settings=material.settings,
        client=material.client,
        key_cache=material.key_cache,
    )


@pytest.mark.parametrize("phase", ["verify", "begin", "persist", "commit"])
@pytest.mark.parametrize("cancelled", [False, True])
async def test_incomplete_google_session_logs_only_stage_and_preserves_failure(
    material: Material, caplog: pytest.LogCaptureFixture, phase: str, cancelled: bool
) -> None:
    failure = (
        asyncio.CancelledError("private-provider-detail")
        if cancelled
        else SQLAlchemyError("private-provider-detail")
    )
    if phase == "verify":
        material.verify.side_effect = failure
    elif phase == "begin":
        material.engine.begin.side_effect = failure
    elif phase == "persist":
        material.persist.side_effect = failure
    else:
        material.commit.side_effect = failure

    with pytest.raises(type(failure)) as caught:
        await invoke(material)
    assert caught.value is failure
    stages = {
        "verify": "verify_provider_session",
        "begin": "open_local_transaction",
        "persist": "persist_local_session",
        "commit": "commit_or_release",
    }
    records = [record for record in caplog.records if record.name == service.__name__]
    assert [record.getMessage() for record in records] == [
        f"Google sign-in incomplete after provider response: stage={stages[phase]}"
    ]
    assert all(record.exc_info is None for record in records)
    for secret in (
        "private-provider-detail",
        material.tokens.access_token.get_secret_value(),
        material.tokens.refresh_token.get_secret_value(),
        material.created.token.get_secret_value(),
    ):
        assert secret not in caplog.text
    assert material.verify.await_count == 1
    assert material.persist.await_count == (1 if phase in ("persist", "commit") else 0)


async def test_returns_only_application_session_after_verification_commit_and_release(
    material: Material,
) -> None:
    result = await invoke(material)
    material.events.append("returned")

    assert result is material.created
    assert material.events == ["verify", "begin", "persist", "commit", "release", "returned"]
    material.verify.assert_awaited_once_with(
        material.tokens.access_token,
        settings=material.settings,
        key_cache=material.key_cache,
        client=material.client,
    )
    material.persist.assert_awaited_once_with(
        material.connection,
        material.settings,
        access_token=material.tokens.access_token,
        refresh_token=material.tokens.refresh_token,
        key_cache=material.key_cache,
    )
    material.engine.begin.assert_called_once_with()
    material.commit.assert_awaited_once_with()
    assert result.token != material.tokens.access_token
    assert result.token != material.tokens.refresh_token
    for token in (material.tokens.access_token, material.tokens.refresh_token, result.token):
        assert token.get_secret_value() not in repr(result)
    assert material.settings.account_google_oauth_api_enabled is False


@pytest.mark.parametrize(
    "missing",
    [
        "supabase_auth_issuer",
        "supabase_auth_publishable_key",
        "account_session_encryption_key",
        "key_cache",
    ],
)
async def test_missing_configuration_stops_before_verification_or_database(
    material: Material, missing: str
) -> None:
    if missing == "key_cache":
        material.key_cache = None
    else:
        material.settings = material.settings.model_copy(update={missing: None})
    with pytest.raises(GoogleCodeExchangeUnavailable, match="^Google sign-in is unavailable\\.$"):
        await invoke(material)

    material.verify.assert_not_awaited()
    material.persist.assert_not_awaited()
    material.engine.begin.assert_not_called()
    assert material.events == []


@pytest.mark.parametrize(
    "failure",
    [
        InvalidAccountToken("Synthetic rejected credential."),
        AccountAuthenticationUnavailable("Synthetic provider outage."),
        SQLAlchemyError("Synthetic verification failure."),
        asyncio.CancelledError(),
    ],
    ids=["rejected", "unavailable", "unexpected-database-error", "cancelled"],
)
async def test_verification_failure_never_opens_transaction(
    material: Material, failure: BaseException
) -> None:
    material.verify.side_effect = failure
    with pytest.raises(type(failure)) as caught:
        await invoke(material)

    assert caught.value is failure
    material.verify.assert_awaited_once()
    material.persist.assert_not_awaited()
    material.engine.begin.assert_not_called()
    material.commit.assert_not_awaited()


@pytest.mark.parametrize(
    "failure",
    [
        InvalidAccountToken("Synthetic expiry during persistence."),
        AccountSessionUnavailable("Synthetic unavailable persistence."),
        AccountSessionAlreadyExists("Synthetic duplicate session."),
        SQLAlchemyError("Synthetic persistence failure."),
        asyncio.CancelledError(),
    ],
    ids=["reverification", "unavailable", "duplicate", "database", "cancelled"],
)
async def test_persistence_failure_rolls_back_without_retry(
    material: Material, failure: BaseException
) -> None:
    material.persist.side_effect = failure
    with pytest.raises(type(failure)) as caught:
        await invoke(material)

    assert caught.value is failure
    assert material.events == ["verify", "begin", "rollback", "release"]
    material.verify.assert_awaited_once()
    material.persist.assert_awaited_once()
    material.commit.assert_not_awaited()
    material.engine.begin.assert_called_once_with()


@pytest.mark.parametrize("cancelled", [False, True], ids=["commit-error", "cancelled"])
async def test_commit_failure_never_returns_browser_credential(
    material: Material, cancelled: bool
) -> None:
    failure = (
        asyncio.CancelledError() if cancelled else SQLAlchemyError("Synthetic commit failure.")
    )
    material.commit.side_effect = failure
    with pytest.raises(type(failure)) as caught:
        await invoke(material)

    assert caught.value is failure
    assert material.events == ["verify", "begin", "persist", "commit", "release"]
    material.persist.assert_awaited_once()
    material.engine.begin.assert_called_once_with()


async def test_connection_failure_after_verification_does_not_persist(material: Material) -> None:
    failure = SQLAlchemyError("Synthetic connection acquisition failure.")
    material.engine.begin.side_effect = failure
    with pytest.raises(SQLAlchemyError) as caught:
        await invoke(material)

    assert caught.value is failure
    assert material.events == ["verify"]
    material.persist.assert_not_awaited()
    material.commit.assert_not_awaited()


async def test_pending_live_verification_does_not_hold_database_transaction(
    material: Material,
) -> None:
    entered = asyncio.Event()
    release = asyncio.Event()

    async def blocked_verify(*args: object, **kwargs: object) -> None:
        entered.set()
        await release.wait()

    material.verify.side_effect = blocked_verify
    async with asyncio.timeout(5):
        async with asyncio.TaskGroup() as group:
            task = group.create_task(invoke(material))
            await entered.wait()
            material.engine.begin.assert_not_called()
            material.persist.assert_not_awaited()
            assert not task.done()
            release.set()
        assert task.result() is material.created


async def test_pending_commit_does_not_expose_browser_credential(material: Material) -> None:
    entered = asyncio.Event()
    release = asyncio.Event()

    async def blocked_commit() -> None:
        entered.set()
        await release.wait()

    material.commit.side_effect = blocked_commit
    async with asyncio.timeout(5):
        async with asyncio.TaskGroup() as group:
            task = group.create_task(invoke(material))
            await entered.wait()
            assert not task.done()
            assert material.events == ["verify", "begin", "persist", "commit"]
            release.set()
        assert task.result() is material.created


@pytest.mark.parametrize("stage", ["verify", "persist", "commit"])
async def test_actual_task_cancellation_returns_no_result(material: Material, stage: str) -> None:
    entered = asyncio.Event()

    async def block(*args: object, **kwargs: object) -> None:
        if stage != "commit":
            material.events.append(stage)
        entered.set()
        await asyncio.Event().wait()

    operation = {"verify": material.verify, "persist": material.persist, "commit": material.commit}[
        stage
    ]
    operation.side_effect = block
    async with asyncio.timeout(5):
        async with asyncio.TaskGroup() as group:
            task = group.create_task(invoke(material))
            await entered.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

    assert task.cancelled()
    if stage == "verify":
        material.engine.begin.assert_not_called()
    elif stage == "persist":
        assert material.events[-2:] == ["rollback", "release"]
        material.commit.assert_not_awaited()
    else:
        assert material.events[-2:] == ["commit", "release"]
