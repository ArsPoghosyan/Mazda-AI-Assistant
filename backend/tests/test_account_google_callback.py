"""Callback sequencing through real transaction wrappers and verifier recovery."""

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
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

import app.account_google_callback as callback
import app.account_google_session as session_service
import app.account_oauth_transactions as transactions
from app.account_auth import AccountAuthenticationUnavailable
from app.account_google_exchange import (
    ExchangedGoogleTokens,
    GoogleCodeExchangeRejected,
    GoogleCodeExchangeUnavailable,
)
from app.account_key_cache import AccountKeyCache
from app.account_oauth_attempts import ConsumedOAuthLoginAttempt, OAuthLoginAttemptUnavailable
from app.account_oauth_material import InvalidOAuthLoginMaterial, recover_oauth_pkce_verifier
from app.account_sessions import (
    AccountSessionAlreadyExists,
    AccountSessionUnavailable,
    CreatedAccountSession,
)
from app.account_token_encryption import AccountTokenCipher
from app.account_tokens import InvalidAccountToken, VerifiedAccount
from app.config import Settings

pytestmark = pytest.mark.anyio
STAGES = ("consume", "consume_commit", "exchange", "verify", "persist", "session_commit")


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@dataclass
class Material:
    engine: Mock
    connection: AsyncConnection
    client: httpx2.AsyncClient
    settings: Settings
    key_cache: AccountKeyCache | None
    code: SecretStr
    browser_token: str
    verifier: SecretStr
    consumed: ConsumedOAuthLoginAttempt
    tokens: ExchangedGoogleTokens
    created: CreatedAccountSession
    operations: dict[str, AsyncMock]
    recover: Mock
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
            "account_google_oauth_timeout_seconds": 15,
            "account_google_oauth_api_enabled": False,
            "account_google_oauth_callback_url": None,
        }
    )
    assert settings.account_session_encryption_key is not None
    cipher = AccountTokenCipher(settings.account_session_encryption_key)
    verifier = SecretStr("v" * 43)
    now = datetime.now(UTC)
    consumed = ConsumedOAuthLoginAttempt(
        uuid4(), cipher.encrypt(verifier), now + timedelta(minutes=10)
    )
    tokens = ExchangedGoogleTokens(SecretStr("synthetic-access"), SecretStr("synthetic-refresh"))
    account = VerifiedAccount(uuid4(), uuid4(), "aal1", now + timedelta(hours=1))
    created = CreatedAccountSession(
        uuid4(),
        account.user_id,
        SecretStr("synthetic-cookie"),
        now + timedelta(days=7),
        now + timedelta(days=30),
    )
    events: list[str] = []

    async def consume(*args: object, **kwargs: object) -> ConsumedOAuthLoginAttempt:
        events.append("consume")
        return consumed

    def recover(ciphertext: bytes, *, cipher: AccountTokenCipher) -> SecretStr:
        events.append("recover")
        return recover_oauth_pkce_verifier(ciphertext, cipher=cipher)

    async def exchange(*args: object, **kwargs: object) -> ExchangedGoogleTokens:
        events.append("exchange")
        return tokens

    async def verify(*args: object, **kwargs: object) -> VerifiedAccount:
        events.append("verify")
        return account

    async def persist(*args: object, **kwargs: object) -> CreatedAccountSession:
        events.append("persist")
        return created

    operations = {
        "consume": AsyncMock(side_effect=consume),
        "consume_commit": AsyncMock(),
        "exchange": AsyncMock(side_effect=exchange),
        "verify": AsyncMock(side_effect=verify),
        "persist": AsyncMock(side_effect=persist),
        "session_commit": AsyncMock(),
    }
    connection = cast(AsyncConnection, Mock(spec=AsyncConnection))
    engine = Mock(spec=AsyncEngine)
    transaction_count = 0

    @asynccontextmanager
    async def transaction() -> AsyncIterator[AsyncConnection]:
        nonlocal transaction_count
        transaction_count += 1
        assert transaction_count <= 2, "Unexpected retry or extra transaction."
        name = "consume" if transaction_count == 1 else "session"
        events.append(f"{name}_begin")
        try:
            yield connection
        except BaseException:
            events.append(f"{name}_rollback")
            raise
        else:
            events.append(f"{name}_commit")
            await operations[f"{name}_commit"]()
        finally:
            events.append(f"{name}_release")

    engine.begin.side_effect = transaction
    recovery = Mock(side_effect=recover)
    monkeypatch.setattr(transactions, "consume_oauth_login_attempt", operations["consume"])
    monkeypatch.setattr(callback, "recover_oauth_pkce_verifier", recovery)
    monkeypatch.setattr(callback, "exchange_google_authorization_code", operations["exchange"])
    monkeypatch.setattr(session_service, "authenticate_active_account_token", operations["verify"])
    monkeypatch.setattr(session_service, "create_account_session", operations["persist"])
    return Material(
        engine,
        connection,
        cast(httpx2.AsyncClient, Mock(spec=httpx2.AsyncClient)),
        settings,
        cast(AccountKeyCache, Mock(spec=AccountKeyCache)),
        SecretStr("synthetic-code"),
        "b" * 43,
        verifier,
        consumed,
        tokens,
        created,
        operations,
        recovery,
        events,
    )


async def invoke(material: Material) -> CreatedAccountSession:
    return await callback.complete_google_callback(
        cast(AsyncEngine, material.engine),
        material.code,
        material.browser_token,
        settings=material.settings,
        client=material.client,
        key_cache=material.key_cache,
    )


def assert_stopped_at(material: Material, stage: str) -> None:
    index = STAGES.index(stage)
    for position, name in enumerate(STAGES):
        operation = material.operations[name]
        if position <= index:
            operation.assert_awaited_once()
        else:
            operation.assert_not_awaited()
    if index < STAGES.index("exchange"):
        material.recover.assert_not_called()
    else:
        material.recover.assert_called_once()


async def test_both_commits_and_release_precede_following_steps_and_return(
    material: Material,
) -> None:
    result = await invoke(material)
    material.events.append("returned")
    assert result is material.created
    assert material.events == [
        "consume_begin",
        "consume",
        "consume_commit",
        "consume_release",
        "recover",
        "exchange",
        "verify",
        "session_begin",
        "persist",
        "session_commit",
        "session_release",
        "returned",
    ]
    material.operations["consume"].assert_awaited_once_with(
        material.connection, material.browser_token
    )
    material.operations["exchange"].assert_awaited_once_with(
        material.code, material.verifier, settings=material.settings, client=material.client
    )
    material.operations["verify"].assert_awaited_once_with(
        material.tokens.access_token,
        settings=material.settings,
        key_cache=material.key_cache,
        client=material.client,
    )
    material.operations["persist"].assert_awaited_once_with(
        material.connection,
        material.settings,
        access_token=material.tokens.access_token,
        refresh_token=material.tokens.refresh_token,
        key_cache=material.key_cache,
    )
    for secret in (
        material.code,
        material.verifier,
        material.tokens.access_token,
        material.tokens.refresh_token,
        result.token,
    ):
        assert secret.get_secret_value() not in repr(result)
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
async def test_missing_prerequisite_preserves_attempt(material: Material, missing: str) -> None:
    if missing == "key_cache":
        material.key_cache = None
    else:
        material.settings = material.settings.model_copy(update={missing: None})
    with pytest.raises(GoogleCodeExchangeUnavailable, match="^Google sign-in is unavailable\\.$"):
        await invoke(material)
    material.engine.begin.assert_not_called()
    material.recover.assert_not_called()
    for operation in material.operations.values():
        operation.assert_not_awaited()


@pytest.mark.parametrize("code", ["", "x" * 1025, " ", "a b", "a\n", "a\x00", "é", "\x7f"])
async def test_invalid_code_preserves_attempt(material: Material, code: str) -> None:
    material.code = SecretStr(code)
    with pytest.raises(GoogleCodeExchangeRejected, match="^Google sign-in was rejected\\.$"):
        await invoke(material)
    material.engine.begin.assert_not_called()
    material.recover.assert_not_called()
    for operation in material.operations.values():
        operation.assert_not_awaited()


@pytest.mark.parametrize("code", ["x", "x" * 1024, "a_-=+/.~"])
async def test_valid_opaque_code_is_forwarded_unchanged(material: Material, code: str) -> None:
    material.code = SecretStr(code)
    assert await invoke(material) is material.created
    assert material.operations["exchange"].await_args is not None
    assert material.operations["exchange"].await_args.args[0].get_secret_value() == code


@pytest.mark.parametrize(
    ("stage", "failure"),
    [
        ("consume", InvalidOAuthLoginMaterial("Synthetic missing or expired attempt.")),
        ("consume", OAuthLoginAttemptUnavailable("Synthetic attempt outage.")),
        ("consume", SQLAlchemyError("Synthetic deletion failure.")),
        ("consume_commit", SQLAlchemyError("Synthetic uncertain consumption commit.")),
        ("exchange", GoogleCodeExchangeRejected("Synthetic code rejection.")),
        ("exchange", GoogleCodeExchangeUnavailable("Synthetic exchange outage.")),
        ("verify", InvalidAccountToken("Synthetic JWT rejection.")),
        ("verify", AccountAuthenticationUnavailable("Synthetic live-check outage.")),
        ("persist", InvalidAccountToken("Synthetic re-verification failure.")),
        ("persist", AccountSessionAlreadyExists("Synthetic duplicate session.")),
        ("persist", AccountSessionUnavailable("Synthetic persistence outage.")),
        ("persist", SQLAlchemyError("Synthetic insert failure.")),
        ("session_commit", SQLAlchemyError("Synthetic uncertain session commit.")),
    ],
)
async def test_failure_stops_later_steps_and_never_retries(
    material: Material,
    stage: str,
    failure: Exception,
) -> None:
    material.operations[stage].side_effect = failure
    with pytest.raises(type(failure)) as caught:
        await invoke(material)
    assert caught.value is failure
    assert_stopped_at(material, stage)
    if stage == "consume":
        assert material.events[-2:] == ["consume_rollback", "consume_release"]
    elif stage == "persist":
        assert material.events[-2:] == ["session_rollback", "session_release"]


@pytest.mark.parametrize("kind", ["empty", "corrupt", "wrong-key", "invalid-format"])
async def test_unreadable_verifier_stops_after_committed_consumption(
    material: Material,
    kind: str,
) -> None:
    assert material.settings.account_session_encryption_key is not None
    cipher = AccountTokenCipher(material.settings.account_session_encryption_key)
    ciphertext = {
        "empty": b"",
        "corrupt": b"invalid-ciphertext",
        "wrong-key": AccountTokenCipher(SecretStr(Fernet.generate_key().decode("ascii"))).encrypt(
            material.verifier
        ),
        "invalid-format": cipher.encrypt(SecretStr("not-a-generated-verifier")),
    }[kind]
    material.operations["consume"].side_effect = None
    material.operations["consume"].return_value = replace(
        material.consumed, pkce_verifier_ciphertext=ciphertext
    )
    with pytest.raises(InvalidOAuthLoginMaterial, match="^Invalid OAuth login material\\.$"):
        await invoke(material)
    material.operations["consume_commit"].assert_awaited_once()
    assert material.events == ["consume_begin", "consume_commit", "consume_release", "recover"]
    for stage in STAGES[2:]:
        material.operations[stage].assert_not_awaited()


@pytest.mark.parametrize("stage", ["consume_commit", "session_commit"])
async def test_pending_commit_exposes_neither_verifier_nor_final_result(
    material: Material,
    stage: str,
) -> None:
    entered = asyncio.Event()
    release = asyncio.Event()

    async def block() -> None:
        entered.set()
        await release.wait()

    material.operations[stage].side_effect = block
    async with asyncio.timeout(5):
        async with asyncio.TaskGroup() as group:
            task = group.create_task(invoke(material))
            await entered.wait()
            assert not task.done()
            assert_stopped_at(material, stage)
            release.set()
        assert task.result() is material.created


@pytest.mark.parametrize("stage", STAGES)
@pytest.mark.parametrize("cancelled", [False, True], ids=["deadline", "caller-cancellation"])
async def test_deadline_and_actual_cancellation_stop_each_awaited_stage(
    material: Material,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
    cancelled: bool,
) -> None:
    entered = asyncio.Event()
    cleaned_up = asyncio.Event()
    deadlines: list[asyncio.Timeout] = []

    def timeout(delay: float | None) -> asyncio.Timeout:
        deadline = asyncio.timeout(delay)
        deadlines.append(deadline)
        return deadline

    timeout_factory = Mock(side_effect=timeout)
    # Replace only this module's reference, preserving the test's safety timeout.
    monkeypatch.setattr(callback, "asyncio", SimpleNamespace(timeout=timeout_factory))

    async def block(*args: object, **kwargs: object) -> None:
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            cleaned_up.set()

    material.operations[stage].side_effect = block
    async with asyncio.timeout(5):
        task = asyncio.create_task(invoke(material))
        try:
            await entered.wait()
            assert not task.done()
            timeout_factory.assert_called_once_with(15)
            if cancelled:
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
                assert task.cancelled()
            else:
                # Expire the real shared Timeout deterministically at this stage.
                deadlines[0].reschedule(asyncio.get_running_loop().time())
                with pytest.raises(GoogleCodeExchangeUnavailable) as caught:
                    await task
                assert str(caught.value) == "Google sign-in is unavailable."
                assert caught.value.__suppress_context__ is True
                assert deadlines[0].expired()
        finally:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    assert cleaned_up.is_set()
    assert_stopped_at(material, stage)
    if stage in ("consume", "persist"):
        name = "consume" if stage == "consume" else "session"
        assert material.events[-2:] == [f"{name}_rollback", f"{name}_release"]


async def test_configured_deadline_expires_without_test_rescheduling(material: Material) -> None:
    material.settings = material.settings.model_copy(
        update={"account_google_oauth_timeout_seconds": 1}
    )
    cleaned_up = asyncio.Event()

    async def block(*args: object, **kwargs: object) -> None:
        try:
            await asyncio.Event().wait()
        finally:
            cleaned_up.set()

    material.operations["exchange"].side_effect = block
    async with asyncio.timeout(5):
        with pytest.raises(
            GoogleCodeExchangeUnavailable, match="^Google sign-in is unavailable\\.$"
        ):
            await invoke(material)
    assert cleaned_up.is_set()
    assert_stopped_at(material, "exchange")


@pytest.mark.parametrize("stage", ["consume", "exchange", "session_commit"])
async def test_nested_timeout_is_generic_and_never_retried(material: Material, stage: str) -> None:
    material.operations[stage].side_effect = TimeoutError("Synthetic private timeout detail.")
    with pytest.raises(GoogleCodeExchangeUnavailable) as caught:
        await invoke(material)
    assert str(caught.value) == "Google sign-in is unavailable."
    assert caught.value.__suppress_context__ is True
    assert_stopped_at(material, stage)
