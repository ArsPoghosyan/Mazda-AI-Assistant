"""Password-reset coordination without live providers or PostgreSQL."""

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import cast
from unittest.mock import AsyncMock, Mock
from uuid import UUID, uuid4

import httpx2
import pytest
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

import app.account_password_reset_service as service
from app.account_key_cache import AccountKeyCache
from app.account_password_update import (
    AccountPasswordUpdateRateLimited,
    AccountPasswordUpdateRejected,
    AccountPasswordUpdateUnavailable,
)
from app.account_recovery_session_cleanup import (
    AccountRecoverySessionCleanupUnavailable,
)
from app.account_recovery_verification import (
    AccountRecoveryVerificationRateLimited,
    AccountRecoveryVerificationRejected,
    AccountRecoveryVerificationUnavailable,
    RecoveryVerificationCredentials,
)
from app.account_tokens import VerifiedAccount
from app.config import Settings

pytestmark = pytest.mark.anyio

EMAIL = SecretStr("owner@example.test")
CODE = SecretStr("001234")
NEW_PASSWORD = SecretStr("  synthetic-new-password-é  ")


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@dataclass(frozen=True)
class ResetMaterial:
    engine: Mock
    connection: AsyncConnection
    settings: Settings
    client: httpx2.AsyncClient
    key_cache: AccountKeyCache | None
    credentials: RecoveryVerificationCredentials
    account: VerifiedAccount
    steps: dict[str, AsyncMock]
    commit: AsyncMock
    events: list[str]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def material(monkeypatch: pytest.MonkeyPatch) -> ResetMaterial:
    settings = IsolatedSettings.model_validate(
        {
            "database_url": None,
            "migration_database_url": None,
            "supabase_auth_issuer": "https://auth.example.test/auth/v1",
            "supabase_auth_publishable_key": "sb_publishable_synthetic_test_key",
            "account_session_encryption_key": None,
        }
    )
    connection = cast(AsyncConnection, Mock(spec=AsyncConnection))
    client = cast(httpx2.AsyncClient, Mock(spec=httpx2.AsyncClient))
    key_cache = cast(AccountKeyCache, Mock(spec=AccountKeyCache))

    account = VerifiedAccount(
        user_id=uuid4(),
        session_id=uuid4(),
        assurance_level="aal1",
        access_token_expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    credentials = RecoveryVerificationCredentials(
        user_id=account.user_id,
        access_token=SecretStr("synthetic-recovery-access-token"),
    )

    events: list[str] = []
    commit = AsyncMock()

    def recorded_step(name: str, result: object = None) -> AsyncMock:
        async def run(*args: object, **kwargs: object) -> object:
            events.append(name)
            return result

        return AsyncMock(side_effect=run)

    steps = {
        "verify": recorded_step("verify", credentials),
        "identity": recorded_step("identity", account),
        "update": recorded_step("update"),
        "cleanup": recorded_step("cleanup"),
        "invalidate": recorded_step("invalidate", 2),
    }

    for step, function in (
        ("verify", "verify_recovery_code"),
        ("identity", "verify_recovery_identity"),
        ("update", "update_recovered_password"),
        ("cleanup", "cleanup_recovery_session"),
        ("invalidate", "invalidate_account_sessions"),
    ):
        monkeypatch.setattr(service, function, steps[step])

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

    return ResetMaterial(
        engine=engine,
        connection=connection,
        settings=settings,
        client=client,
        key_cache=key_cache,
        credentials=credentials,
        account=account,
        steps=steps,
        commit=commit,
        events=events,
    )


async def invoke(material: ResetMaterial) -> None:
    await service.reset_account_password(
        cast(AsyncEngine, material.engine),
        EMAIL,
        CODE,
        NEW_PASSWORD,
        settings=material.settings,
        client=material.client,
        key_cache=material.key_cache,
    )


async def test_reset_returns_only_after_cleanup_and_database_commit(
    material: ResetMaterial,
) -> None:
    await invoke(material)
    material.events.append("returned")

    assert material.events == [
        "verify",
        "identity",
        "update",
        "cleanup",
        "begin",
        "invalidate",
        "commit",
        "release",
        "returned",
    ]

    material.steps["verify"].assert_awaited_once_with(
        EMAIL,
        CODE,
        settings=material.settings,
        client=material.client,
    )
    material.steps["identity"].assert_awaited_once_with(
        material.credentials,
        settings=material.settings,
        key_cache=material.key_cache,
    )
    material.steps["update"].assert_awaited_once_with(
        material.credentials,
        NEW_PASSWORD,
        verified_account=material.account,
        settings=material.settings,
        client=material.client,
    )
    material.steps["cleanup"].assert_awaited_once_with(
        material.credentials,
        verified_account=material.account,
        settings=material.settings,
        client=material.client,
    )
    material.steps["invalidate"].assert_awaited_once_with(
        material.connection,
        material.account,
    )
    material.engine.begin.assert_called_once_with()
    material.commit.assert_awaited_once_with()


@pytest.mark.parametrize(
    "missing",
    ["supabase_auth_issuer", "supabase_auth_publishable_key", "key_cache"],
)
async def test_missing_configuration_stops_before_consuming_recovery_code(
    material: ResetMaterial,
    missing: str,
) -> None:
    if missing == "key_cache":
        material = replace(material, key_cache=None)
    else:
        material = replace(
            material,
            settings=material.settings.model_copy(update={missing: None}),
        )

    with pytest.raises(
        service.AccountPasswordResetUnavailable,
        match="Password reset is not configured",
    ):
        await invoke(material)

    assert material.events == []
    for step in material.steps.values():
        step.assert_not_awaited()
    material.engine.begin.assert_not_called()
    material.commit.assert_not_awaited()


async def test_nil_provider_session_stops_before_password_update(
    material: ResetMaterial,
) -> None:
    identity = material.steps["identity"]
    identity.side_effect = None
    identity.return_value = replace(material.account, session_id=UUID(int=0))

    with pytest.raises(
        service.AccountPasswordResetUnavailable,
        match="Password reset is unavailable",
    ):
        await invoke(material)

    assert material.events == ["verify"]
    material.steps["verify"].assert_awaited_once()
    identity.assert_awaited_once()
    material.steps["update"].assert_not_awaited()
    material.steps["cleanup"].assert_not_awaited()
    material.steps["invalidate"].assert_not_awaited()
    material.engine.begin.assert_not_called()
    material.commit.assert_not_awaited()


@pytest.mark.parametrize(
    ("stage", "failure_type"),
    [
        pytest.param(
            "verify",
            AccountRecoveryVerificationRejected,
            id="recovery-rejected",
        ),
        pytest.param(
            "verify",
            AccountRecoveryVerificationRateLimited,
            id="recovery-rate-limited",
        ),
        pytest.param(
            "verify",
            AccountRecoveryVerificationUnavailable,
            id="recovery-unavailable",
        ),
        pytest.param(
            "identity",
            AccountRecoveryVerificationUnavailable,
            id="identity-unavailable",
        ),
        pytest.param(
            "update",
            AccountPasswordUpdateRejected,
            id="password-rejected",
        ),
        pytest.param(
            "update",
            AccountPasswordUpdateRateLimited,
            id="password-rate-limited",
        ),
        pytest.param(
            "update",
            AccountPasswordUpdateUnavailable,
            id="password-update-unavailable",
        ),
        pytest.param(
            "cleanup",
            AccountRecoverySessionCleanupUnavailable,
            id="cleanup-unavailable",
        ),
        pytest.param(
            "invalidate",
            SQLAlchemyError,
            id="invalidation-failed",
        ),
    ]
    + [
        pytest.param(
            stage,
            asyncio.CancelledError,
            id=f"{stage}-cancelled",
        )
        for stage in ("verify", "identity", "update", "cleanup", "invalidate")
    ],
)
async def test_stage_failure_stops_later_operations_without_retry(
    material: ResetMaterial,
    stage: str,
    failure_type: type[BaseException],
) -> None:
    failure = failure_type("synthetic-failure")
    material.steps[stage].side_effect = failure

    with pytest.raises(failure_type) as caught:
        await invoke(material)

    assert caught.value is failure

    stages = ["verify", "identity", "update", "cleanup", "invalidate"]
    failed_index = stages.index(stage)
    cleanup_after_update_failure = stage == "update" and issubclass(failure_type, Exception)

    for index, name in enumerate(stages):
        should_run = index <= failed_index or (name == "cleanup" and cleanup_after_update_failure)
        if should_run:
            material.steps[name].assert_awaited_once()
        else:
            material.steps[name].assert_not_awaited()

    expected_events = stages[:failed_index]
    if cleanup_after_update_failure:
        expected_events.append("cleanup")
    if stage == "invalidate":
        expected_events += ["begin", "rollback", "release"]
        material.engine.begin.assert_called_once_with()
    else:
        material.engine.begin.assert_not_called()

    assert material.events == expected_events
    material.commit.assert_not_awaited()


@pytest.mark.parametrize(
    "failure_type",
    [SQLAlchemyError, asyncio.CancelledError],
    ids=["database-error", "cancelled"],
)
async def test_transaction_open_failure_prevents_invalidation(
    material: ResetMaterial,
    failure_type: type[BaseException],
) -> None:
    failure = failure_type("synthetic-transaction-open-failure")
    material.engine.begin.side_effect = failure

    with pytest.raises(failure_type) as caught:
        await invoke(material)

    assert caught.value is failure
    assert material.events == ["verify", "identity", "update", "cleanup"]

    for stage in ("verify", "identity", "update", "cleanup"):
        material.steps[stage].assert_awaited_once()

    material.engine.begin.assert_called_once_with()
    material.steps["invalidate"].assert_not_awaited()
    material.commit.assert_not_awaited()


@pytest.mark.parametrize(
    "failure_type",
    [SQLAlchemyError, asyncio.CancelledError],
    ids=["database-error", "cancelled"],
)
async def test_commit_failure_prevents_success_without_repeating_provider_work(
    material: ResetMaterial,
    failure_type: type[BaseException],
) -> None:
    failure = failure_type("synthetic-commit-failure")
    material.commit.side_effect = failure

    with pytest.raises(failure_type) as caught:
        await invoke(material)

    assert caught.value is failure
    assert material.events == [
        "verify",
        "identity",
        "update",
        "cleanup",
        "begin",
        "invalidate",
        "commit",
        "release",
    ]

    for step in material.steps.values():
        step.assert_awaited_once()

    material.engine.begin.assert_called_once_with()
    material.commit.assert_awaited_once_with()


async def test_no_existing_application_sessions_still_commits_successfully(
    material: ResetMaterial,
) -> None:
    invalidate = material.steps["invalidate"]
    invalidate.side_effect = None
    invalidate.return_value = 0

    await invoke(material)
    material.events.append("returned")

    invalidate.assert_awaited_once_with(
        material.connection,
        material.account,
    )
    material.commit.assert_awaited_once_with()
    assert material.events == [
        "verify",
        "identity",
        "update",
        "cleanup",
        "begin",
        "commit",
        "release",
        "returned",
    ]


@pytest.mark.parametrize(
    "update_failure_type",
    [
        AccountPasswordUpdateRejected,
        AccountPasswordUpdateRateLimited,
        AccountPasswordUpdateUnavailable,
    ],
)
async def test_failed_update_and_failed_cleanup_produce_reset_unavailable(
    material: ResetMaterial,
    update_failure_type: type[Exception],
) -> None:
    material.steps["update"].side_effect = update_failure_type("private-update-detail")
    material.steps["cleanup"].side_effect = AccountRecoverySessionCleanupUnavailable(
        "private-cleanup-detail"
    )

    with pytest.raises(service.AccountPasswordResetUnavailable) as caught:
        await invoke(material)

    assert str(caught.value) == "Password reset is unavailable."
    assert caught.value.__suppress_context__
    assert material.events == ["verify", "identity"]

    material.steps["update"].assert_awaited_once()
    material.steps["cleanup"].assert_awaited_once_with(
        material.credentials,
        verified_account=material.account,
        settings=material.settings,
        client=material.client,
    )
    material.steps["invalidate"].assert_not_awaited()
    material.engine.begin.assert_not_called()
    material.commit.assert_not_awaited()


async def test_cancellation_during_failed_update_cleanup_propagates(
    material: ResetMaterial,
) -> None:
    material.steps["update"].side_effect = AccountPasswordUpdateRejected(
        "Password update was rejected."
    )
    cancellation = asyncio.CancelledError()
    material.steps["cleanup"].side_effect = cancellation

    with pytest.raises(asyncio.CancelledError) as caught:
        await invoke(material)

    assert caught.value is cancellation
    material.steps["update"].assert_awaited_once()
    material.steps["cleanup"].assert_awaited_once()
    material.steps["invalidate"].assert_not_awaited()
    material.engine.begin.assert_not_called()
    material.commit.assert_not_awaited()


async def test_failed_update_cleanup_remains_within_the_callers_deadline(
    material: ResetMaterial,
) -> None:
    material.steps["update"].side_effect = AccountPasswordUpdateUnavailable(
        "Password update is unavailable."
    )
    cancelled = False

    async def stalled_cleanup(*args: object, **kwargs: object) -> None:
        nonlocal cancelled
        try:
            await asyncio.Future[None]()
        except asyncio.CancelledError:
            cancelled = True
            raise

    material.steps["cleanup"].side_effect = stalled_cleanup

    with pytest.raises(TimeoutError):
        async with asyncio.timeout(0.05):
            await invoke(material)

    assert cancelled
    material.steps["update"].assert_awaited_once()
    material.steps["cleanup"].assert_awaited_once()
    material.steps["invalidate"].assert_not_awaited()
    material.engine.begin.assert_not_called()
    material.commit.assert_not_awaited()


async def test_caller_cancellation_interrupts_pending_failed_update_cleanup(
    material: ResetMaterial,
) -> None:
    material.steps["update"].side_effect = AccountPasswordUpdateRejected(
        "Password update was rejected."
    )
    started = asyncio.Event()

    async def pending_cleanup(*args: object, **kwargs: object) -> None:
        started.set()
        await asyncio.Future[None]()

    material.steps["cleanup"].side_effect = pending_cleanup
    task = asyncio.create_task(invoke(material))
    try:
        await asyncio.wait_for(started.wait(), timeout=1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    material.steps["update"].assert_awaited_once()
    material.steps["cleanup"].assert_awaited_once()
    material.steps["invalidate"].assert_not_awaited()
    material.engine.begin.assert_not_called()
    material.commit.assert_not_awaited()
