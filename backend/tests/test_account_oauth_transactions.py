"""OAuth results become usable only after successful transaction completion."""

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import cast
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest
from pydantic import SecretStr
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

import app.account_oauth_transactions as transactions
from app.account_oauth_attempts import (
    ConsumedOAuthLoginAttempt,
    CreatedOAuthLoginAttempt,
    OAuthLoginAttemptUnavailable,
)
from app.account_oauth_material import InvalidOAuthLoginMaterial
from app.config import Settings

pytestmark = pytest.mark.anyio
OPERATIONS = ["create", "replace", "consume"]
TOKEN = "a" * 43
type Outcome = CreatedOAuthLoginAttempt | ConsumedOAuthLoginAttempt


@dataclass
class Material:
    engine: Mock
    connection: AsyncConnection
    settings: Settings
    operations: dict[str, AsyncMock]
    commit: AsyncMock
    events: list[str]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def material(monkeypatch: pytest.MonkeyPatch) -> Material:
    connection = cast(AsyncConnection, Mock(spec=AsyncConnection))
    # Configuration is passed through to mocked helpers without loading private files.
    settings = Settings.model_construct()
    expiry = datetime.now(UTC) + timedelta(minutes=10)
    created = CreatedOAuthLoginAttempt(uuid4(), SecretStr(TOKEN), "synthetic-challenge", expiry)
    consumed = ConsumedOAuthLoginAttempt(uuid4(), b"synthetic-ciphertext", expiry)
    operations = {
        "create": AsyncMock(return_value=created),
        "replace": AsyncMock(return_value=created),
        "consume": AsyncMock(return_value=consumed),
    }
    for name, operation in operations.items():
        monkeypatch.setattr(transactions, f"{name}_oauth_login_attempt", operation)
    commit = AsyncMock()
    events: list[str] = []

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
    return Material(engine, connection, settings, operations, commit, events)


async def invoke(material: Material, operation: str) -> Outcome:
    engine = cast(AsyncEngine, material.engine)
    if operation == "create":
        return await transactions.create_oauth_login_attempt_transaction(engine, material.settings)
    if operation == "replace":
        return await transactions.replace_oauth_login_attempt_transaction(
            engine, material.settings, TOKEN
        )
    return await transactions.consume_oauth_login_attempt_transaction(engine, TOKEN)


@pytest.mark.parametrize("operation", OPERATIONS)
async def test_returns_only_after_commit_and_connection_release(
    material: Material, operation: str
) -> None:
    result = await invoke(material, operation)
    material.events.append("returned")

    assert result is material.operations[operation].return_value
    assert material.events == ["begin", "commit", "release", "returned"]
    material.engine.begin.assert_called_once_with()
    material.commit.assert_awaited_once_with()
    if operation == "create":
        material.operations[operation].assert_awaited_once_with(
            material.connection, material.settings
        )
    elif operation == "replace":
        material.operations[operation].assert_awaited_once_with(
            material.connection, material.settings, TOKEN
        )
    else:
        material.operations[operation].assert_awaited_once_with(material.connection, TOKEN)
    for other in OPERATIONS:
        if other != operation:
            material.operations[other].assert_not_awaited()


@pytest.mark.parametrize("operation", OPERATIONS)
async def test_blocked_commit_does_not_expose_a_result(material: Material, operation: str) -> None:
    entered = asyncio.Event()
    release = asyncio.Event()

    async def blocked_commit() -> None:
        entered.set()
        await release.wait()

    material.commit.side_effect = blocked_commit
    async with asyncio.timeout(5):
        async with asyncio.TaskGroup() as group:
            task = group.create_task(invoke(material, operation))
            await entered.wait()
            assert not task.done()
            assert material.events == ["begin", "commit"]
            release.set()
        assert task.result() is material.operations[operation].return_value


@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize("cancelled", [False, True], ids=["commit-error", "cancelled"])
async def test_unsuccessful_commit_prevents_return_and_retry(
    material: Material, operation: str, cancelled: bool
) -> None:
    failure = (
        asyncio.CancelledError() if cancelled else SQLAlchemyError("Synthetic commit failure.")
    )
    material.commit.side_effect = failure

    with pytest.raises(type(failure)) as caught:
        await invoke(material, operation)

    assert caught.value is failure
    assert material.events == ["begin", "commit", "release"]
    material.operations[operation].assert_awaited_once()
    material.engine.begin.assert_called_once_with()


@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize("failure_kind", ["rejected", "unavailable", "database", "cancelled"])
async def test_operation_failure_rolls_back_without_commit_or_retry(
    material: Material, operation: str, failure_kind: str
) -> None:
    failures: dict[str, BaseException] = {
        "rejected": InvalidOAuthLoginMaterial("Invalid OAuth login material."),
        "unavailable": OAuthLoginAttemptUnavailable("OAuth login is unavailable."),
        "database": SQLAlchemyError("Synthetic database failure."),
        "cancelled": asyncio.CancelledError(),
    }
    failure = failures[failure_kind]
    material.operations[operation].side_effect = failure

    with pytest.raises(type(failure)) as caught:
        await invoke(material, operation)

    assert caught.value is failure
    assert material.events == ["begin", "rollback", "release"]
    material.commit.assert_not_awaited()
    material.operations[operation].assert_awaited_once()
    material.engine.begin.assert_called_once_with()


@pytest.mark.parametrize("operation", OPERATIONS)
async def test_connection_acquisition_failure_never_invokes_helper(
    material: Material, operation: str
) -> None:
    failure = SQLAlchemyError("Synthetic connection acquisition failure.")
    material.engine.begin.side_effect = failure

    with pytest.raises(SQLAlchemyError) as caught:
        await invoke(material, operation)

    assert caught.value is failure
    assert material.events == []
    for helper in material.operations.values():
        helper.assert_not_awaited()
    material.commit.assert_not_awaited()


@pytest.mark.parametrize("operation", OPERATIONS)
async def test_task_cancellation_while_commit_is_pending_returns_no_material(
    material: Material, operation: str
) -> None:
    entered = asyncio.Event()

    async def blocked_commit() -> None:
        entered.set()
        await asyncio.Event().wait()

    material.commit.side_effect = blocked_commit
    async with asyncio.timeout(5):
        async with asyncio.TaskGroup() as group:
            task = group.create_task(invoke(material, operation))
            await entered.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

    assert task.cancelled()
    assert material.events == ["begin", "commit", "release"]
    material.operations[operation].assert_awaited_once()
    material.engine.begin.assert_called_once_with()
