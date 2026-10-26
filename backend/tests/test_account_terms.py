"""Authenticated Terms transactions report success only after commit."""

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import httpx2
import pytest
from pydantic import SecretStr, ValidationError
from pydantic_settings import SettingsConfigDict
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

import app.account_terms as terms
from app.account_session_auth import AuthenticatedAccountSession
from app.account_terms_requests import CURRENT_TERMS_VERSION, TermsAcceptanceRequest
from app.account_tokens import VerifiedAccount
from app.config import Settings


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@dataclass
class Material:
    engine: AsyncEngine
    connection: AsyncConnection
    session: AuthenticatedAccountSession
    authenticate: AsyncMock
    record: AsyncMock
    commit: AsyncMock
    events: list[str]


@pytest.fixture
def material(monkeypatch: pytest.MonkeyPatch) -> Material:
    now = datetime.now(UTC)
    session = AuthenticatedAccountSession(
        session_id=uuid4(),
        account=VerifiedAccount(
            user_id=uuid4(),
            session_id=uuid4(),
            assurance_level="aal1",
            access_token_expires_at=now + timedelta(minutes=5),
        ),
        idle_expires_at=now + timedelta(days=7),
        absolute_expires_at=now + timedelta(days=30),
    )
    connection = cast(AsyncConnection, Mock(spec=AsyncConnection))
    authenticate = AsyncMock(return_value=session)
    record = AsyncMock(return_value=now)
    commit = AsyncMock()
    events: list[str] = []

    @asynccontextmanager
    async def transaction() -> AsyncIterator[AsyncConnection]:
        events.append("begin")
        try:
            yield connection
            await commit()
            events.append("committed")
        except BaseException:
            events.append("failed")
            raise

    engine = Mock(spec=AsyncEngine)
    engine.begin.return_value = transaction()
    monkeypatch.setattr(terms, "authenticate_account_session", authenticate)
    monkeypatch.setattr(terms, "record_terms_acceptance", record)
    return Material(
        cast(AsyncEngine, engine), connection, session, authenticate, record, commit, events
    )


async def accept(
    material: Material, acceptance: TermsAcceptanceRequest | None = None
) -> terms.RecordedTermsAcceptance | None:
    return await terms.accept_account_terms_transaction(
        material.engine,
        SecretStr("A" * 43),
        acceptance or TermsAcceptanceRequest(accepted=True, terms_version=CURRENT_TERMS_VERSION),
        settings=IsolatedSettings(),
        client=cast(httpx2.AsyncClient, Mock(spec=httpx2.AsyncClient)),
        key_cache=None,
    )


def test_verified_identity_is_recorded_before_successful_commit(material: Material) -> None:
    result = asyncio.run(accept(material))
    assert result is not None
    assert result.session is material.session
    assert result.accepted_at == material.record.return_value
    material.record.assert_awaited_once_with(
        material.connection,
        material.session,
        TermsAcceptanceRequest(accepted=True, terms_version=CURRENT_TERMS_VERSION),
    )
    assert material.events == ["begin", "committed"]


def test_unknown_session_does_not_write_acceptance(material: Material) -> None:
    material.authenticate.return_value = None
    assert asyncio.run(accept(material)) is None
    material.record.assert_not_awaited()


@pytest.mark.parametrize("stage", ["authenticate", "record", "commit"])
@pytest.mark.parametrize("failure", [SQLAlchemyError("private-detail"), asyncio.CancelledError()])
def test_failure_never_reports_acceptance_or_retries(
    material: Material,
    stage: str,
    failure: BaseException,
) -> None:
    cast(AsyncMock, getattr(material, stage)).side_effect = failure
    with pytest.raises(type(failure)):
        asyncio.run(accept(material))
    assert material.events == ["begin", "failed"]
    assert material.authenticate.await_count == 1
    assert material.record.await_count <= 1
    assert material.commit.await_count <= 1


def test_unchecked_input_is_revalidated_before_authentication(material: Material) -> None:
    invalid = TermsAcceptanceRequest.model_construct(
        accepted=False, terms_version=CURRENT_TERMS_VERSION
    )
    with pytest.raises(ValidationError):
        asyncio.run(accept(material, invalid))
    material.authenticate.assert_not_awaited()
    material.record.assert_not_awaited()


@pytest.mark.parametrize("accepted", [False, True])
def test_status_uses_verified_subject_and_returns_after_commit(
    material: Material,
    monkeypatch: pytest.MonkeyPatch,
    accepted: bool,
) -> None:
    expected = datetime.now(UTC) if accepted else None
    lookup = AsyncMock(return_value=expected)
    monkeypatch.setattr(terms, "current_terms_accepted_at", lookup)
    result = asyncio.run(
        terms.account_terms_status_transaction(
            material.engine,
            SecretStr("A" * 43),
            settings=IsolatedSettings(),
            client=cast(httpx2.AsyncClient, Mock(spec=httpx2.AsyncClient)),
            key_cache=None,
        )
    )
    assert result is not None
    assert result.session is material.session
    assert result.accepted_at == expected
    lookup.assert_awaited_once_with(material.connection, material.session.account.user_id)
    material.record.assert_not_awaited()
    assert material.events == ["begin", "committed"]


def test_status_does_not_read_terms_for_unknown_session(
    material: Material,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    material.authenticate.return_value = None
    lookup = AsyncMock()
    monkeypatch.setattr(terms, "current_terms_accepted_at", lookup)
    result = asyncio.run(
        terms.account_terms_status_transaction(
            material.engine,
            SecretStr("A" * 43),
            settings=IsolatedSettings(),
            client=cast(httpx2.AsyncClient, Mock(spec=httpx2.AsyncClient)),
            key_cache=None,
        )
    )
    assert result is None
    lookup.assert_not_awaited()


@pytest.mark.parametrize("stage", ["authenticate", "lookup", "commit"])
@pytest.mark.parametrize("failure", [SQLAlchemyError("private-detail"), asyncio.CancelledError()])
def test_status_failures_never_return_partial_success(
    material: Material,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
    failure: BaseException,
) -> None:
    lookup = AsyncMock(return_value=datetime.now(UTC))
    monkeypatch.setattr(terms, "current_terms_accepted_at", lookup)
    operation = lookup if stage == "lookup" else getattr(material, stage)
    operation.side_effect = failure
    with pytest.raises(type(failure)):
        asyncio.run(
            terms.account_terms_status_transaction(
                material.engine,
                SecretStr("A" * 43),
                settings=IsolatedSettings(),
                client=cast(httpx2.AsyncClient, Mock(spec=httpx2.AsyncClient)),
                key_cache=None,
            )
        )
    assert material.events == ["begin", "failed"]


async def use_resource(material: Material, settings: Settings, *, fail: bool = False) -> None:
    async with terms.terms_account_transaction(
        material.engine,
        SecretStr("A" * 43),
        settings=settings,
        client=cast(httpx2.AsyncClient, Mock(spec=httpx2.AsyncClient)),
        key_cache=None,
    ) as access:
        assert access.connection is material.connection
        assert access.session is material.session
        material.events.append("resource")
        if fail:
            raise RuntimeError("synthetic resource failure")


@pytest.mark.parametrize("accepted", [False, True])
def test_gate_blocks_missing_acceptance_before_resource_work(
    material: Material,
    monkeypatch: pytest.MonkeyPatch,
    accepted: bool,
) -> None:
    lookup = AsyncMock(return_value=datetime.now(UTC) if accepted else None)
    monkeypatch.setattr(terms, "current_terms_accepted_at", lookup)
    settings = IsolatedSettings(account_terms_api_enabled=True)
    if accepted:
        asyncio.run(use_resource(material, settings))
        assert material.events == ["begin", "resource", "committed"]
    else:
        with pytest.raises(terms.AccountTermsRequired):
            asyncio.run(use_resource(material, settings))
        assert material.events == ["begin", "failed"]
        material.commit.assert_not_awaited()
    lookup.assert_awaited_once_with(material.connection, material.session.account.user_id)
    material.record.assert_not_awaited()


def test_disabled_setup_does_not_bypass_resource_gate(material: Material) -> None:
    with pytest.raises(terms.AccountTermsUnavailable):
        asyncio.run(use_resource(material, IsolatedSettings(account_terms_api_enabled=False)))
    assert material.events == []
    material.authenticate.assert_not_awaited()


def test_gate_rejects_unknown_session_before_acceptance_lookup(
    material: Material,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.account_refresh import AccountRefreshRejected

    material.authenticate.return_value = None
    lookup = AsyncMock()
    monkeypatch.setattr(terms, "current_terms_accepted_at", lookup)
    with pytest.raises(AccountRefreshRejected):
        asyncio.run(use_resource(material, IsolatedSettings(account_terms_api_enabled=True)))
    lookup.assert_not_awaited()
    assert material.events == ["begin", "failed"]


def test_resource_failure_rolls_back_verified_transaction(
    material: Material,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        terms, "current_terms_accepted_at", AsyncMock(return_value=datetime.now(UTC))
    )
    with pytest.raises(RuntimeError, match="synthetic resource failure"):
        asyncio.run(
            use_resource(material, IsolatedSettings(account_terms_api_enabled=True), fail=True)
        )
    material.commit.assert_not_awaited()
    assert material.events == ["begin", "resource", "failed"]


@pytest.mark.parametrize("failure", [SQLAlchemyError("private-detail"), asyncio.CancelledError()])
def test_resource_commit_failure_cannot_report_success(
    material: Material,
    monkeypatch: pytest.MonkeyPatch,
    failure: BaseException,
) -> None:
    monkeypatch.setattr(
        terms, "current_terms_accepted_at", AsyncMock(return_value=datetime.now(UTC))
    )
    material.commit.side_effect = failure
    with pytest.raises(type(failure)):
        asyncio.run(use_resource(material, IsolatedSettings(account_terms_api_enabled=True)))
    assert material.events == ["begin", "resource", "failed"]


@pytest.mark.parametrize("invalid", [datetime(2026, 10, 26), "not-a-timestamp"])
def test_invalid_storage_timestamp_is_unavailable_not_acceptance(invalid: object) -> None:
    connection = Mock(spec=AsyncConnection)
    connection.scalar = AsyncMock(return_value=invalid)
    with pytest.raises(terms.AccountTermsUnavailable):
        asyncio.run(terms.current_terms_accepted_at(cast(AsyncConnection, connection), uuid4()))


@pytest.mark.parametrize("operation", ["status", "accept", "resource"])
def test_account_switch_stops_before_provider_calls_and_writes(
    material: Material,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    lookup = AsyncMock()
    monkeypatch.setattr(terms, "current_terms_accepted_at", lookup)
    monkeypatch.setattr(
        terms,
        "load_locked_account_session",
        AsyncMock(return_value=SimpleNamespace(user_id=material.session.account.user_id)),
    )

    async def check() -> None:
        settings = IsolatedSettings(account_terms_api_enabled=True)
        client = cast(httpx2.AsyncClient, Mock(spec=httpx2.AsyncClient))
        expected = uuid4()
        if operation == "accept":
            await terms.accept_account_terms_transaction(
                material.engine,
                SecretStr("A" * 43),
                TermsAcceptanceRequest(accepted=True, terms_version=CURRENT_TERMS_VERSION),
                settings=settings,
                client=client,
                key_cache=None,
                expected_user_id=expected,
            )
        elif operation == "status":
            await terms.account_terms_status_transaction(
                material.engine,
                SecretStr("A" * 43),
                settings=settings,
                client=client,
                key_cache=None,
                expected_user_id=expected,
            )
        else:
            async with terms.terms_account_transaction(
                material.engine,
                SecretStr("A" * 43),
                settings=settings,
                client=client,
                key_cache=None,
                expected_user_id=expected,
            ):
                raise AssertionError("Switched accounts must not reach resource work.")

    with pytest.raises(terms.AccountTermsSessionChanged):
        asyncio.run(check())
    material.authenticate.assert_not_awaited()
    material.record.assert_not_awaited()
    lookup.assert_not_awaited()
    material.commit.assert_not_awaited()
    assert material.events == ["begin", "failed"]
