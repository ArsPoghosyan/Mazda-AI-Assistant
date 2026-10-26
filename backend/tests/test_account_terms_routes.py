"""Acceptance HTTP guards using mocked authenticated transactions, no network."""

from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import httpx2
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

import app.account_terms as terms
from app.account_auth import AccountAuthenticationUnavailable
from app.account_key_cache import AccountKeyCache
from app.account_refresh import AccountRefreshRejected, AccountRefreshUnavailable
from app.account_session_auth import AuthenticatedAccountSession
from app.account_terms import AccountTermsStatus, AccountTermsUnavailable, RecordedTermsAcceptance
from app.account_terms_requests import CURRENT_TERMS_VERSION, TermsAcceptanceRequest
from app.account_terms_routes import TermsAccountDependency
from app.account_tokens import VerifiedAccount
from app.config import Settings
from app.main import create_app

PATH = "/api/v1/account/terms/accept"
ORIGIN = "https://app.example.test"
COOKIE = "__Host-askm6_account"
TOKEN = "A" * 43
BODY = {"accepted": True, "terms_version": CURRENT_TERMS_VERSION}
STATUS_PATH = "/api/v1/account/terms/status"


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@dataclass
class TermsAPI:
    app: FastAPI
    client: TestClient
    settings: Settings
    accept: AsyncMock
    recorded: RecordedTermsAcceptance
    status: AsyncMock


@pytest.fixture
def api(monkeypatch: pytest.MonkeyPatch) -> Iterator[TermsAPI]:
    settings = IsolatedSettings.model_validate(
        {
            "database_url": None,
            "migration_database_url": None,
            "supabase_auth_issuer": None,
            "account_terms_api_enabled": True,
            "account_cookie_secure": True,
            "csrf_trusted_origins": (ORIGIN,),
        }
    )
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
    recorded = RecordedTermsAcceptance(session=session, accepted_at=now)
    accept = AsyncMock(return_value=recorded)
    status = AsyncMock(return_value=AccountTermsStatus(session=session, accepted_at=now))
    monkeypatch.setattr("app.account_terms_routes.accept_account_terms_transaction", accept)
    monkeypatch.setattr("app.account_terms_routes.account_terms_status_transaction", status)
    application = create_app(settings)
    with TestClient(application, base_url=ORIGIN) as client:
        client.headers["X-Account-Subject"] = str(session.account.user_id)
        # The real transaction is tested separately. No real provider or DB client is used here.
        application.state.database_engine = Mock(spec=AsyncEngine)
        application.state.account_auth_client = Mock(spec=httpx2.AsyncClient)
        application.state.account_key_cache = Mock(spec=AccountKeyCache)
        yield TermsAPI(application, client, settings, accept, recorded, status)


def submit(api: TermsAPI) -> httpx2.Response:
    return api.client.post(
        PATH, headers={"Origin": ORIGIN, "Cookie": f"{COOKIE}={TOKEN}"}, json=BODY
    )


def test_default_is_disabled_and_closed_before_authentication(api: TermsAPI) -> None:
    assert IsolatedSettings().account_terms_api_enabled is False
    api.settings.account_terms_api_enabled = False
    response = submit(api)
    assert response.status_code == 503
    assert response.headers["cache-control"] == "no-store"
    api.accept.assert_not_awaited()


def test_success_returns_only_committed_revision_and_time(api: TermsAPI) -> None:
    response = submit(api)
    assert response.status_code == 200
    assert response.json() == {
        "terms_version": CURRENT_TERMS_VERSION,
        "accepted_at": api.recorded.accepted_at.isoformat().replace("+00:00", "Z"),
    }
    assert response.headers["cache-control"] == "no-store"
    assert "HttpOnly" in response.headers["set-cookie"]
    assert "Secure" in response.headers["set-cookie"]
    assert "SameSite=lax" in response.headers["set-cookie"]
    assert TOKEN not in response.text
    assert str(api.recorded.session.account.user_id) not in response.text
    api.accept.assert_awaited_once_with(
        api.app.state.database_engine,
        SecretStr(TOKEN),
        TermsAcceptanceRequest(accepted=True, terms_version=CURRENT_TERMS_VERSION),
        settings=api.settings,
        client=api.app.state.account_auth_client,
        key_cache=api.app.state.account_key_cache,
        expected_user_id=api.recorded.session.account.user_id,
    )


@pytest.mark.parametrize(
    "headers",
    [
        [],
        [("Origin", "null")],
        [("Origin", "https://other.test")],
        [("Origin", ORIGIN), ("Origin", ORIGIN)],
    ],
)
def test_untrusted_origin_cannot_record_acceptance(
    api: TermsAPI, headers: list[tuple[str, str]]
) -> None:
    response = api.client.post(PATH, headers=[*headers, ("Cookie", f"{COOKIE}={TOKEN}")], json=BODY)
    assert response.status_code == 403
    api.accept.assert_not_awaited()


@pytest.mark.parametrize("cookie", ["", "askm6_guest=" + TOKEN, COOKIE + "=bad"])
def test_missing_or_invalid_account_cookie_never_authenticates(api: TermsAPI, cookie: str) -> None:
    response = api.client.post(PATH, headers={"Origin": ORIGIN, "Cookie": cookie}, json=BODY)
    assert response.status_code == 401
    assert "Max-Age=0" in response.headers["set-cookie"]
    api.accept.assert_not_awaited()


@pytest.mark.parametrize("field", ["database_engine", "account_auth_client", "account_key_cache"])
def test_missing_resources_fail_closed(api: TermsAPI, field: str) -> None:
    setattr(api.app.state, field, None)
    response = submit(api)
    assert response.status_code == 503
    assert "set-cookie" not in response.headers
    api.accept.assert_not_awaited()


@pytest.mark.parametrize(
    "body",
    [
        {"accepted": False, "terms_version": CURRENT_TERMS_VERSION},
        {"accepted": True, "terms_version": "old-version"},
        {**BODY, "user_id": "another-user"},
        {**BODY, "accepted_at": "2000-01-01"},
    ],
)
def test_invalid_acceptance_cannot_reach_authenticated_write(
    api: TermsAPI, body: dict[str, object]
) -> None:
    response = api.client.post(
        PATH, headers={"Origin": ORIGIN, "Cookie": f"{COOKIE}={TOKEN}"}, json=body
    )
    assert response.status_code == 400
    api.accept.assert_not_awaited()


@pytest.mark.parametrize(
    "failure",
    [
        AccountAuthenticationUnavailable("private-detail"),
        AccountRefreshUnavailable("private-detail"),
        AccountTermsUnavailable("private-detail"),
        SQLAlchemyError("private-detail"),
        TimeoutError(),
    ],
)
def test_verification_database_commit_and_timeout_errors_are_private(
    api: TermsAPI, failure: Exception
) -> None:
    api.accept.side_effect = failure
    response = submit(api)
    assert response.status_code == 503
    assert response.json() == {"detail": "Terms acceptance is temporarily unavailable."}
    assert "set-cookie" not in response.headers
    api.accept.assert_awaited_once()


@pytest.mark.parametrize("rejected", [False, True])
def test_expired_unknown_and_provider_rejected_sessions_are_cleared(
    api: TermsAPI, rejected: bool
) -> None:
    if rejected:
        api.accept.side_effect = AccountRefreshRejected("private-detail")
    else:
        api.accept.return_value = None
    response = submit(api)
    assert response.status_code == 401
    assert "Max-Age=0" in response.headers["set-cookie"]
    assert "private-detail" not in response.text
    api.accept.assert_awaited_once()


def test_operation_has_a_real_deadline(api: TermsAPI) -> None:
    import asyncio

    async def blocked(*args: object, **kwargs: object) -> None:
        await asyncio.Event().wait()

    api.settings.account_session_auth_timeout_seconds = 1
    api.accept.side_effect = blocked
    response = submit(api)
    assert response.status_code == 503
    assert "set-cookie" not in response.headers
    api.accept.assert_awaited_once()


def read_status(api: TermsAPI) -> httpx2.Response:
    return api.client.post(STATUS_PATH, headers={"Origin": ORIGIN, "Cookie": f"{COOKIE}={TOKEN}"})


@pytest.mark.parametrize("accepted", [False, True])
def test_status_reports_current_acceptance_without_changing_session_contract(
    api: TermsAPI,
    accepted: bool,
) -> None:
    time = api.recorded.accepted_at if accepted else None
    api.status.return_value = AccountTermsStatus(session=api.recorded.session, accepted_at=time)
    response = read_status(api)
    assert response.status_code == 200
    assert response.json() == {
        "terms_version": CURRENT_TERMS_VERSION,
        "accepted_at": time.isoformat().replace("+00:00", "Z") if time else None,
        "acceptance_required": not accepted,
    }
    assert response.headers["cache-control"] == "no-store"
    assert "HttpOnly" in response.headers["set-cookie"]
    assert TOKEN not in response.text
    api.status.assert_awaited_once_with(
        api.app.state.database_engine,
        SecretStr(TOKEN),
        settings=api.settings,
        client=api.app.state.account_auth_client,
        key_cache=api.app.state.account_key_cache,
        expected_user_id=api.recorded.session.account.user_id,
    )
    api.accept.assert_not_awaited()


@pytest.mark.parametrize(
    "failure",
    [
        SQLAlchemyError("private-detail"),
        AccountTermsUnavailable("private-detail"),
        AccountAuthenticationUnavailable("private-detail"),
        AccountRefreshUnavailable("private-detail"),
        TimeoutError(),
    ],
)
def test_status_failure_preserves_cookie_and_hides_details(
    api: TermsAPI, failure: Exception
) -> None:
    api.status.side_effect = failure
    response = read_status(api)
    assert response.status_code == 503
    assert "set-cookie" not in response.headers
    assert "private-detail" not in response.text
    api.status.assert_awaited_once()


@pytest.mark.parametrize("rejected", [False, True])
def test_status_clears_missing_or_rejected_sessions(api: TermsAPI, rejected: bool) -> None:
    if rejected:
        api.status.side_effect = AccountRefreshRejected("private-detail")
    else:
        api.status.return_value = None
    response = read_status(api)
    assert response.status_code == 401
    assert "Max-Age=0" in response.headers["set-cookie"]


@pytest.mark.parametrize("path,body", [(STATUS_PATH, b"{}"), (STATUS_PATH + "?user_id=other", b"")])
def test_status_rejects_body_or_query_options_before_verification(
    api: TermsAPI, path: str, body: bytes
) -> None:
    response = api.client.post(
        path, headers={"Origin": ORIGIN, "Cookie": f"{COOKIE}={TOKEN}"}, content=body
    )
    assert response.status_code == 400
    api.status.assert_not_awaited()


def test_status_disabled_stops_before_authentication(api: TermsAPI) -> None:
    api.settings.account_terms_api_enabled = False
    assert read_status(api).status_code == 503
    api.status.assert_not_awaited()


@pytest.mark.parametrize("cookie", ["", COOKIE + "=bad", "askm6_guest=" + TOKEN])
def test_status_needs_an_account_cookie(api: TermsAPI, cookie: str) -> None:
    response = api.client.post(STATUS_PATH, headers={"Origin": ORIGIN, "Cookie": cookie})
    assert response.status_code == 401
    api.status.assert_not_awaited()


@pytest.mark.parametrize("origin", ["", "null", "https://other.example.test"])
def test_status_needs_a_trusted_origin(api: TermsAPI, origin: str) -> None:
    response = api.client.post(
        STATUS_PATH, headers={"Origin": origin, "Cookie": f"{COOKIE}={TOKEN}"}
    )
    assert response.status_code == 403
    api.status.assert_not_awaited()


@pytest.mark.parametrize("field", ["database_engine", "account_auth_client", "account_key_cache"])
def test_status_requires_all_resources(api: TermsAPI, field: str) -> None:
    setattr(api.app.state, field, None)
    assert read_status(api).status_code == 503
    api.status.assert_not_awaited()


@dataclass
class GateProbe:
    api: TermsAPI
    authenticate: AsyncMock
    lookup: AsyncMock
    commit: AsyncMock
    events: list[str]


@pytest.fixture
def gate(api: TermsAPI, monkeypatch: pytest.MonkeyPatch) -> GateProbe:
    events: list[str] = []
    connection = cast(AsyncConnection, Mock(spec=AsyncConnection))
    commit = AsyncMock()
    authenticate = AsyncMock(return_value=api.recorded.session)
    lookup = AsyncMock(return_value=api.recorded.accepted_at)
    monkeypatch.setattr(terms, "authenticate_account_session", authenticate)
    monkeypatch.setattr(terms, "current_terms_accepted_at", lookup)
    monkeypatch.setattr(
        terms,
        "load_locked_account_session",
        AsyncMock(return_value=SimpleNamespace(user_id=api.recorded.session.account.user_id)),
    )

    @asynccontextmanager
    async def transaction() -> AsyncIterator[AsyncConnection]:
        events.append("begin")
        try:
            yield connection
            await commit()
            events.append("committed")
        except BaseException:
            events.append("rolled-back")
            raise

    api.app.state.database_engine.begin.side_effect = transaction

    # This route exists only in the fixture, never in the application router.
    @api.app.post("/test-only-protected")
    async def protected(access: TermsAccountDependency) -> dict[str, bool]:
        assert access.connection is connection
        assert access.session is api.recorded.session
        events.append("resource")
        return {"allowed": True}

    return GateProbe(api, authenticate, lookup, commit, events)


def use_protected(gate: GateProbe) -> httpx2.Response:
    return gate.api.client.post(
        "/test-only-protected",
        headers={
            "Origin": ORIGIN,
            "Cookie": f"{COOKIE}={TOKEN}",
        },
    )


def test_resource_dependency_uses_function_scope_commit_before_success(gate: GateProbe) -> None:
    response = use_protected(gate)
    assert response.status_code == 200
    assert response.json() == {"allowed": True}
    assert response.headers["cache-control"] == "no-store"
    assert gate.events == ["begin", "resource", "committed"]
    authenticated_call = gate.authenticate.await_args
    assert authenticated_call is not None
    gate.lookup.assert_awaited_once_with(
        authenticated_call.args[0],
        gate.api.recorded.session.account.user_id,
    )


def test_resource_gate_requires_terms_without_clearing_session(gate: GateProbe) -> None:
    gate.lookup.return_value = None
    response = use_protected(gate)
    assert response.status_code == 428
    assert response.json() == {"detail": "Terms acceptance is required."}
    assert response.headers["X-Account-Setup"] == "terms-required"
    assert "set-cookie" not in response.headers
    assert gate.events == ["begin", "rolled-back"]
    gate.commit.assert_not_awaited()
    # Setup operations remain available; their routes do not depend on this gate.
    assert read_status(gate.api).status_code == 200
    assert submit(gate.api).status_code == 200


@pytest.mark.parametrize("stage", ["authenticate", "lookup", "commit"])
def test_resource_failure_never_sends_http_success(gate: GateProbe, stage: str) -> None:
    getattr(gate, stage).side_effect = SQLAlchemyError("private-detail")
    response = use_protected(gate)
    assert response.status_code == 503
    assert "private-detail" not in response.text
    assert "set-cookie" not in response.headers
    assert gate.events[-1] == "rolled-back"
    assert ("resource" in gate.events) is (stage == "commit")


def test_resource_gate_is_closed_when_setup_disabled(gate: GateProbe) -> None:
    gate.api.settings.account_terms_api_enabled = False
    assert use_protected(gate).status_code == 503
    assert gate.events == []
    gate.authenticate.assert_not_awaited()


def test_resource_gate_rejects_unknown_sessions(gate: GateProbe) -> None:
    gate.authenticate.return_value = None
    response = use_protected(gate)
    assert response.status_code == 401
    assert "Max-Age=0" in response.headers["set-cookie"]
    gate.lookup.assert_not_awaited()
    assert gate.events == ["begin", "rolled-back"]


def test_resource_mutation_still_requires_trusted_origin(gate: GateProbe) -> None:
    response = gate.api.client.post("/test-only-protected", headers={"Cookie": f"{COOKIE}={TOKEN}"})
    assert response.status_code == 403
    assert gate.events == []


def test_sign_out_does_not_require_terms_acceptance(
    gate: GateProbe, monkeypatch: pytest.MonkeyPatch
) -> None:
    gate.lookup.return_value = None
    gate.api.settings.account_sign_out_api_enabled = True
    deletion = AsyncMock(return_value=True)
    monkeypatch.setattr("app.account_sign_out_routes.delete_account_session_transaction", deletion)
    response = gate.api.client.post(
        "/api/v1/account/sign-out",
        headers={
            "Origin": ORIGIN,
            "Cookie": f"{COOKIE}={TOKEN}",
        },
    )
    assert response.status_code == 204
    assert "Max-Age=0" in response.headers["set-cookie"]
    deletion.assert_awaited_once()
    gate.authenticate.assert_not_awaited()
    gate.lookup.assert_not_awaited()


@pytest.mark.parametrize("path,operation", [(PATH, "accept"), (STATUS_PATH, "status")])
def test_changed_account_returns_409_without_clearing_the_other_accounts_cookie(
    api: TermsAPI,
    path: str,
    operation: str,
) -> None:
    getattr(api, operation).side_effect = terms.AccountTermsSessionChanged("private-detail")
    response = api.client.post(
        path,
        headers={"Origin": ORIGIN, "Cookie": f"{COOKIE}={TOKEN}"},
        json=BODY if operation == "accept" else None,
    )
    assert response.status_code == 409
    assert "set-cookie" not in response.headers
    assert "private-detail" not in response.text


@pytest.mark.parametrize(
    "subject", [None, "", "not-an-account", "00000000000000000000000000000000000000"]
)
def test_account_precondition_is_required_before_terms_verification(
    api: TermsAPI, subject: str | None
) -> None:
    del api.client.headers["X-Account-Subject"]
    headers = {"Origin": ORIGIN, "Cookie": f"{COOKIE}={TOKEN}"}
    if subject is not None:
        headers["X-Account-Subject"] = subject
    response = api.client.post(STATUS_PATH, headers=headers)
    assert response.status_code == 400
    api.status.assert_not_awaited()
    api.accept.assert_not_awaited()
