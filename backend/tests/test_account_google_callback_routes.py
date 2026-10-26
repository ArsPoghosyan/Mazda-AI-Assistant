"""Browser callback outcomes, cookie isolation and committed session issuance."""

import asyncio
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from http.cookies import SimpleCookie
from typing import cast
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import httpx2
import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

import app.account_google_callback as completion
import app.account_google_routes as routes
import app.account_google_session as sessions
import app.account_oauth_transactions as transactions
from app.account_auth import AccountAuthenticationUnavailable
from app.account_cookies import account_cookie_name, set_account_cookie
from app.account_google_exchange import (
    ExchangedGoogleTokens,
    GoogleCodeExchangeRejected,
    GoogleCodeExchangeUnavailable,
)
from app.account_key_cache import AccountKeyCache
from app.account_oauth_attempts import ConsumedOAuthLoginAttempt, OAuthLoginAttemptUnavailable
from app.account_oauth_cookies import oauth_cookie_name
from app.account_oauth_material import InvalidOAuthLoginMaterial
from app.account_sessions import (
    AccountSessionAlreadyExists,
    AccountSessionUnavailable,
    CreatedAccountSession,
)
from app.account_token_encryption import AccountTokenCipher
from app.account_tokens import InvalidAccountToken, VerifiedAccount
from app.config import Settings
from app.main import create_app

PATH = "/api/v1/account/google/callback"
CODE = "synthetic-private-code"
BINDING = "b" * 43
ACCOUNT = "a" * 43
ORIGIN = "https://api.example.test"


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@dataclass
class Material:
    application: FastAPI
    client: TestClient
    settings: Settings
    engine: AsyncEngine
    http_client: httpx2.AsyncClient
    key_cache: AccountKeyCache
    created: CreatedAccountSession
    complete: AsyncMock


@pytest.fixture
def material(monkeypatch: pytest.MonkeyPatch) -> Iterator[Material]:
    settings = IsolatedSettings.model_validate(
        {
            "database_url": None,
            "migration_database_url": None,
            "supabase_auth_issuer": "https://auth.example.test/auth/v1",
            "supabase_auth_publishable_key": "sb_publishable_synthetic",
            "account_session_encryption_key": Fernet.generate_key().decode("ascii"),
            "account_google_oauth_api_enabled": True,
            "account_cookie_secure": True,
            "account_google_oauth_callback_url": ORIGIN + PATH,
            "csrf_trusted_origins": (),
        }
    )
    now = datetime.now(UTC)
    created = CreatedAccountSession(
        uuid4(), uuid4(), SecretStr(ACCOUNT), now + timedelta(days=7), now + timedelta(days=30)
    )
    complete = AsyncMock(return_value=created)
    monkeypatch.setattr(routes, "complete_google_callback", complete)
    application = create_app(settings)
    engine = cast(AsyncEngine, Mock(spec=AsyncEngine))
    http_client = cast(httpx2.AsyncClient, Mock(spec=httpx2.AsyncClient))
    key_cache = cast(AccountKeyCache, Mock(spec=AccountKeyCache))
    with TestClient(application, base_url=ORIGIN, follow_redirects=False) as client:
        application.state.database_engine = engine
        application.state.account_auth_client = http_client
        application.state.account_key_cache = key_cache
        yield Material(
            application, client, settings, engine, http_client, key_cache, created, complete
        )


def get(
    material: Material, *, query: str = "code=" + CODE, cookie: str | None = None
) -> httpx2.Response:
    if cookie is None:
        cookie = f"{oauth_cookie_name(material.settings)}={BINDING}; guest=preserve"
    return material.client.get(PATH + "?" + query, headers={"Cookie": cookie})


def assert_outcome(material: Material, response: httpx2.Response, outcome: str) -> SimpleCookie:
    assert response.status_code == 303
    assert response.headers["Location"] == ORIGIN + "/#google-sign-in=" + outcome
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert response.content == b""
    assert CODE not in response.headers["Location"]
    cookies: SimpleCookie = SimpleCookie()
    for header in response.headers.get_list("set-cookie"):
        cookies.load(header)
    pending = cookies[oauth_cookie_name(material.settings)]
    assert pending.value == ""
    assert pending["max-age"] == "0"
    assert bool(pending["secure"]) is material.settings.account_cookie_secure
    assert bool(pending["httponly"])
    assert pending["samesite"] == "lax"
    assert pending["path"] == "/"
    assert pending["domain"] == ""
    if outcome != "success":
        assert list(cookies) == [oauth_cookie_name(material.settings)]
    return cookies


@pytest.mark.parametrize("secure", [True, False])
def test_success_sets_account_cookie_and_clears_only_pending_cookie_without_origin(
    material: Material,
    secure: bool,
) -> None:
    material.settings.account_cookie_secure = secure
    cookies = assert_outcome(material, get(material), "success")
    assert set(cookies) == {
        oauth_cookie_name(material.settings),
        account_cookie_name(material.settings),
    }
    account = cookies[account_cookie_name(material.settings)]
    assert account.value == ACCOUNT
    assert bool(account["secure"]) is secure
    assert bool(account["httponly"])
    assert account["samesite"] == "lax"
    assert account["path"] == "/"
    assert account["domain"] == ""
    assert parsedate_to_datetime(account["expires"]) == material.created.idle_expires_at.replace(
        microsecond=0
    )
    material.complete.assert_awaited_once_with(
        material.engine,
        SecretStr(CODE),
        BINDING,
        settings=material.settings,
        client=material.http_client,
        key_cache=material.key_cache,
        signup_terms_receipt=None,
    )


@pytest.mark.parametrize("missing", ["flag", "callback"])
def test_disabled_or_unconfigured_callback_is_generic_503_with_no_redirect(
    material: Material, missing: str
) -> None:
    if missing == "flag":
        material.settings.account_google_oauth_api_enabled = False
    else:
        material.settings.account_google_oauth_callback_url = None
    response = get(material)
    assert response.status_code == 503
    assert response.json() == {"detail": "Google sign-in is temporarily unavailable."}
    assert "Location" not in response.headers
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert "Max-Age=0" in response.headers["set-cookie"]
    material.complete.assert_not_awaited()


@pytest.mark.parametrize(
    "missing",
    [
        "database_engine",
        "account_auth_client",
        "account_key_cache",
        "supabase_auth_issuer",
        "supabase_auth_publishable_key",
        "account_session_encryption_key",
    ],
)
def test_missing_prerequisite_returns_only_fixed_unavailable_outcome(
    material: Material, missing: str
) -> None:
    if missing in {"database_engine", "account_auth_client", "account_key_cache"}:
        setattr(material.application.state, missing, None)
    else:
        setattr(material.settings, missing, None)
    assert_outcome(material, get(material), "unavailable")
    material.complete.assert_not_awaited()


@pytest.mark.parametrize(
    "query",
    [
        "",
        "code=",
        "code=first&code=second",
        "code=x&next=https://untrusted.example",
        "error=access_denied&error_description=synthetic-private",
        "code=x&error=access_denied",
        "code=%FF",
        "code=%00",
        "code=%GG",
    ],
)
def test_bad_query_and_cancelled_consent_stop_before_completion(
    material: Material, query: str
) -> None:
    assert_outcome(material, get(material, query=query), "rejected")
    material.complete.assert_not_awaited()


@pytest.mark.parametrize(
    "cookie",
    [
        "guest=preserve",
        "__Host-askm6_oauth=bad",
        "__Host-askm6_oauth=",
        f"__Host-askm6_oauth={BINDING}; __Host-askm6_oauth={BINDING}",
    ],
)
def test_missing_malformed_duplicate_binding_never_exchanges_code(
    material: Material, cookie: str
) -> None:
    assert_outcome(material, get(material, cookie=cookie), "rejected")
    material.complete.assert_not_awaited()


@pytest.mark.parametrize("value", ["", "stale", "x" * 43])
def test_account_cookie_presence_prevents_silent_account_switch(
    material: Material, value: str
) -> None:
    response = get(material, cookie=f"__Host-askm6_account={value}; __Host-askm6_oauth={BINDING}")
    assert_outcome(material, response, "sign-out-required")
    material.complete.assert_not_awaited()


@pytest.mark.parametrize(
    ("failure", "outcome"),
    [
        (InvalidOAuthLoginMaterial("synthetic-private"), "rejected"),
        (GoogleCodeExchangeRejected("synthetic-private"), "rejected"),
        (InvalidAccountToken("synthetic-private"), "rejected"),
        (GoogleCodeExchangeUnavailable("synthetic-private"), "unavailable"),
        (OAuthLoginAttemptUnavailable("synthetic-private"), "unavailable"),
        (AccountAuthenticationUnavailable("synthetic-private"), "unavailable"),
        (AccountSessionAlreadyExists("synthetic-private"), "unavailable"),
        (AccountSessionUnavailable("synthetic-private"), "unavailable"),
        (SQLAlchemyError("synthetic-private"), "unavailable"),
        (TimeoutError("synthetic-private"), "unavailable"),
    ],
)
def test_expected_failures_preserve_account_guest_and_use_generic_marker(
    material: Material,
    failure: Exception,
    outcome: str,
) -> None:
    material.complete.side_effect = failure
    assert_outcome(material, get(material), outcome)
    material.complete.assert_awaited_once()


@pytest.mark.parametrize("suffix", ["/", "//", "/extra", "/extra" + PATH])
def test_noncanonical_callback_never_redirects_with_query_or_host_input(
    material: Material, suffix: str
) -> None:
    response = material.client.get(
        PATH + suffix + "?code=" + CODE,
        headers={"Host": "untrusted.example", "X-Forwarded-Host": "other.example"},
    )
    assert_outcome(material, response, "rejected")
    material.complete.assert_not_awaited()


def test_success_destination_is_independent_of_host_and_forwarded_headers(
    material: Material,
) -> None:
    response = material.client.get(
        PATH + "?code=" + CODE,
        headers={
            "Host": "untrusted.example",
            "X-Forwarded-Host": "other.example",
            "X-Forwarded-Proto": "http",
            "Cookie": "__Host-askm6_oauth=" + BINDING,
        },
    )
    assert_outcome(material, response, "success")


@pytest.mark.parametrize(
    "base", ["https://app.example.test:8443", "http://127.0.0.1:5173", "http://[::1]:5173"]
)
def test_return_origin_comes_from_validated_callback_setting(material: Material, base: str) -> None:
    material.settings.account_cookie_secure = base.startswith("https:")
    validated = IsolatedSettings.model_validate(
        {
            "account_cookie_secure": material.settings.account_cookie_secure,
            "account_google_oauth_callback_url": base + PATH,
        }
    )
    material.settings.account_google_oauth_callback_url = (
        validated.account_google_oauth_callback_url
    )
    response = get(material)
    assert response.status_code == 303
    assert response.headers["Location"] == base + "/#google-sign-in=success"


def test_post_cannot_complete_callback(material: Material) -> None:
    response = material.client.post(PATH + "?code=" + CODE)
    assert response.status_code == 405
    material.complete.assert_not_awaited()


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_caller_cancellation_propagates_without_account_cookie(material: Material) -> None:
    entered = asyncio.Event()
    cleaned = asyncio.Event()

    async def block(*args: object, **kwargs: object) -> None:
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            cleaned.set()

    material.complete.side_effect = block
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": PATH,
            "query_string": ("code=" + CODE).encode("ascii"),
            "headers": [(b"cookie", ("__Host-askm6_oauth=" + BINDING).encode("ascii"))],
            "app": material.application,
        }
    )
    async with asyncio.timeout(5):
        task = asyncio.create_task(routes.finish_google_login(request))
        try:
            await entered.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        finally:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    assert task.cancelled()
    assert cleaned.is_set()


@pytest.mark.parametrize(
    "failed_commit", [None, 1, 2], ids=["success", "attempt-commit", "session-commit"]
)
def test_real_completion_pipeline_obeys_both_commits_before_cookie_issuance(
    material: Material,
    monkeypatch: pytest.MonkeyPatch,
    failed_commit: int | None,
) -> None:
    monkeypatch.setattr(routes, "complete_google_callback", completion.complete_google_callback)
    assert material.settings.account_session_encryption_key is not None
    cipher = AccountTokenCipher(material.settings.account_session_encryption_key)
    verifier = SecretStr("v" * 43)
    consumed = ConsumedOAuthLoginAttempt(
        uuid4(), cipher.encrypt(verifier), datetime.now(UTC) + timedelta(minutes=10)
    )
    tokens = ExchangedGoogleTokens(SecretStr("synthetic-access"), SecretStr("synthetic-refresh"))
    verified = VerifiedAccount(
        material.created.user_id, uuid4(), "aal1", datetime.now(UTC) + timedelta(hours=1)
    )
    events: list[str] = []
    count = 0
    connection = cast(AsyncConnection, Mock(spec=AsyncConnection))

    @asynccontextmanager
    async def transaction() -> AsyncIterator[AsyncConnection]:
        nonlocal count
        count += 1
        number = count
        assert number <= 2
        events.append(f"begin-{number}")
        try:
            yield connection
            events.append(f"commit-{number}")
            if failed_commit == number:
                raise SQLAlchemyError("synthetic-private")
        finally:
            events.append(f"release-{number}")

    engine = Mock(spec=AsyncEngine)
    engine.begin.side_effect = transaction
    material.application.state.database_engine = engine
    consume = AsyncMock(return_value=consumed)

    async def exchange(*args: object, **kwargs: object) -> ExchangedGoogleTokens:
        assert events[-2:] == ["commit-1", "release-1"]
        events.append("exchange")
        return tokens

    exchange_mock = AsyncMock(side_effect=exchange)
    monkeypatch.setattr(transactions, "consume_oauth_login_attempt", consume)
    monkeypatch.setattr(completion, "exchange_google_authorization_code", exchange_mock)
    monkeypatch.setattr(
        sessions, "authenticate_active_account_token", AsyncMock(return_value=verified)
    )
    monkeypatch.setattr(
        sessions, "create_account_session", AsyncMock(return_value=material.created)
    )

    def issue(
        response: Response, token: SecretStr, expires_at: datetime, settings: Settings
    ) -> None:
        assert events[-2:] == ["commit-2", "release-2"]
        events.append("cookie")
        set_account_cookie(response, token, expires_at, settings)

    # Cookie issuance is observed at the HTTP boundary, after the real service returns.
    issue_mock = Mock(side_effect=issue)
    monkeypatch.setattr(routes, "set_account_cookie", issue_mock)
    response = get(material)
    assert_outcome(material, response, "success" if failed_commit is None else "unavailable")
    consume.assert_awaited_once()
    if failed_commit == 1:
        exchange_mock.assert_not_awaited()
    else:
        exchange_mock.assert_awaited_once()
    if failed_commit is None:
        issue_mock.assert_called_once()
        assert events[-1] == "cookie"
    else:
        issue_mock.assert_not_called()


@pytest.mark.parametrize("fails", [False, True])
def test_callback_receipt_forwarded_but_cleared_only_after_success(
    material: Material, fails: bool
) -> None:
    from app.account_signup_terms import (
        make_signup_terms_receipt,
        set_signup_terms_cookie,
        signup_terms_cookie_name,
    )

    receipt = make_signup_terms_receipt(SecretStr("signup@example.test")).model_copy(
        update={"confirmed_user_id": material.created.user_id}
    )
    response = Response()
    set_signup_terms_cookie(response, receipt, material.settings)
    parsed = SimpleCookie()
    parsed.load(response.headers["set-cookie"])
    name = signup_terms_cookie_name(material.settings)
    value = parsed[name].value
    if fails:
        material.complete.side_effect = SQLAlchemyError("private")
    result = material.client.get(
        PATH + "?code=" + CODE,
        headers={
            "Cookie": f"__Host-askm6_oauth={BINDING}; {name}={value}; __Host-askm6_guest=preserved"
        },
    )
    assert result.status_code == 303
    assert result.headers["Location"].endswith("unavailable" if fails else "success")
    assert material.complete.await_args is not None
    assert material.complete.await_args.kwargs["signup_terms_receipt"] == SecretStr(value)
    cookies = SimpleCookie()
    for header in result.headers.get_list("set-cookie"):
        cookies.load(header)
    if fails:
        assert name not in cookies
        assert account_cookie_name(material.settings) not in cookies
    else:
        assert cookies[name]["max-age"] == "0"
        assert cookies[name]["secure"] and cookies[name]["httponly"]
        assert cookies[name]["path"] == "/"
        assert account_cookie_name(material.settings) in cookies
    assert "__Host-askm6_guest" not in cookies
