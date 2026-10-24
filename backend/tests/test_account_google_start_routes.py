"""Google initiation guards, committed replacement and transient cookie issuance."""

import asyncio
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from http.cookies import SimpleCookie
from typing import cast
from unittest.mock import AsyncMock, Mock
from urllib.parse import parse_qs, urlsplit
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

import app.account_google_routes as routes
import app.account_oauth_transactions as transactions
from app.account_google_authorization import GoogleAuthorizationUnavailable
from app.account_key_cache import AccountKeyCache
from app.account_oauth_attempts import CreatedOAuthLoginAttempt, OAuthLoginAttemptUnavailable
from app.account_oauth_cookies import oauth_cookie_name, set_oauth_cookie
from app.account_oauth_material import InvalidOAuthLoginMaterial
from app.auth_rate_limit_keys import AuthRateLimitKeyUnavailable, get_google_start_ip_key
from app.auth_rate_limits import AuthRateLimitDecision, AuthRateLimitUnavailable
from app.client_ip import ClientIPUnavailable
from app.config import Settings
from app.main import create_app

PATH = "/api/v1/account/google/start"
ORIGIN = "https://app.example.test"
NEW_TOKEN = "n" * 43
OLD_TOKEN = "o" * 43


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@dataclass
class Material:
    application: FastAPI
    client: TestClient
    settings: Settings
    engine: Mock
    connection: AsyncConnection
    created: CreatedOAuthLoginAttempt
    create: AsyncMock
    replace: AsyncMock
    commit: AsyncMock
    cookie: Mock
    events: list[str]
    limit: AsyncMock


@pytest.fixture
def material(monkeypatch: pytest.MonkeyPatch) -> Iterator[Material]:
    settings = IsolatedSettings.model_validate(
        {
            "database_url": None,
            "migration_database_url": None,
            "supabase_auth_issuer": "https://auth.example.test/auth/v1",
            "supabase_auth_publishable_key": "sb_publishable_synthetic",
            "account_session_encryption_key": Fernet.generate_key().decode("ascii"),
            "account_cookie_secure": True,
            "csrf_trusted_origins": (ORIGIN,),
            "account_google_oauth_api_enabled": True,
            "auth_rate_limit_hmac_secret": "ab" * 32,
            "account_google_oauth_callback_url": "https://api.example.test/api/v1/account/google/callback",
        }
    )
    created = CreatedOAuthLoginAttempt(
        uuid4(), SecretStr(NEW_TOKEN), "c" * 43, datetime.now(UTC) + timedelta(minutes=10)
    )
    events: list[str] = []

    async def create(*args: object, **kwargs: object) -> CreatedOAuthLoginAttempt:
        events.append("create")
        return created

    async def replace(*args: object, **kwargs: object) -> CreatedOAuthLoginAttempt:
        events.append("replace")
        return created

    creation = AsyncMock(side_effect=create)
    replacement = AsyncMock(side_effect=replace)
    commit = AsyncMock()
    connection = cast(AsyncConnection, Mock(spec=AsyncConnection))

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

    def issue(
        response: Response, token: SecretStr, expires_at: datetime, settings: Settings
    ) -> None:
        assert events[-2:] == ["commit", "release"]
        events.append("cookie")
        set_oauth_cookie(response, token, expires_at, settings)

    cookie = Mock(side_effect=issue)
    monkeypatch.setattr(transactions, "create_oauth_login_attempt", creation)
    monkeypatch.setattr(transactions, "replace_oauth_login_attempt", replacement)
    monkeypatch.setattr(routes, "set_oauth_cookie", cookie)
    limit = AsyncMock(return_value=AuthRateLimitDecision(True, datetime.now(UTC), 0, None))
    monkeypatch.setattr(routes, "commit_google_start_attempt", limit)
    application = create_app(settings)
    with TestClient(
        application, base_url="https://api.example.test", client=("192.0.2.12", 12345)
    ) as client:
        application.state.database_engine = engine
        application.state.account_auth_client = Mock(spec=httpx2.AsyncClient)
        application.state.account_key_cache = Mock(spec=AccountKeyCache)
        yield Material(
            application,
            client,
            settings,
            engine,
            connection,
            created,
            creation,
            replacement,
            commit,
            cookie,
            events,
            limit,
        )


def post(material: Material, cookie: str | None = None) -> httpx2.Response:
    headers = {"Origin": ORIGIN}
    if cookie is not None:
        headers["Cookie"] = cookie
    return material.client.post(PATH, headers=headers)


def assert_failure(response: httpx2.Response, status: int, *, clear: bool = False) -> None:
    assert response.status_code == status
    assert response.headers["Cache-Control"] == "no-store"
    assert ("set-cookie" in response.headers) is clear
    for secret in (NEW_TOKEN, OLD_TOKEN, "synthetic-private", "sb_publishable_synthetic"):
        assert secret not in response.text
    assert "Location" not in response.headers


@pytest.mark.parametrize("secure", [True, False])
def test_success_returns_fixed_destination_after_commit_and_sets_only_binding(
    material: Material,
    secure: bool,
) -> None:
    material.settings.account_cookie_secure = secure
    response = post(material)
    assert response.status_code == 200
    payload = response.json()
    assert set(payload) == {"authorization_url", "expires_at"}
    parsed = urlsplit(payload["authorization_url"])
    assert (parsed.scheme, parsed.netloc, parsed.path) == (
        "https",
        "auth.example.test",
        "/auth/v1/authorize",
    )
    assert parse_qs(parsed.query) == {
        "provider": ["google"],
        "redirect_to": [str(material.settings.account_google_oauth_callback_url)],
        "code_challenge": [material.created.code_challenge],
        "code_challenge_method": ["s256"],
    }
    cookies: SimpleCookie = SimpleCookie()
    cookies.load(response.headers["set-cookie"])
    assert list(cookies) == [oauth_cookie_name(material.settings)]
    binding = cookies[oauth_cookie_name(material.settings)]
    assert binding.value == NEW_TOKEN
    assert bool(binding["secure"]) is secure
    assert bool(binding["httponly"])
    assert binding["samesite"] == "lax"
    assert binding["domain"] == ""
    assert parsedate_to_datetime(binding["expires"]) == material.created.expires_at.replace(
        microsecond=0
    )
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert NEW_TOKEN not in response.text
    material.create.assert_awaited_once_with(material.connection, material.settings)
    material.replace.assert_not_awaited()
    assert material.events == ["begin", "create", "commit", "release", "cookie"]


def test_existing_binding_uses_committed_replacement_without_fresh_fallback(
    material: Material,
) -> None:
    response = post(material, f"__Host-askm6_oauth={OLD_TOKEN}; guest=preserve")
    assert response.status_code == 200
    material.replace.assert_awaited_once_with(material.connection, material.settings, OLD_TOKEN)
    material.create.assert_not_awaited()
    assert material.events == ["begin", "replace", "commit", "release", "cookie"]


def test_disabled_flag_stops_before_cookie_reading_body_or_database(material: Material) -> None:
    material.settings.account_google_oauth_api_enabled = False
    response = material.client.post(PATH, content=b"bad", headers={"Origin": ORIGIN})
    assert_failure(response, 503)
    assert material.events == []


@pytest.mark.parametrize(
    "origins",
    [
        [],
        [("Origin", "")],
        [("Origin", "null")],
        [("Origin", ORIGIN + "/")],
        [("Origin", "https://untrusted.example")],
        [("Origin", ORIGIN), ("Origin", ORIGIN)],
    ],
)
def test_origin_guard_precedes_attempt_creation(
    material: Material, origins: list[tuple[str, str]]
) -> None:
    response = material.client.post(PATH, content=b"bad", headers=origins)
    assert_failure(response, 403)
    assert material.events == []


@pytest.mark.parametrize(
    "missing",
    [
        "database_engine",
        "account_auth_client",
        "account_key_cache",
        "supabase_auth_issuer",
        "supabase_auth_publishable_key",
        "account_session_encryption_key",
        "account_google_oauth_callback_url",
    ],
)
def test_missing_prerequisite_never_creates_attempt(material: Material, missing: str) -> None:
    if missing in {"database_engine", "account_auth_client", "account_key_cache"}:
        setattr(material.application.state, missing, None)
    else:
        setattr(material.settings, missing, None)
    assert_failure(post(material), 503)
    assert material.events == []


@pytest.mark.parametrize(
    "query", ["?next=https://untrusted.example", "?provider=github", "?code=x"]
)
def test_browser_options_in_query_are_rejected(material: Material, query: str) -> None:
    response = material.client.post(PATH + query, headers={"Origin": ORIGIN})
    assert_failure(response, 400)
    assert material.events == []


@pytest.mark.parametrize("body", [b"{}", b" ", b"next=/untrusted", b"x" * 16384])
def test_any_body_is_rejected_without_creating_attempt(material: Material, body: bytes) -> None:
    response = material.client.post(
        PATH, content=body, headers={"Origin": ORIGIN, "Content-Length": "0"}
    )
    assert_failure(response, 400)
    assert material.events == []


@pytest.mark.parametrize("value", ["", "x" * 43, "malformed"])
def test_account_cookie_requires_explicit_sign_out(material: Material, value: str) -> None:
    response = post(material, f"__Host-askm6_account={value}")
    assert_failure(response, 409)
    assert material.events == []


@pytest.mark.parametrize(
    "cookie",
    [
        "__Host-askm6_oauth=bad",
        "__Host-askm6_oauth=",
        f"__Host-askm6_oauth={OLD_TOKEN}; __Host-askm6_oauth={OLD_TOKEN}",
    ],
)
def test_bad_pending_cookie_is_cleared_for_controlled_restart(
    material: Material, cookie: str
) -> None:
    response = post(material, cookie)
    assert_failure(response, 400, clear=True)
    assert "Max-Age=0" in response.headers["set-cookie"]
    assert response.headers["set-cookie"].startswith("__Host-askm6_oauth=")
    assert material.events == []


def test_consumed_previous_attempt_requires_restart_and_never_falls_back(
    material: Material,
) -> None:
    material.replace.side_effect = InvalidOAuthLoginMaterial("synthetic-private")
    response = post(material, f"__Host-askm6_oauth={OLD_TOKEN}")
    assert_failure(response, 400, clear=True)
    material.create.assert_not_awaited()
    material.replace.assert_awaited_once()
    material.commit.assert_not_awaited()
    assert material.events == ["begin", "rollback", "release"]


@pytest.mark.parametrize("stage", ["create", "replace", "commit"])
@pytest.mark.parametrize(
    "failure",
    [SQLAlchemyError("synthetic-private"), OAuthLoginAttemptUnavailable("synthetic-private")],
)
def test_persistence_or_commit_failure_never_issues_cookie_or_retries(
    material: Material,
    stage: str,
    failure: Exception,
) -> None:
    operation = {"create": material.create, "replace": material.replace, "commit": material.commit}[
        stage
    ]
    operation.side_effect = failure
    cookie = f"__Host-askm6_oauth={OLD_TOKEN}" if stage == "replace" else None
    response = post(material, cookie)
    assert_failure(response, 503)
    material.cookie.assert_not_called()
    material.engine.begin.assert_called_once_with()
    operation.assert_awaited_once()


def test_destination_build_failure_does_not_issue_browser_binding(
    material: Material,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    build = Mock(side_effect=GoogleAuthorizationUnavailable("synthetic-private"))
    monkeypatch.setattr(routes, "build_google_authorization_url", build)
    assert_failure(post(material), 503)
    material.commit.assert_awaited_once()
    material.cookie.assert_not_called()


def test_host_and_forwarded_headers_never_choose_the_destination(material: Material) -> None:
    response = material.client.post(
        PATH,
        headers={
            "Origin": ORIGIN,
            "Host": "untrusted.example",
            "X-Forwarded-Host": "other.example",
            "X-Forwarded-Proto": "http",
        },
    )
    assert response.status_code == 200
    assert "untrusted.example" not in response.text
    assert "other.example" not in response.text
    assert (
        str(material.settings.account_google_oauth_callback_url)
        in parse_qs(urlsplit(response.json()["authorization_url"]).query)["redirect_to"]
    )


def test_non_post_method_cannot_start_login(material: Material) -> None:
    response = material.client.get(PATH, headers={"Origin": ORIGIN})
    assert response.status_code == 405
    assert material.events == []


@pytest.mark.parametrize("stage", ["body", "limit", "create", "commit"])
def test_overall_deadline_cancels_stalled_work_before_cookie_issuance(
    material: Material,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
) -> None:
    material.settings.account_google_oauth_timeout_seconds = 1
    cleaned_up: list[bool] = []

    async def block(*args: object, **kwargs: object) -> None:
        try:
            await asyncio.sleep(3)
        finally:
            cleaned_up.append(True)

    if stage == "body":

        async def stream(request: Request) -> AsyncIterator[bytes]:
            await block()
            yield b""

        monkeypatch.setattr(Request, "stream", stream)
    else:
        operation = {"limit": material.limit, "create": material.create, "commit": material.commit}[
            stage
        ]
        operation.side_effect = block
    assert_failure(post(material), 503)
    assert cleaned_up == [True]
    material.cookie.assert_not_called()
    if stage == "body":
        material.create.assert_not_awaited()


@pytest.mark.anyio
@pytest.mark.parametrize("stage", ["limit", "create", "commit"])
async def test_actual_caller_cancellation_propagates_without_cookie(
    material: Material,
    stage: str,
) -> None:
    entered = asyncio.Event()
    cleaned_up = asyncio.Event()

    async def block(*args: object, **kwargs: object) -> None:
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            cleaned_up.set()

    operation = {"limit": material.limit, "create": material.create, "commit": material.commit}[
        stage
    ]
    operation.side_effect = block

    async def receive() -> dict[str, object]:
        return {"type": "http.request", "body": b"", "more_body": False}

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": PATH,
            "headers": [],
            "query_string": b"",
            "client": ("192.0.2.12", 12345),
            "app": material.application,
        },
        receive=receive,
    )
    response = Response()
    async with asyncio.timeout(5):
        task = asyncio.create_task(routes.start_google_login(request, response))
        try:
            await entered.wait()
            assert not task.done()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        finally:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    assert cleaned_up.is_set()
    assert "set-cookie" not in response.headers
    material.cookie.assert_not_called()


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.parametrize(
    "cookie", [None, "__Host-askm6_oauth=bad", f"__Host-askm6_oauth={OLD_TOKEN}"]
)
def test_limit_denies_before_reading_binding_or_starting_transactions(
    material: Material, cookie: str | None
) -> None:
    material.limit.return_value = AuthRateLimitDecision(
        False, datetime.now(UTC), 61, datetime.now(UTC) + timedelta(seconds=61)
    )
    response = post(material, cookie)
    assert_failure(response, 429)
    assert response.json() == {"detail": "Google sign-in is temporarily rate limited."}
    assert response.headers["Retry-After"] == "61"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert material.events == []
    material.cookie.assert_not_called()
    material.limit.assert_awaited_once_with(
        material.engine,
        get_google_start_ip_key(
            Request({"type": "http", "client": ("192.0.2.12", 12345), "headers": []}),
            material.settings,
        ),
        max_requests=10,
        window_seconds=600,
    )


@pytest.mark.parametrize(
    "failure", [SQLAlchemyError("synthetic-private"), AuthRateLimitUnavailable("synthetic-private")]
)
def test_accounting_failure_stops_before_binding_creation(
    material: Material, failure: Exception
) -> None:
    material.limit.side_effect = failure
    assert_failure(post(material), 503)
    assert material.events == []
    material.limit.assert_awaited_once()
    material.cookie.assert_not_called()


@pytest.mark.parametrize(
    "failure",
    [AuthRateLimitKeyUnavailable("synthetic-private"), ClientIPUnavailable("synthetic-private")],
)
def test_key_failure_stops_before_accounting(
    material: Material, monkeypatch: pytest.MonkeyPatch, failure: Exception
) -> None:
    monkeypatch.setattr(routes, "get_google_start_ip_key", Mock(side_effect=failure))
    assert_failure(post(material), 503)
    material.limit.assert_not_awaited()
    assert material.events == []
