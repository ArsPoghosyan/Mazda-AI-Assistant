"""Sign-in route guards without provider or database requests."""

import asyncio
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from http.cookies import SimpleCookie
from secrets import token_hex
from typing import cast
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import httpx2
import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine

from app.account_auth import AccountAuthenticationUnavailable
from app.account_cookies import account_cookie_name
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
)
from app.account_sign_in_requests import SignInCredentials, read_sign_in_credentials
from app.account_tokens import InvalidAccountToken
from app.auth_rate_limit_keys import AuthRateLimitKeyUnavailable, get_sign_in_ip_key
from app.auth_rate_limits import AuthRateLimitDecision, AuthRateLimitUnavailable
from app.client_ip import ClientIPUnavailable
from app.config import Settings
from app.main import create_app

PATH = "/api/v1/account/sign-in"
ORIGIN = "https://app.example.test"
PEER = "192.0.2.12"


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


def make_settings(enabled: bool = True) -> Settings:
    return IsolatedSettings.model_validate(
        {
            "database_url": None,
            "migration_database_url": None,
            "supabase_auth_issuer": "https://auth.example.test/auth/v1",
            "supabase_auth_publishable_key": "sb_publishable_synthetic_test_key",
            "account_session_encryption_key": Fernet.generate_key().decode("ascii"),
            "auth_rate_limit_hmac_secret": token_hex(32),
            "account_cookie_secure": True,
            "account_sign_in_api_enabled": enabled,
            "csrf_trusted_origins": (ORIGIN,),
        }
    )


@dataclass
class GuardMocks:
    parse: AsyncMock
    sign_in: AsyncMock
    counter: AsyncMock


@pytest.fixture
def guards(monkeypatch: pytest.MonkeyPatch) -> GuardMocks:
    parse = AsyncMock()
    sign_in = AsyncMock()
    counter = AsyncMock(return_value=AuthRateLimitDecision(True, datetime.now(UTC), 0, None))

    monkeypatch.setattr(
        "app.account_sign_in_routes.read_sign_in_credentials",
        parse,
    )
    monkeypatch.setattr(
        "app.account_sign_in_routes.sign_in_account",
        sign_in,
    )

    monkeypatch.setattr("app.account_sign_in_routes.commit_sign_in_attempt", counter)
    return GuardMocks(parse=parse, sign_in=sign_in, counter=counter)


def install_resources(application: FastAPI) -> None:
    """Provide placeholders that guard tests must never use."""
    application.state.database_engine = Mock(spec=AsyncEngine)
    application.state.account_auth_client = Mock(spec=httpx2.AsyncClient)
    application.state.account_key_cache = Mock(spec=AccountKeyCache)


def assert_blocked(
    response: httpx2.Response,
    guards: GuardMocks,
    status_code: int,
    detail: str,
) -> None:
    assert response.status_code == status_code
    assert response.json() == {"detail": detail}
    assert response.headers["Cache-Control"] == "no-store"
    assert "set-cookie" not in response.headers
    guards.parse.assert_not_awaited()
    guards.sign_in.assert_not_awaited()
    assert response.headers.get("X-Account-Verification") is None
    guards.counter.assert_not_awaited()


def test_disabled_route_stops_before_reading_credentials(
    guards: GuardMocks,
) -> None:
    application = create_app(make_settings(enabled=False))

    with TestClient(application, base_url="https://api.example.test") as client:
        install_resources(application)
        response = client.post(
            PATH,
            content=b"not-json",
            headers={
                "Origin": ORIGIN,
                "Content-Type": "application/json",
            },
        )

    assert_blocked(
        response,
        guards,
        503,
        "Account sign-in is temporarily unavailable.",
    )


@pytest.mark.parametrize(
    "origin_headers",
    [
        [],
        [("Origin", "")],
        [("Origin", "null")],
        [("Origin", "https://untrusted.example.test")],
        [("Origin", ORIGIN + "/")],
        [("Origin", ORIGIN), ("Origin", ORIGIN)],
        [
            ("Origin", ORIGIN),
            ("Origin", "https://untrusted.example.test"),
        ],
    ],
    ids=[
        "missing",
        "empty",
        "null",
        "untrusted",
        "trailing-slash",
        "duplicate",
        "conflicting",
    ],
)
def test_invalid_origin_stops_before_reading_credentials(
    guards: GuardMocks,
    origin_headers: list[tuple[str, str]],
) -> None:
    application = create_app(make_settings())

    with TestClient(application, base_url="https://api.example.test") as client:
        install_resources(application)
        response = client.post(
            PATH,
            content=b"not-json",
            headers=[
                *origin_headers,
                ("Content-Type", "application/json"),
            ],
        )

    assert_blocked(
        response,
        guards,
        403,
        "Request origin is not allowed.",
    )


@pytest.mark.parametrize(
    "missing",
    [
        "database_engine",
        "account_auth_client",
        "account_key_cache",
    ],
)
def test_missing_resource_stops_before_reading_credentials(
    guards: GuardMocks,
    missing: str,
) -> None:
    application = create_app(make_settings())

    with TestClient(application, base_url="https://api.example.test") as client:
        install_resources(application)
        setattr(application.state, missing, None)

        response = client.post(
            PATH,
            content=b"not-json",
            headers={
                "Origin": ORIGIN,
                "Content-Type": "application/json",
            },
        )

    assert_blocked(
        response,
        guards,
        503,
        "Account sign-in is temporarily unavailable.",
    )


@pytest.mark.parametrize("secure", [False, True], ids=["local", "secure"])
@pytest.mark.parametrize("value", ["", "stale", "B" * 43], ids=["empty", "malformed", "shaped"])
def test_account_cookie_requires_sign_out_before_any_login_work(
    guards: GuardMocks, secure: bool, value: str
) -> None:
    settings = make_settings()
    settings.account_cookie_secure = secure
    application = create_app(settings)
    cookie = account_cookie_name(settings)
    with TestClient(application, base_url="https://api.example.test") as client:
        install_resources(application)
        response = client.post(
            PATH,
            content=b"not-json",
            headers={"Origin": ORIGIN, "Cookie": f"{cookie}={value}"},
        )
    assert_blocked(response, guards, 409, "Sign out before starting another account login.")


@pytest.mark.parametrize("sign_out_fails", [False, True], ids=["signed-out", "sign-out-failed"])
def test_switch_requires_successful_explicit_sign_out(
    route_material: "RouteMaterial", monkeypatch: pytest.MonkeyPatch, sign_out_fails: bool
) -> None:
    material = route_material
    material.settings.account_sign_out_api_enabled = True
    delete_session = AsyncMock(
        side_effect=SQLAlchemyError("synthetic-private") if sign_out_fails else None
    )
    monkeypatch.setattr(
        "app.account_sign_out_routes.delete_account_session_transaction", delete_session
    )
    material.client.cookies.set(
        "__Host-askm6_guest", "preserved-guest", domain="api.example.test", path="/"
    )
    assert post_credentials(material).status_code == 200
    first_token = material.created.token.get_secret_value()
    assert material.client.cookies.get(COOKIE_NAME) == first_token
    assert post_credentials(material).status_code == 409
    material.sign_in.assert_awaited_once()
    material.counter.assert_awaited_once()

    signed_out = material.client.post("/api/v1/account/sign-out", headers={"Origin": ORIGIN})
    delete_session.assert_awaited_once_with(material.engine, SecretStr(first_token))
    material.sign_in.return_value = replace(
        material.created, user_id=uuid4(), token=SecretStr("C" * 43)
    )
    if sign_out_fails:
        assert signed_out.status_code == 503
        assert "set-cookie" not in signed_out.headers
        assert material.client.cookies.get(COOKIE_NAME) == first_token
        assert post_credentials(material).status_code == 409
        material.sign_in.assert_awaited_once()
        material.counter.assert_awaited_once()
    else:
        assert signed_out.status_code == 204
        assert material.client.cookies.get(COOKIE_NAME) is None
        switched = post_credentials(material)
        assert switched.status_code == 200
        assert switched.json()["user_id"] == str(material.sign_in.return_value.user_id)
        assert material.client.cookies.get(COOKIE_NAME) == "C" * 43
        assert material.sign_in.await_count == 2
        assert material.counter.await_count == 2
    assert material.client.cookies.get("__Host-askm6_guest") == "preserved-guest"


EMAIL = "owner@example.test"
PASSWORD = "  synthetic-password-é  "
COOKIE_NAME = "__Host-askm6_account"
OLD_BROWSER_TOKEN = "B" * 43
PRIVATE_DETAIL = "synthetic-private-provider-detail"
CAPTCHA_TOKEN = "synthetic-account-captcha-proof"


@dataclass
class RouteMaterial:
    client: TestClient
    settings: Settings
    engine: AsyncEngine
    http_client: httpx2.AsyncClient
    key_cache: AccountKeyCache
    created: CreatedAccountSession
    sign_in: AsyncMock
    counter: AsyncMock
    parse: AsyncMock


@pytest.fixture
def route_material(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[RouteMaterial]:
    settings = make_settings()
    application = create_app(settings)

    now = datetime.now(UTC)
    created = CreatedAccountSession(
        session_id=uuid4(),
        user_id=uuid4(),
        token=SecretStr("A" * 43),
        idle_expires_at=now + timedelta(days=7),
        absolute_expires_at=now + timedelta(days=30),
    )
    sign_in = AsyncMock(return_value=created)
    counter = AsyncMock(return_value=AuthRateLimitDecision(True, datetime.now(UTC), 0, None))
    parse = AsyncMock(wraps=read_sign_in_credentials)
    monkeypatch.setattr("app.account_sign_in_routes.commit_sign_in_attempt", counter)
    monkeypatch.setattr("app.account_sign_in_routes.read_sign_in_credentials", parse)
    monkeypatch.setattr(
        "app.account_sign_in_routes.sign_in_account",
        sign_in,
    )

    with TestClient(
        application, base_url="https://api.example.test", client=(PEER, 12345)
    ) as client:
        install_resources(application)

        yield RouteMaterial(
            client=client,
            settings=settings,
            engine=cast(AsyncEngine, application.state.database_engine),
            http_client=cast(
                httpx2.AsyncClient,
                application.state.account_auth_client,
            ),
            key_cache=cast(
                AccountKeyCache,
                application.state.account_key_cache,
            ),
            created=created,
            sign_in=sign_in,
            counter=counter,
            parse=parse,
        )


def post_credentials(material: RouteMaterial) -> httpx2.Response:
    return material.client.post(
        PATH,
        json={
            "email": EMAIL,
            "password": PASSWORD,
            "captcha_token": CAPTCHA_TOKEN,
        },
        headers={
            "Origin": ORIGIN,
        },
    )


def assert_service_called_once(material: RouteMaterial) -> None:
    key = get_sign_in_ip_key(
        Request({"type": "http", "headers": [], "client": (PEER, 12345)}), material.settings
    )
    material.counter.assert_awaited_once_with(
        material.engine,
        key,
        max_requests=material.settings.account_sign_in_ip_max_requests,
        window_seconds=material.settings.account_sign_in_ip_window_seconds,
    )
    material.sign_in.assert_awaited_once_with(
        material.engine,
        SecretStr(EMAIL),
        SecretStr(PASSWORD),
        settings=material.settings,
        client=material.http_client,
        key_cache=material.key_cache,
        captcha_token=SecretStr(CAPTCHA_TOKEN),
        signup_terms_receipt=None,
    )


def assert_sign_in_failure(
    response: httpx2.Response,
    status_code: int,
    detail: str,
) -> None:
    assert response.status_code == status_code
    assert response.json() == {"detail": detail}
    assert response.headers["Cache-Control"] == "no-store"
    assert "set-cookie" not in response.headers
    assert "www-authenticate" not in response.headers

    for secret in (EMAIL, PASSWORD, OLD_BROWSER_TOKEN, PRIVATE_DETAIL):
        assert secret not in response.text


def test_success_issues_secure_cookie_and_returns_only_session_metadata(
    route_material: RouteMaterial,
) -> None:
    response = post_credentials(route_material)

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    assert_service_called_once(route_material)

    body = response.json()
    assert set(body) == {"user_id", "expires_at", "absolute_expires_at"}
    assert body["user_id"] == str(route_material.created.user_id)
    assert datetime.fromisoformat(body["expires_at"]) == (route_material.created.idle_expires_at)
    assert datetime.fromisoformat(body["absolute_expires_at"]) == (
        route_material.created.absolute_expires_at
    )

    cookies: SimpleCookie = SimpleCookie()
    cookies.load(response.headers["set-cookie"])
    cookie = cookies[COOKIE_NAME]

    new_token = route_material.created.token.get_secret_value()
    assert cookie.value == new_token
    assert cookie.value != OLD_BROWSER_TOKEN
    assert bool(cookie["secure"])
    assert bool(cookie["httponly"])
    assert cookie["samesite"] == "lax"
    assert cookie["path"] == "/"
    assert cookie["domain"] == ""
    assert parsedate_to_datetime(cookie["expires"]) == (
        route_material.created.idle_expires_at.replace(microsecond=0)
    )

    for secret in (EMAIL, PASSWORD, OLD_BROWSER_TOKEN, new_token):
        assert secret not in response.text
    assert str(route_material.created.session_id) not in response.text


def test_rejected_credentials_return_generic_401_without_changing_cookie(
    route_material: RouteMaterial,
) -> None:
    route_material.sign_in.side_effect = AccountSignInRejected(PRIVATE_DETAIL)

    response = post_credentials(route_material)

    assert_sign_in_failure(response, 401, "Sign-in was rejected.")
    assert_service_called_once(route_material)
    assert response.headers.get("X-Account-Verification") is None


@pytest.mark.parametrize(
    "failure",
    [
        AccountSignInUnavailable(PRIVATE_DETAIL),
        AccountAuthenticationUnavailable(PRIVATE_DETAIL),
        AccountSessionUnavailable(PRIVATE_DETAIL),
        AccountSessionAlreadyExists(PRIVATE_DETAIL),
        InvalidAccountToken(PRIVATE_DETAIL),
        SQLAlchemyError(PRIVATE_DETAIL),
        TimeoutError(PRIVATE_DETAIL),
    ],
    ids=[
        "provider-unavailable",
        "verification-unavailable",
        "session-unavailable",
        "duplicate-session",
        "invalid-provider-token",
        "database-error",
        "timeout",
    ],
)
def test_service_failure_returns_generic_503_without_changing_cookie(
    route_material: RouteMaterial,
    failure: Exception,
) -> None:
    route_material.sign_in.side_effect = failure

    response = post_credentials(route_material)

    assert_sign_in_failure(
        response,
        503,
        "Account sign-in is temporarily unavailable.",
    )
    assert_service_called_once(route_material)
    assert response.headers.get("X-Account-Verification") is None


@pytest.mark.parametrize(
    ("body", "content_type", "status_code", "detail"),
    [
        (
            b'{"email":"owner@example.test","password":',
            "application/json",
            400,
            "Invalid sign-in request.",
        ),
        (
            b" " * (16 * 1024 + 1),
            "application/json",
            413,
            "Sign-in request is too large.",
        ),
        (
            b"{}",
            "text/plain",
            415,
            "Sign-in requires a JSON request.",
        ),
    ],
    ids=["malformed-json", "oversized-body", "unsupported-content-type"],
)
def test_invalid_request_stops_before_sign_in_service(
    route_material: RouteMaterial,
    body: bytes,
    content_type: str,
    status_code: int,
    detail: str,
) -> None:
    response = route_material.client.post(
        PATH,
        content=body,
        headers={
            "Origin": ORIGIN,
            "Content-Type": content_type,
        },
    )

    assert_sign_in_failure(response, status_code, detail)
    route_material.sign_in.assert_not_awaited()


def test_deadline_cancels_stalled_sign_in_service(
    route_material: RouteMaterial,
) -> None:
    route_material.settings.account_sign_in_timeout_seconds = 1
    was_cancelled = False

    async def stalled(
        *args: object,
        **kwargs: object,
    ) -> CreatedAccountSession:
        nonlocal was_cancelled
        try:
            # Longer than the route deadline, but finite if it stops working.
            await asyncio.sleep(3)
        except asyncio.CancelledError:
            was_cancelled = True
            raise

        raise AssertionError("Stalled sign-in unexpectedly completed.")

    route_material.sign_in.side_effect = stalled

    response = post_credentials(route_material)

    assert_sign_in_failure(
        response,
        503,
        "Account sign-in is temporarily unavailable.",
    )
    assert was_cancelled
    assert_service_called_once(route_material)


def test_deadline_covers_stalled_body_reading(
    route_material: RouteMaterial,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    route_material.settings.account_sign_in_timeout_seconds = 1
    was_cancelled = False

    async def stalled_stream(request: Request) -> AsyncIterator[bytes]:
        nonlocal was_cancelled
        try:
            yield b" "
            await asyncio.sleep(3)
        except asyncio.CancelledError:
            was_cancelled = True
            raise

        raise AssertionError("Stalled body stream unexpectedly completed.")

    monkeypatch.setattr(
        "app.account_sign_in_requests.Request.stream",
        stalled_stream,
    )

    response = post_credentials(route_material)

    assert_sign_in_failure(
        response,
        503,
        "Account sign-in is temporarily unavailable.",
    )
    assert was_cancelled
    route_material.sign_in.assert_not_awaited()


@pytest.mark.parametrize(
    "include_null",
    [False, True],
    ids=["omitted", "null"],
)
def test_missing_captcha_stops_before_sign_in_service(
    route_material: RouteMaterial,
    include_null: bool,
) -> None:
    payload: dict[str, object] = {
        "email": EMAIL,
        "password": PASSWORD,
    }
    if include_null:
        payload["captcha_token"] = None

    response = route_material.client.post(
        PATH,
        json=payload,
        headers={
            "Origin": ORIGIN,
        },
    )

    assert_sign_in_failure(
        response,
        403,
        "Human verification is required or was rejected.",
    )
    assert response.headers["X-Account-Verification"] == "required"
    route_material.sign_in.assert_not_awaited()


def test_provider_captcha_rejection_requests_fresh_verification(
    route_material: RouteMaterial,
) -> None:
    route_material.sign_in.side_effect = AccountSignInCaptchaRejected(PRIVATE_DETAIL)

    response = post_credentials(route_material)

    assert_sign_in_failure(
        response,
        403,
        "Human verification is required or was rejected.",
    )
    assert response.headers["X-Account-Verification"] == "required"
    assert CAPTCHA_TOKEN not in response.text
    assert_service_called_once(route_material)


@pytest.mark.parametrize(
    "missing",
    [
        "supabase_auth_issuer",
        "supabase_auth_publishable_key",
        "account_session_encryption_key",
        "auth_rate_limit_hmac_secret",
    ],
)
def test_missing_configuration_never_counts_or_parses(
    guards: GuardMocks,
    missing: str,
) -> None:
    settings = make_settings()
    setattr(settings, missing, None)
    application = create_app(settings)
    with TestClient(application, base_url="https://api.example.test") as client:
        install_resources(application)
        response = client.post(PATH, json={}, headers={"Origin": ORIGIN})
    assert_blocked(response, guards, 503, "Account sign-in is temporarily unavailable.")


@pytest.mark.parametrize("body", [b"not-json", b"{}"])
def test_local_cap_returns_retry_without_parsing_or_provider_work(
    route_material: RouteMaterial,
    body: bytes,
) -> None:
    now = datetime.now(UTC)
    route_material.counter.return_value = AuthRateLimitDecision(
        False, now, 61, now + timedelta(seconds=61)
    )
    response = route_material.client.post(
        PATH, content=body, headers={"Origin": ORIGIN, "Content-Type": "application/json"}
    )
    assert_sign_in_failure(response, 429, "Sign-in is temporarily rate limited.")
    assert response.headers["Retry-After"] == "61"
    assert "X-Account-Verification" not in response.headers
    route_material.counter.assert_awaited_once()
    route_material.parse.assert_not_awaited()
    route_material.sign_in.assert_not_awaited()


@pytest.mark.parametrize(
    "failure",
    [
        AuthRateLimitUnavailable(PRIVATE_DETAIL),
        SQLAlchemyError(PRIVATE_DETAIL),
        TimeoutError(PRIVATE_DETAIL),
    ],
)
def test_accounting_failure_returns_503_without_parsing_or_retry(
    route_material: RouteMaterial,
    failure: Exception,
) -> None:
    route_material.counter.side_effect = failure
    response = post_credentials(route_material)
    assert_sign_in_failure(response, 503, "Account sign-in is temporarily unavailable.")
    assert (
        "Retry-After" not in response.headers and "X-Account-Verification" not in response.headers
    )
    route_material.counter.assert_awaited_once()
    route_material.parse.assert_not_awaited()
    route_material.sign_in.assert_not_awaited()


@pytest.mark.parametrize(
    "failure", [AuthRateLimitKeyUnavailable(PRIVATE_DETAIL), ClientIPUnavailable(PRIVATE_DETAIL)]
)
def test_fingerprint_failure_has_no_database_or_provider_work(
    route_material: RouteMaterial,
    monkeypatch: pytest.MonkeyPatch,
    failure: Exception,
) -> None:
    key = Mock(side_effect=failure)
    monkeypatch.setattr("app.account_sign_in_routes.get_sign_in_ip_key", key)
    response = post_credentials(route_material)
    assert_sign_in_failure(response, 503, "Account sign-in is temporarily unavailable.")
    assert (
        "Retry-After" not in response.headers and "X-Account-Verification" not in response.headers
    )
    key.assert_called_once()
    route_material.counter.assert_not_awaited()
    route_material.parse.assert_not_awaited()
    route_material.sign_in.assert_not_awaited()


def test_sign_in_deadline_includes_accounting(
    route_material: RouteMaterial,
) -> None:
    route_material.settings.account_sign_in_timeout_seconds = 1
    cancelled = False

    async def stalled(*args: object, **kwargs: object) -> AuthRateLimitDecision:
        nonlocal cancelled
        try:
            await asyncio.sleep(3)
        except asyncio.CancelledError:
            cancelled = True
            raise
        raise AssertionError("Accounting unexpectedly completed.")

    route_material.counter.side_effect = stalled
    response = post_credentials(route_material)
    assert_sign_in_failure(response, 503, "Account sign-in is temporarily unavailable.")
    assert cancelled
    route_material.counter.assert_awaited_once()
    route_material.parse.assert_not_awaited()
    route_material.sign_in.assert_not_awaited()


def test_accounting_finishes_before_credentials_and_sign_in_service(
    route_material: RouteMaterial,
) -> None:
    events: list[str] = []

    async def account(*args: object, **kwargs: object) -> AuthRateLimitDecision:
        events.append("accounting")
        return AuthRateLimitDecision(True, datetime.now(UTC), 0, None)

    async def parse(request: Request) -> SignInCredentials:
        assert events == ["accounting"]
        events.append("parse")
        return await read_sign_in_credentials(request)

    async def sign_in(*args: object, **kwargs: object) -> CreatedAccountSession:
        assert events == ["accounting", "parse"]
        events.append("service")
        return route_material.created

    route_material.counter.side_effect = account
    route_material.parse.side_effect = parse
    route_material.sign_in.side_effect = sign_in
    assert post_credentials(route_material).status_code == 200
    assert events == ["accounting", "parse", "service"]
    assert_service_called_once(route_material)


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"CF-Connecting-IP": "198.51.100.20", "X-Forwarded-For": "198.51.100.20"},
        {"X-AskM6-Client-IP": "198.51.100.20", "X-AskM6-Proxy-Secret": "00" * 32},
        {"X-AskM6-Client-IP": "198.51.100.20, 203.0.113.30", "X-AskM6-Proxy-Secret": "ab" * 32},
    ],
)
def test_untrusted_proxy_request_never_reads_credentials_or_counts(
    guards: GuardMocks, headers: dict[str, str]
) -> None:
    settings = make_settings()
    settings.auth_proxy_trust_enabled = True
    settings.auth_proxy_shared_secret = SecretStr("ab" * 32)
    application = create_app(settings)
    with TestClient(application, base_url="https://api.example.test") as client:
        install_resources(application)
        response = client.post(PATH, content=b"not-json", headers={"Origin": ORIGIN, **headers})
    assert_blocked(response, guards, 503, "Account sign-in is temporarily unavailable.")
