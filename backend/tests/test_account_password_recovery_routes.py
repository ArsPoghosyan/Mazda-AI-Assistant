"""Password-recovery HTTP guards with a mocked provider adapter."""

import asyncio
import json
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from secrets import token_hex
from unittest.mock import AsyncMock, Mock

import httpx2
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine

from app.account_password_recovery import (
    AccountPasswordRecoveryCaptchaRejected,
    AccountPasswordRecoveryRateLimited,
    AccountPasswordRecoveryRejected,
    AccountPasswordRecoveryUnavailable,
)
from app.account_password_recovery_requests import (
    PasswordRecoveryCredentials,
    read_password_recovery_credentials,
)
from app.account_password_recovery_routes import router
from app.auth_rate_limits import AuthRateLimitDecision, AuthRateLimitUnavailable
from app.config import Settings
from app.main import create_app

PATH = "/api/v1/account/password-recovery"
ORIGIN = "https://app.example.test"
EMAIL = "owner@example.test"
CAPTCHA = "synthetic-captcha-proof"
UNAVAILABLE = "Password recovery is temporarily unavailable."


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@dataclass
class RouteMaterial:
    client: TestClient
    application: FastAPI
    settings: Settings
    adapter: AsyncMock
    parse: AsyncMock
    provider_client: Mock
    engine: Mock
    counter: AsyncMock


@pytest.fixture
def material(monkeypatch: pytest.MonkeyPatch) -> Iterator[RouteMaterial]:
    settings = IsolatedSettings.model_validate(
        {
            "database_url": None,
            "migration_database_url": None,
            "supabase_auth_issuer": "https://auth.example.test/auth/v1",
            "supabase_auth_publishable_key": "sb_publishable_synthetic_test_key",
            "account_password_recovery_api_enabled": True,
            "auth_rate_limit_hmac_secret": token_hex(32),
            "csrf_trusted_origins": (ORIGIN,),
        }
    )
    adapter = AsyncMock(return_value=None)
    parse = AsyncMock(wraps=read_password_recovery_credentials)
    provider_client = Mock(spec=httpx2.AsyncClient)
    engine = Mock(spec=AsyncEngine)
    counter = AsyncMock(return_value=AuthRateLimitDecision(True, datetime.now(UTC), 0, None))
    monkeypatch.setattr(
        "app.account_password_recovery_routes.commit_password_recovery_attempt", counter
    )

    monkeypatch.setattr(
        "app.account_password_recovery_routes.request_password_recovery",
        adapter,
    )
    monkeypatch.setattr(
        "app.account_password_recovery_routes.read_password_recovery_credentials",
        parse,
    )

    application = FastAPI()
    application.state.settings = settings
    application.state.account_auth_client = provider_client
    application.state.database_engine = engine
    application.include_router(router)

    with TestClient(application, client=("192.0.2.12", 12345)) as client:
        yield RouteMaterial(
            client, application, settings, adapter, parse, provider_client, engine, counter
        )


def assert_private_response(response: httpx2.Response) -> None:
    assert response.headers["Cache-Control"] == "no-store"
    assert "set-cookie" not in response.headers
    assert EMAIL not in response.text
    assert CAPTCHA not in response.text


def test_router_is_registered_in_application(material: RouteMaterial) -> None:
    application = create_app(material.settings)
    assert "post" in application.openapi()["paths"][PATH]


def test_accepted_request_returns_only_generic_metadata(material: RouteMaterial) -> None:
    response = material.client.post(
        PATH,
        json={"email": EMAIL, "captcha_token": CAPTCHA},
        headers={"Origin": ORIGIN},
    )

    assert response.status_code == 202
    assert response.json() == {
        "status": "accepted",
        "message": ("If password recovery can proceed, check your email for the next steps."),
    }
    assert_private_response(response)
    material.adapter.assert_awaited_once_with(
        SecretStr(EMAIL),
        SecretStr(CAPTCHA),
        settings=material.settings,
        client=material.provider_client,
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
        [("Origin", ORIGIN), ("Origin", "https://untrusted.example.test")],
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
def test_invalid_origin_stops_before_parsing(
    material: RouteMaterial,
    origin_headers: list[tuple[str, str]],
) -> None:
    response = material.client.post(
        PATH,
        content=b"not-json",
        headers=[*origin_headers, ("Content-Type", "application/json")],
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "Request origin is not allowed."}
    assert_private_response(response)
    assert "X-Account-Verification" not in response.headers
    material.parse.assert_not_awaited()
    material.adapter.assert_not_awaited()
    material.counter.assert_not_awaited()


def test_disabled_endpoint_stops_before_parsing(material: RouteMaterial) -> None:
    material.settings.account_password_recovery_api_enabled = False
    response = material.client.post(
        PATH,
        content=b"not-json",
        headers={"Origin": ORIGIN, "Content-Type": "application/json"},
    )

    assert response.status_code == 503
    assert response.json() == {"detail": UNAVAILABLE}
    assert_private_response(response)
    material.parse.assert_not_awaited()
    material.adapter.assert_not_awaited()
    material.counter.assert_not_awaited()


@pytest.mark.parametrize("missing", ["client", "issuer", "publishable-key", "engine", "secret"])
def test_missing_resources_stop_before_parsing(
    material: RouteMaterial,
    missing: str,
) -> None:
    if missing == "client":
        material.application.state.account_auth_client = None
    elif missing == "issuer":
        material.settings.supabase_auth_issuer = None
    elif missing == "publishable-key":
        material.settings.supabase_auth_publishable_key = None
    elif missing == "engine":
        material.application.state.database_engine = None
    else:
        material.settings.auth_rate_limit_hmac_secret = None

    response = material.client.post(
        PATH,
        content=b"not-json",
        headers={"Origin": ORIGIN, "Content-Type": "application/json"},
    )

    assert response.status_code == 503
    assert response.json() == {"detail": UNAVAILABLE}
    assert_private_response(response)
    material.parse.assert_not_awaited()
    material.adapter.assert_not_awaited()
    material.counter.assert_not_awaited()


@pytest.mark.parametrize(
    ("body", "content_type", "expected_status", "detail"),
    [
        (
            b"not-json",
            "application/json",
            400,
            "Invalid password recovery request.",
        ),
        (b"{}", "application/json", 400, "Invalid password recovery request."),
        (
            b'{"email":"owner@example.test"}',
            "application/json",
            400,
            "Invalid password recovery request.",
        ),
        (
            b" " * (16 * 1024 + 1),
            "application/json",
            413,
            "Password recovery request is too large.",
        ),
        (
            b"{}",
            "text/plain",
            415,
            "Password recovery requires a JSON request.",
        ),
    ],
    ids=["malformed", "missing-fields", "missing-proof", "oversized", "media-type"],
)
def test_invalid_input_never_reaches_adapter(
    material: RouteMaterial,
    body: bytes,
    content_type: str,
    expected_status: int,
    detail: str,
) -> None:
    response = material.client.post(
        PATH,
        content=body,
        headers={"Origin": ORIGIN, "Content-Type": content_type},
    )

    assert response.status_code == expected_status
    assert response.json() == {"detail": detail}
    assert_private_response(response)
    material.adapter.assert_not_awaited()
    material.counter.assert_awaited_once()


@pytest.mark.parametrize(
    ("exception_type", "expected_status", "detail"),
    [
        (
            AccountPasswordRecoveryCaptchaRejected,
            403,
            "Human verification is required or was rejected.",
        ),
        (
            AccountPasswordRecoveryRejected,
            400,
            "Password recovery was rejected.",
        ),
        (
            AccountPasswordRecoveryRateLimited,
            429,
            "Password recovery is temporarily rate limited.",
        ),
        (AccountPasswordRecoveryUnavailable, 503, UNAVAILABLE),
        (TimeoutError, 503, UNAVAILABLE),
    ],
)
def test_adapter_errors_are_controlled_without_retry(
    material: RouteMaterial,
    exception_type: type[Exception],
    expected_status: int,
    detail: str,
) -> None:
    material.adapter.side_effect = exception_type("private-provider-detail")

    response = material.client.post(
        PATH,
        json={"email": EMAIL, "captcha_token": CAPTCHA},
        headers={"Origin": ORIGIN},
    )

    assert response.status_code == expected_status
    assert response.json() == {"detail": detail}
    assert_private_response(response)
    assert "private-provider-detail" not in response.text
    assert response.headers.get("X-Account-Verification") == (
        "required" if expected_status == 403 else None
    )
    # No reset time is invented when the provider has not supplied one.
    assert "Retry-After" not in response.headers
    material.adapter.assert_awaited_once()


@pytest.mark.parametrize("stalled_stage", ["body", "provider", "limiter"])
def test_total_deadline_cancels_stalled_work(
    material: RouteMaterial,
    monkeypatch: pytest.MonkeyPatch,
    stalled_stage: str,
) -> None:
    material.settings.account_password_recovery_timeout_seconds = 1
    cancelled = False

    async def stall() -> None:
        nonlocal cancelled
        try:
            await asyncio.sleep(3)
        except asyncio.CancelledError:
            cancelled = True
            raise
        raise AssertionError("Stalled work unexpectedly completed.")

    if stalled_stage == "body":

        async def stalled_stream(request: Request) -> AsyncIterator[bytes]:
            yield b" "
            await stall()

        monkeypatch.setattr(
            "app.account_password_recovery_requests.Request.stream",
            stalled_stream,
        )
    elif stalled_stage == "provider":

        async def stalled_adapter(*args: object, **kwargs: object) -> None:
            await stall()

        material.adapter.side_effect = stalled_adapter
    else:

        async def stalled_counter(*args: object, **kwargs: object) -> AuthRateLimitDecision:
            await stall()
            raise AssertionError("Stalled limiter unexpectedly completed.")

        material.counter.side_effect = stalled_counter

    response = material.client.post(
        PATH,
        json={"email": EMAIL, "captcha_token": CAPTCHA},
        headers={"Origin": ORIGIN},
    )

    assert response.status_code == 503
    assert response.json() == {"detail": UNAVAILABLE}
    assert_private_response(response)
    assert cancelled

    if stalled_stage in {"body", "limiter"}:
        material.adapter.assert_not_awaited()
    else:
        material.adapter.assert_awaited_once()
    if stalled_stage == "limiter":
        material.parse.assert_not_awaited()
        material.counter.assert_awaited_once()


@pytest.mark.parametrize("method", ["GET", "PUT", "DELETE"])
def test_unsupported_methods_do_not_reach_adapter(
    material: RouteMaterial,
    method: str,
) -> None:
    response = material.client.request(
        method,
        PATH,
        headers={"Origin": ORIGIN},
    )

    assert response.status_code == 405
    material.parse.assert_not_awaited()
    material.adapter.assert_not_awaited()


def test_origin_is_checked_even_when_endpoint_is_disabled(
    material: RouteMaterial,
) -> None:
    material.settings.account_password_recovery_api_enabled = False

    response = material.client.post(PATH, json={})

    assert response.status_code == 403
    assert response.json() == {"detail": "Request origin is not allowed."}
    assert_private_response(response)
    material.parse.assert_not_awaited()
    material.adapter.assert_not_awaited()


class ProviderResponseStream(httpx2.AsyncByteStream):
    def __init__(self, payload: object) -> None:
        self.body = json.dumps(payload).encode("utf-8")

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield self.body


@pytest.mark.parametrize(
    ("provider_status", "payload", "expected_status"),
    [
        (200, {}, 202),
        (404, {"code": "user_not_found"}, 202),
        (429, {"code": "over_email_send_rate_limit"}, 202),
        (400, {"code": "captcha_failed"}, 403),
        (429, {"code": "over_request_rate_limit"}, 429),
        (200, {"access_token": "synthetic-provider-secret"}, 503),
    ],
    ids=[
        "accepted",
        "unknown-account",
        "email-cooldown",
        "captcha-rejected",
        "client-rate-limit",
        "unexpected-credentials",
    ],
)
def test_complete_recovery_path_with_mocked_provider(
    monkeypatch: pytest.MonkeyPatch,
    provider_status: int,
    payload: object,
    expected_status: int,
) -> None:
    issuer = "https://auth.example.test/auth/v1"
    publishable_key = "sb_publishable_synthetic_test_key"
    settings = IsolatedSettings.model_validate(
        {
            "database_url": None,
            "migration_database_url": None,
            "supabase_auth_issuer": issuer,
            "supabase_auth_publishable_key": publishable_key,
            "account_session_encryption_key": None,
            "account_password_recovery_api_enabled": True,
            "auth_rate_limit_hmac_secret": token_hex(32),
            "csrf_trusted_origins": (ORIGIN,),
            "turnstile_secret_key": None,
            "turnstile_allowed_hostnames": (),
        }
    )
    requests: list[httpx2.Request] = []
    provider_response = httpx2.Response(
        provider_status,
        headers={"Content-Type": "application/json"},
        stream=ProviderResponseStream(payload),
    )

    def handler(request: httpx2.Request) -> httpx2.Response:
        assert str(request.url) == f"{issuer}/recover"
        requests.append(request)
        return provider_response

    http_client = httpx2.AsyncClient(
        transport=httpx2.MockTransport(handler),
        trust_env=False,
    )
    fetch_keys = AsyncMock(side_effect=AssertionError("Recovery must not fetch signing keys."))
    monkeypatch.setattr("app.main.fetch_account_key_set", fetch_keys)
    engine = Mock(spec=AsyncEngine)
    counter = AsyncMock(return_value=AuthRateLimitDecision(True, datetime.now(UTC), 0, None))
    monkeypatch.setattr(
        "app.account_password_recovery_routes.commit_password_recovery_attempt", counter
    )
    application = create_app(settings)

    with monkeypatch.context() as startup_patch:
        startup_patch.setattr(
            "app.main.httpx2.AsyncClient",
            Mock(return_value=http_client),
        )
        startup_patch.setattr("app.main.create_database_engine", Mock(return_value=engine))
        with TestClient(application, client=("192.0.2.12", 12345)) as client:
            # Restore the class before runtime type casts execute.
            startup_patch.undo()

            assert application.state.account_auth_client is http_client
            assert application.state.database_engine is engine

            response = client.post(
                PATH,
                json={"email": EMAIL, "captcha_token": CAPTCHA},
                headers={
                    "Origin": ORIGIN,
                    "Cookie": "askm6_account=synthetic-cookie",
                },
            )

            assert response.status_code == expected_status
            assert_private_response(response)
            assert "synthetic-provider-secret" not in response.text

            if expected_status == 202:
                assert response.json() == {
                    "status": "accepted",
                    "message": (
                        "If password recovery can proceed, check your email for the next steps."
                    ),
                }
            else:
                details = {
                    403: "Human verification is required or was rejected.",
                    429: "Password recovery is temporarily rate limited.",
                    503: UNAVAILABLE,
                }
                assert response.json() == {"detail": details[expected_status]}

            assert response.headers.get("X-Account-Verification") == (
                "required" if expected_status == 403 else None
            )
            assert len(requests) == 1
            counter.assert_awaited_once()
            request = requests[0]
            assert request.method == "POST"
            assert request.headers["apikey"] == publishable_key
            assert "cookie" not in request.headers
            assert "authorization" not in request.headers
            assert json.loads(request.content) == {
                "email": EMAIL,
                "gotrue_meta_security": {"captcha_token": CAPTCHA},
            }
            assert provider_response.is_closed

    fetch_keys.assert_not_awaited()
    assert http_client.is_closed
    assert application.state.account_auth_client is None
    engine.dispose.assert_awaited_once()
    assert application.state.database_engine is None


def test_limiter_denial_stops_before_body_and_provider(material: RouteMaterial) -> None:
    now = datetime.now(UTC)
    material.counter.return_value = AuthRateLimitDecision(
        False, now, 37, now + timedelta(seconds=37)
    )
    response = material.client.post(
        PATH, content=b"not-json", headers={"Origin": ORIGIN, "Content-Type": "application/json"}
    )
    assert response.status_code == 429
    assert response.json() == {"detail": "Password recovery is temporarily rate limited."}
    assert response.headers["Retry-After"] == "37"
    assert "X-Account-Verification" not in response.headers
    assert_private_response(response)
    material.counter.assert_awaited_once()
    material.parse.assert_not_awaited()
    material.adapter.assert_not_awaited()


@pytest.mark.parametrize("error_type", [AuthRateLimitUnavailable, SQLAlchemyError, TimeoutError])
def test_limiter_failure_is_generic_and_never_reaches_provider(
    material: RouteMaterial, error_type: type[Exception]
) -> None:
    material.counter.side_effect = error_type("private-database-detail")
    response = material.client.post(
        PATH, json={"email": EMAIL, "captcha_token": CAPTCHA}, headers={"Origin": ORIGIN}
    )
    assert response.status_code == 503
    assert response.json() == {"detail": UNAVAILABLE}
    assert "private-database-detail" not in response.text
    assert "Retry-After" not in response.headers
    assert_private_response(response)
    material.counter.assert_awaited_once()
    material.parse.assert_not_awaited()
    material.adapter.assert_not_awaited()


def test_invalid_key_configuration_fails_before_counting(material: RouteMaterial) -> None:
    material.settings.auth_rate_limit_hmac_secret = SecretStr("invalid-synthetic-secret")
    response = material.client.post(PATH, json={}, headers={"Origin": ORIGIN})
    assert response.status_code == 503
    assert response.json() == {"detail": UNAVAILABLE}
    assert_private_response(response)
    material.counter.assert_not_awaited()
    material.parse.assert_not_awaited()
    material.adapter.assert_not_awaited()


def test_unusable_peer_fails_before_counting(material: RouteMaterial) -> None:
    with TestClient(material.application, client=("not-an-ip", 12345)) as client:
        response = client.post(PATH, json={}, headers={"Origin": ORIGIN})
    assert response.status_code == 503
    assert response.json() == {"detail": UNAVAILABLE}
    assert_private_response(response)
    material.counter.assert_not_awaited()
    material.parse.assert_not_awaited()
    material.adapter.assert_not_awaited()


def test_committed_counting_precedes_parsing_and_provider(material: RouteMaterial) -> None:
    events: list[str] = []

    async def counted(*args: object, **kwargs: object) -> AuthRateLimitDecision:
        events.append("count-committed")
        return AuthRateLimitDecision(True, datetime.now(UTC), 0, None)

    async def parsed(request: Request) -> PasswordRecoveryCredentials:
        events.append("parse")
        return await read_password_recovery_credentials(request)

    async def sent(*args: object, **kwargs: object) -> None:
        events.append("provider")

    material.counter.side_effect = counted
    material.parse.side_effect = parsed
    material.adapter.side_effect = sent
    response = material.client.post(
        PATH, json={"email": EMAIL, "captcha_token": CAPTCHA}, headers={"Origin": ORIGIN}
    )
    assert response.status_code == 202
    assert events == ["count-committed", "parse", "provider"]
    arguments = material.counter.await_args
    assert arguments is not None
    assert arguments.args[0] is material.engine
    assert isinstance(arguments.args[1], bytes) and len(arguments.args[1]) == 32
    assert arguments.kwargs == {"max_requests": 10, "window_seconds": 600}
