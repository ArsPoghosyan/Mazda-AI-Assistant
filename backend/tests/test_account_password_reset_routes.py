"""Password-reset HTTP boundaries without live providers or PostgreSQL."""

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

from app.account_key_cache import AccountKeyCache
from app.account_password_reset_requests import read_password_reset_credentials
from app.account_password_reset_routes import router
from app.account_password_reset_service import AccountPasswordResetUnavailable
from app.account_password_update import (
    AccountPasswordUpdateRateLimited,
    AccountPasswordUpdateRejected,
    AccountPasswordUpdateUnavailable,
)
from app.account_recovery_session_cleanup import AccountRecoverySessionCleanupUnavailable
from app.account_recovery_verification import (
    AccountRecoveryVerificationRateLimited,
    AccountRecoveryVerificationRejected,
    AccountRecoveryVerificationUnavailable,
)
from app.auth_rate_limit_keys import AuthRateLimitKeyUnavailable, get_password_reset_ip_key
from app.auth_rate_limits import AuthRateLimitDecision, AuthRateLimitUnavailable
from app.client_ip import ClientIPUnavailable
from app.config import Settings
from app.main import create_app

PATH = "/api/v1/account/password-reset"
ORIGIN = "https://app.example.test"
EMAIL = "owner@example.test"
CODE = "001234"
PASSWORD = "  synthetic-new-password-é  "
BODY = {"email": EMAIL, "code": CODE, "new_password": PASSWORD}
UNAVAILABLE = "Password reset is temporarily unavailable."


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@dataclass
class RouteMaterial:
    client: TestClient
    application: FastAPI
    settings: Settings
    service: AsyncMock
    parse: AsyncMock
    engine: Mock
    provider_client: Mock
    key_cache: Mock
    counter: AsyncMock


@pytest.fixture
def material(monkeypatch: pytest.MonkeyPatch) -> Iterator[RouteMaterial]:
    settings = IsolatedSettings.model_validate(
        {
            "database_url": None,
            "migration_database_url": None,
            "supabase_auth_issuer": "https://auth.example.test/auth/v1",
            "supabase_auth_publishable_key": "sb_publishable_synthetic_test_key",
            "account_session_encryption_key": None,
            "account_password_reset_api_enabled": True,
            "auth_rate_limit_hmac_secret": token_hex(32),
            "csrf_trusted_origins": (ORIGIN,),
        }
    )
    counter = AsyncMock(return_value=AuthRateLimitDecision(True, datetime.now(UTC), 0, None))
    monkeypatch.setattr("app.account_password_reset_routes.commit_password_reset_attempt", counter)
    service = AsyncMock(return_value=None)
    parse = AsyncMock(wraps=read_password_reset_credentials)
    monkeypatch.setattr("app.account_password_reset_routes.reset_account_password", service)
    monkeypatch.setattr("app.account_password_reset_routes.read_password_reset_credentials", parse)
    engine = Mock(spec=AsyncEngine)
    provider_client = Mock(spec=httpx2.AsyncClient)
    key_cache = Mock(spec=AccountKeyCache)
    application = FastAPI()
    application.state.settings = settings
    application.state.database_engine = engine
    application.state.account_auth_client = provider_client
    application.state.account_key_cache = key_cache
    application.include_router(router)

    with TestClient(application, client=("192.0.2.12", 12345)) as client:
        yield RouteMaterial(
            client,
            application,
            settings,
            service,
            parse,
            engine,
            provider_client,
            key_cache,
            counter,
        )


def assert_private_response(response: httpx2.Response) -> None:
    assert response.headers["Cache-Control"] == "no-store"
    assert "set-cookie" not in response.headers
    assert "X-Account-Verification" not in response.headers
    for private_value in (EMAIL, CODE, PASSWORD, "private-provider-detail", "synthetic-cookie"):
        assert private_value not in response.text


def test_reset_route_is_registered_in_application(material: RouteMaterial) -> None:
    application = create_app(material.settings)
    assert "post" in application.openapi()["paths"][PATH]


def test_completed_reset_returns_only_metadata_without_login(material: RouteMaterial) -> None:
    response = material.client.post(
        PATH,
        json=BODY,
        headers={
            "Origin": ORIGIN,
            "Authorization": "Bearer untrusted-browser-token",
            "Cookie": "askm6_account=synthetic-cookie; askm6_guest=synthetic-guest-cookie",
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "status": "completed",
        "message": "Password reset completed. Sign in with your new password.",
    }
    assert_private_response(response)
    material.service.assert_awaited_once_with(
        material.engine,
        SecretStr(EMAIL),
        SecretStr(CODE),
        SecretStr(PASSWORD),
        settings=material.settings,
        client=material.provider_client,
        key_cache=material.key_cache,
    )
    key = get_password_reset_ip_key(
        Request({"type": "http", "headers": [], "client": ("192.0.2.12", 12345)}),
        material.settings,
    )
    material.counter.assert_awaited_once_with(
        material.engine, key, max_requests=10, window_seconds=600
    )
    material.engine.begin.assert_not_called()


@pytest.mark.parametrize(
    "headers",
    [
        [],
        [("Origin", "")],
        [("Origin", "null")],
        [("Origin", "https://untrusted.example.test")],
        [("Origin", ORIGIN + "/")],
        [("Origin", ORIGIN), ("Origin", ORIGIN)],
        [("Origin", ORIGIN), ("Origin", "https://untrusted.example.test")],
    ],
    ids=["missing", "empty", "null", "untrusted", "slash", "duplicate", "conflicting"],
)
def test_invalid_origin_stops_before_parsing(
    material: RouteMaterial, headers: list[tuple[str, str]]
) -> None:
    response = material.client.post(
        PATH, content=b"not-json", headers=[*headers, ("Content-Type", "application/json")]
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "Request origin is not allowed."}
    assert_private_response(response)
    material.parse.assert_not_awaited()
    material.counter.assert_not_awaited()
    material.service.assert_not_awaited()


def test_disabled_endpoint_stops_before_parsing(material: RouteMaterial) -> None:
    material.settings.account_password_reset_api_enabled = False
    response = material.client.post(
        PATH, content=b"not-json", headers={"Origin": ORIGIN, "Content-Type": "application/json"}
    )

    assert response.status_code == 503
    assert response.json() == {"detail": UNAVAILABLE}
    assert_private_response(response)
    material.parse.assert_not_awaited()
    material.counter.assert_not_awaited()
    material.service.assert_not_awaited()


def test_origin_is_checked_even_when_reset_is_disabled(material: RouteMaterial) -> None:
    material.settings.account_password_reset_api_enabled = False
    response = material.client.post(PATH, json=BODY)

    assert response.status_code == 403
    assert_private_response(response)
    material.parse.assert_not_awaited()
    material.counter.assert_not_awaited()
    material.service.assert_not_awaited()


@pytest.mark.parametrize(
    "missing", ["engine", "client", "key-cache", "hmac", "issuer", "publishable-key"]
)
def test_missing_resources_stop_before_parsing(material: RouteMaterial, missing: str) -> None:
    if missing == "engine":
        material.application.state.database_engine = None
    elif missing == "client":
        material.application.state.account_auth_client = None
    elif missing == "key-cache":
        material.application.state.account_key_cache = None
    elif missing == "hmac":
        material.settings.auth_rate_limit_hmac_secret = None
    elif missing == "issuer":
        material.settings.supabase_auth_issuer = None
    else:
        material.settings.supabase_auth_publishable_key = None

    response = material.client.post(
        PATH, content=b"not-json", headers={"Origin": ORIGIN, "Content-Type": "application/json"}
    )

    assert response.status_code == 503
    assert response.json() == {"detail": UNAVAILABLE}
    assert_private_response(response)
    material.parse.assert_not_awaited()
    material.counter.assert_not_awaited()
    material.service.assert_not_awaited()


@pytest.mark.parametrize(
    ("body", "content_type", "expected_status", "detail"),
    [
        (b"not-json", "application/json", 400, "Invalid password reset request."),
        (b"{}", "application/json", 400, "Invalid password reset request."),
        (
            json.dumps({"email": EMAIL, "new_password": PASSWORD}).encode(),
            "application/json",
            400,
            "Invalid password reset request.",
        ),
        (
            json.dumps({**BODY, "code": "12abcd"}).encode(),
            "application/json",
            400,
            "Invalid password reset request.",
        ),
        (
            json.dumps({**BODY, "new_password": ""}).encode(),
            "application/json",
            400,
            "Invalid password reset request.",
        ),
        (
            b" " * (16 * 1024 + 1),
            "application/json",
            413,
            "Password reset request is too large.",
        ),
        (b"{}", "text/plain", 415, "Password reset requires a JSON request."),
    ],
    ids=["malformed", "empty", "missing-proof", "invalid-code", "empty-password", "size", "media"],
)
def test_invalid_body_does_not_reach_service(
    material: RouteMaterial, body: bytes, content_type: str, expected_status: int, detail: str
) -> None:
    response = material.client.post(
        PATH, content=body, headers={"Origin": ORIGIN, "Content-Type": content_type}
    )

    assert response.status_code == expected_status
    assert response.json() == {"detail": detail}
    assert_private_response(response)
    material.service.assert_not_awaited()


@pytest.mark.parametrize("field", ["user_id", "access_token", "refresh_token", "type"])
def test_browser_cannot_supply_identity_tokens_or_recovery_purpose(
    material: RouteMaterial, field: str
) -> None:
    response = material.client.post(
        PATH, json={**BODY, field: "untrusted-input"}, headers={"Origin": ORIGIN}
    )

    assert response.status_code == 400
    assert_private_response(response)
    material.service.assert_not_awaited()


@pytest.mark.parametrize(
    ("failure_type", "expected_status", "detail"),
    [
        (AccountRecoveryVerificationRejected, 400, "Password reset was rejected."),
        (AccountPasswordUpdateRejected, 400, "Password reset was rejected."),
        (
            AccountRecoveryVerificationRateLimited,
            429,
            "Password reset is temporarily rate limited.",
        ),
        (AccountPasswordUpdateRateLimited, 429, "Password reset is temporarily rate limited."),
        (AccountPasswordResetUnavailable, 503, UNAVAILABLE),
        (AccountRecoveryVerificationUnavailable, 503, UNAVAILABLE),
        (AccountPasswordUpdateUnavailable, 503, UNAVAILABLE),
        (AccountRecoverySessionCleanupUnavailable, 503, UNAVAILABLE),
        (SQLAlchemyError, 503, UNAVAILABLE),
        (TimeoutError, 503, UNAVAILABLE),
    ],
)
def test_service_failures_are_masked_without_retry_or_login(
    material: RouteMaterial, failure_type: type[Exception], expected_status: int, detail: str
) -> None:
    material.service.side_effect = failure_type("private-provider-detail")
    response = material.client.post(PATH, json=BODY, headers={"Origin": ORIGIN})

    assert response.status_code == expected_status
    assert response.json() == {"detail": detail}
    assert_private_response(response)
    assert "Retry-After" not in response.headers
    material.service.assert_awaited_once()


@pytest.mark.parametrize("stage", ["accounting", "body", "service"])
def test_total_deadline_interrupts_stalled_work(
    material: RouteMaterial, monkeypatch: pytest.MonkeyPatch, stage: str
) -> None:
    material.settings.account_password_reset_timeout_seconds = 1
    cancelled = False

    async def stall() -> None:
        nonlocal cancelled
        try:
            await asyncio.Future[None]()
        except asyncio.CancelledError:
            cancelled = True
            raise

    if stage == "accounting":

        async def stalled_counter(*args: object, **kwargs: object) -> AuthRateLimitDecision:
            await stall()
            raise AssertionError("Stalled accounting unexpectedly completed.")

        material.counter.side_effect = stalled_counter
    elif stage == "body":

        async def stalled_stream(request: Request) -> AsyncIterator[bytes]:
            yield b" "
            await stall()

        monkeypatch.setattr("app.account_password_reset_requests.Request.stream", stalled_stream)
    else:

        async def stalled_service(*args: object, **kwargs: object) -> None:
            await stall()

        material.service.side_effect = stalled_service

    response = material.client.post(PATH, json=BODY, headers={"Origin": ORIGIN})

    assert response.status_code == 503
    assert response.json() == {"detail": UNAVAILABLE}
    assert_private_response(response)
    assert cancelled
    if stage != "service":
        material.service.assert_not_awaited()
    else:
        material.service.assert_awaited_once()


@pytest.mark.parametrize("stage", ["accounting", "body", "service"])
def test_caller_cancellation_propagates_without_a_success_response(
    material: RouteMaterial, monkeypatch: pytest.MonkeyPatch, stage: str
) -> None:
    async def run() -> None:
        started = asyncio.Event()
        cancelled = False

        async def stall() -> None:
            nonlocal cancelled
            started.set()
            try:
                await asyncio.Future[None]()
            except asyncio.CancelledError:
                cancelled = True
                raise

        if stage == "accounting":

            async def stalled_counter(*args: object, **kwargs: object) -> AuthRateLimitDecision:
                await stall()
                raise AssertionError("Stalled accounting unexpectedly completed.")

            material.counter.side_effect = stalled_counter
        elif stage == "body":

            async def stalled_stream(request: Request) -> AsyncIterator[bytes]:
                yield b" "
                await stall()

            monkeypatch.setattr(
                "app.account_password_reset_requests.Request.stream", stalled_stream
            )
        else:

            async def stalled_service(*args: object, **kwargs: object) -> None:
                await stall()

            material.service.side_effect = stalled_service

        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=material.application),
            base_url="https://app.example.test",
        ) as client:
            task = asyncio.create_task(client.post(PATH, json=BODY, headers={"Origin": ORIGIN}))
            try:
                await asyncio.wait_for(started.wait(), timeout=1)
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
            finally:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
        assert cancelled

    asyncio.run(run())
    if stage != "service":
        material.service.assert_not_awaited()
    else:
        material.service.assert_awaited_once()


def test_success_waits_for_service_completion(material: RouteMaterial) -> None:
    async def run() -> None:
        started = asyncio.Event()
        completed = asyncio.Event()

        async def pending_service(*args: object, **kwargs: object) -> None:
            started.set()
            await completed.wait()

        material.service.side_effect = pending_service
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=material.application),
            base_url="https://app.example.test",
        ) as client:
            task = asyncio.create_task(client.post(PATH, json=BODY, headers={"Origin": ORIGIN}))
            try:
                await asyncio.wait_for(started.wait(), timeout=1)
                assert not task.done()
                completed.set()
                response = await asyncio.wait_for(task, timeout=1)
                assert response.status_code == 200
                assert_private_response(response)
            finally:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

    asyncio.run(run())
    material.service.assert_awaited_once()


@pytest.mark.parametrize("method", ["GET", "PUT", "DELETE", "PATCH"])
def test_unsupported_methods_do_not_reach_service(material: RouteMaterial, method: str) -> None:
    response = material.client.request(method, PATH, headers={"Origin": ORIGIN})

    assert response.status_code == 405
    material.parse.assert_not_awaited()
    material.counter.assert_not_awaited()
    material.service.assert_not_awaited()


def test_local_cap_blocks_parsing_and_provider(material: RouteMaterial) -> None:
    now = datetime.now(UTC)
    material.counter.return_value = AuthRateLimitDecision(
        False, now, 61, now + timedelta(seconds=61)
    )
    response = material.client.post(
        PATH, content=b"not-json", headers={"Origin": ORIGIN, "Content-Type": "application/json"}
    )
    assert response.status_code == 429
    assert response.json() == {"detail": "Password reset is temporarily rate limited."}
    assert_private_response(response)
    assert response.headers["Retry-After"] == "61"
    assert "X-Account-Verification" not in response.headers
    material.parse.assert_not_awaited()
    material.service.assert_not_awaited()


@pytest.mark.parametrize(
    "failure",
    [
        SQLAlchemyError("private-provider-detail"),
        AuthRateLimitUnavailable("private-provider-detail"),
        TimeoutError("private-provider-detail"),
    ],
)
def test_accounting_failure_has_no_provider_work(
    material: RouteMaterial, failure: Exception
) -> None:
    material.counter.side_effect = failure
    response = material.client.post(PATH, json=BODY, headers={"Origin": ORIGIN})
    assert response.status_code == 503
    assert response.json() == {"detail": UNAVAILABLE}
    assert_private_response(response)
    assert "Retry-After" not in response.headers
    material.parse.assert_not_awaited()
    material.service.assert_not_awaited()


@pytest.mark.parametrize(
    "failure",
    [
        AuthRateLimitKeyUnavailable("private-provider-detail"),
        ClientIPUnavailable("private-provider-detail"),
    ],
)
def test_fingerprint_failure_never_counts(
    material: RouteMaterial, monkeypatch: pytest.MonkeyPatch, failure: Exception
) -> None:
    monkeypatch.setattr(
        "app.account_password_reset_routes.get_password_reset_ip_key",
        Mock(side_effect=failure),
    )
    response = material.client.post(PATH, json=BODY, headers={"Origin": ORIGIN})
    assert response.status_code == 503
    assert response.json() == {"detail": UNAVAILABLE}
    assert_private_response(response)
    material.counter.assert_not_awaited()
    material.parse.assert_not_awaited()
    material.service.assert_not_awaited()
