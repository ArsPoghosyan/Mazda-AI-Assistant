"""Confirmation HTTP boundaries with mocked provider HTTP and no database."""

import asyncio
import json
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from unittest.mock import AsyncMock, Mock

import httpx2
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from pydantic_settings import SettingsConfigDict

from app.account_email_confirmation_requests import (
    read_email_confirmation_credentials,
)
from app.config import Settings
from app.main import create_app

PATH = "/api/v1/account/confirm-email"
ORIGIN = "https://app.example.test"
ISSUER = "https://auth.example.test/auth/v1"
EMAIL = "owner@example.test"
CODE = "001234"
USER_ID = "563128d6-22fd-464f-a3bd-31018fdf1b3c"
PRIVATE_DETAIL = "private-provider-detail"
UNAVAILABLE = "Email confirmation is temporarily unavailable."


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


class ResponseStream(httpx2.AsyncByteStream):
    def __init__(self, body: bytes) -> None:
        self.body = body

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield self.body


def provider_response(payload: object, status_code: int = 200) -> httpx2.Response:
    return httpx2.Response(
        status_code,
        headers={"Content-Type": "application/json"},
        stream=ResponseStream(json.dumps(payload).encode("utf-8")),
    )


@dataclass
class RouteMaterial:
    client: TestClient
    application: FastAPI
    settings: Settings
    provider: AsyncMock
    requests: list[httpx2.Request]
    parse: AsyncMock


@pytest.fixture
def route_material(monkeypatch: pytest.MonkeyPatch) -> Iterator[RouteMaterial]:
    settings = IsolatedSettings.model_validate(
        {
            "database_url": None,
            "migration_database_url": None,
            "supabase_auth_issuer": ISSUER,
            "supabase_auth_publishable_key": "sb_publishable_synthetic_test_key",
            "account_session_encryption_key": None,
            "account_email_confirmation_api_enabled": True,
            "account_email_confirmation_timeout_seconds": 15,
            "account_sign_up_api_enabled": False,
            "account_sign_in_api_enabled": False,
            "account_sign_out_api_enabled": False,
            "account_session_api_enabled": False,
            "guest_session_api_enabled": False,
            "csrf_trusted_origins": (ORIGIN,),
            "turnstile_secret_key": None,
            "turnstile_allowed_hostnames": (),
        }
    )
    requests: list[httpx2.Request] = []
    provider = AsyncMock(
        return_value=provider_response(
            {
                "user": {
                    "id": USER_ID,
                    "email_confirmed_at": "2026-10-22T10:00:00Z",
                },
                "access_token": "synthetic-access-token",
                "refresh_token": "synthetic-refresh-token",
            }
        )
    )

    async def handler(request: httpx2.Request) -> httpx2.Response:
        assert str(request.url) == f"{ISSUER}/verify"
        requests.append(request)
        response: httpx2.Response = await provider(request)
        return response

    http_client = httpx2.AsyncClient(
        transport=httpx2.MockTransport(handler),
        trust_env=False,
    )
    fetch_keys = AsyncMock(side_effect=AssertionError("Confirmation must not fetch signing keys."))
    monkeypatch.setattr("app.main.fetch_account_key_set", fetch_keys)
    parse = AsyncMock(wraps=read_email_confirmation_credentials)
    monkeypatch.setattr(
        "app.account_email_confirmation_routes.read_email_confirmation_credentials",
        parse,
    )
    application = create_app(settings)

    with monkeypatch.context() as startup_patch:
        startup_patch.setattr(
            "app.main.httpx2.AsyncClient",
            Mock(return_value=http_client),
        )
        with TestClient(application, base_url="https://api.example.test") as client:
            # Restore the class before serving requests that use runtime casts.
            startup_patch.undo()
            assert application.state.database_engine is None
            assert application.state.turnstile_client is None
            yield RouteMaterial(client, application, settings, provider, requests, parse)

    fetch_keys.assert_not_awaited()
    assert http_client.is_closed


def post_credentials(material: RouteMaterial) -> httpx2.Response:
    return material.client.post(
        PATH,
        json={"email": EMAIL, "code": CODE},
        headers={
            "Origin": ORIGIN,
            "Cookie": (f"__Host-askm6_account={'a' * 43}; __Host-askm6_guest={'b' * 43}"),
        },
    )


def assert_private_response(response: httpx2.Response) -> None:
    assert response.headers["Cache-Control"] == "no-store"
    assert "set-cookie" not in response.headers

    for value in (
        EMAIL,
        CODE,
        USER_ID,
        PRIVATE_DETAIL,
        "synthetic-access-token",
        "synthetic-refresh-token",
    ):
        assert value not in response.text


def assert_failure(
    response: httpx2.Response,
    status_code: int,
    detail: str,
) -> None:
    assert response.status_code == status_code
    assert response.json() == {"detail": detail}
    assert_private_response(response)


def test_confirmation_does_not_establish_application_login(
    route_material: RouteMaterial,
) -> None:
    route_material.application.state.account_key_cache = None
    response = post_credentials(route_material)

    assert response.status_code == 200
    assert response.json() == {
        "status": "confirmed",
        "message": "Email confirmed. You can now sign in.",
    }
    assert_private_response(response)
    assert len(route_material.requests) == 1

    request = route_material.requests[0]
    assert request.method == "POST"
    assert json.loads(request.content) == {
        "email": EMAIL,
        "token": CODE,
        "type": "signup",
    }
    assert "cookie" not in request.headers
    assert "authorization" not in request.headers
    assert route_material.provider.return_value.is_closed


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
def test_untrusted_origin_stops_before_body_parsing(
    route_material: RouteMaterial,
    origin_headers: list[tuple[str, str]],
) -> None:
    response = route_material.client.post(
        PATH,
        content=b"not-json",
        headers=[*origin_headers, ("Content-Type", "application/json")],
    )

    assert_failure(response, 403, "Request origin is not allowed.")
    route_material.parse.assert_not_awaited()
    assert route_material.requests == []


def test_disabled_confirmation_stops_before_body_parsing(
    route_material: RouteMaterial,
) -> None:
    route_material.settings.account_email_confirmation_api_enabled = False
    response = post_credentials(route_material)

    assert_failure(response, 503, UNAVAILABLE)
    route_material.parse.assert_not_awaited()
    assert route_material.requests == []


def test_origin_is_checked_even_when_confirmation_is_disabled(
    route_material: RouteMaterial,
) -> None:
    route_material.settings.account_email_confirmation_api_enabled = False
    response = route_material.client.post(PATH, json={})

    assert_failure(response, 403, "Request origin is not allowed.")
    route_material.parse.assert_not_awaited()
    assert route_material.requests == []


@pytest.mark.parametrize("missing", ["client", "issuer", "publishable-key"])
def test_incomplete_configuration_stops_before_body_parsing(
    route_material: RouteMaterial,
    missing: str,
) -> None:
    if missing == "client":
        route_material.application.state.account_auth_client = None
    elif missing == "issuer":
        route_material.settings.supabase_auth_issuer = None
    else:
        route_material.settings.supabase_auth_publishable_key = None

    response = post_credentials(route_material)

    assert_failure(response, 503, UNAVAILABLE)
    route_material.parse.assert_not_awaited()
    assert route_material.requests == []


@pytest.mark.parametrize(
    ("body", "content_type", "status_code", "detail"),
    [
        (
            b"not-json",
            "application/json",
            400,
            "Invalid email confirmation request.",
        ),
        (
            b"{}",
            "application/json",
            400,
            "Invalid email confirmation request.",
        ),
        (
            json.dumps({"email": EMAIL}).encode("utf-8"),
            "application/json",
            400,
            "Invalid email confirmation request.",
        ),
        (
            json.dumps({"email": EMAIL, "code": CODE, "type": "recovery"}).encode("utf-8"),
            "application/json",
            400,
            "Invalid email confirmation request.",
        ),
        (
            b" " * (4 * 1024 + 1),
            "application/json",
            413,
            "Email confirmation request is too large.",
        ),
        (
            b"{}",
            "text/plain",
            415,
            "Email confirmation requires a JSON request.",
        ),
    ],
    ids=[
        "malformed",
        "missing-fields",
        "missing-code",
        "extra-verification-type",
        "oversized",
        "media-type",
    ],
)
def test_invalid_input_never_contacts_provider(
    route_material: RouteMaterial,
    body: bytes,
    content_type: str,
    status_code: int,
    detail: str,
) -> None:
    response = route_material.client.post(
        PATH,
        content=body,
        headers={"Origin": ORIGIN, "Content-Type": content_type},
    )

    assert_failure(response, status_code, detail)
    assert "X-Account-Verification" not in response.headers
    assert route_material.requests == []


@pytest.mark.parametrize(
    ("status_code", "code", "expected_status", "detail"),
    [
        (403, "otp_expired", 400, "Email confirmation was rejected."),
        (422, "validation_failed", 400, "Email confirmation was rejected."),
        (400, "email_address_invalid", 400, "Email confirmation was rejected."),
        (403, "user_banned", 400, "Email confirmation was rejected."),
        (422, "unknown-provider-code", 503, UNAVAILABLE),
        (429, "otp_expired", 503, UNAVAILABLE),
        (503, "otp_expired", 503, UNAVAILABLE),
    ],
)
def test_provider_errors_are_controlled_and_not_retried(
    route_material: RouteMaterial,
    status_code: int,
    code: str,
    expected_status: int,
    detail: str,
) -> None:
    route_material.provider.return_value = provider_response(
        {"error_code": code, "msg": PRIVATE_DETAIL},
        status_code,
    )

    response = post_credentials(route_material)

    assert_failure(response, expected_status, detail)
    assert "X-Account-Verification" not in response.headers
    assert len(route_material.requests) == 1
    assert route_material.provider.return_value.is_closed


def test_malformed_success_does_not_confirm_or_expose_credentials(
    route_material: RouteMaterial,
) -> None:
    route_material.provider.return_value = provider_response(
        {
            "access_token": "synthetic-access-token",
            "refresh_token": "synthetic-refresh-token",
        }
    )

    response = post_credentials(route_material)

    assert_failure(response, 503, UNAVAILABLE)
    assert len(route_material.requests) == 1
    assert route_material.provider.return_value.is_closed


def test_provider_connection_failure_remains_generic(
    route_material: RouteMaterial,
) -> None:
    route_material.provider.side_effect = httpx2.ConnectError(PRIVATE_DETAIL)

    response = post_credentials(route_material)

    assert_failure(response, 503, UNAVAILABLE)
    assert len(route_material.requests) == 1


@pytest.mark.parametrize("method", ["GET", "PUT", "DELETE"])
def test_unsupported_methods_do_not_parse_or_contact_provider(
    route_material: RouteMaterial,
    method: str,
) -> None:
    response = route_material.client.request(
        method,
        PATH,
        headers={"Origin": ORIGIN},
    )

    assert response.status_code == 405
    assert "set-cookie" not in response.headers
    route_material.parse.assert_not_awaited()
    assert route_material.requests == []


@pytest.mark.parametrize("stalled_stage", ["body", "provider"])
def test_total_deadline_cancels_stalled_work(
    route_material: RouteMaterial,
    monkeypatch: pytest.MonkeyPatch,
    stalled_stage: str,
) -> None:
    route_material.settings.account_email_confirmation_timeout_seconds = 1
    cancelled = False

    async def stall() -> None:
        nonlocal cancelled

        try:
            # Finite so a broken deadline cannot hang the test indefinitely.
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
            "app.account_email_confirmation_requests.Request.stream",
            stalled_stream,
        )
    else:

        async def stalled_provider(request: httpx2.Request) -> httpx2.Response:
            await stall()
            raise AssertionError("Stalled provider unexpectedly completed.")

        route_material.provider.side_effect = stalled_provider

    response = post_credentials(route_material)

    assert_failure(response, 503, UNAVAILABLE)
    assert cancelled
    assert len(route_material.requests) == (1 if stalled_stage == "provider" else 0)

    if stalled_stage == "body":
        route_material.provider.assert_not_awaited()
    else:
        route_material.provider.assert_awaited_once()
