"""Email-confirmation HTTP tests with synthetic data and mocked transport."""

import asyncio
import json
from collections.abc import AsyncIterator, Callable

import httpx2
import pytest
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict

import app.account_email_confirmation as account_email_confirmation
from app.account_email_confirmation import (
    AccountEmailConfirmationRejected,
    AccountEmailConfirmationUnavailable,
    confirm_email_code,
)
from app.config import Settings

ISSUER = "https://auth.example.test/auth/v1"
VERIFY_URL = f"{ISSUER}/verify"
PUBLISHABLE_KEY = "sb_publishable_synthetic_test_key"
EMAIL = "owner@example.test"
CODE = "001234"
USER_ID = "563128d6-22fd-464f-a3bd-31018fdf1b3c"


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


class ResponseStream(httpx2.AsyncByteStream):
    def __init__(self, body: bytes) -> None:
        self.body = body

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield self.body


@pytest.fixture
def settings() -> Settings:
    return IsolatedSettings.model_validate(
        {
            "database_url": None,
            "migration_database_url": None,
            "supabase_auth_issuer": ISSUER,
            "supabase_auth_publishable_key": PUBLISHABLE_KEY,
            "account_session_encryption_key": None,
        }
    )


def response_for(
    payload: object,
    *,
    status_code: int = 200,
) -> httpx2.Response:
    return httpx2.Response(
        status_code,
        headers={"Content-Type": "application/json; charset=utf-8"},
        stream=ResponseStream(json.dumps(payload).encode("utf-8")),
    )


def run_confirmation(
    settings: Settings,
    handler: Callable[[httpx2.Request], httpx2.Response],
    *,
    email: str = EMAIL,
    code: str = CODE,
) -> None:
    async def run() -> None:
        async with httpx2.AsyncClient(
            transport=httpx2.MockTransport(handler),
            auth=("synthetic-user", "synthetic-client-password"),
            follow_redirects=True,
            trust_env=False,
        ) as client:
            await confirm_email_code(
                SecretStr(email),
                SecretStr(code),
                settings=settings,
                client=client,
            )

    asyncio.run(run())


@pytest.mark.parametrize("length", [6, 7, 8, 9, 10])
def test_forwards_exact_code_once_with_fixed_signup_type(
    settings: Settings,
    length: int,
) -> None:
    code = "0" * (length - 1) + "1"
    requests: list[httpx2.Request] = []
    response = response_for(
        {
            "user": {
                "id": USER_ID,
                "email_confirmed_at": "2026-10-22T10:00:00Z",
            },
            "access_token": "synthetic-access-token",
            "refresh_token": "synthetic-refresh-token",
            "token_type": "bearer",
        }
    )

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return response

    run_confirmation(settings, handler, code=code)

    assert len(requests) == 1
    request = requests[0]
    assert request.method == "POST"
    assert str(request.url) == VERIFY_URL
    assert json.loads(request.content) == {
        "email": EMAIL,
        "token": code,
        "type": "signup",
    }
    assert request.headers["apikey"] == PUBLISHABLE_KEY
    assert request.headers["accept"] == "application/json"
    assert request.headers["accept-encoding"] == "identity"
    assert "authorization" not in request.headers
    assert response.is_closed


@pytest.mark.parametrize(
    "field",
    ["supabase_auth_issuer", "supabase_auth_publishable_key"],
)
def test_missing_configuration_prevents_requests(
    settings: Settings,
    field: str,
) -> None:
    incomplete = settings.model_copy(update={field: None})

    def handler(request: httpx2.Request) -> httpx2.Response:
        raise AssertionError("No provider request should be made.")

    with pytest.raises(AccountEmailConfirmationUnavailable, match="not configured"):
        run_confirmation(incomplete, handler)


@pytest.mark.parametrize(
    ("email", "code"),
    [
        ("", CODE),
        ("e" * 321, CODE),
        ("\ud800", CODE),
        (EMAIL, ""),
        (EMAIL, "12345"),
        (EMAIL, "1" * 11),
        (EMAIL, "123 56"),
        (EMAIL, "12345\n"),
        (EMAIL, "１２３４５６"),
        (EMAIL, "\ud800"),
    ],
)
def test_invalid_input_prevents_requests(
    settings: Settings,
    email: str,
    code: str,
) -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        raise AssertionError("No provider request should be made.")

    with pytest.raises(AccountEmailConfirmationRejected) as caught:
        run_confirmation(settings, handler, email=email, code=code)

    assert str(caught.value) == "Email confirmation was rejected."


@pytest.mark.parametrize(
    "error_code",
    [
        "otp_expired",
        "validation_failed",
        "email_address_invalid",
        "user_banned",
    ],
)
def test_provider_rejection_is_generic_and_not_retried(
    settings: Settings,
    error_code: str,
) -> None:
    requests: list[httpx2.Request] = []
    response = response_for(
        {
            "error_code": error_code,
            "msg": "private-provider-detail",
        },
        status_code=403,
    )

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return response

    with pytest.raises(AccountEmailConfirmationRejected) as caught:
        run_confirmation(settings, handler)

    assert str(caught.value) == "Email confirmation was rejected."
    assert "private-provider-detail" not in repr(caught.value)
    assert len(requests) == 1
    assert response.is_closed


def raw_response(
    body: bytes,
    *,
    status_code: int = 200,
) -> httpx2.Response:
    return httpx2.Response(
        status_code,
        headers={"Content-Type": "application/json"},
        stream=ResponseStream(body),
    )


@pytest.mark.parametrize("status_code", [429, 500, 503])
def test_provider_unavailability_is_generic_and_not_retried(
    settings: Settings,
    status_code: int,
) -> None:
    requests: list[httpx2.Request] = []
    response = response_for(
        {"error_code": "otp_expired", "msg": "private-provider-detail"},
        status_code=status_code,
    )

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return response

    with pytest.raises(AccountEmailConfirmationUnavailable) as caught:
        run_confirmation(settings, handler)

    assert str(caught.value) == "Email confirmation is unavailable."
    assert "private-provider-detail" not in repr(caught.value)
    assert len(requests) == 1
    assert response.is_closed


@pytest.mark.parametrize("status_code", [302, 307, 308])
def test_redirects_do_not_forward_confirmation_credentials(
    settings: Settings,
    status_code: int,
) -> None:
    requests: list[httpx2.Request] = []
    response = raw_response(b"", status_code=status_code)
    response.headers["Location"] = "https://other.example.test/collect"

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        assert str(request.url) == VERIFY_URL
        return response

    with pytest.raises(AccountEmailConfirmationUnavailable):
        run_confirmation(settings, handler)

    assert len(requests) == 1
    assert response.is_closed


@pytest.mark.parametrize("content_type", [None, "text/html", "text/plain"])
def test_requires_json_provider_response(
    settings: Settings,
    content_type: str | None,
) -> None:
    response = response_for(
        {
            "user": {
                "id": USER_ID,
                "email_confirmed_at": "2026-10-22T10:00:00Z",
            }
        }
    )

    if content_type is None:
        del response.headers["Content-Type"]
    else:
        response.headers["Content-Type"] = content_type

    with pytest.raises(AccountEmailConfirmationUnavailable):
        run_confirmation(settings, lambda request: response)

    assert response.is_closed


@pytest.mark.parametrize("encoding", ["gzip", "br"])
def test_rejects_compressed_responses(
    settings: Settings,
    encoding: str,
) -> None:
    response = raw_response(b"{}")
    response.headers["Content-Encoding"] = encoding

    with pytest.raises(AccountEmailConfirmationUnavailable):
        run_confirmation(settings, lambda request: response)

    assert response.is_closed


@pytest.mark.parametrize(
    "body",
    [b"", b"private-provider-detail", b"\xff", b"[]", b"{}"],
    ids=["empty", "malformed", "invalid-utf8", "array", "missing-user"],
)
def test_invalid_response_bodies_remain_generic(
    settings: Settings,
    body: bytes,
) -> None:
    response = raw_response(body)

    with pytest.raises(AccountEmailConfirmationUnavailable) as caught:
        run_confirmation(settings, lambda request: response)

    assert str(caught.value) == "Email confirmation is unavailable."
    assert "private-provider-detail" not in repr(caught.value)
    assert response.is_closed


@pytest.mark.parametrize("extra_bytes", [0, 1], ids=["at-limit", "over-limit"])
def test_response_limit_counts_actual_bytes(
    settings: Settings,
    extra_bytes: int,
) -> None:
    document = json.dumps(
        {
            "user": {
                "id": USER_ID,
                "email_confirmed_at": "2026-10-22T10:00:00Z",
            }
        }
    ).encode("utf-8")
    body = document + b" " * (64 * 1024 + extra_bytes - len(document))
    response = raw_response(body)
    response.headers["Content-Length"] = "1"

    if extra_bytes:
        with pytest.raises(AccountEmailConfirmationUnavailable):
            run_confirmation(settings, lambda request: response)
    else:
        run_confirmation(settings, lambda request: response)

    assert response.is_closed


@pytest.mark.parametrize(
    "failure",
    [
        httpx2.ConnectError("private-connection-detail"),
        httpx2.ReadTimeout("private-timeout-detail"),
        httpx2.RemoteProtocolError("private-protocol-detail"),
    ],
    ids=["connection", "read-timeout", "protocol"],
)
def test_transport_failures_are_masked_without_retrying(
    settings: Settings,
    failure: httpx2.HTTPError,
) -> None:
    requests: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        raise failure

    with pytest.raises(AccountEmailConfirmationUnavailable) as caught:
        run_confirmation(settings, handler)

    assert str(caught.value) == "Email confirmation is unavailable."
    assert "private-" not in repr(caught.value)
    assert caught.value.__cause__ is None
    assert len(requests) == 1


class StalledResponseStream(httpx2.AsyncByteStream):
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield b" "
        self.started.set()
        await asyncio.Future[None]()

    async def aclose(self) -> None:
        self.closed = True


def test_total_deadline_stops_a_stalled_request(
    settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        account_email_confirmation,
        "_CONFIRMATION_TIMEOUT_SECONDS",
        0.05,
    )
    requests: list[httpx2.Request] = []

    async def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        await asyncio.Future[None]()
        raise AssertionError("Stalled request unexpectedly resumed.")

    async def run() -> None:
        async with httpx2.AsyncClient(
            transport=httpx2.MockTransport(handler),
            trust_env=False,
        ) as client:
            await asyncio.wait_for(
                confirm_email_code(
                    SecretStr(EMAIL),
                    SecretStr(CODE),
                    settings=settings,
                    client=client,
                ),
                timeout=1,
            )

    with pytest.raises(AccountEmailConfirmationUnavailable):
        asyncio.run(run())

    assert len(requests) == 1


def test_total_deadline_closes_a_stalled_response(
    settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        account_email_confirmation,
        "_CONFIRMATION_TIMEOUT_SECONDS",
        0.05,
    )

    async def run() -> None:
        stream = StalledResponseStream()
        response = httpx2.Response(
            200,
            headers={"Content-Type": "application/json"},
            stream=stream,
        )
        requests: list[httpx2.Request] = []

        def handler(request: httpx2.Request) -> httpx2.Response:
            requests.append(request)
            return response

        async with httpx2.AsyncClient(
            transport=httpx2.MockTransport(handler),
            trust_env=False,
        ) as client:
            with pytest.raises(AccountEmailConfirmationUnavailable):
                await asyncio.wait_for(
                    confirm_email_code(
                        SecretStr(EMAIL),
                        SecretStr(CODE),
                        settings=settings,
                        client=client,
                    ),
                    timeout=1,
                )

            assert stream.started.is_set()
            assert stream.closed
            assert response.is_closed
            assert len(requests) == 1

    asyncio.run(run())


def test_cancellation_propagates_and_closes_the_response(
    settings: Settings,
) -> None:
    async def run() -> None:
        stream = StalledResponseStream()
        response = httpx2.Response(
            200,
            headers={"Content-Type": "application/json"},
            stream=stream,
        )
        requests: list[httpx2.Request] = []

        def handler(request: httpx2.Request) -> httpx2.Response:
            requests.append(request)
            return response

        async with httpx2.AsyncClient(
            transport=httpx2.MockTransport(handler),
            trust_env=False,
        ) as client:
            task = asyncio.create_task(
                confirm_email_code(
                    SecretStr(EMAIL),
                    SecretStr(CODE),
                    settings=settings,
                    client=client,
                )
            )

            try:
                await asyncio.wait_for(stream.started.wait(), timeout=1)
                task.cancel()

                with pytest.raises(asyncio.CancelledError):
                    await task

                assert stream.closed
                assert response.is_closed
                assert len(requests) == 1
            finally:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

    asyncio.run(run())


def test_response_read_failure_is_masked_and_closes_the_stream(
    settings: Settings,
) -> None:
    class BrokenStream(httpx2.AsyncByteStream):
        def __init__(self) -> None:
            self.closed = False

        async def __aiter__(self) -> AsyncIterator[bytes]:
            yield b"{"
            raise httpx2.ReadError("private-response-read-detail")

        async def aclose(self) -> None:
            self.closed = True

    stream = BrokenStream()
    response = httpx2.Response(
        200,
        headers={"Content-Type": "application/json"},
        stream=stream,
    )
    requests: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return response

    with pytest.raises(AccountEmailConfirmationUnavailable) as caught:
        run_confirmation(settings, handler)

    assert str(caught.value) == "Email confirmation is unavailable."
    assert "private-response-read-detail" not in repr(caught.value)
    assert caught.value.__cause__ is None
    assert stream.closed
    assert response.is_closed
    assert len(requests) == 1


def test_response_limit_is_cumulative_across_chunks(
    settings: Settings,
) -> None:
    class ChunkedStream(httpx2.AsyncByteStream):
        def __init__(self) -> None:
            self.chunks_read = 0
            self.closed = False

        async def __aiter__(self) -> AsyncIterator[bytes]:
            document = json.dumps(
                {
                    "user": {
                        "id": USER_ID,
                        "email_confirmed_at": "2026-10-22T10:00:00Z",
                    }
                }
            ).encode("utf-8")
            first = document + b" " * (32 * 1024 - len(document))

            for chunk in (first, b" " * (32 * 1024 + 1), b" "):
                self.chunks_read += 1
                yield chunk

        async def aclose(self) -> None:
            self.closed = True

    stream = ChunkedStream()
    response = httpx2.Response(
        200,
        headers={"Content-Type": "application/json"},
        stream=stream,
    )

    with pytest.raises(AccountEmailConfirmationUnavailable):
        run_confirmation(settings, lambda request: response)

    assert stream.chunks_read == 2
    assert stream.closed
    assert response.is_closed
