"""Recovery-code verification using mocked provider HTTP."""

import asyncio
import json
from collections.abc import AsyncIterator, Callable
from unittest.mock import Mock
from uuid import UUID

import httpx2
import pytest
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict

import app.account_recovery_verification as recovery_verification
from app.account_recovery_verification import (
    AccountRecoveryVerificationRateLimited,
    AccountRecoveryVerificationRejected,
    AccountRecoveryVerificationUnavailable,
    RecoveryVerificationCredentials,
    verify_recovery_code,
)
from app.config import Settings

ISSUER = "https://auth.example.test/auth/v1"
PUBLISHABLE_KEY = "sb_publishable_synthetic_test_key"
EMAIL = "Owner+é@example.test"
CODE = "001234"
USER_ID = "563128d6-22fd-464f-a3bd-31018fdf1b3c"
ACCESS_TOKEN = "synthetic-recovery-access-token"
PRIVATE_DETAIL = "private-provider-detail"


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


class ResponseStream(httpx2.AsyncByteStream):
    def __init__(self, body: bytes) -> None:
        self.body = body
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield self.body

    async def aclose(self) -> None:
        self.closed = True


@pytest.fixture
def settings() -> Settings:
    return IsolatedSettings.model_validate(
        {
            "database_url": None,
            "migration_database_url": None,
            "supabase_auth_issuer": ISSUER,
            "supabase_auth_publishable_key": PUBLISHABLE_KEY,
        }
    )


def success_payload() -> dict[str, object]:
    return {
        "token_type": "bearer",
        "access_token": ACCESS_TOKEN,
        "refresh_token": "synthetic-refresh-token",
        "user": {"id": USER_ID, "is_anonymous": False},
    }


def response_for(payload: object, status_code: int = 200) -> httpx2.Response:
    return httpx2.Response(
        status_code,
        headers={"Content-Type": "application/json; charset=utf-8"},
        stream=ResponseStream(json.dumps(payload).encode("utf-8")),
    )


def run_verification(
    settings: Settings,
    handler: Callable[[httpx2.Request], httpx2.Response],
    *,
    email: str = EMAIL,
    code: str = CODE,
) -> RecoveryVerificationCredentials:
    async def run() -> RecoveryVerificationCredentials:
        async with httpx2.AsyncClient(
            transport=httpx2.MockTransport(handler),
            auth=("synthetic-user", "synthetic-client-password"),
            follow_redirects=True,
            trust_env=False,
        ) as client:
            return await verify_recovery_code(
                SecretStr(email),
                SecretStr(code),
                settings=settings,
                client=client,
            )

    return asyncio.run(run())


def test_submits_exact_code_with_fixed_recovery_type_once(settings: Settings) -> None:
    requests: list[httpx2.Request] = []
    response = response_for(success_payload())

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return response

    result = run_verification(settings, handler)

    assert len(requests) == 1
    request = requests[0]
    assert request.method == "POST"
    assert str(request.url) == f"{ISSUER}/verify"
    assert json.loads(request.content) == {
        "email": EMAIL,
        "token": CODE,
        "type": "recovery",
    }
    assert request.headers["apikey"] == PUBLISHABLE_KEY
    assert request.headers["accept"] == "application/json"
    assert request.headers["accept-encoding"] == "identity"
    assert "authorization" not in request.headers
    assert "cookie" not in request.headers

    assert result.user_id == UUID(USER_ID)
    assert result.access_token.get_secret_value() == ACCESS_TOKEN
    assert ACCESS_TOKEN not in repr(result)
    assert "synthetic-refresh-token" not in repr(result)
    assert response.is_closed


@pytest.mark.parametrize(
    "field",
    ["supabase_auth_issuer", "supabase_auth_publishable_key"],
)
def test_missing_configuration_prevents_http(
    settings: Settings,
    field: str,
) -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        raise AssertionError("No provider request should be made.")

    with pytest.raises(AccountRecoveryVerificationUnavailable, match="not configured"):
        run_verification(settings.model_copy(update={field: None}), handler)


@pytest.mark.parametrize(
    ("email", "code"),
    [
        ("", CODE),
        ("e" * 321, CODE),
        ("\ud800", CODE),
        (EMAIL, ""),
        (EMAIL, "12345"),
        (EMAIL, "12345678901"),
        (EMAIL, "１２３４５６"),
        (EMAIL, "12345\n"),
        (EMAIL, "12a456"),
    ],
)
def test_invalid_input_prevents_http(
    settings: Settings,
    email: str,
    code: str,
) -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        raise AssertionError("No provider request should be made.")

    with pytest.raises(AccountRecoveryVerificationRejected):
        run_verification(settings, handler, email=email, code=code)


@pytest.mark.parametrize(
    ("status_code", "code", "exception_type"),
    [
        (400, "otp_expired", AccountRecoveryVerificationRejected),
        (429, "over_request_rate_limit", AccountRecoveryVerificationRateLimited),
        (503, "otp_expired", AccountRecoveryVerificationUnavailable),
        (422, "unknown-provider-code", AccountRecoveryVerificationUnavailable),
    ],
)
def test_provider_errors_are_masked_without_retry(
    settings: Settings,
    status_code: int,
    code: str,
    exception_type: type[Exception],
) -> None:
    response = response_for(
        {"code": code, "msg": PRIVATE_DETAIL},
        status_code,
    )
    handler = Mock(return_value=response)

    with pytest.raises(exception_type) as caught:
        run_verification(settings, handler)

    assert PRIVATE_DETAIL not in str(caught.value)
    handler.assert_called_once()
    assert response.is_closed


@pytest.mark.parametrize("status_code", [301, 302])
def test_redirects_are_not_followed(
    settings: Settings,
    status_code: int,
) -> None:
    response = response_for({}, status_code)
    response.headers["Location"] = "https://untrusted.example.test/collect"
    handler = Mock(return_value=response)

    with pytest.raises(AccountRecoveryVerificationUnavailable):
        run_verification(settings, handler)

    handler.assert_called_once()
    assert response.is_closed


@pytest.mark.parametrize(
    "exception_type",
    [httpx2.ConnectError, httpx2.ReadTimeout, httpx2.RemoteProtocolError],
)
def test_transport_errors_are_masked_without_retry(
    settings: Settings,
    exception_type: type[httpx2.HTTPError],
) -> None:
    handler = Mock(side_effect=exception_type(PRIVATE_DETAIL))

    with pytest.raises(AccountRecoveryVerificationUnavailable) as caught:
        run_verification(settings, handler)

    assert PRIVATE_DETAIL not in str(caught.value)
    assert caught.value.__suppress_context__
    handler.assert_called_once()


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Content-Type": "text/html"},
        {"Content-Type": "application/json", "Content-Encoding": "gzip"},
        {"Content-Type": "application/json", "Content-Encoding": "br"},
    ],
)
def test_rejects_unsupported_response_format(
    settings: Settings,
    headers: dict[str, str],
) -> None:
    stream = ResponseStream(b"{}")
    response = httpx2.Response(200, headers=headers, stream=stream)

    with pytest.raises(AccountRecoveryVerificationUnavailable):
        run_verification(settings, lambda request: response)

    assert stream.closed
    assert response.is_closed


@pytest.mark.parametrize("body", [b"", b"not-json", b"\xff"])
def test_rejects_malformed_json(settings: Settings, body: bytes) -> None:
    stream = ResponseStream(body)
    response = httpx2.Response(
        200,
        headers={"Content-Type": "application/json"},
        stream=stream,
    )

    with pytest.raises(AccountRecoveryVerificationUnavailable):
        run_verification(settings, lambda request: response)

    assert stream.closed
    assert response.is_closed


@pytest.mark.parametrize("extra_bytes", [0, 1], ids=["at-limit", "over-limit"])
def test_response_limit_uses_actual_bytes(
    settings: Settings,
    extra_bytes: int,
) -> None:
    body = json.dumps(success_payload()).encode("utf-8")
    body += b" " * (64 * 1024 + extra_bytes - len(body))
    stream = ResponseStream(body)
    response = httpx2.Response(
        200,
        headers={
            "Content-Type": "application/json",
            "Content-Length": "1",
        },
        stream=stream,
    )

    if extra_bytes:
        with pytest.raises(AccountRecoveryVerificationUnavailable):
            run_verification(settings, lambda request: response)
    else:
        result = run_verification(settings, lambda request: response)
        assert result.user_id == UUID(USER_ID)

    assert stream.closed
    assert response.is_closed


def test_response_limit_accumulates_chunks_and_stops_reading(
    settings: Settings,
) -> None:
    class ChunkedStream(ResponseStream):
        def __init__(self) -> None:
            super().__init__(b"")
            self.chunks_read = 0

        async def __aiter__(self) -> AsyncIterator[bytes]:
            for chunk in (b" " * 32768, b" " * 32769, b"unused"):
                self.chunks_read += 1
                yield chunk

    stream = ChunkedStream()
    response = httpx2.Response(
        200,
        headers={"Content-Type": "application/json"},
        stream=stream,
    )

    with pytest.raises(AccountRecoveryVerificationUnavailable):
        run_verification(settings, lambda request: response)

    assert stream.chunks_read == 2
    assert stream.closed
    assert response.is_closed


def test_stream_read_failure_is_masked_and_response_closed(
    settings: Settings,
) -> None:
    class BrokenStream(ResponseStream):
        async def __aiter__(self) -> AsyncIterator[bytes]:
            yield b"{"
            raise httpx2.ReadError(PRIVATE_DETAIL)

    stream = BrokenStream(b"")
    response = httpx2.Response(
        200,
        headers={"Content-Type": "application/json"},
        stream=stream,
    )

    with pytest.raises(AccountRecoveryVerificationUnavailable) as caught:
        run_verification(settings, lambda request: response)

    assert PRIVATE_DETAIL not in str(caught.value)
    assert stream.closed
    assert response.is_closed


@pytest.mark.parametrize("stalled_stage", ["request", "body"])
def test_total_deadline_cancels_stalled_http_work(
    settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
    stalled_stage: str,
) -> None:
    monkeypatch.setattr(
        recovery_verification,
        "_VERIFICATION_TIMEOUT_SECONDS",
        0.05,
    )
    cancelled = False
    calls = 0

    async def stall() -> None:
        nonlocal cancelled
        try:
            await asyncio.Future[None]()
        except asyncio.CancelledError:
            cancelled = True
            raise

    class StalledStream(ResponseStream):
        async def __aiter__(self) -> AsyncIterator[bytes]:
            yield b" "
            await stall()

    stream = StalledStream(b"")
    response = httpx2.Response(
        200,
        headers={"Content-Type": "application/json"},
        stream=stream,
    )

    async def handler(request: httpx2.Request) -> httpx2.Response:
        nonlocal calls
        calls += 1

        if stalled_stage == "request":
            await stall()
            raise AssertionError("Stalled request unexpectedly completed.")

        return response

    async def run() -> None:
        async with httpx2.AsyncClient(
            transport=httpx2.MockTransport(handler),
            trust_env=False,
        ) as client:
            with pytest.raises(AccountRecoveryVerificationUnavailable):
                await asyncio.wait_for(
                    verify_recovery_code(
                        SecretStr(EMAIL),
                        SecretStr(CODE),
                        settings=settings,
                        client=client,
                    ),
                    timeout=1,
                )

    asyncio.run(run())

    assert cancelled
    assert calls == 1

    if stalled_stage == "body":
        assert stream.closed
        assert response.is_closed


def test_caller_cancellation_propagates_and_closes_response(
    settings: Settings,
) -> None:
    async def run() -> None:
        started = asyncio.Event()

        class PendingStream(ResponseStream):
            async def __aiter__(self) -> AsyncIterator[bytes]:
                yield b" "
                started.set()
                await asyncio.Future[None]()

        stream = PendingStream(b"")
        response = httpx2.Response(
            200,
            headers={"Content-Type": "application/json"},
            stream=stream,
        )
        handler = Mock(return_value=response)

        async with httpx2.AsyncClient(
            transport=httpx2.MockTransport(handler),
            trust_env=False,
        ) as client:
            task = asyncio.create_task(
                verify_recovery_code(
                    SecretStr(EMAIL),
                    SecretStr(CODE),
                    settings=settings,
                    client=client,
                )
            )

            try:
                await asyncio.wait_for(started.wait(), timeout=1)
                task.cancel()

                with pytest.raises(asyncio.CancelledError):
                    await task
            finally:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

        handler.assert_called_once()
        assert stream.closed
        assert response.is_closed

    asyncio.run(run())
