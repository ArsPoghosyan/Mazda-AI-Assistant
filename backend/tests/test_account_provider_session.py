"""Provider-session checks using synthetic credentials and mocked HTTP."""

import asyncio
import json
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock
from uuid import UUID

import httpx2
import pytest
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict

import app.account_provider_session as provider_session
from app.account_provider_session import (
    AccountProviderSessionRejected,
    AccountProviderSessionUnavailable,
    check_provider_session,
)
from app.account_tokens import VerifiedAccount
from app.config import Settings

ISSUER = "https://auth.example.test/auth/v1"
PUBLISHABLE_KEY = "sb_publishable_synthetic_test_key"
ACCESS_TOKEN = "synthetic-account-access-token"
USER_ID = UUID("563128d6-22fd-464f-a3bd-31018fdf1b3c")
OTHER_USER_ID = UUID("33333333-3333-4333-8333-333333333333")
SESSION_ID = UUID("22222222-2222-4222-8222-222222222222")
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
            "supabase_auth_issuer": ISSUER,
            "supabase_auth_publishable_key": PUBLISHABLE_KEY,
        }
    )


@pytest.fixture
def account() -> VerifiedAccount:
    return VerifiedAccount(
        user_id=USER_ID,
        session_id=SESSION_ID,
        assurance_level="aal1",
        access_token_expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def response_for(payload: object, status_code: int = 200) -> httpx2.Response:
    return httpx2.Response(
        status_code,
        headers={"Content-Type": "application/json; charset=utf-8"},
        stream=ResponseStream(json.dumps(payload).encode("utf-8")),
    )


def run_check(
    settings: Settings,
    account: VerifiedAccount,
    handler: Callable[[httpx2.Request], httpx2.Response],
    *,
    token: str = ACCESS_TOKEN,
) -> None:
    async def run() -> None:
        async with httpx2.AsyncClient(
            transport=httpx2.MockTransport(handler),
            auth=("synthetic-user", "synthetic-client-password"),
            follow_redirects=True,
            trust_env=False,
        ) as client:
            await check_provider_session(
                SecretStr(token),
                verified_account=account,
                settings=settings,
                client=client,
            )

    asyncio.run(run())


def test_requests_expected_user_once_with_explicit_bearer(
    settings: Settings,
    account: VerifiedAccount,
) -> None:
    response = response_for({"id": str(USER_ID), "is_anonymous": False})
    handler = Mock(return_value=response)

    run_check(settings, account, handler)

    handler.assert_called_once()
    request = handler.call_args.args[0]
    assert request.method == "GET"
    assert str(request.url) == f"{ISSUER}/user"
    assert request.content == b""
    assert request.headers["authorization"] == f"Bearer {ACCESS_TOKEN}"
    assert request.headers["apikey"] == PUBLISHABLE_KEY
    assert request.headers["accept"] == "application/json"
    assert request.headers["accept-encoding"] == "identity"
    assert "cookie" not in request.headers
    assert response.is_closed


@pytest.mark.parametrize(
    "field",
    ["supabase_auth_issuer", "supabase_auth_publishable_key"],
)
def test_missing_configuration_prevents_http(
    settings: Settings,
    account: VerifiedAccount,
    field: str,
) -> None:
    handler = Mock(side_effect=AssertionError("Unexpected provider request."))

    with pytest.raises(AccountProviderSessionUnavailable, match="not configured"):
        run_check(settings.model_copy(update={field: None}), account, handler)

    handler.assert_not_called()


@pytest.mark.parametrize(
    "token",
    ["", "x" * 8193, "has space", "line\nbreak", "é", "\x00", "abc\x7f"],
)
def test_invalid_token_prevents_http(
    settings: Settings,
    account: VerifiedAccount,
    token: str,
) -> None:
    handler = Mock(side_effect=AssertionError("Unexpected provider request."))

    with pytest.raises(AccountProviderSessionUnavailable):
        run_check(settings, account, handler, token=token)

    handler.assert_not_called()


@pytest.mark.parametrize(
    ("status_code", "code", "exception_type"),
    [
        (401, "bad_jwt", AccountProviderSessionRejected),
        (403, "session_not_found", AccountProviderSessionRejected),
        (429, "over_request_rate_limit", AccountProviderSessionUnavailable),
        (503, "session_not_found", AccountProviderSessionUnavailable),
        (401, "unknown-provider-code", AccountProviderSessionUnavailable),
    ],
)
def test_provider_errors_are_masked_without_retry(
    settings: Settings,
    account: VerifiedAccount,
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
        run_check(settings, account, handler)

    for secret in (PRIVATE_DETAIL, ACCESS_TOKEN, PUBLISHABLE_KEY):
        assert secret not in str(caught.value)

    handler.assert_called_once()
    assert response.is_closed


def test_another_accounts_response_is_not_accepted(
    settings: Settings,
    account: VerifiedAccount,
) -> None:
    response = response_for({"id": str(OTHER_USER_ID), "is_anonymous": False})
    handler = Mock(return_value=response)

    with pytest.raises(AccountProviderSessionUnavailable):
        run_check(settings, account, handler)

    handler.assert_called_once()
    assert response.is_closed


@pytest.mark.parametrize("status_code", [301, 302])
def test_redirects_are_not_followed(
    settings: Settings,
    account: VerifiedAccount,
    status_code: int,
) -> None:
    response = response_for({}, status_code)
    response.headers["Location"] = "https://untrusted.example.test/collect"
    handler = Mock(return_value=response)

    with pytest.raises(AccountProviderSessionUnavailable):
        run_check(settings, account, handler)

    handler.assert_called_once()
    assert response.is_closed


@pytest.mark.parametrize(
    "exception_type",
    [httpx2.ConnectError, httpx2.ReadTimeout, httpx2.RemoteProtocolError],
)
def test_transport_errors_are_masked_without_retry(
    settings: Settings,
    account: VerifiedAccount,
    exception_type: type[httpx2.HTTPError],
) -> None:
    handler = Mock(side_effect=exception_type(PRIVATE_DETAIL))

    with pytest.raises(AccountProviderSessionUnavailable) as caught:
        run_check(settings, account, handler)

    assert PRIVATE_DETAIL not in str(caught.value)
    assert ACCESS_TOKEN not in str(caught.value)
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
    account: VerifiedAccount,
    headers: dict[str, str],
) -> None:
    stream = ResponseStream(b"{}")
    response = httpx2.Response(200, headers=headers, stream=stream)

    with pytest.raises(AccountProviderSessionUnavailable):
        run_check(settings, account, lambda request: response)

    assert stream.closed
    assert response.is_closed


@pytest.mark.parametrize("body", [b"", b"not-json", b"\xff"])
def test_rejects_malformed_json(
    settings: Settings,
    account: VerifiedAccount,
    body: bytes,
) -> None:
    stream = ResponseStream(body)
    response = httpx2.Response(
        200,
        headers={"Content-Type": "application/json"},
        stream=stream,
    )

    with pytest.raises(AccountProviderSessionUnavailable):
        run_check(settings, account, lambda request: response)

    assert stream.closed
    assert response.is_closed


@pytest.mark.parametrize("extra_bytes", [0, 1], ids=["at-limit", "over-limit"])
def test_response_limit_uses_actual_bytes(
    settings: Settings,
    account: VerifiedAccount,
    extra_bytes: int,
) -> None:
    body = json.dumps({"id": str(USER_ID), "is_anonymous": False}).encode()
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
        with pytest.raises(AccountProviderSessionUnavailable):
            run_check(settings, account, lambda request: response)
    else:
        run_check(settings, account, lambda request: response)

    assert stream.closed
    assert response.is_closed


def test_response_limit_accumulates_chunks_and_stops_reading(
    settings: Settings,
    account: VerifiedAccount,
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

    with pytest.raises(AccountProviderSessionUnavailable):
        run_check(settings, account, lambda request: response)

    assert stream.chunks_read == 2
    assert stream.closed
    assert response.is_closed


def test_stream_failure_is_masked_and_response_closed(
    settings: Settings,
    account: VerifiedAccount,
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

    with pytest.raises(AccountProviderSessionUnavailable) as caught:
        run_check(settings, account, lambda request: response)

    assert PRIVATE_DETAIL not in str(caught.value)
    assert stream.closed
    assert response.is_closed


@pytest.mark.parametrize("stalled_stage", ["request", "body"])
def test_total_deadline_cancels_stalled_http_work(
    settings: Settings,
    account: VerifiedAccount,
    monkeypatch: pytest.MonkeyPatch,
    stalled_stage: str,
) -> None:
    monkeypatch.setattr(
        provider_session,
        "_SESSION_CHECK_TIMEOUT_SECONDS",
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
            with pytest.raises(AccountProviderSessionUnavailable):
                await asyncio.wait_for(
                    check_provider_session(
                        SecretStr(ACCESS_TOKEN),
                        verified_account=account,
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
    account: VerifiedAccount,
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
                check_provider_session(
                    SecretStr(ACCESS_TOKEN),
                    verified_account=account,
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
