"""Temporary recovery-session cleanup using synthetic credentials and mocked HTTP."""

import asyncio
import json
from collections.abc import AsyncIterator, Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock
from uuid import UUID

import httpx2
import pytest
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict

import app.account_recovery_session_cleanup as cleanup
from app.account_recovery_session_cleanup import (
    AccountRecoverySessionCleanupUnavailable,
    cleanup_recovery_session,
)
from app.account_recovery_verification import RecoveryVerificationCredentials
from app.account_tokens import VerifiedAccount
from app.config import Settings

ISSUER = "https://auth.example.test/auth/v1"
PUBLISHABLE_KEY = "sb_publishable_synthetic_test_key"
USER_ID = UUID("563128d6-22fd-464f-a3bd-31018fdf1b3c")
OTHER_USER_ID = UUID("33333333-3333-4333-8333-333333333333")
SESSION_ID = UUID("22222222-2222-4222-8222-222222222222")
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


@pytest.fixture
def account() -> VerifiedAccount:
    return VerifiedAccount(
        user_id=USER_ID,
        session_id=SESSION_ID,
        assurance_level="aal1",
        access_token_expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def response_for(status_code: int, payload: object) -> httpx2.Response:
    return httpx2.Response(
        status_code,
        headers={"Content-Type": "application/json; charset=utf-8"},
        stream=ResponseStream(json.dumps(payload).encode("utf-8")),
    )


async def perform_cleanup(
    settings: Settings,
    account: VerifiedAccount,
    client: httpx2.AsyncClient,
    *,
    token: str = ACCESS_TOKEN,
) -> None:
    await cleanup_recovery_session(
        RecoveryVerificationCredentials(user_id=USER_ID, access_token=SecretStr(token)),
        verified_account=account,
        settings=settings,
        client=client,
    )


def run_cleanup(
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
            await perform_cleanup(settings, account, client, token=token)

    asyncio.run(run())


def test_ends_only_the_recovery_provider_session_once(
    settings: Settings, account: VerifiedAccount
) -> None:
    stream = ResponseStream(b"")
    response = httpx2.Response(204, stream=stream)
    handler = Mock(return_value=response)

    run_cleanup(settings, account, handler)

    handler.assert_called_once()
    request = handler.call_args.args[0]
    assert request.method == "POST"
    assert str(request.url) == ISSUER + "/logout?scope=local"
    assert request.content == b""
    assert request.headers["authorization"] == f"Bearer {ACCESS_TOKEN}"
    assert request.headers["apikey"] == PUBLISHABLE_KEY
    assert request.headers["accept"] == "application/json"
    assert request.headers["accept-encoding"] == "identity"
    assert "cookie" not in request.headers
    assert stream.closed
    assert response.is_closed


def test_already_absent_session_is_accepted_and_response_closed(
    settings: Settings, account: VerifiedAccount
) -> None:
    response = response_for(403, {"code": "session_not_found", "msg": PRIVATE_DETAIL})
    handler = Mock(return_value=response)

    run_cleanup(settings, account, handler)

    handler.assert_called_once()
    assert response.is_closed


@pytest.mark.parametrize("field", ["supabase_auth_issuer", "supabase_auth_publishable_key"])
def test_missing_configuration_prevents_http(
    settings: Settings, account: VerifiedAccount, field: str
) -> None:
    handler = Mock(side_effect=AssertionError("Unexpected provider request."))

    with pytest.raises(AccountRecoverySessionCleanupUnavailable, match="not configured"):
        run_cleanup(settings.model_copy(update={field: None}), account, handler)

    handler.assert_not_called()


@pytest.mark.parametrize("problem", ["different-account", "nil-session"])
def test_invalid_identity_binding_prevents_http(
    settings: Settings, account: VerifiedAccount, problem: str
) -> None:
    account = (
        replace(account, user_id=OTHER_USER_ID)
        if problem == "different-account"
        else replace(account, session_id=UUID(int=0))
    )
    handler = Mock(side_effect=AssertionError("Unexpected provider request."))

    with pytest.raises(AccountRecoverySessionCleanupUnavailable):
        run_cleanup(settings, account, handler)

    handler.assert_not_called()


@pytest.mark.parametrize(
    "token", ["", "x" * 8193, "has space", "line\nbreak", "é", "\x00", "abc\x7f"]
)
def test_invalid_token_prevents_http(
    settings: Settings, account: VerifiedAccount, token: str
) -> None:
    handler = Mock(side_effect=AssertionError("Unexpected provider request."))

    with pytest.raises(AccountRecoverySessionCleanupUnavailable):
        run_cleanup(settings, account, handler, token=token)

    handler.assert_not_called()


@pytest.mark.parametrize("token", ["x", "x" * 8192], ids=["minimum", "maximum"])
def test_valid_token_size_boundaries_preserve_the_exact_bearer(
    settings: Settings, account: VerifiedAccount, token: str
) -> None:
    response = httpx2.Response(204, stream=ResponseStream(b""))
    handler = Mock(return_value=response)

    run_cleanup(settings, account, handler, token=token)

    handler.assert_called_once()
    assert handler.call_args.args[0].headers["authorization"] == f"Bearer {token}"
    assert response.is_closed


@pytest.mark.parametrize("status_code", [200, 201, 202, 400, 401, 404, 422, 429, 500, 503])
def test_unexpected_status_does_not_confirm_cleanup_or_retry(
    settings: Settings, account: VerifiedAccount, status_code: int
) -> None:
    response = response_for(status_code, {"code": "session_not_found", "msg": PRIVATE_DETAIL})
    handler = Mock(return_value=response)

    with pytest.raises(AccountRecoverySessionCleanupUnavailable) as caught:
        run_cleanup(settings, account, handler)

    assert str(caught.value) == "Recovery session cleanup is unavailable."
    for private_value in (PRIVATE_DETAIL, ACCESS_TOKEN, PUBLISHABLE_KEY):
        assert private_value not in repr(caught.value)
    handler.assert_called_once()
    assert response.is_closed


@pytest.mark.parametrize("status_code", [301, 302])
def test_redirects_are_not_followed(
    settings: Settings, account: VerifiedAccount, status_code: int
) -> None:
    response = response_for(status_code, {})
    response.headers["Location"] = "https://untrusted.example.test/collect"
    handler = Mock(return_value=response)

    with pytest.raises(AccountRecoverySessionCleanupUnavailable):
        run_cleanup(settings, account, handler)

    handler.assert_called_once()
    assert response.is_closed


@pytest.mark.parametrize(
    "payload",
    [
        {"code": "bad_jwt", "msg": PRIVATE_DETAIL},
        {"error_code": "session_not_found", "code": "bad_jwt"},
        {"code": "unknown-provider-code"},
    ],
)
def test_unconfirmed_forbidden_reply_is_unavailable(
    settings: Settings, account: VerifiedAccount, payload: object
) -> None:
    response = response_for(403, payload)
    handler = Mock(return_value=response)

    with pytest.raises(AccountRecoverySessionCleanupUnavailable):
        run_cleanup(settings, account, handler)

    handler.assert_called_once()
    assert response.is_closed


@pytest.mark.parametrize(
    ("status_code", "headers"),
    [
        (403, {}),
        (403, {"Content-Type": "text/html"}),
        (403, {"Content-Type": "application/json", "Content-Encoding": "gzip"}),
        (403, {"Content-Type": "application/json", "Content-Encoding": "br"}),
        (204, {"Content-Encoding": "gzip"}),
    ],
)
def test_rejects_unsupported_response_format(
    settings: Settings, account: VerifiedAccount, status_code: int, headers: dict[str, str]
) -> None:
    stream = ResponseStream(b"{}")
    response = httpx2.Response(status_code, headers=headers, stream=stream)

    with pytest.raises(AccountRecoverySessionCleanupUnavailable):
        run_cleanup(settings, account, lambda request: response)

    assert stream.closed
    assert response.is_closed


@pytest.mark.parametrize("body", [b"", b"not-json", b"\xff"])
def test_rejects_malformed_error_json(
    settings: Settings, account: VerifiedAccount, body: bytes
) -> None:
    stream = ResponseStream(body)
    response = httpx2.Response(403, headers={"Content-Type": "application/json"}, stream=stream)

    with pytest.raises(AccountRecoverySessionCleanupUnavailable):
        run_cleanup(settings, account, lambda request: response)

    assert stream.closed
    assert response.is_closed


@pytest.mark.parametrize("body", [b"{}", b" ", b"unexpected"])
def test_no_content_reply_must_have_an_empty_body(
    settings: Settings, account: VerifiedAccount, body: bytes
) -> None:
    stream = ResponseStream(body)
    response = httpx2.Response(204, stream=stream)

    with pytest.raises(AccountRecoverySessionCleanupUnavailable):
        run_cleanup(settings, account, lambda request: response)

    assert stream.closed
    assert response.is_closed


@pytest.mark.parametrize("extra_bytes", [0, 1], ids=["at-limit", "over-limit"])
def test_response_limit_uses_actual_bytes(
    settings: Settings, account: VerifiedAccount, extra_bytes: int
) -> None:
    body = json.dumps({"code": "session_not_found"}).encode()
    body += b" " * (64 * 1024 + extra_bytes - len(body))
    stream = ResponseStream(body)
    response = httpx2.Response(
        403, headers={"Content-Type": "application/json", "Content-Length": "1"}, stream=stream
    )

    if extra_bytes:
        with pytest.raises(AccountRecoverySessionCleanupUnavailable):
            run_cleanup(settings, account, lambda request: response)
    else:
        run_cleanup(settings, account, lambda request: response)

    assert stream.closed
    assert response.is_closed


def test_response_limit_accumulates_chunks_and_stops_reading(
    settings: Settings, account: VerifiedAccount
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
    response = httpx2.Response(403, headers={"Content-Type": "application/json"}, stream=stream)

    with pytest.raises(AccountRecoverySessionCleanupUnavailable):
        run_cleanup(settings, account, lambda request: response)

    assert stream.chunks_read == 2
    assert stream.closed
    assert response.is_closed


@pytest.mark.parametrize(
    "exception_type", [httpx2.ConnectError, httpx2.ReadTimeout, httpx2.RemoteProtocolError]
)
def test_transport_errors_are_masked_without_retry(
    settings: Settings, account: VerifiedAccount, exception_type: type[httpx2.HTTPError]
) -> None:
    handler = Mock(side_effect=exception_type(PRIVATE_DETAIL))

    with pytest.raises(AccountRecoverySessionCleanupUnavailable) as caught:
        run_cleanup(settings, account, handler)

    assert str(caught.value) == "Recovery session cleanup is unavailable."
    assert caught.value.__suppress_context__
    handler.assert_called_once()


@pytest.mark.parametrize("status_code", [204, 403])
def test_stream_read_failure_is_masked_and_response_closed(
    settings: Settings, account: VerifiedAccount, status_code: int
) -> None:
    class BrokenStream(ResponseStream):
        async def __aiter__(self) -> AsyncIterator[bytes]:
            if status_code == 403:
                yield b"{"
            raise httpx2.ReadError(PRIVATE_DETAIL)

    stream = BrokenStream(b"")
    response = httpx2.Response(
        status_code, headers={"Content-Type": "application/json"}, stream=stream
    )

    with pytest.raises(AccountRecoverySessionCleanupUnavailable) as caught:
        run_cleanup(settings, account, lambda request: response)

    assert PRIVATE_DETAIL not in str(caught.value)
    assert stream.closed
    assert response.is_closed


@pytest.mark.parametrize("stage", ["request", "body-204", "body-403"])
def test_total_deadline_cancels_stalled_http_work(
    settings: Settings, account: VerifiedAccount, monkeypatch: pytest.MonkeyPatch, stage: str
) -> None:
    monkeypatch.setattr(cleanup, "_CLEANUP_TIMEOUT_SECONDS", 0.05)
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
            yield b""
            await stall()

    stream = StalledStream(b"")
    response = httpx2.Response(
        403 if stage == "body-403" else 204,
        headers={"Content-Type": "application/json"},
        stream=stream,
    )

    async def handler(request: httpx2.Request) -> httpx2.Response:
        nonlocal calls
        calls += 1
        if stage == "request":
            await stall()
            raise AssertionError("Stalled request unexpectedly completed.")
        return response

    async def run() -> None:
        async with httpx2.AsyncClient(
            transport=httpx2.MockTransport(handler), trust_env=False
        ) as client:
            with pytest.raises(AccountRecoverySessionCleanupUnavailable):
                await asyncio.wait_for(perform_cleanup(settings, account, client), timeout=1)

    asyncio.run(run())

    assert cancelled
    assert calls == 1
    if stage != "request":
        assert stream.closed
        assert response.is_closed


@pytest.mark.parametrize("stage", ["request", "body-204", "body-403"])
def test_caller_cancellation_propagates_and_closes_available_response(
    settings: Settings, account: VerifiedAccount, stage: str
) -> None:
    async def run() -> None:
        started = asyncio.Event()
        calls = 0

        async def stall() -> None:
            started.set()
            await asyncio.Future[None]()

        class PendingStream(ResponseStream):
            async def __aiter__(self) -> AsyncIterator[bytes]:
                yield b""
                await stall()

        stream = PendingStream(b"")
        response = httpx2.Response(
            403 if stage == "body-403" else 204,
            headers={"Content-Type": "application/json"},
            stream=stream,
        )

        async def handler(request: httpx2.Request) -> httpx2.Response:
            nonlocal calls
            calls += 1
            if stage == "request":
                await stall()
                raise AssertionError("Cancelled request unexpectedly completed.")
            return response

        async with httpx2.AsyncClient(
            transport=httpx2.MockTransport(handler), trust_env=False
        ) as client:
            task = asyncio.create_task(perform_cleanup(settings, account, client))
            try:
                await asyncio.wait_for(started.wait(), timeout=1)
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
            finally:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

        assert calls == 1
        if stage != "request":
            assert stream.closed
            assert response.is_closed

    asyncio.run(run())
