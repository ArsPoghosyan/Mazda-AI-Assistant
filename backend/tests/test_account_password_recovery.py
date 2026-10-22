"""Provider password recovery with synthetic input and mocked HTTP."""

import asyncio
import json
from collections.abc import AsyncIterator, Callable

import httpx2
import pytest
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict

import app.account_password_recovery as recovery
from app.account_password_recovery import (
    AccountPasswordRecoveryCaptchaRejected,
    AccountPasswordRecoveryRateLimited,
    AccountPasswordRecoveryRejected,
    AccountPasswordRecoveryUnavailable,
    request_password_recovery,
)
from app.config import Settings

ISSUER = "https://auth.example.test/auth/v1"
RECOVERY_URL = f"{ISSUER}/recover"
PUBLISHABLE_KEY = "sb_publishable_synthetic_test_key"
EMAIL = "Owner+é@example.test"
CAPTCHA = "synthetic-captcha-proof"


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


class ResponseStream(httpx2.AsyncByteStream):
    def __init__(self, *chunks: bytes) -> None:
        self.chunks = chunks
        self.closed = False
        self.chunks_read = 0

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self.chunks:
            self.chunks_read += 1
            yield chunk

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
            "account_session_encryption_key": None,
            "account_password_recovery_api_enabled": False,
        }
    )


def response_for(payload: object, status_code: int = 200) -> httpx2.Response:
    return httpx2.Response(
        status_code,
        headers={"Content-Type": "application/json; charset=utf-8"},
        stream=ResponseStream(json.dumps(payload).encode("utf-8")),
    )


def run_recovery(
    settings: Settings,
    handler: Callable[[httpx2.Request], httpx2.Response],
    *,
    email: str = EMAIL,
    captcha_token: str = CAPTCHA,
) -> None:
    async def run() -> None:
        async with httpx2.AsyncClient(
            transport=httpx2.MockTransport(handler),
            auth=("synthetic-user", "synthetic-client-password"),
            follow_redirects=True,
            trust_env=False,
        ) as client:
            await request_password_recovery(
                SecretStr(email),
                SecretStr(captcha_token),
                settings=settings,
                client=client,
            )

    asyncio.run(run())


def test_forwards_only_exact_email_and_proof_once(settings: Settings) -> None:
    requests: list[httpx2.Request] = []
    response = response_for({})

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return response

    run_recovery(settings, handler)

    assert len(requests) == 1
    request = requests[0]
    assert request.method == "POST"
    assert str(request.url) == RECOVERY_URL
    assert json.loads(request.content) == {
        "email": EMAIL,
        "gotrue_meta_security": {"captcha_token": CAPTCHA},
    }
    assert request.headers["apikey"] == PUBLISHABLE_KEY
    assert request.headers["accept"] == "application/json"
    assert request.headers["accept-encoding"] == "identity"
    assert "authorization" not in request.headers
    assert response.is_closed


@pytest.mark.parametrize("field", ["supabase_auth_issuer", "supabase_auth_publishable_key"])
def test_missing_configuration_prevents_requests(settings: Settings, field: str) -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        raise AssertionError("No provider request should be made.")

    with pytest.raises(AccountPasswordRecoveryUnavailable, match="not configured"):
        run_recovery(settings.model_copy(update={field: None}), handler)


@pytest.mark.parametrize(
    ("email", "captcha_token"),
    [
        ("", CAPTCHA),
        ("e" * 321, CAPTCHA),
        ("\ud800", CAPTCHA),
        (EMAIL, ""),
        (EMAIL, "x" * 2049),
        (EMAIL, "\ud800"),
    ],
)
def test_invalid_input_prevents_requests(
    settings: Settings, email: str, captcha_token: str
) -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        raise AssertionError("No provider request should be made.")

    with pytest.raises(AccountPasswordRecoveryRejected, match="rejected"):
        run_recovery(settings, handler, email=email, captcha_token=captcha_token)


@pytest.mark.parametrize("token", ["has space", "line\nbreak", "é"])
def test_invalid_captcha_characters_prevent_requests(settings: Settings, token: str) -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        raise AssertionError("No provider request should be made.")

    with pytest.raises(AccountPasswordRecoveryCaptchaRejected, match="Human verification"):
        run_recovery(settings, handler, captcha_token=token)


@pytest.mark.parametrize(
    ("status_code", "code"),
    [
        (422, "email_address_invalid"),
        (404, "user_not_found"),
        (403, "user_banned"),
        (400, "email_not_confirmed"),
        (429, "over_email_send_rate_limit"),
    ],
)
def test_account_dependent_outcomes_return_without_retry(
    settings: Settings, status_code: int, code: str
) -> None:
    calls = 0
    response = response_for({"code": code, "msg": "private-provider-detail"}, status_code)

    def handler(request: httpx2.Request) -> httpx2.Response:
        nonlocal calls
        calls += 1
        return response

    run_recovery(settings, handler)
    assert calls == 1
    assert response.is_closed


@pytest.mark.parametrize(
    ("status_code", "code", "exception_type"),
    [
        (400, "captcha_failed", AccountPasswordRecoveryCaptchaRejected),
        (422, "validation_failed", AccountPasswordRecoveryRejected),
        (429, "over_request_rate_limit", AccountPasswordRecoveryRateLimited),
    ],
)
def test_controlled_rejections_do_not_leak_provider_details(
    settings: Settings,
    status_code: int,
    code: str,
    exception_type: type[Exception],
) -> None:
    calls = 0
    response = response_for({"code": code, "msg": "private-provider-detail"}, status_code)

    def handler(request: httpx2.Request) -> httpx2.Response:
        nonlocal calls
        calls += 1
        return response

    with pytest.raises(exception_type) as caught:
        run_recovery(settings, handler)

    assert "private-provider-detail" not in str(caught.value)
    assert calls == 1
    assert response.is_closed


@pytest.mark.parametrize("status_code", [201, 202, 204, 301, 302, 401, 500, 503])
def test_unexpected_status_closes_response_and_never_follows_redirects(
    settings: Settings, status_code: int
) -> None:
    calls = 0
    response = response_for({}, status_code)
    response.headers["Location"] = "https://untrusted.example.test/collect"

    def handler(request: httpx2.Request) -> httpx2.Response:
        nonlocal calls
        calls += 1
        assert str(request.url) == RECOVERY_URL
        return response

    with pytest.raises(AccountPasswordRecoveryUnavailable):
        run_recovery(settings, handler)

    assert calls == 1
    assert response.is_closed


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Content-Type": "text/html"},
        {"Content-Type": "application/json", "Content-Encoding": "gzip"},
        {"Content-Type": "application/json", "Content-Encoding": "br"},
    ],
)
def test_rejects_unsupported_response_representation(
    settings: Settings, headers: dict[str, str]
) -> None:
    stream = ResponseStream(b"{}")
    response = httpx2.Response(200, headers=headers, stream=stream)

    with pytest.raises(AccountPasswordRecoveryUnavailable):
        run_recovery(settings, lambda request: response)

    assert stream.chunks_read == 0
    assert stream.closed
    assert response.is_closed


@pytest.mark.parametrize(
    "body",
    [b"", b"not-json", b"\xff", b"null", b'{"access_token":"private-token"}'],
)
def test_rejects_malformed_or_unexpected_payloads(settings: Settings, body: bytes) -> None:
    response = httpx2.Response(
        200, headers={"Content-Type": "application/json"}, stream=ResponseStream(body)
    )
    with pytest.raises(AccountPasswordRecoveryUnavailable) as caught:
        run_recovery(settings, lambda request: response)
    assert "private-token" not in str(caught.value)
    assert response.is_closed


def test_accepts_response_at_actual_byte_limit(settings: Settings) -> None:
    stream = ResponseStream(b"{}" + b" " * (64 * 1024 - 2))
    response = httpx2.Response(200, headers={"Content-Type": "application/json"}, stream=stream)
    run_recovery(settings, lambda request: response)
    assert stream.closed


def test_rejects_oversized_body_despite_false_content_length(settings: Settings) -> None:
    stream = ResponseStream(b"{}" + b" " * (64 * 1024 - 1))
    response = httpx2.Response(
        200,
        headers={"Content-Type": "application/json", "Content-Length": "1"},
        stream=stream,
    )
    with pytest.raises(AccountPasswordRecoveryUnavailable):
        run_recovery(settings, lambda request: response)
    assert stream.closed


def test_byte_limit_is_cumulative_and_stops_reading(settings: Settings) -> None:
    stream = ResponseStream(b" " * 32768, b" " * 32769, b"unused")
    response = httpx2.Response(200, headers={"Content-Type": "application/json"}, stream=stream)
    with pytest.raises(AccountPasswordRecoveryUnavailable):
        run_recovery(settings, lambda request: response)
    assert stream.chunks_read == 2
    assert stream.closed


@pytest.mark.parametrize(
    "exception_type", [httpx2.ConnectError, httpx2.ReadTimeout, httpx2.RemoteProtocolError]
)
def test_masks_transport_errors_without_retry(
    settings: Settings, exception_type: type[httpx2.HTTPError]
) -> None:
    calls = 0

    def handler(request: httpx2.Request) -> httpx2.Response:
        nonlocal calls
        calls += 1
        raise exception_type("private-transport-detail")

    with pytest.raises(AccountPasswordRecoveryUnavailable) as caught:
        run_recovery(settings, handler)
    assert "private-transport-detail" not in str(caught.value)
    assert caught.value.__suppress_context__
    assert calls == 1


def test_total_deadline_bounds_stalled_request(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(recovery, "_PASSWORD_RECOVERY_TIMEOUT_SECONDS", 0.05)
    calls = 0

    async def handler(request: httpx2.Request) -> httpx2.Response:
        nonlocal calls
        calls += 1
        await asyncio.Future[None]()
        raise AssertionError("Unreachable.")

    async def run() -> None:
        async with httpx2.AsyncClient(
            transport=httpx2.MockTransport(handler), trust_env=False
        ) as client:
            with pytest.raises(AccountPasswordRecoveryUnavailable):
                await asyncio.wait_for(
                    request_password_recovery(
                        SecretStr(EMAIL), SecretStr(CAPTCHA), settings=settings, client=client
                    ),
                    timeout=1,
                )

    asyncio.run(run())
    assert calls == 1


class StalledStream(httpx2.AsyncByteStream):
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield b" "
        self.started.set()
        await asyncio.Future[None]()

    async def aclose(self) -> None:
        self.closed = True


def test_total_deadline_bounds_stalled_body_and_closes_stream(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(recovery, "_PASSWORD_RECOVERY_TIMEOUT_SECONDS", 0.05)
    stream = StalledStream()
    response = httpx2.Response(200, headers={"Content-Type": "application/json"}, stream=stream)
    with pytest.raises(AccountPasswordRecoveryUnavailable):
        run_recovery(settings, lambda request: response)
    assert stream.started.is_set()
    assert stream.closed
    assert response.is_closed


def test_cancellation_propagates_and_closes_stream(settings: Settings) -> None:
    async def run() -> None:
        stream = StalledStream()
        response = httpx2.Response(200, headers={"Content-Type": "application/json"}, stream=stream)
        async with httpx2.AsyncClient(
            transport=httpx2.MockTransport(lambda request: response), trust_env=False
        ) as client:
            task = asyncio.create_task(
                request_password_recovery(
                    SecretStr(EMAIL), SecretStr(CAPTCHA), settings=settings, client=client
                )
            )
            try:
                await asyncio.wait_for(stream.started.wait(), timeout=1)
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
            finally:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
        assert stream.closed
        assert response.is_closed

    asyncio.run(run())


def test_body_read_error_is_masked_and_stream_closed(settings: Settings) -> None:
    class BrokenStream(ResponseStream):
        async def __aiter__(self) -> AsyncIterator[bytes]:
            yield b"{"
            raise httpx2.ReadError("private-stream-detail")

    stream = BrokenStream()
    response = httpx2.Response(200, headers={"Content-Type": "application/json"}, stream=stream)
    with pytest.raises(AccountPasswordRecoveryUnavailable) as caught:
        run_recovery(settings, lambda request: response)
    assert "private-stream-detail" not in str(caught.value)
    assert stream.closed
    assert response.is_closed
