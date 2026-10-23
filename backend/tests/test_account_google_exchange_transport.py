"""Bounded PKCE exchange over mocked HTTP only; no live provider credentials."""

import asyncio
import json
from collections.abc import AsyncIterator, Callable, Coroutine

import httpx2
import pytest
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict

import app.account_google_exchange as exchange
from app.account_google_exchange import (
    ExchangedGoogleTokens,
    GoogleCodeExchangeRejected,
    GoogleCodeExchangeUnavailable,
    exchange_google_authorization_code,
)
from app.config import Settings

ISSUER = "https://auth.example.test/auth/v1"
URL = f"{ISSUER}/token?grant_type=pkce"
KEY = "sb_publishable_synthetic_test_key"
CODE = "synthetic-authorization-code"
VERIFIER = "v" * 41 + "-_"
SUCCESS = {
    "access_token": "synthetic-access",
    "refresh_token": "synthetic-refresh",
    "token_type": "bearer",
}
type Handler = (
    Callable[[httpx2.Request], httpx2.Response]
    | Callable[[httpx2.Request], Coroutine[None, None, httpx2.Response]]
)
pytestmark = pytest.mark.anyio


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


class ResponseStream(httpx2.AsyncByteStream):
    def __init__(self, body: bytes) -> None:
        self.body = body
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for offset in range(0, len(self.body), 4096):
            yield self.body[offset : offset + 4096]

    async def aclose(self) -> None:
        self.closed = True


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def settings() -> Settings:
    return IsolatedSettings.model_validate(
        {
            "supabase_auth_issuer": ISSUER,
            "supabase_auth_publishable_key": KEY,
            "account_google_oauth_api_enabled": False,
        }
    )


def response_for(payload: object, status: int = 200) -> httpx2.Response:
    return httpx2.Response(
        status,
        headers={"Content-Type": "application/json"},
        stream=ResponseStream(json.dumps(payload).encode("utf-8")),
    )


async def run_exchange(
    settings: Settings, handler: Handler, *, code: str = CODE, verifier: str = VERIFIER
) -> ExchangedGoogleTokens:
    async with httpx2.AsyncClient(
        transport=httpx2.MockTransport(handler),
        follow_redirects=True,
        auth=("synthetic-user", "synthetic-password"),
        trust_env=False,
        headers={
            "Authorization": "Bearer synthetic-unrelated-credential",
            "Cookie": "unrelated=synthetic",
        },
        params={"grant_type": "password", "unexpected": "synthetic"},
        cookies={"other": "synthetic"},
        timeout=0.5,
    ) as client:
        result = await exchange_google_authorization_code(
            SecretStr(code), SecretStr(verifier), settings=settings, client=client
        )
        assert not client.is_closed
        return result


async def test_request_is_fixed_and_ignores_shared_client_defaults(settings: Settings) -> None:
    requests: list[httpx2.Request] = []
    response = response_for(SUCCESS)
    response.headers["Content-Type"] = "Application/JSON; charset=utf-8"

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return response

    result = await run_exchange(settings, handler)
    assert len(requests) == 1
    request = requests[0]
    assert request.method == "POST"
    assert str(request.url) == URL
    assert json.loads(request.content) == {"auth_code": CODE, "code_verifier": VERIFIER}
    assert request.headers["apikey"] == KEY
    assert request.headers["accept"] == "application/json"
    assert request.headers["accept-encoding"] == "identity"
    assert request.headers["cache-control"] == "no-store"
    assert "authorization" not in request.headers
    assert "cookie" not in request.headers
    assert all(value == 5.0 for value in request.extensions["timeout"].values())
    assert CODE not in str(request.url) and VERIFIER not in str(request.url)
    assert result.access_token.get_secret_value() == SUCCESS["access_token"]
    assert result.refresh_token.get_secret_value() == SUCCESS["refresh_token"]
    assert response.is_closed
    assert settings.account_google_oauth_api_enabled is False


@pytest.mark.parametrize("missing", ["supabase_auth_issuer", "supabase_auth_publishable_key"])
async def test_missing_config_never_sends_request(settings: Settings, missing: str) -> None:
    def unexpected(request: httpx2.Request) -> httpx2.Response:
        raise AssertionError("Missing configuration must not contact the provider.")

    with pytest.raises(GoogleCodeExchangeUnavailable):
        await run_exchange(settings.model_copy(update={missing: None}), unexpected)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("code", ""),
        ("code", "c" * 1025),
        ("code", "code value"),
        ("code", "code\n"),
        ("code", "code\x00"),
        ("code", "code\N{SNOWMAN}"),
        ("verifier", ""),
        ("verifier", "v" * 42),
        ("verifier", "v" * 44),
        ("verifier", "v" * 42 + "="),
        ("verifier", "v" * 42 + "+"),
        ("verifier", "v" * 42 + "\n"),
        ("verifier", "v" * 42 + "\N{SNOWMAN}"),
    ],
)
async def test_invalid_credentials_never_send_request(
    settings: Settings, field: str, value: str
) -> None:
    def unexpected(request: httpx2.Request) -> httpx2.Response:
        raise AssertionError("Malformed credentials must not contact the provider.")

    with pytest.raises(GoogleCodeExchangeRejected, match="^Google sign-in was rejected\\.$"):
        await run_exchange(
            settings,
            unexpected,
            code=value if field == "code" else CODE,
            verifier=value if field == "verifier" else VERIFIER,
        )


@pytest.mark.parametrize("code", ["c", "c" * 1024, "00+/&=?opaque-code"])
async def test_opaque_code_is_preserved_in_json_only(settings: Settings, code: str) -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        assert str(request.url) == URL
        assert json.loads(request.content)["auth_code"] == code
        return response_for(SUCCESS)

    await run_exchange(settings, handler, code=code)


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308, 429, 500, 503])
async def test_redirects_and_unexpected_statuses_are_not_followed_or_retried(
    settings: Settings, status: int
) -> None:
    requests: list[httpx2.Request] = []
    response = response_for({"error_code": "flow_state_expired"}, status)
    response.headers["Location"] = "https://unexpected.example/collect"

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return response

    with pytest.raises(GoogleCodeExchangeUnavailable):
        await run_exchange(settings, handler)
    assert len(requests) == 1
    assert response.is_closed


@pytest.mark.parametrize("status", [400, 401, 403, 404, 422])
async def test_known_rejection_is_interpreted_after_bounded_read(
    settings: Settings, status: int
) -> None:
    response = response_for(
        {"error_code": "bad_code_verifier", "message": "private-detail"}, status
    )
    with pytest.raises(GoogleCodeExchangeRejected, match="^Google sign-in was rejected\\.$"):
        await run_exchange(settings, lambda request: response)
    assert response.is_closed


@pytest.mark.parametrize("content_type", [None, "text/html", "application/problem+json"])
async def test_non_json_content_type_is_unavailable(
    settings: Settings, content_type: str | None
) -> None:
    response = response_for(SUCCESS)
    if content_type is None:
        del response.headers["Content-Type"]
    else:
        response.headers["Content-Type"] = content_type
    with pytest.raises(GoogleCodeExchangeUnavailable):
        await run_exchange(settings, lambda request: response)
    assert response.is_closed


@pytest.mark.parametrize("encoding", ["gzip", "br", "deflate"])
async def test_compressed_response_is_rejected_without_decompression(
    settings: Settings, encoding: str
) -> None:
    response = response_for(SUCCESS)
    response.headers["Content-Encoding"] = encoding
    with pytest.raises(GoogleCodeExchangeUnavailable):
        await run_exchange(settings, lambda request: response)
    assert response.is_closed


@pytest.mark.parametrize("size", [65536, 65537])
async def test_actual_streamed_bytes_are_bounded_regardless_of_content_length(
    settings: Settings, size: int
) -> None:
    data = json.dumps(SUCCESS).encode("ascii")
    stream = ResponseStream(data + b" " * (size - len(data)))
    response = httpx2.Response(
        200, headers={"Content-Type": "application/json", "Content-Length": "1"}, stream=stream
    )
    if size == 65536:
        assert (
            await run_exchange(settings, lambda request: response)
        ).access_token.get_secret_value() == (SUCCESS["access_token"])
    else:
        with pytest.raises(GoogleCodeExchangeUnavailable):
            await run_exchange(settings, lambda request: response)
    assert stream.closed


@pytest.mark.parametrize("body", [b"", b"{", b"\xff", b"null", b"[" * 1100 + b"]" * 1100])
async def test_malformed_or_unusable_json_is_unavailable(settings: Settings, body: bytes) -> None:
    response = httpx2.Response(
        200, headers={"Content-Type": "application/json"}, stream=ResponseStream(body)
    )
    with pytest.raises(GoogleCodeExchangeUnavailable):
        await run_exchange(settings, lambda request: response)
    assert response.is_closed


@pytest.mark.parametrize("kind", ["connection", "read-timeout"])
async def test_network_failures_are_generic_and_not_retried(settings: Settings, kind: str) -> None:
    requests: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        error = httpx2.ConnectError if kind == "connection" else httpx2.ReadTimeout
        raise error(f"Synthetic failure with {CODE} and {KEY}", request=request)

    with pytest.raises(GoogleCodeExchangeUnavailable) as caught:
        await run_exchange(settings, handler)
    assert str(caught.value) == "Google sign-in is unavailable."
    assert caught.value.__suppress_context__ is True
    assert len(requests) == 1


async def test_body_read_failure_closes_response_without_retry(settings: Settings) -> None:
    requests: list[httpx2.Request] = []

    class FailedStream(ResponseStream):
        async def __aiter__(self) -> AsyncIterator[bytes]:
            yield b"{"
            raise httpx2.ReadError(f"Synthetic read failure with {CODE}")

    stream = FailedStream(b"")

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return httpx2.Response(200, headers={"Content-Type": "application/json"}, stream=stream)

    with pytest.raises(GoogleCodeExchangeUnavailable, match="^Google sign-in is unavailable\\.$"):
        await run_exchange(settings, handler)
    assert stream.closed
    assert len(requests) == 1


@pytest.mark.parametrize("cancelled", [False, True], ids=["deadline", "caller-cancellation"])
@pytest.mark.parametrize("stage", ["headers", "body"])
async def test_deadline_and_cancellation_cover_connection_and_body(
    settings: Settings, monkeypatch: pytest.MonkeyPatch, cancelled: bool, stage: str
) -> None:
    entered = asyncio.Event()
    requests: list[httpx2.Request] = []

    class StalledStream(ResponseStream):
        async def __aiter__(self) -> AsyncIterator[bytes]:
            yield b"{"
            entered.set()
            await asyncio.Event().wait()

    stream = StalledStream(b"")

    async def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        if stage == "headers":
            entered.set()
            await asyncio.Event().wait()
        return httpx2.Response(200, headers={"Content-Type": "application/json"}, stream=stream)

    monkeypatch.setattr(exchange, "_EXCHANGE_TIMEOUT_SECONDS", 5.0 if cancelled else 0.02)
    async with asyncio.timeout(2):
        if cancelled:
            async with asyncio.TaskGroup() as group:
                task = group.create_task(run_exchange(settings, handler))
                await entered.wait()
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
            assert task.cancelled()
        else:
            with pytest.raises(GoogleCodeExchangeUnavailable):
                await run_exchange(settings, handler)
    assert len(requests) == 1
    if stage == "body":
        assert stream.closed
