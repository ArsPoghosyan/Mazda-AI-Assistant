"""Provider refresh tests using synthetic credentials and mocked HTTP."""

import asyncio
import json
from collections.abc import AsyncIterator, Callable

import httpx2
import pytest
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict

import app.account_refresh as account_refresh
from app.account_refresh import (
    AccountRefreshRejected,
    AccountRefreshUnavailable,
    RefreshedAccountTokens,
    refresh_account_tokens,
)
from app.config import Settings

ISSUER = "https://auth.example.test/auth/v1"
REFRESH_URL = f"{ISSUER}/token?grant_type=refresh_token"
PUBLISHABLE_KEY = "sb_publishable_synthetic_test_key"
OLD_REFRESH = "synthetic-old-refresh"
NEW_ACCESS = "synthetic-new-access"
NEW_REFRESH = "synthetic-new-refresh"


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


class ResponseStream(httpx2.AsyncByteStream):
    def __init__(self, body: bytes) -> None:
        self.body = body

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for offset in range(0, len(self.body), 4096):
            yield self.body[offset : offset + 4096]


@pytest.fixture
def settings() -> Settings:
    return IsolatedSettings.model_validate(
        {
            "supabase_auth_issuer": ISSUER,
            "supabase_auth_publishable_key": PUBLISHABLE_KEY,
        }
    )


def response_for(
    payload: object,
    *,
    status_code: int = 200,
) -> httpx2.Response:
    return httpx2.Response(
        status_code,
        headers={
            "Content-Type": "application/json",
            "Content-Encoding": "identity",
        },
        stream=ResponseStream(json.dumps(payload).encode("utf-8")),
    )


def run_refresh(
    settings: Settings,
    handler: Callable[[httpx2.Request], httpx2.Response],
    *,
    raw_token: str = OLD_REFRESH,
) -> RefreshedAccountTokens:
    async def run() -> RefreshedAccountTokens:
        async with httpx2.AsyncClient(
            transport=httpx2.MockTransport(handler),
            auth=("synthetic-user", "synthetic-password"),
            follow_redirects=True,
            trust_env=False,
        ) as client:
            return await refresh_account_tokens(
                SecretStr(raw_token),
                settings=settings,
                client=client,
            )

    return asyncio.run(run())


@pytest.mark.parametrize("token_type", ["bearer", "Bearer"])
def test_refreshes_once_using_the_configured_provider(
    settings: Settings,
    token_type: str,
) -> None:
    requests: list[httpx2.Request] = []
    response = response_for(
        {
            "access_token": NEW_ACCESS,
            "refresh_token": NEW_REFRESH,
            "token_type": token_type,
        }
    )
    response.headers["Content-Type"] = "application/json; charset=utf-8"

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return response

    result = run_refresh(settings, handler)

    assert len(requests) == 1
    request = requests[0]
    assert request.method == "POST"
    assert str(request.url) == REFRESH_URL
    assert json.loads(request.content) == {"refresh_token": OLD_REFRESH}
    assert request.headers["apikey"] == PUBLISHABLE_KEY
    assert request.headers["accept"] == "application/json"
    assert request.headers["accept-encoding"] == "identity"
    assert "authorization" not in request.headers

    assert result.access_token.get_secret_value() == NEW_ACCESS
    assert result.refresh_token.get_secret_value() == NEW_REFRESH
    assert NEW_ACCESS not in repr(result)
    assert NEW_REFRESH not in repr(result)
    assert response.is_closed


@pytest.mark.parametrize(
    "field",
    ["supabase_auth_issuer", "supabase_auth_publishable_key"],
)
def test_missing_configuration_prevents_network_requests(
    settings: Settings,
    field: str,
) -> None:
    incomplete = settings.model_copy(update={field: None})

    def handler(request: httpx2.Request) -> httpx2.Response:
        raise AssertionError("No HTTP request should be made.")

    with pytest.raises(AccountRefreshUnavailable, match="not configured"):
        run_refresh(incomplete, handler)


@pytest.mark.parametrize(
    "raw_token",
    [
        "",
        "synthetic\nrefresh",
        "synthetic refresh",
        "\N{SNOWMAN}",
        "x" * 8193,
    ],
)
def test_invalid_input_prevents_network_requests(
    settings: Settings,
    raw_token: str,
) -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        raise AssertionError("No HTTP request should be made.")

    with pytest.raises(AccountRefreshRejected):
        run_refresh(settings, handler, raw_token=raw_token)


@pytest.mark.parametrize(
    ("status_code", "error_code"),
    [
        (400, "refresh_token_not_found"),
        (400, "refresh_token_already_used"),
        (403, "session_not_found"),
        (403, "session_expired"),
        (401, "user_not_found"),
        (422, "user_banned"),
    ],
)
def test_known_credential_rejection_is_reported_without_provider_details(
    settings: Settings,
    status_code: int,
    error_code: str,
) -> None:
    private_message = "Private provider response details"
    response = response_for(
        {"error_code": error_code, "msg": private_message},
        status_code=status_code,
    )
    requests: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return response

    with pytest.raises(AccountRefreshRejected) as caught:
        run_refresh(settings, handler)

    assert len(requests) == 1
    assert str(caught.value) == "Account credentials were rejected."
    assert private_message not in str(caught.value)
    assert response.is_closed


def raw_response(body: bytes) -> httpx2.Response:
    return httpx2.Response(
        200,
        headers={"Content-Type": "application/json"},
        stream=ResponseStream(body),
    )


@pytest.mark.parametrize(
    "body",
    [b"", b"not JSON", b"\xff", b"null", b"[]", b"{}"],
)
def test_invalid_response_documents_are_unavailable(
    settings: Settings,
    body: bytes,
) -> None:
    response = raw_response(body)

    with pytest.raises(AccountRefreshUnavailable):
        run_refresh(settings, lambda request: response)

    assert response.is_closed


@pytest.mark.parametrize("field", ["access_token", "refresh_token"])
@pytest.mark.parametrize(
    "invalid_value",
    [None, 123, "", "contains space", "line\nbreak", "\N{SNOWMAN}", "x" * 8193],
)
def test_invalid_returned_tokens_are_unavailable(
    settings: Settings,
    field: str,
    invalid_value: object,
) -> None:
    payload: dict[str, object] = {
        "access_token": NEW_ACCESS,
        "refresh_token": NEW_REFRESH,
        "token_type": "bearer",
    }
    payload[field] = invalid_value
    response = response_for(payload)

    with pytest.raises(AccountRefreshUnavailable):
        run_refresh(settings, lambda request: response)

    assert response.is_closed


@pytest.mark.parametrize("field", ["access_token", "refresh_token", "token_type"])
def test_missing_response_fields_are_unavailable(
    settings: Settings,
    field: str,
) -> None:
    payload = {
        "access_token": NEW_ACCESS,
        "refresh_token": NEW_REFRESH,
        "token_type": "bearer",
    }
    del payload[field]
    response = response_for(payload)

    with pytest.raises(AccountRefreshUnavailable):
        run_refresh(settings, lambda request: response)

    assert response.is_closed


@pytest.mark.parametrize("token_type", [None, 123, "", "mac"])
def test_invalid_token_type_is_unavailable(
    settings: Settings,
    token_type: object,
) -> None:
    response = response_for(
        {
            "access_token": NEW_ACCESS,
            "refresh_token": NEW_REFRESH,
            "token_type": token_type,
        }
    )

    with pytest.raises(AccountRefreshUnavailable):
        run_refresh(settings, lambda request: response)

    assert response.is_closed


@pytest.mark.parametrize("content_type", ["", "text/html"])
def test_unexpected_content_type_is_rejected(
    settings: Settings,
    content_type: str,
) -> None:
    response = response_for(
        {
            "access_token": NEW_ACCESS,
            "refresh_token": NEW_REFRESH,
            "token_type": "bearer",
        }
    )
    response.headers["Content-Type"] = content_type

    with pytest.raises(AccountRefreshUnavailable):
        run_refresh(settings, lambda request: response)

    assert response.is_closed


@pytest.mark.parametrize("encoding", ["gzip", "br"])
def test_compressed_responses_are_rejected(
    settings: Settings,
    encoding: str,
) -> None:
    response = response_for({})
    response.headers["Content-Encoding"] = encoding

    with pytest.raises(AccountRefreshUnavailable):
        run_refresh(settings, lambda request: response)

    assert response.is_closed


@pytest.mark.parametrize("extra_bytes", [0, 1])
def test_response_size_boundary(
    settings: Settings,
    extra_bytes: int,
) -> None:
    document = json.dumps(
        {
            "access_token": NEW_ACCESS,
            "refresh_token": NEW_REFRESH,
            "token_type": "bearer",
        }
    ).encode("ascii")
    body = document + b" " * (64 * 1024 - len(document) + extra_bytes)
    response = raw_response(body)

    if extra_bytes:
        with pytest.raises(AccountRefreshUnavailable):
            run_refresh(settings, lambda request: response)
    else:
        result = run_refresh(settings, lambda request: response)
        assert result.access_token.get_secret_value() == NEW_ACCESS

    assert response.is_closed


def test_maximum_token_lengths_are_accepted(settings: Settings) -> None:
    access_token = "a" * 8192
    refresh_token = "r" * 8192
    response = response_for(
        {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
        }
    )
    requests: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return response

    result = run_refresh(settings, handler, raw_token=refresh_token)

    assert len(requests) == 1
    assert json.loads(requests[0].content) == {"refresh_token": refresh_token}
    assert result.access_token.get_secret_value() == access_token
    assert result.refresh_token.get_secret_value() == refresh_token
    assert response.is_closed


def test_total_deadline_stops_a_stalled_request(
    settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(account_refresh, "_REFRESH_TIMEOUT_SECONDS", 0.05)

    async def handler(request: httpx2.Request) -> httpx2.Response:
        await asyncio.Future[None]()
        return response_for({})

    async def run() -> None:
        async with httpx2.AsyncClient(
            transport=httpx2.MockTransport(handler),
            trust_env=False,
        ) as client:
            await asyncio.wait_for(
                refresh_account_tokens(
                    SecretStr(OLD_REFRESH),
                    settings=settings,
                    client=client,
                ),
                timeout=1,
            )

    with pytest.raises(AccountRefreshUnavailable):
        asyncio.run(run())


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


def test_total_deadline_closes_a_stalled_response_body(
    settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(account_refresh, "_REFRESH_TIMEOUT_SECONDS", 0.05)

    async def run() -> None:
        stream = StalledResponseStream()
        response = httpx2.Response(
            200,
            headers={"Content-Type": "application/json"},
            stream=stream,
        )

        async with httpx2.AsyncClient(
            transport=httpx2.MockTransport(lambda request: response),
            trust_env=False,
        ) as client:
            with pytest.raises(AccountRefreshUnavailable):
                await asyncio.wait_for(
                    refresh_account_tokens(
                        SecretStr(OLD_REFRESH),
                        settings=settings,
                        client=client,
                    ),
                    timeout=1,
                )

            assert stream.started.is_set()
            assert stream.closed
            assert response.is_closed

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

        async with httpx2.AsyncClient(
            transport=httpx2.MockTransport(lambda request: response),
            trust_env=False,
        ) as client:
            task = asyncio.create_task(
                refresh_account_tokens(
                    SecretStr(OLD_REFRESH),
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
            finally:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

    asyncio.run(run())


@pytest.mark.parametrize(
    ("status_code", "payload"),
    [
        (400, {"error_code": "validation_failed"}),
        (401, {"message": "Invalid API key"}),
        (403, {"error_code": "unexpected_audience"}),
        (422, {"error_code": ["refresh_token_not_found"]}),
    ],
)
def test_other_errors_do_not_claim_credentials_are_invalid(
    settings: Settings,
    status_code: int,
    payload: object,
) -> None:
    response = response_for(payload, status_code=status_code)

    with pytest.raises(AccountRefreshUnavailable):
        run_refresh(settings, lambda request: response)

    assert response.is_closed


@pytest.mark.parametrize("status_code", [429, 500, 502, 503, 504])
def test_temporary_failures_are_not_retried_or_treated_as_rejection(
    settings: Settings,
    status_code: int,
) -> None:
    # Even a rejection-looking body must not override a server-error status.
    response = response_for(
        {"error_code": "refresh_token_not_found"},
        status_code=status_code,
    )
    requests: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return response

    with pytest.raises(AccountRefreshUnavailable):
        run_refresh(settings, handler)

    assert len(requests) == 1
    assert response.is_closed


def test_redirects_are_not_followed(settings: Settings) -> None:
    response = response_for({}, status_code=302)
    response.headers["Location"] = "https://other.example.test/token"
    requests: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return response

    with pytest.raises(AccountRefreshUnavailable):
        run_refresh(settings, handler)

    assert len(requests) == 1
    assert str(requests[0].url) == REFRESH_URL
    assert response.is_closed


@pytest.mark.parametrize(
    "error_type",
    [httpx2.ConnectError, httpx2.ReadTimeout],
)
def test_transport_failures_hide_details_and_are_not_retried(
    settings: Settings,
    error_type: type[httpx2.RequestError],
) -> None:
    requests: list[httpx2.Request] = []
    private_message = "Private connection details"

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        raise error_type(private_message, request=request)

    with pytest.raises(AccountRefreshUnavailable) as caught:
        run_refresh(settings, handler)

    assert len(requests) == 1
    assert str(caught.value) == "Account refresh is unavailable."
    assert private_message not in str(caught.value)
