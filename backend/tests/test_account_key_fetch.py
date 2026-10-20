"""Public-key fetching tests using mocked HTTP responses."""

import asyncio
from collections.abc import AsyncIterator, Callable

import httpx2
import pytest
from pydantic_settings import SettingsConfigDict

import app.account_key_fetch as key_fetch
from app.account_key_fetch import AccountKeyFetchError, fetch_account_key_set
from app.config import Settings

ISSUER = "https://auth.example.test/auth/v1"
JWKS_URL = f"{ISSUER}/.well-known/jwks.json"


class IsolatedSettings(Settings):
    """Do not read private dotenv files."""

    model_config = SettingsConfigDict(env_file=None)


class ResponseStream(httpx2.AsyncByteStream):
    """Provide a response body in small chunks."""

    def __init__(self, body: bytes) -> None:
        self.body = body

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for offset in range(0, len(self.body), 4096):
            yield self.body[offset : offset + 4096]


@pytest.fixture
def settings(monkeypatch: pytest.MonkeyPatch) -> Settings:
    monkeypatch.delenv("SUPABASE_AUTH_ISSUER", raising=False)
    monkeypatch.delenv("SUPABASE_AUTH_AUDIENCE", raising=False)

    return IsolatedSettings.model_validate({"supabase_auth_issuer": ISSUER})


def make_response(
    body: bytes = b'{"keys":[]}',
    *,
    status_code: int = 200,
    content_type: str = "application/json",
    encoding: str = "identity",
) -> httpx2.Response:
    return httpx2.Response(
        status_code,
        headers={
            "Content-Type": content_type,
            "Content-Encoding": encoding,
        },
        stream=ResponseStream(body),
    )


def run_fetch(
    settings: Settings,
    handler: Callable[[httpx2.Request], httpx2.Response],
) -> dict[str, object]:
    async def run() -> dict[str, object]:
        async with httpx2.AsyncClient(
            transport=httpx2.MockTransport(handler),
            follow_redirects=True,
            trust_env=False,
        ) as client:
            return await fetch_account_key_set(settings, client=client)

    return asyncio.run(run())


@pytest.mark.parametrize(
    "content_type",
    [
        "application/json; charset=utf-8",
        "application/jwk-set+json",
    ],
)
def test_fetches_from_configured_issuer(
    settings: Settings,
    content_type: str,
) -> None:
    requests: list[httpx2.Request] = []
    response = make_response(content_type=content_type)

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return response

    result = run_fetch(settings, handler)

    assert result == {"keys": []}
    assert len(requests) == 1
    assert requests[0].method == "GET"
    assert str(requests[0].url) == JWKS_URL
    assert requests[0].headers["accept-encoding"] == "identity"
    assert response.is_closed


def test_does_not_follow_redirects(settings: Settings) -> None:
    requests: list[httpx2.Request] = []
    response = make_response(status_code=302)
    response.headers["Location"] = "https://other.example.test/keys"

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return response

    with pytest.raises(AccountKeyFetchError, match="unavailable"):
        run_fetch(settings, handler)

    assert len(requests) == 1
    assert str(requests[0].url) == JWKS_URL
    assert response.is_closed


@pytest.mark.parametrize("status_code", [401, 429, 503])
def test_rejects_unsuccessful_responses(
    settings: Settings,
    status_code: int,
) -> None:
    response = make_response(status_code=status_code)

    with pytest.raises(AccountKeyFetchError, match="unavailable"):
        run_fetch(settings, lambda request: response)

    assert response.is_closed


@pytest.mark.parametrize(
    "body",
    [
        b"not JSON",
        b"null",
        b"[]",
        b"{}",
        b'{"keys":{}}',
        b"\xff",
    ],
)
def test_rejects_invalid_response_documents(
    settings: Settings,
    body: bytes,
) -> None:
    response = make_response(body)

    with pytest.raises(AccountKeyFetchError, match="Invalid"):
        run_fetch(settings, lambda request: response)

    assert response.is_closed


@pytest.mark.parametrize("content_type", ["text/html", ""])
def test_rejects_unexpected_content_types(
    settings: Settings,
    content_type: str,
) -> None:
    response = make_response(content_type=content_type)

    with pytest.raises(AccountKeyFetchError, match="Invalid"):
        run_fetch(settings, lambda request: response)


def test_rejects_compressed_responses(settings: Settings) -> None:
    response = make_response(encoding="gzip")

    with pytest.raises(AccountKeyFetchError, match="encoding"):
        run_fetch(settings, lambda request: response)


def test_accepts_response_at_size_limit(settings: Settings) -> None:
    document = b'{"keys":[]}'
    body = document + b" " * (64 * 1024 - len(document))
    response = make_response(body)

    assert run_fetch(settings, lambda request: response) == {"keys": []}


def test_rejects_response_over_size_limit(settings: Settings) -> None:
    response = make_response(b" " * (64 * 1024 + 1))

    with pytest.raises(AccountKeyFetchError, match="too large"):
        run_fetch(settings, lambda request: response)

    assert response.is_closed


@pytest.mark.parametrize(
    "error_type",
    [httpx2.ConnectError, httpx2.ReadTimeout],
)
def test_network_failures_hide_internal_details(
    settings: Settings,
    error_type: type[httpx2.RequestError],
) -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        raise error_type("Private transport details", request=request)

    with pytest.raises(AccountKeyFetchError, match="unavailable") as caught:
        run_fetch(settings, handler)

    assert "Private transport details" not in str(caught.value)


def test_total_deadline_stops_a_stalled_request(
    settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(key_fetch, "_FETCH_TIMEOUT_SECONDS", 0.01)

    async def handler(request: httpx2.Request) -> httpx2.Response:
        await asyncio.sleep(10)
        return make_response()

    async def run() -> None:
        async with httpx2.AsyncClient(
            transport=httpx2.MockTransport(handler),
            trust_env=False,
        ) as client:
            await fetch_account_key_set(settings, client=client)

    with pytest.raises(AccountKeyFetchError, match="unavailable"):
        asyncio.run(run())
