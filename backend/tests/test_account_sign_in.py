"""Email/password provider sign-in using synthetic credentials and mocked HTTP."""

import asyncio
import json
from collections.abc import AsyncIterator, Callable

import httpx2
import pytest
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict

import app.account_sign_in as account_sign_in
from app.account_sign_in import (
    AccountSignInRejected,
    AccountSignInUnavailable,
    SignedInAccountTokens,
    sign_in_with_password,
)
from app.config import Settings

ISSUER = "https://auth.example.test/auth/v1"
SIGN_IN_URL = f"{ISSUER}/token?grant_type=password"
PUBLISHABLE_KEY = "sb_publishable_synthetic_test_key"
EMAIL = "owner@example.test"
PASSWORD = "  synthetic-password-é  "
ACCESS_TOKEN = "synthetic-access-token"
REFRESH_TOKEN = "synthetic-refresh-token"


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


def run_sign_in(
    settings: Settings,
    handler: Callable[[httpx2.Request], httpx2.Response],
    *,
    email: str = EMAIL,
    password: str = PASSWORD,
) -> SignedInAccountTokens:
    async def run() -> SignedInAccountTokens:
        async with httpx2.AsyncClient(
            transport=httpx2.MockTransport(handler),
            auth=("synthetic-user", "synthetic-client-password"),
            follow_redirects=True,
            trust_env=False,
        ) as client:
            return await sign_in_with_password(
                SecretStr(email),
                SecretStr(password),
                settings=settings,
                client=client,
            )

    return asyncio.run(run())


@pytest.mark.parametrize("token_type", ["bearer", "Bearer"])
def test_sign_in_preserves_credentials_and_returns_masked_tokens(
    settings: Settings,
    token_type: str,
) -> None:
    requests: list[httpx2.Request] = []
    response = response_for(
        {
            "access_token": ACCESS_TOKEN,
            "refresh_token": REFRESH_TOKEN,
            "token_type": token_type,
        }
    )

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return response

    result = run_sign_in(settings, handler)

    assert len(requests) == 1
    request = requests[0]
    assert request.method == "POST"
    assert str(request.url) == SIGN_IN_URL
    assert json.loads(request.content) == {
        "email": EMAIL,
        "password": PASSWORD,
    }
    assert request.headers["apikey"] == PUBLISHABLE_KEY
    assert request.headers["accept"] == "application/json"
    assert request.headers["accept-encoding"] == "identity"
    assert "authorization" not in request.headers

    assert result.access_token.get_secret_value() == ACCESS_TOKEN
    assert result.refresh_token.get_secret_value() == REFRESH_TOKEN
    assert ACCESS_TOKEN not in repr(result)
    assert REFRESH_TOKEN not in repr(result)
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

    with pytest.raises(AccountSignInUnavailable, match="not configured"):
        run_sign_in(incomplete, handler)


@pytest.mark.parametrize(
    ("email", "password"),
    [
        ("", PASSWORD),
        ("e" * 321, PASSWORD),
        ("\ud800", PASSWORD),
        (EMAIL, ""),
        (EMAIL, "p" * 1025),
        (EMAIL, "\ud800"),
    ],
    ids=[
        "empty-email",
        "oversized-email",
        "invalid-unicode-email",
        "empty-password",
        "oversized-password",
        "invalid-unicode-password",
    ],
)
def test_invalid_input_prevents_requests(
    settings: Settings,
    email: str,
    password: str,
) -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        raise AssertionError("No provider request should be made.")

    with pytest.raises(AccountSignInRejected) as caught:
        run_sign_in(settings, handler, email=email, password=password)

    assert str(caught.value) == "Sign-in was rejected."


@pytest.mark.parametrize(
    ("status_code", "error_code"),
    [
        (400, "invalid_credentials"),
        (400, "email_not_confirmed"),
        (403, "user_banned"),
        (422, "validation_failed"),
    ],
)
def test_known_rejection_is_generic_and_not_retried(
    settings: Settings,
    status_code: int,
    error_code: str,
) -> None:
    requests: list[httpx2.Request] = []
    response = response_for(
        {
            "error_code": error_code,
            "msg": "Synthetic private provider details",
        },
        status_code=status_code,
    )

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return response

    with pytest.raises(AccountSignInRejected) as caught:
        run_sign_in(settings, handler)

    assert str(caught.value) == "Sign-in was rejected."
    assert len(requests) == 1
    assert response.is_closed


@pytest.mark.parametrize("status_code", [302, 401, 429, 500, 503])
def test_other_failures_are_unavailable_without_retry_or_redirect(
    settings: Settings,
    status_code: int,
) -> None:
    requests: list[httpx2.Request] = []
    response = response_for(
        {
            "error_code": "unexpected_provider_error",
            "msg": "Synthetic private provider details",
        },
        status_code=status_code,
    )
    if status_code == 302:
        response.headers["Location"] = "https://other.example.test/sign-in"

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        assert str(request.url) == SIGN_IN_URL
        assert len(requests) == 1
        return response

    with pytest.raises(AccountSignInUnavailable) as caught:
        run_sign_in(settings, handler)

    assert str(caught.value) == "Account sign-in is unavailable."
    assert len(requests) == 1
    assert response.is_closed


def success_payload() -> dict[str, object]:
    return {
        "access_token": ACCESS_TOKEN,
        "refresh_token": REFRESH_TOKEN,
        "token_type": "bearer",
    }


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

    with pytest.raises(AccountSignInUnavailable):
        run_sign_in(settings, lambda request: response)

    assert response.is_closed


@pytest.mark.parametrize("field", ["access_token", "refresh_token"])
@pytest.mark.parametrize(
    "invalid_value",
    [
        None,
        123,
        "",
        "contains space",
        "line\nbreak",
        "é",
        "x" * 8193,
    ],
)
def test_invalid_returned_tokens_are_unavailable(
    settings: Settings,
    field: str,
    invalid_value: object,
) -> None:
    payload = success_payload()
    payload[field] = invalid_value
    response = response_for(payload)

    with pytest.raises(AccountSignInUnavailable):
        run_sign_in(settings, lambda request: response)

    assert response.is_closed


@pytest.mark.parametrize(
    "field",
    ["access_token", "refresh_token", "token_type"],
)
def test_missing_response_fields_are_unavailable(
    settings: Settings,
    field: str,
) -> None:
    payload = success_payload()
    del payload[field]
    response = response_for(payload)

    with pytest.raises(AccountSignInUnavailable):
        run_sign_in(settings, lambda request: response)

    assert response.is_closed


@pytest.mark.parametrize("token_type", [None, 123, "", "mac"])
def test_invalid_token_type_is_unavailable(
    settings: Settings,
    token_type: object,
) -> None:
    payload = success_payload()
    payload["token_type"] = token_type
    response = response_for(payload)

    with pytest.raises(AccountSignInUnavailable):
        run_sign_in(settings, lambda request: response)

    assert response.is_closed


@pytest.mark.parametrize("content_type", [None, "text/html"])
def test_unexpected_content_type_is_rejected(
    settings: Settings,
    content_type: str | None,
) -> None:
    response = response_for(success_payload())
    if content_type is None:
        del response.headers["Content-Type"]
    else:
        response.headers["Content-Type"] = content_type

    with pytest.raises(AccountSignInUnavailable):
        run_sign_in(settings, lambda request: response)

    assert response.is_closed


@pytest.mark.parametrize("encoding", ["gzip", "br"])
def test_compressed_responses_are_rejected(
    settings: Settings,
    encoding: str,
) -> None:
    response = response_for(success_payload())
    response.headers["Content-Encoding"] = encoding

    with pytest.raises(AccountSignInUnavailable):
        run_sign_in(settings, lambda request: response)

    assert response.is_closed


@pytest.mark.parametrize("extra_bytes", [0, 1])
def test_response_size_boundary(
    settings: Settings,
    extra_bytes: int,
) -> None:
    document = json.dumps(success_payload()).encode("utf-8")
    body = document + b" " * (64 * 1024 - len(document) + extra_bytes)
    response = raw_response(body)

    if extra_bytes:
        with pytest.raises(AccountSignInUnavailable):
            run_sign_in(settings, lambda request: response)
    else:
        result = run_sign_in(settings, lambda request: response)
        assert result.access_token.get_secret_value() == ACCESS_TOKEN

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
    response.headers["Content-Encoding"] = "identity"

    result = run_sign_in(settings, lambda request: response)

    assert result.access_token.get_secret_value() == access_token
    assert result.refresh_token.get_secret_value() == refresh_token
    assert response.is_closed


@pytest.mark.parametrize(
    "failure",
    [
        httpx2.ConnectError("Synthetic private connection error"),
        httpx2.ReadTimeout("Synthetic private read timeout"),
        httpx2.RemoteProtocolError("Synthetic private protocol error"),
    ],
    ids=["connection", "read-timeout", "protocol"],
)
def test_transport_failure_is_generic_and_not_retried(
    settings: Settings,
    failure: httpx2.HTTPError,
) -> None:
    requests: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        raise failure

    with pytest.raises(AccountSignInUnavailable) as caught:
        run_sign_in(settings, handler)

    assert str(caught.value) == "Account sign-in is unavailable."
    assert len(requests) == 1


def test_total_deadline_stops_a_stalled_request(
    settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(account_sign_in, "_SIGN_IN_TIMEOUT_SECONDS", 0.05)
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
                sign_in_with_password(
                    SecretStr(EMAIL),
                    SecretStr(PASSWORD),
                    settings=settings,
                    client=client,
                ),
                timeout=1,
            )

    with pytest.raises(AccountSignInUnavailable):
        asyncio.run(run())

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


def test_total_deadline_closes_a_stalled_response(
    settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(account_sign_in, "_SIGN_IN_TIMEOUT_SECONDS", 0.05)

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
            with pytest.raises(AccountSignInUnavailable):
                await asyncio.wait_for(
                    sign_in_with_password(
                        SecretStr(EMAIL),
                        SecretStr(PASSWORD),
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
                sign_in_with_password(
                    SecretStr(EMAIL),
                    SecretStr(PASSWORD),
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


def test_response_read_failure_closes_response_without_retry(
    settings: Settings,
) -> None:
    class BrokenStream(httpx2.AsyncByteStream):
        async def __aiter__(self) -> AsyncIterator[bytes]:
            yield b"{"
            raise httpx2.ReadError("Synthetic private response-read error")

    response = httpx2.Response(
        200,
        headers={"Content-Type": "application/json"},
        stream=BrokenStream(),
    )
    requests: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return response

    with pytest.raises(AccountSignInUnavailable) as caught:
        run_sign_in(settings, handler)

    assert str(caught.value) == "Account sign-in is unavailable."
    assert response.is_closed
    assert len(requests) == 1
