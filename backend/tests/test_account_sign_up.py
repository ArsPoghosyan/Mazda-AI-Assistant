"""Provider registration with synthetic credentials and mocked HTTP."""

import asyncio
import json
from collections.abc import AsyncIterator, Callable

import httpx2
import pytest
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict

import app.account_sign_up as account_sign_up
from app.account_sign_up import (
    AccountSignUpCaptchaRejected,
    AccountSignUpRejected,
    AccountSignUpUnavailable,
    sign_up_with_password,
)
from app.config import Settings

ISSUER = "https://auth.example.test/auth/v1"
SIGN_UP_URL = f"{ISSUER}/signup"
PUBLISHABLE_KEY = "sb_publishable_synthetic_test_key"
EMAIL = "owner@example.test"
PASSWORD = "  synthetic-password-é  "
CAPTCHA = "synthetic-captcha-proof"
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


def run_sign_up(
    settings: Settings,
    handler: Callable[[httpx2.Request], httpx2.Response],
    *,
    email: str = EMAIL,
    password: str = PASSWORD,
    captcha_token: str = CAPTCHA,
) -> None:
    async def run() -> None:
        async with httpx2.AsyncClient(
            transport=httpx2.MockTransport(handler),
            auth=("synthetic-user", "synthetic-client-password"),
            follow_redirects=True,
            trust_env=False,
        ) as client:
            await sign_up_with_password(
                SecretStr(email),
                SecretStr(password),
                SecretStr(captcha_token),
                settings=settings,
                client=client,
            )

    asyncio.run(run())


def test_forwards_exact_credentials_and_captcha_once(
    settings: Settings,
) -> None:
    requests: list[httpx2.Request] = []
    response = response_for({"id": USER_ID, "email": EMAIL})

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return response

    run_sign_up(settings, handler)

    assert len(requests) == 1
    request = requests[0]
    assert request.method == "POST"
    assert str(request.url) == SIGN_UP_URL
    assert json.loads(request.content) == {
        "email": EMAIL,
        "password": PASSWORD,
        "gotrue_meta_security": {
            "captcha_token": CAPTCHA,
        },
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

    with pytest.raises(AccountSignUpUnavailable, match="not configured"):
        run_sign_up(incomplete, handler)


@pytest.mark.parametrize(
    ("email", "password", "captcha_token"),
    [
        ("", PASSWORD, CAPTCHA),
        ("e" * 321, PASSWORD, CAPTCHA),
        ("\ud800", PASSWORD, CAPTCHA),
        (EMAIL, "", CAPTCHA),
        (EMAIL, "p" * 1025, CAPTCHA),
        (EMAIL, "\ud800", CAPTCHA),
        (EMAIL, PASSWORD, ""),
        (EMAIL, PASSWORD, "x" * 2049),
        (EMAIL, PASSWORD, "\ud800"),
    ],
)
def test_invalid_input_prevents_requests(
    settings: Settings,
    email: str,
    password: str,
    captcha_token: str,
) -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        raise AssertionError("No provider request should be made.")

    with pytest.raises(AccountSignUpRejected, match="Registration was rejected"):
        run_sign_up(
            settings,
            handler,
            email=email,
            password=password,
            captcha_token=captcha_token,
        )


@pytest.mark.parametrize("token", ["has space", "line\nbreak", "é"])
def test_invalid_captcha_characters_prevent_requests(
    settings: Settings,
    token: str,
) -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        raise AssertionError("No provider request should be made.")

    with pytest.raises(AccountSignUpCaptchaRejected):
        run_sign_up(settings, handler, captcha_token=token)


@pytest.mark.parametrize("code", ["user_already_exists", "email_exists"])
def test_existing_account_is_handled_without_retrying(
    settings: Settings,
    code: str,
) -> None:
    requests: list[httpx2.Request] = []
    response = response_for(
        {"error_code": code, "msg": "private-provider-detail"},
        status_code=422,
    )

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return response

    run_sign_up(settings, handler)

    assert len(requests) == 1
    assert response.is_closed


@pytest.mark.parametrize(
    ("code", "status_code", "exception_type", "message"),
    [
        (
            "captcha_failed",
            403,
            AccountSignUpCaptchaRejected,
            "Human verification was rejected.",
        ),
        (
            "weak_password",
            422,
            AccountSignUpRejected,
            "Registration was rejected.",
        ),
        (
            "email_address_invalid",
            400,
            AccountSignUpRejected,
            "Registration was rejected.",
        ),
    ],
)
def test_provider_rejections_remain_controlled(
    settings: Settings,
    code: str,
    status_code: int,
    exception_type: type[AccountSignUpRejected],
    message: str,
) -> None:
    requests: list[httpx2.Request] = []
    response = response_for(
        {"error_code": code, "msg": "private-provider-detail"},
        status_code=status_code,
    )

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return response

    with pytest.raises(exception_type) as caught:
        run_sign_up(settings, handler)

    assert type(caught.value) is exception_type
    assert str(caught.value) == message
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
        {"error_code": "user_already_exists", "msg": "private-provider-detail"},
        status_code=status_code,
    )

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return response

    with pytest.raises(AccountSignUpUnavailable) as caught:
        run_sign_up(settings, handler)

    assert str(caught.value) == "Account registration is unavailable."
    assert "private-provider-detail" not in repr(caught.value)
    assert len(requests) == 1
    assert response.is_closed


@pytest.mark.parametrize("status_code", [302, 307, 308])
def test_redirects_are_rejected_without_forwarding_credentials(
    settings: Settings,
    status_code: int,
) -> None:
    requests: list[httpx2.Request] = []
    response = raw_response(b"", status_code=status_code)
    response.headers["Location"] = "https://other.example.test/collect"

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        assert str(request.url) == SIGN_UP_URL
        return response

    with pytest.raises(AccountSignUpUnavailable):
        run_sign_up(settings, handler)

    assert len(requests) == 1
    assert response.is_closed


@pytest.mark.parametrize("content_type", [None, "text/html", "text/plain"])
def test_requires_a_json_provider_response(
    settings: Settings,
    content_type: str | None,
) -> None:
    response = response_for({"id": USER_ID})

    if content_type is None:
        del response.headers["Content-Type"]
    else:
        response.headers["Content-Type"] = content_type

    with pytest.raises(AccountSignUpUnavailable):
        run_sign_up(settings, lambda request: response)

    assert response.is_closed


@pytest.mark.parametrize("encoding", ["gzip", "br"])
def test_compressed_responses_are_rejected(
    settings: Settings,
    encoding: str,
) -> None:
    response = response_for({"id": USER_ID})
    response.headers["Content-Encoding"] = encoding

    with pytest.raises(AccountSignUpUnavailable):
        run_sign_up(settings, lambda request: response)

    assert response.is_closed


@pytest.mark.parametrize(
    "body",
    [b"", b"private-provider-detail", b"\xff", b"[]", b"{}"],
    ids=["empty", "malformed-json", "invalid-utf8", "array", "missing-user"],
)
def test_invalid_response_bodies_remain_generic(
    settings: Settings,
    body: bytes,
) -> None:
    response = raw_response(body)

    with pytest.raises(AccountSignUpUnavailable) as caught:
        run_sign_up(settings, lambda request: response)

    assert str(caught.value) == "Account registration is unavailable."
    assert "private-provider-detail" not in repr(caught.value)
    assert response.is_closed


@pytest.mark.parametrize("extra_bytes", [0, 1], ids=["at-limit", "over-limit"])
def test_response_limit_counts_actual_bytes(
    settings: Settings,
    extra_bytes: int,
) -> None:
    document = json.dumps({"id": USER_ID}).encode("utf-8")
    body = document + b" " * (64 * 1024 + extra_bytes - len(document))
    response = raw_response(body)
    response.headers["Content-Length"] = "1"

    if extra_bytes:
        with pytest.raises(AccountSignUpUnavailable):
            run_sign_up(settings, lambda request: response)
    else:
        run_sign_up(settings, lambda request: response)

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

    with pytest.raises(AccountSignUpUnavailable) as caught:
        run_sign_up(settings, handler)

    assert str(caught.value) == "Account registration is unavailable."
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
    monkeypatch.setattr(account_sign_up, "_SIGN_UP_TIMEOUT_SECONDS", 0.05)
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
                sign_up_with_password(
                    SecretStr(EMAIL),
                    SecretStr(PASSWORD),
                    SecretStr(CAPTCHA),
                    settings=settings,
                    client=client,
                ),
                timeout=1,
            )

    with pytest.raises(AccountSignUpUnavailable):
        asyncio.run(run())

    assert len(requests) == 1


def test_total_deadline_closes_a_stalled_response(
    settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(account_sign_up, "_SIGN_UP_TIMEOUT_SECONDS", 0.05)

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
            with pytest.raises(AccountSignUpUnavailable):
                await asyncio.wait_for(
                    sign_up_with_password(
                        SecretStr(EMAIL),
                        SecretStr(PASSWORD),
                        SecretStr(CAPTCHA),
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
                sign_up_with_password(
                    SecretStr(EMAIL),
                    SecretStr(PASSWORD),
                    SecretStr(CAPTCHA),
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

    with pytest.raises(AccountSignUpUnavailable) as caught:
        run_sign_up(settings, handler)

    assert str(caught.value) == "Account registration is unavailable."
    assert "private-response-read-detail" not in repr(caught.value)
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
            document = json.dumps({"id": USER_ID}).encode("utf-8")
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

    with pytest.raises(AccountSignUpUnavailable):
        run_sign_up(settings, lambda request: response)

    assert stream.chunks_read == 2
    assert stream.closed
    assert response.is_closed
