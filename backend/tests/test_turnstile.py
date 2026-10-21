"""Turnstile verification using synthetic tokens and mocked HTTP."""

import asyncio
import json
from collections.abc import AsyncIterator, Callable

import httpx2
import pytest
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict

from app.config import Settings
from app.turnstile import (
    TurnstileRejected,
    TurnstileUnavailable,
    verify_turnstile_token,
)

SECRET = "synthetic-turnstile-secret"
TOKEN = "synthetic-challenge-token"
HOSTNAME = "askm6.example.test"
ACTION = "guest_start"
SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"


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
            "database_url": None,
            "migration_database_url": None,
            "supabase_auth_issuer": None,
            "supabase_auth_publishable_key": None,
            "account_session_encryption_key": None,
            "turnstile_secret_key": SECRET,
            "turnstile_allowed_hostnames": (HOSTNAME,),
            "turnstile_timeout_seconds": 5,
        }
    )


def successful_payload() -> dict[str, object]:
    return {
        "success": True,
        "hostname": HOSTNAME,
        "action": ACTION,
        "error-codes": [],
    }


def response_for(payload: object) -> httpx2.Response:
    return httpx2.Response(
        200,
        headers={"Content-Type": "application/json; charset=utf-8"},
        stream=ResponseStream(json.dumps(payload).encode("utf-8")),
    )


def run_verification(
    settings: Settings,
    handler: Callable[[httpx2.Request], httpx2.Response],
    *,
    token: str = TOKEN,
) -> None:
    async def run() -> None:
        async with httpx2.AsyncClient(
            transport=httpx2.MockTransport(handler),
            auth=("synthetic-user", "synthetic-password"),
            follow_redirects=True,
            trust_env=False,
        ) as client:
            await verify_turnstile_token(
                SecretStr(token),
                expected_action=ACTION,
                settings=settings,
                client=client,
            )

    asyncio.run(run())


def test_success_posts_expected_fields_and_closes_response(
    settings: Settings,
) -> None:
    requests: list[httpx2.Request] = []
    response = response_for(successful_payload())

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return response

    run_verification(settings, handler)

    assert len(requests) == 1
    request = requests[0]
    assert request.method == "POST"
    assert str(request.url) == SITEVERIFY_URL
    assert json.loads(request.content) == {
        "secret": SECRET,
        "response": TOKEN,
    }
    assert request.headers["accept"] == "application/json"
    assert request.headers["accept-encoding"] == "identity"
    assert "authorization" not in request.headers
    assert response.is_closed


@pytest.mark.parametrize(
    "updates",
    [
        {"turnstile_secret_key": None},
        {"turnstile_secret_key": SecretStr("")},
        {"turnstile_allowed_hostnames": ()},
    ],
)
def test_missing_configuration_prevents_requests(
    settings: Settings,
    updates: dict[str, object],
) -> None:
    incomplete = settings.model_copy(update=updates)

    def handler(request: httpx2.Request) -> httpx2.Response:
        raise AssertionError("No provider request should be made.")

    with pytest.raises(TurnstileUnavailable, match="not configured"):
        run_verification(incomplete, handler)


@pytest.mark.parametrize(
    "token",
    ["", "t" * 2049, "token with space", "token\n", "tokén"],
)
def test_invalid_token_prevents_requests(
    settings: Settings,
    token: str,
) -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        raise AssertionError("No provider request should be made.")

    with pytest.raises(TurnstileRejected) as caught:
        run_verification(settings, handler, token=token)

    assert str(caught.value) == "Human verification was rejected."


@pytest.mark.parametrize(
    "code",
    [
        "missing-input-response",
        "invalid-input-response",
        "timeout-or-duplicate",
    ],
)
def test_rejected_challenge_is_generic_and_not_retried(
    settings: Settings,
    code: str,
) -> None:
    requests: list[httpx2.Request] = []
    response = response_for(
        {
            "success": False,
            "error-codes": [code],
            "private-details": SECRET,
        }
    )

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return response

    with pytest.raises(TurnstileRejected) as caught:
        run_verification(settings, handler)

    assert str(caught.value) == "Human verification was rejected."
    assert len(requests) == 1
    assert response.is_closed


@pytest.mark.parametrize(
    "codes",
    [
        [],
        ["invalid-input-secret"],
        ["internal-error"],
        ["unexpected-error"],
        ["invalid-input-response", "internal-error"],
        "invalid-input-response",
    ],
)
def test_provider_errors_do_not_become_challenge_rejections(
    settings: Settings,
    codes: object,
) -> None:
    response = response_for({"success": False, "error-codes": codes})

    def handler(request: httpx2.Request) -> httpx2.Response:
        return response

    with pytest.raises(TurnstileUnavailable) as caught:
        run_verification(settings, handler)

    assert str(caught.value) == "Human verification is unavailable."
    assert response.is_closed


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        {},
        {"success": "true", "hostname": HOSTNAME, "action": ACTION},
        {"success": 1, "hostname": HOSTNAME, "action": ACTION},
        {"success": True, "action": ACTION},
        {"success": True, "hostname": HOSTNAME},
        {
            "success": True,
            "hostname": HOSTNAME,
            "action": ACTION,
            "error-codes": ["internal-error"],
        },
    ],
)
def test_malformed_or_contradictory_responses_fail_closed(
    settings: Settings,
    payload: object,
) -> None:
    response = response_for(payload)

    def handler(request: httpx2.Request) -> httpx2.Response:
        return response

    with pytest.raises(TurnstileUnavailable):
        run_verification(settings, handler)

    assert response.is_closed


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("hostname", "other.example.test"),
        ("hostname", f"subdomain.{HOSTNAME}"),
        ("action", "sign_in"),
    ],
)
def test_hostname_and_action_require_exact_matches(
    settings: Settings,
    field: str,
    value: str,
) -> None:
    payload = successful_payload()
    payload[field] = value
    response = response_for(payload)

    def handler(request: httpx2.Request) -> httpx2.Response:
        return response

    with pytest.raises(TurnstileRejected):
        run_verification(settings, handler)

    assert response.is_closed


@pytest.mark.parametrize("status_code", [302, 400, 403, 429, 503])
def test_http_failure_is_not_retried_or_redirected(
    settings: Settings,
    status_code: int,
) -> None:
    requests: list[httpx2.Request] = []
    response = httpx2.Response(
        status_code,
        headers={
            "Content-Type": "application/json",
            "Location": "https://other.example.test/verify",
        },
        stream=ResponseStream(b"{}"),
    )

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return response

    with pytest.raises(TurnstileUnavailable):
        run_verification(settings, handler)

    assert len(requests) == 1
    assert str(requests[0].url) == SITEVERIFY_URL
    assert response.is_closed


@pytest.mark.parametrize(
    ("content_type", "encoding"),
    [
        ("text/html", "identity"),
        ("", "identity"),
        ("application/json", "gzip"),
        ("application/json", "br"),
    ],
)
def test_unexpected_response_format_is_unavailable(
    settings: Settings,
    content_type: str,
    encoding: str,
) -> None:
    response = httpx2.Response(
        200,
        headers={
            "Content-Type": content_type,
            "Content-Encoding": encoding,
        },
        stream=ResponseStream(json.dumps(successful_payload()).encode("utf-8")),
    )

    with pytest.raises(TurnstileUnavailable):
        run_verification(settings, lambda request: response)

    assert response.is_closed


@pytest.mark.parametrize(
    "body",
    [b"not-json", b"\xff", b"[" * 2000],
    ids=["invalid-json", "invalid-encoding", "excessive-nesting"],
)
def test_invalid_json_is_unavailable(
    settings: Settings,
    body: bytes,
) -> None:
    response = httpx2.Response(
        200,
        headers={"Content-Type": "application/json"},
        stream=ResponseStream(body),
    )

    with pytest.raises(TurnstileUnavailable):
        run_verification(settings, lambda request: response)

    assert response.is_closed


@pytest.mark.parametrize("extra_bytes", [0, 1], ids=["at-limit", "over-limit"])
def test_response_size_boundary(
    settings: Settings,
    extra_bytes: int,
) -> None:
    document = json.dumps(successful_payload()).encode("utf-8")
    body = document + b" " * (64 * 1024 - len(document) + extra_bytes)
    response = httpx2.Response(
        200,
        headers={"Content-Type": "application/json"},
        stream=ResponseStream(body),
    )

    if extra_bytes:
        with pytest.raises(TurnstileUnavailable):
            run_verification(settings, lambda request: response)
    else:
        run_verification(settings, lambda request: response)

    assert response.is_closed


@pytest.mark.parametrize(
    "failure",
    [
        httpx2.ConnectError("Synthetic private connection details"),
        httpx2.ReadTimeout("Synthetic private timeout details"),
    ],
    ids=["connection", "read-timeout"],
)
def test_transport_failure_is_generic_and_not_retried(
    settings: Settings,
    failure: httpx2.HTTPError,
) -> None:
    requests: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        raise failure

    with pytest.raises(TurnstileUnavailable) as caught:
        run_verification(settings, handler)

    assert str(caught.value) == "Human verification is unavailable."
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


@pytest.mark.parametrize("phase", ["request", "body"])
def test_total_deadline_stops_stalled_verification(
    settings: Settings,
    phase: str,
) -> None:
    bounded_settings = settings.model_copy(update={"turnstile_timeout_seconds": 1})

    async def run() -> None:
        stream = StalledResponseStream()
        response = httpx2.Response(
            200,
            headers={"Content-Type": "application/json"},
            stream=stream,
        )
        requests: list[httpx2.Request] = []

        async def handler(request: httpx2.Request) -> httpx2.Response:
            requests.append(request)
            if phase == "request":
                await asyncio.Future[None]()
                raise AssertionError("Stalled request unexpectedly resumed.")
            return response

        async with httpx2.AsyncClient(
            transport=httpx2.MockTransport(handler),
            trust_env=False,
        ) as client:
            with pytest.raises(TurnstileUnavailable):
                await asyncio.wait_for(
                    verify_turnstile_token(
                        SecretStr(TOKEN),
                        expected_action=ACTION,
                        settings=bounded_settings,
                        client=client,
                    ),
                    timeout=3,
                )

            assert len(requests) == 1
            if phase == "body":
                assert stream.started.is_set()
                assert stream.closed
                assert response.is_closed

    asyncio.run(run())


def test_caller_cancellation_propagates_and_closes_response(
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
                verify_turnstile_token(
                    SecretStr(TOKEN),
                    expected_action=ACTION,
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
