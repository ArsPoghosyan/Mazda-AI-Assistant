"""Guest challenge parsing without database or provider access."""

import asyncio
import json
from collections.abc import Iterator
from dataclasses import dataclass

import httpx2
import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient
from pydantic import SecretStr
from starlette.types import Message, Scope

from app.guest_session_requests import read_guest_challenge

TOKEN = "synthetic-turnstile-challenge"


@dataclass
class ParserHarness:
    client: TestClient
    parsed: list[SecretStr | None]


@pytest.fixture
def harness() -> Iterator[ParserHarness]:
    application = FastAPI()
    parsed: list[SecretStr | None] = []

    @application.post("/parse")
    async def parse(request: Request) -> dict[str, str]:
        token = await read_guest_challenge(request)
        parsed.append(token)
        return {"status": "ok"}

    with TestClient(application) as client:
        yield ParserHarness(client=client, parsed=parsed)


def assert_error(
    response: httpx2.Response,
    harness: ParserHarness,
    status_code: int,
    detail: str,
) -> None:
    assert response.status_code == status_code
    assert response.json() == {"detail": detail}
    assert response.headers["Cache-Control"] == "no-store"
    assert "set-cookie" not in response.headers
    assert TOKEN not in response.text
    assert harness.parsed == []


@pytest.mark.parametrize("token", [TOKEN, "t" * 2048])
def test_preserves_token_and_masks_its_representation(
    harness: ParserHarness,
    token: str,
) -> None:
    response = harness.client.post(
        "/parse",
        content=json.dumps({"turnstile_token": token}).encode("utf-8"),
        headers={"Content-Type": "Application/JSON; charset=utf-8"},
    )

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert len(harness.parsed) == 1

    parsed = harness.parsed[0]
    assert parsed is not None
    assert parsed.get_secret_value() == token
    assert token not in repr(parsed)
    assert token not in response.text


@pytest.mark.parametrize(
    ("body", "content_type"),
    [
        (b"", None),
        (b"", "application/json"),
        (b"{}", "application/json"),
        (b'{"turnstile_token":null}', "application/json"),
    ],
    ids=["empty", "empty-json-body", "empty-object", "null-token"],
)
def test_absent_challenge_returns_none(
    harness: ParserHarness,
    body: bytes,
    content_type: str | None,
) -> None:
    headers = {} if content_type is None else {"Content-Type": content_type}

    response = harness.client.post(
        "/parse",
        content=body,
        headers=headers,
    )

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert harness.parsed == [None]


@pytest.mark.parametrize(
    "content_type",
    [None, "text/plain", "application/x-www-form-urlencoded"],
    ids=["missing", "text", "form"],
)
def test_nonempty_body_requires_json(
    harness: ParserHarness,
    content_type: str | None,
) -> None:
    headers = {} if content_type is None else {"Content-Type": content_type}

    response = harness.client.post(
        "/parse",
        content=json.dumps({"turnstile_token": TOKEN}).encode("utf-8"),
        headers=headers,
    )

    assert_error(
        response,
        harness,
        415,
        "Guest-session input requires JSON.",
    )


@pytest.mark.parametrize(
    "body",
    [
        b" ",
        b"not-json",
        b"\xff",
        b"null",
        b"[]",
        b'"text"',
        b"[" * 2000,
    ],
    ids=[
        "whitespace",
        "malformed",
        "invalid-utf8",
        "null-document",
        "array",
        "string",
        "excessive-nesting",
    ],
)
def test_invalid_documents_return_generic_errors(
    harness: ParserHarness,
    body: bytes,
) -> None:
    response = harness.client.post(
        "/parse",
        content=body,
        headers={"Content-Type": "application/json"},
    )

    assert_error(response, harness, 400, "Invalid guest-session request.")


@pytest.mark.parametrize(
    "value",
    [False, 123, [], {}, "", "t" * 2049, "\ud800"],
    ids=[
        "boolean",
        "number",
        "array",
        "object",
        "empty-string",
        "oversized-token",
        "unpaired-surrogate",
    ],
)
def test_invalid_token_fields_are_rejected(
    harness: ParserHarness,
    value: object,
) -> None:
    body = json.dumps({"turnstile_token": value}).encode("ascii")

    response = harness.client.post(
        "/parse",
        content=body,
        headers={"Content-Type": "application/json"},
    )

    assert_error(response, harness, 400, "Invalid guest-session request.")


def test_extra_fields_are_rejected(harness: ParserHarness) -> None:
    response = harness.client.post(
        "/parse",
        json={
            "turnstile_token": TOKEN,
            "guest_session_id": "untrusted-owner",
        },
    )

    assert_error(response, harness, 400, "Invalid guest-session request.")


@pytest.mark.parametrize("extra_bytes", [0, 1], ids=["at-limit", "over-limit"])
def test_streamed_body_limit_uses_actual_bytes(extra_bytes: int) -> None:
    document = json.dumps({"turnstile_token": TOKEN}).encode("utf-8")
    body = document + b" " * (16 * 1024 + extra_bytes - len(document))

    async def run() -> None:
        scope: Scope = {
            "type": "http",
            "method": "POST",
            "path": "/parse",
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", b"1"),
            ],
        }
        messages: list[Message] = [
            {
                "type": "http.request",
                "body": body[:8192],
                "more_body": True,
            },
            {
                "type": "http.request",
                "body": body[8192:],
                "more_body": False,
            },
        ]
        pending = iter(messages)
        received = 0

        async def receive() -> Message:
            nonlocal received
            received += 1
            return next(pending)

        request = Request(scope, receive=receive)

        if extra_bytes:
            with pytest.raises(HTTPException) as caught:
                await read_guest_challenge(request)

            assert caught.value.status_code == 413
            assert caught.value.detail == "Guest-session request is too large."
            assert caught.value.headers == {"Cache-Control": "no-store"}
        else:
            parsed = await read_guest_challenge(request)
            assert parsed is not None
            assert parsed.get_secret_value() == TOKEN

        assert received == 2

    asyncio.run(run())
