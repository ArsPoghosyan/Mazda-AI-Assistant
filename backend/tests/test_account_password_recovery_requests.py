"""Password-recovery parsing through an in-memory test endpoint."""

import asyncio
import json
from collections.abc import Iterator
from dataclasses import dataclass

import httpx2
import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient
from starlette.types import Message

from app.account_password_recovery_requests import (
    PasswordRecoveryCredentials,
    read_password_recovery_credentials,
)

EMAIL = "Owner+é@example.test"
CAPTCHA = "synthetic-captcha-proof"


def valid_payload() -> dict[str, object]:
    return {
        "email": EMAIL,
        "captcha_token": CAPTCHA,
    }


@dataclass
class ParserHarness:
    client: TestClient
    parsed: list[PasswordRecoveryCredentials]


@pytest.fixture
def harness() -> Iterator[ParserHarness]:
    application = FastAPI()
    parsed: list[PasswordRecoveryCredentials] = []

    @application.post("/parse")
    async def parse(request: Request) -> dict[str, str]:
        credentials = await read_password_recovery_credentials(request)
        parsed.append(credentials)
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
    assert harness.parsed == []

    for secret in (EMAIL, CAPTCHA):
        assert secret not in response.text


def test_preserves_credentials_and_masks_their_representation(
    harness: ParserHarness,
) -> None:
    response = harness.client.post(
        "/parse",
        content=json.dumps(valid_payload(), ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "Application/JSON; charset=utf-8"},
    )

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert len(harness.parsed) == 1

    credentials = harness.parsed[0]
    assert credentials.email.get_secret_value() == EMAIL
    assert credentials.captcha_token.get_secret_value() == CAPTCHA

    for secret in (EMAIL, CAPTCHA):
        assert secret not in repr(credentials)
        assert secret not in credentials.model_dump_json()
        assert secret not in response.text


@pytest.mark.parametrize(
    "content_type",
    [None, "text/plain", "application/x-www-form-urlencoded"],
)
def test_requires_json_content_type(
    harness: ParserHarness,
    content_type: str | None,
) -> None:
    headers = {} if content_type is None else {"Content-Type": content_type}

    response = harness.client.post(
        "/parse",
        content=json.dumps(valid_payload()).encode("ascii"),
        headers=headers,
    )

    assert_error(
        response,
        harness,
        415,
        "Password recovery requires a JSON request.",
    )


@pytest.mark.parametrize(
    "body",
    [b"", b"not-json", b"\xff", b"null", b"[]", b"{}"],
    ids=["empty", "malformed", "invalid-utf8", "null", "array", "empty-object"],
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

    assert_error(response, harness, 400, "Invalid password recovery request.")


@pytest.mark.parametrize("missing", ["email", "captcha_token"])
def test_requires_both_fields(
    harness: ParserHarness,
    missing: str,
) -> None:
    payload = valid_payload()
    del payload[missing]

    response = harness.client.post("/parse", json=payload)

    assert_error(response, harness, 400, "Invalid password recovery request.")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("email", None),
        ("email", 123),
        ("email", ""),
        ("email", "e" * 321),
        ("captcha_token", None),
        ("captcha_token", 123),
        ("captcha_token", ""),
        ("captcha_token", "x" * 2049),
        ("captcha_token", "has space"),
        ("captcha_token", "line\nbreak"),
        ("captcha_token", "é"),
    ],
)
def test_rejects_invalid_fields_without_exposing_credentials(
    harness: ParserHarness,
    field: str,
    value: object,
) -> None:
    payload = valid_payload()
    payload[field] = value

    response = harness.client.post("/parse", json=payload)

    assert_error(response, harness, 400, "Invalid password recovery request.")


@pytest.mark.parametrize(
    "field",
    ["user_id", "role", "password", "redirect_to", "code"],
)
def test_rejects_extra_fields(
    harness: ParserHarness,
    field: str,
) -> None:
    payload = valid_payload()
    payload[field] = "untrusted-value"

    response = harness.client.post("/parse", json=payload)

    assert_error(response, harness, 400, "Invalid password recovery request.")


@pytest.mark.parametrize("extra_bytes", [0, 1], ids=["at-limit", "over-limit"])
def test_body_limit_uses_actual_bytes(
    harness: ParserHarness,
    extra_bytes: int,
) -> None:
    body = json.dumps(valid_payload(), ensure_ascii=False).encode("utf-8")
    body += b" " * (16 * 1024 + extra_bytes - len(body))

    response = harness.client.post(
        "/parse",
        content=body,
        headers={
            "Content-Type": "application/json",
            "Content-Length": "1",
        },
    )

    if extra_bytes:
        assert_error(
            response,
            harness,
            413,
            "Password recovery request is too large.",
        )
    else:
        assert response.status_code == 200
        assert len(harness.parsed) == 1


def test_body_limit_accumulates_stream_chunks() -> None:
    messages: list[Message] = [
        {
            "type": "http.request",
            "body": b" " * (9 * 1024),
            "more_body": True,
        },
        {
            "type": "http.request",
            "body": b" " * (9 * 1024),
            "more_body": False,
        },
    ]

    async def receive() -> Message:
        return messages.pop(0)

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/parse",
            "headers": [(b"content-type", b"application/json")],
        },
        receive=receive,
    )

    with pytest.raises(HTTPException) as caught:
        asyncio.run(read_password_recovery_credentials(request))

    assert caught.value.status_code == 413
    assert caught.value.detail == "Password recovery request is too large."
    assert caught.value.headers == {"Cache-Control": "no-store"}
    assert messages == []


@pytest.mark.parametrize("field", ["email", "captcha_token"])
def test_rejects_unpaired_unicode_surrogates(
    harness: ParserHarness,
    field: str,
) -> None:
    payload = valid_payload()
    payload[field] = "\ud800"

    response = harness.client.post(
        "/parse",
        content=json.dumps(payload).encode("ascii"),
        headers={"Content-Type": "application/json"},
    )

    assert_error(response, harness, 400, "Invalid password recovery request.")


def test_accepts_structurally_valid_maximum_field_lengths(
    harness: ParserHarness,
) -> None:
    response = harness.client.post(
        "/parse",
        json={
            "email": "a" * 307 + "@example.test",
            "captcha_token": "x" * 2048,
        },
    )

    assert response.status_code == 200
    assert len(harness.parsed) == 1
    assert len(harness.parsed[0].email.get_secret_value()) == 320
    assert len(harness.parsed[0].captcha_token.get_secret_value()) == 2048
