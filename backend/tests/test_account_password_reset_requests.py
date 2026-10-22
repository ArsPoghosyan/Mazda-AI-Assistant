"""Password-reset parsing without provider requests or password changes."""

import asyncio
import json
from collections.abc import Iterator
from dataclasses import dataclass

import httpx2
import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient
from starlette.types import Message

from app.account_password_reset_requests import (
    PasswordResetCredentials,
    read_password_reset_credentials,
)

EMAIL = "Owner+é@example.test"
CODE = "001234"
PASSWORD = "  synthetic-new-password-é  "


def valid_payload() -> dict[str, object]:
    return {
        "email": EMAIL,
        "code": CODE,
        "new_password": PASSWORD,
    }


@dataclass
class ParserHarness:
    client: TestClient
    parsed: list[PasswordResetCredentials]


@pytest.fixture
def harness() -> Iterator[ParserHarness]:
    application = FastAPI()
    parsed: list[PasswordResetCredentials] = []

    @application.post("/parse")
    async def parse(request: Request) -> dict[str, str]:
        credentials = await read_password_reset_credentials(request)
        parsed.append(credentials)
        return {"status": "ok"}

    with TestClient(application) as client:
        yield ParserHarness(client, parsed)


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

    for secret in (EMAIL, CODE, PASSWORD):
        assert secret not in response.text


def test_preserves_values_and_masks_credentials(harness: ParserHarness) -> None:
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
    assert credentials.code.get_secret_value() == CODE
    assert credentials.new_password.get_secret_value() == PASSWORD

    for secret in (EMAIL, CODE, PASSWORD):
        assert secret not in repr(credentials)
        assert secret not in credentials.model_dump_json()
        assert secret not in response.text


@pytest.mark.parametrize(
    "content_type",
    [None, "text/plain", "application/x-www-form-urlencoded"],
)
def test_requires_json(
    harness: ParserHarness,
    content_type: str | None,
) -> None:
    headers = {} if content_type is None else {"Content-Type": content_type}
    response = harness.client.post(
        "/parse",
        content=json.dumps(valid_payload()).encode("ascii"),
        headers=headers,
    )

    assert_error(response, harness, 415, "Password reset requires a JSON request.")


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

    assert_error(response, harness, 400, "Invalid password reset request.")


@pytest.mark.parametrize("missing", ["email", "code", "new_password"])
def test_requires_each_field(harness: ParserHarness, missing: str) -> None:
    payload = valid_payload()
    del payload[missing]

    response = harness.client.post("/parse", json=payload)

    assert_error(response, harness, 400, "Invalid password reset request.")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("email", None),
        ("email", 123),
        ("email", ""),
        ("email", "e" * 321),
        ("new_password", None),
        ("new_password", 123),
        ("new_password", ""),
        ("new_password", "p" * 1025),
        ("code", None),
        ("code", 123),
        ("code", ""),
        ("code", "12345"),
        ("code", "12345678901"),
        ("code", "12a456"),
        ("code", "１２３４５６"),
        ("code", "12 456"),
        ("code", "12345\n"),
    ],
)
def test_rejects_invalid_fields(
    harness: ParserHarness,
    field: str,
    value: object,
) -> None:
    payload = valid_payload()
    payload[field] = value

    response = harness.client.post("/parse", json=payload)

    assert_error(response, harness, 400, "Invalid password reset request.")


@pytest.mark.parametrize(
    "field",
    ["user_id", "access_token", "refresh_token", "redirect_to", "type"],
)
def test_rejects_client_supplied_authorization_fields(
    harness: ParserHarness,
    field: str,
) -> None:
    payload = valid_payload()
    payload[field] = "untrusted-value"

    response = harness.client.post("/parse", json=payload)

    assert_error(response, harness, 400, "Invalid password reset request.")


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
        assert_error(response, harness, 413, "Password reset request is too large.")
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
        asyncio.run(read_password_reset_credentials(request))

    assert caught.value.status_code == 413
    assert caught.value.detail == "Password reset request is too large."
    assert caught.value.headers == {"Cache-Control": "no-store"}
    assert messages == []


@pytest.mark.parametrize("field", ["email", "new_password"])
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

    assert_error(response, harness, 400, "Invalid password reset request.")


def test_accepts_structural_maximum_lengths(harness: ParserHarness) -> None:
    response = harness.client.post(
        "/parse",
        json={
            "email": "a" * 307 + "@example.test",
            "code": "0012345678",
            "new_password": "p" * 1024,
        },
    )

    assert response.status_code == 200
    assert len(harness.parsed) == 1

    credentials = harness.parsed[0]
    assert len(credentials.email.get_secret_value()) == 320
    assert credentials.code.get_secret_value() == "0012345678"
    assert len(credentials.new_password.get_secret_value()) == 1024
