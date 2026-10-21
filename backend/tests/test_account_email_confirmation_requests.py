"""Email-confirmation parsing through an in-memory test endpoint."""

import json
from collections.abc import Iterator
from dataclasses import dataclass

import httpx2
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from app.account_email_confirmation_requests import (
    EmailConfirmationCredentials,
    read_email_confirmation_credentials,
)

EMAIL = "owner@example.test"
CODE = "001234"


def valid_payload() -> dict[str, object]:
    return {"email": EMAIL, "code": CODE}


@dataclass
class ParserHarness:
    client: TestClient
    parsed: list[EmailConfirmationCredentials]


@pytest.fixture
def harness() -> Iterator[ParserHarness]:
    application = FastAPI()
    parsed: list[EmailConfirmationCredentials] = []

    @application.post("/parse")
    async def parse(request: Request) -> dict[str, str]:
        credentials = await read_email_confirmation_credentials(request)
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

    for secret in (EMAIL, CODE):
        assert secret not in response.text


@pytest.mark.parametrize("length", [6, 7, 8, 9, 10])
def test_preserves_leading_zeros_and_masks_credentials(
    harness: ParserHarness,
    length: int,
) -> None:
    code = "0" * (length - 1) + "1"

    response = harness.client.post(
        "/parse",
        content=json.dumps({"email": EMAIL, "code": code}).encode("utf-8"),
        headers={"Content-Type": "Application/JSON; charset=utf-8"},
    )

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert "set-cookie" not in response.headers
    assert len(harness.parsed) == 1

    credentials = harness.parsed[0]
    assert credentials.email.get_secret_value() == EMAIL
    assert credentials.code.get_secret_value() == code

    for secret in (EMAIL, code):
        assert secret not in repr(credentials)
        assert secret not in credentials.model_dump_json()
        assert secret not in response.text


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("email", None),
        ("email", 123),
        ("email", ""),
        ("email", "e" * 321),
        ("email", "\ud800"),
        ("code", None),
        ("code", 123456),
        ("code", True),
        ("code", ""),
        ("code", "12345"),
        ("code", "1" * 11),
        ("code", "123 56"),
        ("code", "12345\n"),
        ("code", "abc123"),
        ("code", "１２３４５６"),
        ("code", "\ud800"),
    ],
)
def test_invalid_fields_return_generic_errors(
    harness: ParserHarness,
    field: str,
    value: object,
) -> None:
    payload = valid_payload()
    payload[field] = value

    response = harness.client.post(
        "/parse",
        content=json.dumps(payload).encode("ascii"),
        headers={"Content-Type": "application/json"},
    )

    assert_error(response, harness, 400, "Invalid email confirmation request.")


@pytest.mark.parametrize("missing", ["email", "code"])
def test_requires_both_fields(
    harness: ParserHarness,
    missing: str,
) -> None:
    payload = valid_payload()
    del payload[missing]

    response = harness.client.post("/parse", json=payload)

    assert_error(response, harness, 400, "Invalid email confirmation request.")


@pytest.mark.parametrize("field", ["type", "token_hash", "user_id", "password"])
def test_rejects_extra_fields(
    harness: ParserHarness,
    field: str,
) -> None:
    payload = valid_payload()
    payload[field] = "untrusted-value"

    response = harness.client.post("/parse", json=payload)

    assert_error(response, harness, 400, "Invalid email confirmation request.")


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
        "Email confirmation requires a JSON request.",
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

    assert_error(response, harness, 400, "Invalid email confirmation request.")


@pytest.mark.parametrize("extra_bytes", [0, 1], ids=["at-limit", "over-limit"])
def test_body_limit_uses_actual_bytes(
    harness: ParserHarness,
    extra_bytes: int,
) -> None:
    payload = {"email": "ownér@example.test", "code": CODE}
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    body += b" " * (4 * 1024 + extra_bytes - len(body))

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
            "Email confirmation request is too large.",
        )
    else:
        assert response.status_code == 200
        assert len(harness.parsed) == 1
        assert harness.parsed[0].email.get_secret_value() == payload["email"]


def test_accepts_maximum_email_length(harness: ParserHarness) -> None:
    email = "a" * 307 + "@example.test"

    response = harness.client.post(
        "/parse",
        json={"email": email, "code": CODE},
    )

    assert response.status_code == 200
    assert len(harness.parsed) == 1
    assert harness.parsed[0].email.get_secret_value() == email
