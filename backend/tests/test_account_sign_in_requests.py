"""Credential parsing through an in-memory HTTP endpoint."""

import json
from collections.abc import Iterator
from dataclasses import dataclass

import httpx2
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from app.account_sign_in_requests import SignInCredentials, read_sign_in_credentials

EMAIL = "owner@example.test"
PASSWORD = "  synthetic-password-é  "


@dataclass
class ParserHarness:
    client: TestClient
    parsed: list[SignInCredentials]


@pytest.fixture
def harness() -> Iterator[ParserHarness]:
    application = FastAPI()
    parsed: list[SignInCredentials] = []

    @application.post("/parse")
    async def parse(request: Request) -> dict[str, str]:
        credentials = await read_sign_in_credentials(request)
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
    assert EMAIL not in response.text
    assert PASSWORD not in response.text
    assert harness.parsed == []


def test_preserves_credentials_and_masks_their_representation(
    harness: ParserHarness,
) -> None:
    body = json.dumps(
        {"email": EMAIL, "password": PASSWORD},
        ensure_ascii=False,
    ).encode("utf-8")

    response = harness.client.post(
        "/parse",
        content=body,
        headers={"Content-Type": "Application/JSON; charset=utf-8"},
    )

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert len(harness.parsed) == 1

    credentials = harness.parsed[0]
    assert credentials.email.get_secret_value() == EMAIL
    assert credentials.password.get_secret_value() == PASSWORD
    assert EMAIL not in repr(credentials)
    assert PASSWORD not in repr(credentials)


@pytest.mark.parametrize(
    "content_type",
    [None, "text/plain", "application/x-www-form-urlencoded"],
    ids=["missing", "text", "form"],
)
def test_requires_json_content_type(
    harness: ParserHarness,
    content_type: str | None,
) -> None:
    headers = {} if content_type is None else {"Content-Type": content_type}
    response = harness.client.post(
        "/parse",
        content=b'{"email":"owner@example.test","password":"synthetic"}',
        headers=headers,
    )

    assert_error(
        response,
        harness,
        415,
        "Sign-in requires a JSON request.",
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

    assert_error(response, harness, 400, "Invalid sign-in request.")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("email", None),
        ("email", 123),
        ("email", ""),
        ("email", "a" * 321),
        ("password", None),
        ("password", False),
        ("password", ""),
        ("password", "p" * 1025),
    ],
    ids=[
        "null-email",
        "numeric-email",
        "empty-email",
        "long-email",
        "null-password",
        "boolean-password",
        "empty-password",
        "long-password",
    ],
)
def test_invalid_fields_do_not_echo_submitted_input(
    harness: ParserHarness,
    field: str,
    value: object,
) -> None:
    payload: dict[str, object] = {"email": EMAIL, "password": PASSWORD}
    payload[field] = value

    response = harness.client.post("/parse", json=payload)

    assert_error(response, harness, 400, "Invalid sign-in request.")


@pytest.mark.parametrize("missing", ["email", "password"])
def test_requires_both_fields(
    harness: ParserHarness,
    missing: str,
) -> None:
    payload = {"email": EMAIL, "password": PASSWORD}
    del payload[missing]

    response = harness.client.post("/parse", json=payload)

    assert_error(response, harness, 400, "Invalid sign-in request.")


def test_rejects_extra_fields(harness: ParserHarness) -> None:
    response = harness.client.post(
        "/parse",
        json={
            "email": EMAIL,
            "password": PASSWORD,
            "user_id": "untrusted-owner",
        },
    )

    assert_error(response, harness, 400, "Invalid sign-in request.")


@pytest.mark.parametrize("extra_bytes", [0, 1], ids=["at-limit", "over-limit"])
def test_body_limit_uses_actual_bytes(
    harness: ParserHarness,
    extra_bytes: int,
) -> None:
    body = json.dumps({"email": EMAIL, "password": PASSWORD}).encode("utf-8")
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
        assert_error(response, harness, 413, "Sign-in request is too large.")
    else:
        assert response.status_code == 200
        assert len(harness.parsed) == 1


@pytest.mark.parametrize("field", ["email", "password"])
def test_rejects_unpaired_unicode_surrogates(
    harness: ParserHarness,
    field: str,
) -> None:
    payload = {"email": EMAIL, "password": PASSWORD}
    payload[field] = "\ud800"

    response = harness.client.post(
        "/parse",
        content=json.dumps(payload).encode("ascii"),
        headers={"Content-Type": "application/json"},
    )

    assert_error(response, harness, 400, "Invalid sign-in request.")
