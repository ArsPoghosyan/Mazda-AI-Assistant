"""Bounded callback queries preserve opaque codes and reject ambiguous input."""

from dataclasses import dataclass
from unittest.mock import AsyncMock, Mock
from urllib.parse import quote

import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient
from pydantic import SecretStr

import app.account_google_requests as parsing
from app.account_google_requests import read_google_callback_code


def make_request(query: bytes) -> Request:
    return Request(
        {"type": "http", "method": "GET", "path": "/callback", "query_string": query, "headers": []}
    )


def assert_rejected(query: bytes) -> HTTPException:
    with pytest.raises(HTTPException) as caught:
        read_google_callback_code(make_request(query))
    error = caught.value
    assert error.status_code == 400
    assert error.detail == "Google sign-in was rejected."
    assert error.headers == {"Cache-Control": "no-store"}
    assert "synthetic-private" not in str(error)
    return error


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        (b"code=x", "x"),
        (b"code=" + b"a" * 1024, "a" * 1024),
        (b"code=synthetic-private", "synthetic-private"),
        (b"code=a_-.~", "a_-.~"),
        (b"code=a%2Bb%2Fc%3D", "a+b/c="),
        (b"code=a%2bb%2fc%3d", "a+b/c="),
        (b"code=a%26b%3Dc", "a&b=c"),
        (b"code=%2520", "%20"),
        (b"code=%25", "%"),
        (b"code=a;b=c", "a;b=c"),
        (b"%63%6F%64%65=opaque", "opaque"),
    ],
)
def test_accepts_one_code_with_exactly_one_url_decoding(query: bytes, expected: str) -> None:
    request = make_request(query)
    result = read_google_callback_code(request)
    assert isinstance(result, SecretStr)
    assert result.get_secret_value() == expected
    assert request.scope["query_string"] == query


@pytest.mark.parametrize(
    "query",
    [
        b"",
        b"code",
        b"code=",
        b"=synthetic-private",
        b"other=synthetic-private",
        b"Code=synthetic-private",
        b"code[]=synthetic-private",
        b"code=first&code=second",
        b"code=same&code=same",
        b"code=first&%63ode=second",
        b"code=first&code=",
        b"code=first&",
        b"&code=first",
        b"code=first&&",
        b"error=access_denied",
        b"error_description=synthetic-private",
        b"code=synthetic-private&error=access_denied",
        b"error=access_denied&code=synthetic-private",
        b"code=synthetic-private&next=https%3A%2F%2Funtrusted.example",
        b"code=synthetic-private&state=untrusted",
        b"code=synthetic-private&user_id=untrusted",
    ],
)
def test_missing_duplicate_error_and_extra_fields_are_rejected(query: bytes) -> None:
    assert_rejected(query)


@pytest.mark.parametrize(
    "query",
    [
        b"code=%",
        b"code=%0",
        b"code=%GG",
        b"code=%2G",
        b"code=%G2",
        b"co%de=synthetic-private",
    ],
)
def test_malformed_percent_encoding_is_rejected(query: bytes) -> None:
    assert_rejected(query)


@pytest.mark.parametrize(
    "encoded",
    [
        b"%00",
        b"%09",
        b"%0A",
        b"%0D",
        b"%20",
        b"+",
        b"%7F",
        b"%FF",
        b"%C3%A9",
    ],
)
def test_decoded_whitespace_control_and_non_ascii_codes_are_rejected(encoded: bytes) -> None:
    assert_rejected(b"code=synthetic-private" + encoded)


@pytest.mark.parametrize("raw", [b" ", b"\t", b"\r", b"\n", b"\x00", b"\x7f", b"\xff"])
def test_raw_non_visible_query_bytes_are_rejected(raw: bytes) -> None:
    assert_rejected(b"code=synthetic-private" + raw)


@pytest.mark.parametrize("encoded", [False, True], ids=["raw", "percent-encoded"])
def test_decoded_code_length_cannot_exceed_1024(encoded: bool) -> None:
    assert_rejected(b"code=" + (b"%61" if encoded else b"a") * 1025)


def test_fully_encoded_maximum_code_is_accepted_without_truncation() -> None:
    query = b"%63%6F%64%65=" + b"%61" * 1024
    result = read_google_callback_code(make_request(query))
    assert result.get_secret_value() == "a" * 1024


def test_query_over_4096_bytes_is_rejected_before_url_parsing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parse = Mock(side_effect=AssertionError("Oversized input reached URL parsing."))
    monkeypatch.setattr(parsing, "parse_qsl", parse)
    query = b"code=" + b"a" * (4097 - len(b"code="))
    assert_rejected(query)
    parse.assert_not_called()


@pytest.mark.parametrize("value", [None, "code=synthetic-private", bytearray(b"code=x")])
def test_non_byte_query_scope_is_rejected(value: object) -> None:
    request = make_request(b"code=synthetic-private")
    request.scope["query_string"] = value
    with pytest.raises(HTTPException) as caught:
        read_google_callback_code(request)
    assert caught.value.status_code == 400
    assert caught.value.detail == "Google sign-in was rejected."


def test_missing_query_scope_is_rejected() -> None:
    request = make_request(b"code=synthetic-private")
    del request.scope["query_string"]
    with pytest.raises(HTTPException) as caught:
        read_google_callback_code(request)
    assert caught.value.status_code == 400


def test_credential_representations_are_masked() -> None:
    result = read_google_callback_code(make_request(b"code=synthetic-private-code"))
    assert result.get_secret_value() == "synthetic-private-code"
    assert "synthetic-private-code" not in repr(result)
    assert "synthetic-private-code" not in str(result)


@dataclass
class ParserHarness:
    client: TestClient
    complete: AsyncMock


@pytest.fixture
def harness() -> ParserHarness:
    application = FastAPI()
    complete = AsyncMock()

    @application.get("/callback")
    async def parse_callback(request: Request) -> dict[str, str]:
        code = read_google_callback_code(request)
        await complete(code)
        return {"status": "parsed"}

    return ParserHarness(TestClient(application), complete)


def test_valid_request_passes_only_the_masked_code_to_downstream(harness: ParserHarness) -> None:
    code = "synthetic-private+code/="
    response = harness.client.get("/callback?code=" + quote(code, safe=""))
    assert response.status_code == 200
    assert response.json() == {"status": "parsed"}
    assert code not in response.text
    assert "set-cookie" not in response.headers
    harness.complete.assert_awaited_once_with(SecretStr(code))


@pytest.mark.parametrize(
    "query",
    [
        "code=synthetic-private&code=other",
        "error=access_denied&error_description=synthetic-private",
        "code=synthetic-private&error_code=provider-error",
        "code=synthetic-private%00",
    ],
)
def test_rejection_is_generic_uncacheable_and_stops_downstream(
    harness: ParserHarness,
    query: str,
) -> None:
    response = harness.client.get("/callback?" + query)
    assert response.status_code == 400
    assert response.json() == {"detail": "Google sign-in was rejected."}
    assert response.headers["Cache-Control"] == "no-store"
    assert "set-cookie" not in response.headers
    assert "synthetic-private" not in response.text
    assert "provider-error" not in response.text
    harness.complete.assert_not_awaited()
