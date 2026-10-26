"""Explicit, current-version acceptance without trusting identity or client time."""

import asyncio
import json

import pytest
from fastapi import HTTPException, Request

from app.account_terms_requests import CURRENT_TERMS_VERSION, read_terms_acceptance


def request(body: bytes, content_type: str = "application/json", query: bytes = b"") -> Request:
    async def receive() -> dict[str, object]:
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(
        {
            "type": "http",
            "headers": [(b"content-type", content_type.encode())],
            "query_string": query,
        },
        receive,
    )


def test_explicit_current_acceptance_is_valid() -> None:
    result = asyncio.run(
        read_terms_acceptance(
            request(
                json.dumps(
                    {
                        "accepted": True,
                        "terms_version": CURRENT_TERMS_VERSION,
                    }
                ).encode(),
                "application/json; charset=utf-8",
            )
        )
    )
    assert result.accepted is True
    assert result.terms_version == CURRENT_TERMS_VERSION


@pytest.mark.parametrize("accepted", [False, None, 0, 1, "true", "yes", [], {}])
def test_truthy_values_and_non_acceptance_are_rejected(accepted: object) -> None:
    with pytest.raises(HTTPException) as caught:
        asyncio.run(
            read_terms_acceptance(
                request(
                    json.dumps(
                        {
                            "accepted": accepted,
                            "terms_version": CURRENT_TERMS_VERSION,
                        }
                    ).encode()
                )
            )
        )
    assert caught.value.status_code == 400
    assert caught.value.headers == {"Cache-Control": "no-store"}


@pytest.mark.parametrize("version", ["", "2020-01-01", "2099-01-01", " 2026-10-26", None, 1])
def test_only_the_exact_current_revision_is_accepted(version: object) -> None:
    with pytest.raises(HTTPException) as caught:
        asyncio.run(
            read_terms_acceptance(
                request(
                    json.dumps(
                        {
                            "accepted": True,
                            "terms_version": version,
                        }
                    ).encode()
                )
            )
        )
    assert caught.value.status_code == 400


@pytest.mark.parametrize("extra", ["user_id", "accepted_at", "privacy_consent", "ip_address"])
def test_client_identity_time_and_unrelated_consent_are_forbidden(extra: str) -> None:
    with pytest.raises(HTTPException) as caught:
        asyncio.run(
            read_terms_acceptance(
                request(
                    json.dumps(
                        {
                            "accepted": True,
                            "terms_version": CURRENT_TERMS_VERSION,
                            extra: "private-detail",
                        }
                    ).encode()
                )
            )
        )
    assert caught.value.status_code == 400
    assert "private-detail" not in str(caught.value.detail)


@pytest.mark.parametrize("body", [b"", b"{", b"[]", b"null", b"{}", b"\xff"])
def test_malformed_or_incomplete_json_is_rejected(body: bytes) -> None:
    with pytest.raises(HTTPException) as caught:
        asyncio.run(read_terms_acceptance(request(body)))
    assert caught.value.status_code == 400


def test_limit_counts_actual_bytes_without_content_length() -> None:
    with pytest.raises(HTTPException) as caught:
        asyncio.run(read_terms_acceptance(request(b" " * 1025)))
    assert caught.value.status_code == 413


def test_non_json_is_rejected() -> None:
    with pytest.raises(HTTPException) as caught:
        asyncio.run(read_terms_acceptance(request(b"{}", "text/plain")))
    assert caught.value.status_code == 415


def test_query_identity_is_not_accepted() -> None:
    with pytest.raises(HTTPException) as caught:
        asyncio.run(read_terms_acceptance(request(b"{}", query=b"user_id=another-account")))
    assert caught.value.status_code == 400
