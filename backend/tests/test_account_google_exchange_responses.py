"""Offline PKCE response interpretation with synthetic provider credentials."""

from copy import deepcopy

import pytest
from pydantic import SecretStr

from app.account_google_exchange import (
    GoogleCodeExchangeRejected,
    GoogleCodeExchangeUnavailable,
    interpret_google_code_exchange_response,
)

ACCESS_TOKEN = "synthetic-supabase-access-token"
REFRESH_TOKEN = "synthetic-supabase-refresh-token"
PRIVATE_DETAIL = "synthetic-private-provider-detail"


def success_payload() -> dict[str, object]:
    return {
        "access_token": ACCESS_TOKEN,
        "refresh_token": REFRESH_TOKEN,
        "token_type": "bearer",
    }


@pytest.mark.parametrize("token_type", ["bearer", "BeArEr"])
def test_success_returns_redacted_unverified_token_pair(token_type: str) -> None:
    payload = success_payload()
    payload["token_type"] = token_type
    tokens = interpret_google_code_exchange_response(200, payload)

    assert isinstance(tokens.access_token, SecretStr)
    assert isinstance(tokens.refresh_token, SecretStr)
    assert tokens.access_token.get_secret_value() == ACCESS_TOKEN
    assert tokens.refresh_token.get_secret_value() == REFRESH_TOKEN
    for rendered in (str(tokens), repr(tokens)):
        assert ACCESS_TOKEN not in rendered
        assert REFRESH_TOKEN not in rendered


def test_success_discards_google_credentials_and_user_metadata_without_mutating_payload() -> None:
    payload = success_payload()
    payload.update(
        {
            "provider_token": "synthetic-google-api-token",
            "provider_refresh_token": "synthetic-google-refresh-token",
            "user": {"id": "untrusted-user-id", "email": "synthetic@example.com"},
            "expires_in": 3600,
        }
    )
    original = deepcopy(payload)
    tokens = interpret_google_code_exchange_response(200, payload)

    assert not hasattr(tokens, "provider_token")
    assert not hasattr(tokens, "provider_refresh_token")
    assert not hasattr(tokens, "user")
    assert "synthetic-google" not in repr(tokens)
    assert "untrusted-user-id" not in repr(tokens)
    assert payload == original


@pytest.mark.parametrize("field", ["access_token", "refresh_token"])
@pytest.mark.parametrize("size", [1, 8192])
def test_token_size_boundaries_are_accepted(field: str, size: int) -> None:
    payload = success_payload()
    payload[field] = "t" * size
    tokens = interpret_google_code_exchange_response(200, payload)
    actual = tokens.access_token if field == "access_token" else tokens.refresh_token
    assert actual.get_secret_value() == "t" * size


@pytest.mark.parametrize("field", ["access_token", "refresh_token"])
def test_both_credentials_are_required(field: str) -> None:
    payload = success_payload()
    del payload[field]
    with pytest.raises(GoogleCodeExchangeUnavailable):
        interpret_google_code_exchange_response(200, payload)


@pytest.mark.parametrize("field", ["access_token", "refresh_token"])
@pytest.mark.parametrize(
    "value",
    [
        pytest.param(None, id="null"),
        pytest.param(True, id="boolean"),
        pytest.param(123, id="number"),
        pytest.param([], id="array"),
        pytest.param("", id="empty"),
        pytest.param("t" * 8193, id="oversized"),
        pytest.param("token value", id="space"),
        pytest.param("token\n", id="newline"),
        pytest.param("token\x00", id="nul"),
        pytest.param("token\x7f", id="del"),
        pytest.param("token\N{SNOWMAN}", id="unicode"),
    ],
)
def test_invalid_token_values_are_unavailable(field: str, value: object) -> None:
    payload = success_payload()
    payload[field] = value
    with pytest.raises(GoogleCodeExchangeUnavailable, match="^Google sign-in is unavailable\\.$"):
        interpret_google_code_exchange_response(200, payload)


@pytest.mark.parametrize("token_type", [None, 123, "", "basic", "bearer ", " bearer"])
def test_success_requires_an_unpadded_bearer_token_type(token_type: object) -> None:
    payload = success_payload()
    payload["token_type"] = token_type
    with pytest.raises(GoogleCodeExchangeUnavailable):
        interpret_google_code_exchange_response(200, payload)


@pytest.mark.parametrize("payload", [None, [], PRIVATE_DETAIL, 123, True])
def test_non_object_responses_are_unavailable(payload: object) -> None:
    with pytest.raises(GoogleCodeExchangeUnavailable):
        interpret_google_code_exchange_response(200, payload)


@pytest.mark.parametrize(
    "code", ["flow_state_not_found", "flow_state_expired", "bad_code_verifier"]
)
@pytest.mark.parametrize("shape", ["legacy", "current", "matching-both"])
def test_known_provider_codes_are_rejected(code: str, shape: str) -> None:
    payload: dict[str, object] = {"message": PRIVATE_DETAIL}
    if shape != "current":
        payload["error_code"] = code
    if shape != "legacy":
        payload["code"] = code
    with pytest.raises(GoogleCodeExchangeRejected, match="^Google sign-in was rejected\\.$"):
        interpret_google_code_exchange_response(400, payload)


@pytest.mark.parametrize("status", [400, 401, 403, 404, 422])
def test_known_rejection_requires_an_allowed_error_status(status: int) -> None:
    with pytest.raises(GoogleCodeExchangeRejected):
        interpret_google_code_exchange_response(status, {"error_code": "flow_state_not_found"})


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"message": "flow_state_expired"},
        {"error_code": "unknown_provider_failure"},
        {"error_code": "validation_failed"},
        {"error_code": "flow_state_expired", "code": "bad_code_verifier"},
        {"error_code": 123, "code": "flow_state_expired"},
        {"code": []},
        {"error_code": False},
    ],
)
def test_unknown_or_conflicting_provider_errors_are_unavailable(payload: dict[str, object]) -> None:
    with pytest.raises(GoogleCodeExchangeUnavailable):
        interpret_google_code_exchange_response(400, payload)


@pytest.mark.parametrize("status", [201, 204, 302, 307, 429, 500, 503])
def test_unexpected_status_is_not_misclassified_as_rejection(status: int) -> None:
    payload = success_payload()
    payload["error_code"] = "flow_state_expired"
    with pytest.raises(GoogleCodeExchangeUnavailable):
        interpret_google_code_exchange_response(status, payload)


@pytest.mark.parametrize("field", ["error", "error_code", "code"])
def test_success_with_error_fields_fails_closed(field: str) -> None:
    payload = success_payload()
    payload[field] = None
    with pytest.raises(GoogleCodeExchangeUnavailable):
        interpret_google_code_exchange_response(200, payload)


@pytest.mark.parametrize("status", [400, 503])
def test_errors_do_not_expose_provider_details_or_credentials(status: int) -> None:
    payload = success_payload()
    payload.update({"error_code": "bad_code_verifier", "message": PRIVATE_DETAIL})
    expected = GoogleCodeExchangeRejected if status == 400 else GoogleCodeExchangeUnavailable
    with pytest.raises(expected) as caught:
        interpret_google_code_exchange_response(status, payload)
    rendered = str(caught.value)
    assert PRIVATE_DETAIL not in rendered
    assert ACCESS_TOKEN not in rendered
    assert REFRESH_TOKEN not in rendered
