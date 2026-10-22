"""Provider-session response handling using synthetic provider data."""

from copy import deepcopy
from uuid import UUID

import pytest

from app.account_provider_session import (
    AccountProviderSessionRejected,
    AccountProviderSessionUnavailable,
    interpret_provider_session_response,
)

USER_ID = UUID("563128d6-22fd-464f-a3bd-31018fdf1b3c")
OTHER_USER_ID = UUID("33333333-3333-4333-8333-333333333333")
PRIVATE_DETAIL = "private-provider-detail"


def valid_payload() -> dict[str, object]:
    return {
        "id": str(USER_ID),
        "is_anonymous": False,
        "email": "owner@example.test",
        "user_metadata": {"display_name": PRIVATE_DETAIL},
    }


def assert_unavailable(status_code: int, payload: object) -> None:
    with pytest.raises(AccountProviderSessionUnavailable) as caught:
        interpret_provider_session_response(status_code, payload, expected_user_id=USER_ID)

    assert str(caught.value) == "Account session verification is unavailable."
    assert PRIVATE_DETAIL not in repr(caught.value)
    assert str(USER_ID) not in repr(caught.value)
    assert str(OTHER_USER_ID) not in repr(caught.value)
    assert "owner@example.test" not in repr(caught.value)


def test_accepts_matching_user_without_mutating_provider_data() -> None:
    payload = valid_payload()
    original = deepcopy(payload)

    interpret_provider_session_response(200, payload, expected_user_id=USER_ID)

    assert payload == original


def test_accepts_identity_without_optional_profile_fields() -> None:
    interpret_provider_session_response(
        200,
        {"id": str(USER_ID), "is_anonymous": False},
        expected_user_id=USER_ID,
    )


@pytest.mark.parametrize("status_code", [200, 401, 403, 503])
@pytest.mark.parametrize("payload", [None, [], PRIVATE_DETAIL, 123, True])
def test_rejects_non_object_payloads(status_code: int, payload: object) -> None:
    assert_unavailable(status_code, payload)


@pytest.mark.parametrize("missing", ["id", "is_anonymous"])
def test_requires_identity_fields(missing: str) -> None:
    payload = valid_payload()
    del payload[missing]

    assert_unavailable(200, payload)


@pytest.mark.parametrize("value", [None, 123, True, "", "invalid", "x" * 65])
def test_rejects_invalid_user_ids(value: object) -> None:
    payload = valid_payload()
    payload["id"] = value

    assert_unavailable(200, payload)


def test_rejects_another_accounts_response() -> None:
    payload = valid_payload()
    payload["id"] = str(OTHER_USER_ID)

    assert_unavailable(200, payload)


@pytest.mark.parametrize("value", [None, True, 0, 1, "false"])
def test_requires_explicit_non_anonymous_user(value: object) -> None:
    payload = valid_payload()
    payload["is_anonymous"] = value

    assert_unavailable(200, payload)


@pytest.mark.parametrize("field", ["access_token", "refresh_token", "session"])
@pytest.mark.parametrize("value", [None, PRIVATE_DETAIL])
def test_rejects_unexpected_session_fields(field: str, value: object) -> None:
    payload = valid_payload()
    payload[field] = value

    assert_unavailable(200, payload)


@pytest.mark.parametrize("status_code", [401, 403])
@pytest.mark.parametrize(
    "code",
    ["session_not_found", "user_not_found", "user_banned", "bad_jwt", "no_authorization"],
)
@pytest.mark.parametrize("source", ["legacy", "current", "legacy-http-code", "matching"])
def test_known_rejections_have_generic_errors(status_code: int, code: str, source: str) -> None:
    payload: dict[str, object] = {"msg": PRIVATE_DETAIL}
    if source == "current":
        payload["code"] = code
    else:
        payload["error_code"] = code
        if source == "legacy-http-code":
            payload["code"] = status_code
        elif source == "matching":
            payload["code"] = code

    with pytest.raises(AccountProviderSessionRejected) as caught:
        interpret_provider_session_response(status_code, payload, expected_user_id=USER_ID)

    assert str(caught.value) == "Account session was rejected."
    assert PRIVATE_DETAIL not in repr(caught.value)


@pytest.mark.parametrize("status_code", [401, 403])
@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"msg": "session_not_found"},
        {"code": "unknown-provider-code"},
        {"code": 401},
        {"error_code": 123, "code": "session_not_found"},
        {"error_code": [], "code": "session_not_found"},
        {"error_code": "session_not_found", "code": "user_banned"},
    ],
)
def test_unknown_or_conflicting_errors_are_unavailable(status_code: int, payload: object) -> None:
    assert_unavailable(status_code, payload)


@pytest.mark.parametrize("status_code", [201, 202, 204, 301, 302, 400, 404, 422, 429, 500, 503])
def test_rejection_code_on_unexpected_status_is_unavailable(status_code: int) -> None:
    assert_unavailable(status_code, {"code": "session_not_found", "msg": PRIVATE_DETAIL})


def test_rate_limits_are_unavailable() -> None:
    assert_unavailable(429, {"code": "over_request_rate_limit", "msg": PRIVATE_DETAIL})


@pytest.mark.parametrize("status_code", [401, 403, 429, 503])
def test_valid_user_body_does_not_override_failure_status(status_code: int) -> None:
    assert_unavailable(status_code, valid_payload())


def test_success_status_does_not_override_error_body() -> None:
    assert_unavailable(200, {"code": "session_not_found", "msg": PRIVATE_DETAIL})


def test_requires_raw_user_response_instead_of_a_wrapper() -> None:
    assert_unavailable(200, {"user": valid_payload()})
