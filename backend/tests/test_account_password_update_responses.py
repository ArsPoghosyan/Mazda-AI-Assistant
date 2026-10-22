"""Password-update response handling using synthetic provider data."""

from uuid import UUID

import pytest

from app.account_password_update import (
    AccountPasswordUpdateRateLimited,
    AccountPasswordUpdateRejected,
    AccountPasswordUpdateUnavailable,
    interpret_password_update_response,
)

USER_ID = UUID("563128d6-22fd-464f-a3bd-31018fdf1b3c")
OTHER_USER_ID = UUID("33333333-3333-4333-8333-333333333333")
PRIVATE_DETAIL = "private-provider-detail"
ERROR_FORMATS = ["legacy", "current", "legacy-http-code"]


def valid_payload() -> dict[str, object]:
    return {
        "id": str(USER_ID),
        "is_anonymous": False,
        "email": "owner@example.test",
    }


def provider_error(
    code: str,
    source: str,
    status_code: int,
) -> dict[str, object]:
    payload: dict[str, object] = {"msg": PRIVATE_DETAIL}

    if source == "current":
        payload["code"] = code
    elif source == "legacy":
        payload["error_code"] = code
    elif source == "legacy-http-code":
        payload["error_code"] = code
        payload["code"] = status_code
    else:
        raise AssertionError("Unexpected error format.")

    return payload


def assert_unavailable(status_code: int, payload: object) -> None:
    with pytest.raises(AccountPasswordUpdateUnavailable) as caught:
        interpret_password_update_response(
            status_code,
            payload,
            expected_user_id=USER_ID,
        )

    assert str(caught.value) == "Password update is unavailable."
    assert PRIVATE_DETAIL not in repr(caught.value)
    assert str(USER_ID) not in repr(caught.value)
    assert "owner@example.test" not in repr(caught.value)


def test_accepts_matching_user_without_returning_provider_data() -> None:
    interpret_password_update_response(
        200,
        valid_payload(),
        expected_user_id=USER_ID,
    )


@pytest.mark.parametrize("payload", [None, [], PRIVATE_DETAIL, 123, True])
def test_rejects_non_object_payloads(payload: object) -> None:
    assert_unavailable(200, payload)


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


@pytest.mark.parametrize(
    ("status_code", "code"),
    [
        (422, "weak_password"),
        (422, "same_password"),
        (400, "validation_failed"),
        (400, "reauthentication_needed"),
        (400, "reauthentication_not_valid"),
        (401, "insufficient_aal"),
        (400, "current_password_required"),
        (400, "current_password_mismatch"),
    ],
)
@pytest.mark.parametrize("source", ERROR_FORMATS)
def test_recognized_rejections_have_generic_errors(
    status_code: int,
    code: str,
    source: str,
) -> None:
    with pytest.raises(AccountPasswordUpdateRejected) as caught:
        interpret_password_update_response(
            status_code,
            provider_error(code, source, status_code),
            expected_user_id=USER_ID,
        )

    assert str(caught.value) == "Password update was rejected."
    assert PRIVATE_DETAIL not in repr(caught.value)


@pytest.mark.parametrize("source", ERROR_FORMATS)
def test_recognized_rate_limit_remains_distinct(source: str) -> None:
    with pytest.raises(AccountPasswordUpdateRateLimited) as caught:
        interpret_password_update_response(
            429,
            provider_error("over_request_rate_limit", source, 429),
            expected_user_id=USER_ID,
        )

    assert str(caught.value) == "Password update is temporarily rate limited."
    assert PRIVATE_DETAIL not in repr(caught.value)


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"msg": PRIVATE_DETAIL},
        {"code": "unknown-provider-code"},
        {"code": 422},
        {"error_code": 123, "code": "weak_password"},
        {"error_code": [], "code": "same_password"},
        {"error_code": "weak_password", "code": "same_password"},
    ],
)
def test_unknown_or_conflicting_errors_are_unavailable(payload: object) -> None:
    assert_unavailable(422, payload)


@pytest.mark.parametrize("status_code", [201, 202, 204, 301, 302, 500, 503])
def test_unexpected_status_cannot_be_treated_as_input_rejection(
    status_code: int,
) -> None:
    assert_unavailable(
        status_code,
        {"code": "weak_password", "msg": PRIVATE_DETAIL},
    )


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"code": "weak_password"},
        {"code": "over_email_send_rate_limit"},
        {
            "error_code": "over_request_rate_limit",
            "code": "weak_password",
        },
    ],
)
def test_unknown_or_conflicting_rate_limits_are_unavailable(
    payload: object,
) -> None:
    assert_unavailable(429, payload)


def test_requires_raw_user_response_instead_of_a_session_wrapper() -> None:
    assert_unavailable(200, {"user": valid_payload()})
