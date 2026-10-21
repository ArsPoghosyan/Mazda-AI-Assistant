"""Offline email-confirmation response tests with synthetic provider data."""

import pytest

from app.account_email_confirmation import (
    AccountEmailConfirmationRejected,
    AccountEmailConfirmationUnavailable,
    interpret_email_confirmation_response,
)

USER_ID = "563128d6-22fd-464f-a3bd-31018fdf1b3c"
CONFIRMED_AT = "2026-10-22T10:00:00Z"
PRIVATE_DETAIL = "private-provider-detail"


def confirmed_payload() -> dict[str, object]:
    return {
        "user": {
            "id": USER_ID,
            "email_confirmed_at": CONFIRMED_AT,
        }
    }


@pytest.mark.parametrize(
    "confirmed_at",
    [
        "2026-10-22T10:00:00Z",
        "2026-10-22T10:00:00+00:00",
        "2026-10-22T14:00:00+04:00",
        "2026-10-22T10:00:00.123456Z",
    ],
)
def test_accepts_confirmed_users_with_timezone_aware_timestamps(
    confirmed_at: str,
) -> None:
    interpret_email_confirmation_response(
        200,
        {
            "user": {
                "id": USER_ID,
                "email_confirmed_at": confirmed_at,
            }
        },
    )


def test_confirmation_ignores_unused_provider_credentials() -> None:
    payload = confirmed_payload()
    payload["access_token"] = "synthetic-access-token"
    payload["refresh_token"] = "synthetic-refresh-token"
    payload["token_type"] = "bearer"

    interpret_email_confirmation_response(200, payload)

    # The interpreter does not mutate the caller's provider response.
    assert payload["access_token"] == "synthetic-access-token"
    assert payload["refresh_token"] == "synthetic-refresh-token"


@pytest.mark.parametrize("payload", [None, [], PRIVATE_DETAIL, 123, True])
def test_non_object_responses_are_unavailable(payload: object) -> None:
    with pytest.raises(AccountEmailConfirmationUnavailable):
        interpret_email_confirmation_response(200, payload)


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"user": None},
        {"user": []},
        {"user": PRIVATE_DETAIL},
    ],
)
def test_success_requires_a_user_object(payload: object) -> None:
    with pytest.raises(AccountEmailConfirmationUnavailable):
        interpret_email_confirmation_response(200, payload)


@pytest.mark.parametrize("user_id", [None, 123, "", "not-a-uuid", "x" * 65])
def test_success_requires_a_valid_user_id(user_id: object) -> None:
    with pytest.raises(AccountEmailConfirmationUnavailable):
        interpret_email_confirmation_response(
            200,
            {
                "user": {
                    "id": user_id,
                    "email_confirmed_at": CONFIRMED_AT,
                }
            },
        )


@pytest.mark.parametrize(
    "confirmed_at",
    [
        None,
        123,
        "",
        "not-a-timestamp",
        "2026-10-22",
        "2026-10-22T10:00:00",
        "2026-99-22T10:00:00Z",
        "x" * 65,
    ],
)
def test_success_requires_a_valid_confirmation_timestamp(
    confirmed_at: object,
) -> None:
    with pytest.raises(AccountEmailConfirmationUnavailable) as caught:
        interpret_email_confirmation_response(
            200,
            {
                "user": {
                    "id": USER_ID,
                    "email_confirmed_at": confirmed_at,
                }
            },
        )

    assert str(caught.value) == "Email confirmation is unavailable."
    assert caught.value.__cause__ is None


@pytest.mark.parametrize(
    "code",
    [
        "otp_expired",
        "validation_failed",
        "email_address_invalid",
        "user_banned",
    ],
)
@pytest.mark.parametrize("source", ["legacy", "current", "legacy-with-http-code"])
def test_known_rejections_use_the_same_controlled_message(
    code: str,
    source: str,
) -> None:
    payload: dict[str, object] = {"msg": PRIVATE_DETAIL}

    if source == "current":
        payload["code"] = code
    else:
        payload["error_code"] = code

        if source == "legacy-with-http-code":
            payload["code"] = 422

    with pytest.raises(AccountEmailConfirmationRejected) as caught:
        interpret_email_confirmation_response(422, payload)

    assert str(caught.value) == "Email confirmation was rejected."
    assert PRIVATE_DETAIL not in repr(caught.value)


@pytest.mark.parametrize("status_code", [400, 401, 403, 404, 422])
def test_recognized_rejection_accepts_supported_client_error_statuses(
    status_code: int,
) -> None:
    with pytest.raises(AccountEmailConfirmationRejected):
        interpret_email_confirmation_response(
            status_code,
            {"error_code": "otp_expired", "msg": PRIVATE_DETAIL},
        )


@pytest.mark.parametrize("status_code", [201, 204, 302, 429, 500, 503])
def test_unexpected_status_cannot_be_mistaken_for_confirmation(
    status_code: int,
) -> None:
    payload = confirmed_payload()
    payload["error_code"] = "otp_expired"
    payload["msg"] = PRIVATE_DETAIL

    with pytest.raises(AccountEmailConfirmationUnavailable) as caught:
        interpret_email_confirmation_response(status_code, payload)

    assert str(caught.value) == "Email confirmation is unavailable."
    assert PRIVATE_DETAIL not in repr(caught.value)


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"msg": PRIVATE_DETAIL},
        {"error_code": "unknown-provider-code", "msg": PRIVATE_DETAIL},
        {"error_code": "user_banned", "code": "otp_expired"},
        {"code": 422},
        {"error_code": 123, "code": "otp_expired"},
    ],
)
def test_unknown_malformed_or_conflicting_errors_are_unavailable(
    payload: object,
) -> None:
    with pytest.raises(AccountEmailConfirmationUnavailable) as caught:
        interpret_email_confirmation_response(422, payload)

    assert str(caught.value) == "Email confirmation is unavailable."
    assert PRIVATE_DETAIL not in repr(caught.value)
