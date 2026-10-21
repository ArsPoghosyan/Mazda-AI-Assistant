"""Offline registration-response tests using synthetic provider data."""

import pytest

from app.account_sign_up import (
    AccountSignUpCaptchaRejected,
    AccountSignUpRejected,
    AccountSignUpUnavailable,
    interpret_sign_up_response,
)

USER_ID = "563128d6-22fd-464f-a3bd-31018fdf1b3c"
PRIVATE_DETAIL = "private-provider-detail"


def test_accepted_registration_does_not_return_provider_user_details() -> None:
    interpret_sign_up_response(
        200,
        {
            "id": USER_ID,
            "email": "owner@example.test",
            "identities": [],
        },
    )


@pytest.mark.parametrize("code", ["user_already_exists", "email_exists"])
@pytest.mark.parametrize("source", ["legacy", "current", "legacy-with-http-code"])
def test_existing_account_has_the_same_generic_outcome(
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

    interpret_sign_up_response(422, payload)


@pytest.mark.parametrize(
    "code",
    ["validation_failed", "email_address_invalid", "weak_password"],
)
@pytest.mark.parametrize("field", ["error_code", "code"])
def test_input_rejections_use_a_controlled_message(
    code: str,
    field: str,
) -> None:
    with pytest.raises(AccountSignUpRejected) as caught:
        interpret_sign_up_response(
            422,
            {field: code, "msg": PRIVATE_DETAIL},
        )

    assert type(caught.value) is AccountSignUpRejected
    assert str(caught.value) == "Registration was rejected."
    assert PRIVATE_DETAIL not in repr(caught.value)


@pytest.mark.parametrize("field", ["error_code", "code"])
def test_captcha_rejection_remains_distinct(field: str) -> None:
    with pytest.raises(AccountSignUpCaptchaRejected) as caught:
        interpret_sign_up_response(
            403,
            {field: "captcha_failed", "msg": PRIVATE_DETAIL},
        )

    assert str(caught.value) == "Human verification was rejected."
    assert PRIVATE_DETAIL not in repr(caught.value)


@pytest.mark.parametrize("status_code", [201, 204, 302, 429, 500, 503])
def test_unexpected_status_cannot_be_mistaken_for_acceptance(
    status_code: int,
) -> None:
    with pytest.raises(AccountSignUpUnavailable) as caught:
        interpret_sign_up_response(
            status_code,
            {
                "id": USER_ID,
                "error_code": "user_already_exists",
                "msg": PRIVATE_DETAIL,
            },
        )

    assert str(caught.value) == "Account registration is unavailable."
    assert PRIVATE_DETAIL not in repr(caught.value)


@pytest.mark.parametrize("payload", [None, [], PRIVATE_DETAIL, 123, True])
def test_non_object_responses_are_unavailable(payload: object) -> None:
    with pytest.raises(AccountSignUpUnavailable):
        interpret_sign_up_response(200, payload)


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"id": None},
        {"id": 123},
        {"id": "not-a-uuid"},
        {"id": "x" * 65},
    ],
)
def test_success_requires_a_valid_provider_response_shape(
    payload: object,
) -> None:
    with pytest.raises(AccountSignUpUnavailable):
        interpret_sign_up_response(200, payload)


@pytest.mark.parametrize("field", ["access_token", "refresh_token", "session"])
@pytest.mark.parametrize("value", [None, "synthetic-provider-secret"])
def test_registration_never_accepts_a_session_response(
    field: str,
    value: object,
) -> None:
    payload: dict[str, object] = {
        "id": USER_ID,
        field: value,
    }

    with pytest.raises(AccountSignUpUnavailable) as caught:
        interpret_sign_up_response(200, payload)

    assert str(caught.value) == "Account registration is unavailable."
    assert "synthetic-provider-secret" not in repr(caught.value)


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"msg": PRIVATE_DETAIL},
        {"error_code": "unknown-provider-code", "msg": PRIVATE_DETAIL},
        {"code": 422},
        {
            "error_code": "user_already_exists",
            "code": "captcha_failed",
        },
        {
            "error_code": 123,
            "code": "user_already_exists",
        },
    ],
)
def test_unknown_malformed_or_conflicting_errors_are_unavailable(
    payload: object,
) -> None:
    with pytest.raises(AccountSignUpUnavailable) as caught:
        interpret_sign_up_response(422, payload)

    assert str(caught.value) == "Account registration is unavailable."
    assert PRIVATE_DETAIL not in repr(caught.value)
