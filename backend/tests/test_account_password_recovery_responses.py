"""Offline recovery-response tests using synthetic provider data."""

import pytest

from app.account_password_recovery import (
    AccountPasswordRecoveryCaptchaRejected,
    AccountPasswordRecoveryRateLimited,
    AccountPasswordRecoveryRejected,
    AccountPasswordRecoveryUnavailable,
    interpret_password_recovery_response,
)

PRIVATE_DETAIL = "private-provider-detail"
ERROR_FORMATS = ["legacy", "current", "legacy-http-code"]


def provider_error(
    error_code: str,
    source: str,
    status_code: int,
) -> dict[str, object]:
    payload: dict[str, object] = {"msg": PRIVATE_DETAIL}

    if source == "current":
        payload["code"] = error_code
    elif source == "legacy":
        payload["error_code"] = error_code
    elif source == "legacy-http-code":
        payload["error_code"] = error_code
        payload["code"] = status_code
    else:
        raise AssertionError("Unexpected test error format")

    return payload


def assert_unavailable(status_code: int, payload: object) -> None:
    with pytest.raises(AccountPasswordRecoveryUnavailable) as caught:
        interpret_password_recovery_response(status_code, payload)

    assert str(caught.value) == "Password recovery is unavailable."
    assert PRIVATE_DETAIL not in repr(caught.value)
    assert caught.value.__cause__ is None


def test_empty_success_has_a_generic_acknowledgement() -> None:
    interpret_password_recovery_response(200, {})


@pytest.mark.parametrize(
    ("status_code", "error_code"),
    [
        (400, "email_address_invalid"),
        (404, "user_not_found"),
        (403, "user_banned"),
        (403, "email_not_confirmed"),
    ],
)
@pytest.mark.parametrize("source", ERROR_FORMATS)
def test_account_specific_errors_have_the_same_generic_outcome(
    status_code: int,
    error_code: str,
    source: str,
) -> None:
    interpret_password_recovery_response(
        status_code,
        provider_error(error_code, source, status_code),
    )


@pytest.mark.parametrize("source", ERROR_FORMATS)
def test_address_specific_cooldown_has_a_generic_acknowledgement(
    source: str,
) -> None:
    interpret_password_recovery_response(
        429,
        provider_error("over_email_send_rate_limit", source, 429),
    )


@pytest.mark.parametrize("source", ERROR_FORMATS)
def test_client_wide_rate_limit_remains_distinct(source: str) -> None:
    with pytest.raises(AccountPasswordRecoveryRateLimited) as caught:
        interpret_password_recovery_response(
            429,
            provider_error("over_request_rate_limit", source, 429),
        )

    assert str(caught.value) == "Password recovery is temporarily rate limited."
    assert PRIVATE_DETAIL not in repr(caught.value)


@pytest.mark.parametrize("source", ERROR_FORMATS)
def test_captcha_rejection_uses_a_controlled_message(source: str) -> None:
    with pytest.raises(AccountPasswordRecoveryCaptchaRejected) as caught:
        interpret_password_recovery_response(
            403,
            provider_error("captcha_failed", source, 403),
        )

    assert str(caught.value) == "Human verification was rejected."
    assert PRIVATE_DETAIL not in repr(caught.value)


@pytest.mark.parametrize("source", ERROR_FORMATS)
def test_validation_rejection_uses_a_controlled_message(source: str) -> None:
    with pytest.raises(AccountPasswordRecoveryRejected) as caught:
        interpret_password_recovery_response(
            400,
            provider_error("validation_failed", source, 400),
        )

    assert type(caught.value) is AccountPasswordRecoveryRejected
    assert str(caught.value) == "Password recovery was rejected."
    assert PRIVATE_DETAIL not in repr(caught.value)


@pytest.mark.parametrize(
    "status_code",
    [201, 202, 204, 301, 302, 401, 500, 503],
)
def test_unexpected_status_cannot_be_mistaken_for_acceptance(
    status_code: int,
) -> None:
    assert_unavailable(
        status_code,
        {
            "error_code": "email_address_invalid",
            "msg": PRIVATE_DETAIL,
        },
    )


@pytest.mark.parametrize("payload", [None, [], PRIVATE_DETAIL, 123, True])
def test_non_object_responses_are_unavailable(payload: object) -> None:
    assert_unavailable(200, payload)


@pytest.mark.parametrize(
    "payload",
    [
        {"message": PRIVATE_DETAIL},
        {"id": "563128d6-22fd-464f-a3bd-31018fdf1b3c"},
        {"user": {"email": "owner@example.test"}},
        {"access_token": PRIVATE_DETAIL},
        {"refresh_token": None},
        {"session": {"access_token": PRIVATE_DETAIL}},
    ],
)
def test_success_requires_the_expected_empty_response(payload: object) -> None:
    assert_unavailable(200, payload)


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"msg": PRIVATE_DETAIL},
        {"error_code": "unknown-provider-code"},
        {"code": 422},
        {
            "error_code": "email_address_invalid",
            "code": "captcha_failed",
        },
        {
            "error_code": 123,
            "code": "email_address_invalid",
        },
        {
            "error_code": [],
            "code": "captcha_failed",
        },
        {
            "error_code": "captcha_failed",
            "code": "over_request_rate_limit",
        },
    ],
)
def test_unknown_malformed_or_conflicting_errors_are_unavailable(
    payload: object,
) -> None:
    assert_unavailable(422, payload)


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"code": "unknown-provider-code"},
        {"code": "captcha_failed"},
        {
            "error_code": 123,
            "code": "over_email_send_rate_limit",
        },
        {
            "error_code": "over_email_send_rate_limit",
            "code": "over_request_rate_limit",
        },
    ],
)
def test_unknown_or_conflicting_rate_limits_are_unavailable(
    payload: object,
) -> None:
    assert_unavailable(429, payload)
