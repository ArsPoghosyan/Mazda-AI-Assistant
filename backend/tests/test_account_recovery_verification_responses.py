"""Recovery-verification responses using synthetic provider data."""

from uuid import UUID

import pytest

from app.account_recovery_verification import (
    AccountRecoveryVerificationRateLimited,
    AccountRecoveryVerificationRejected,
    AccountRecoveryVerificationUnavailable,
    interpret_recovery_verification_response,
)

USER_ID = "563128d6-22fd-464f-a3bd-31018fdf1b3c"
ACCESS_TOKEN = "synthetic-recovery-access-token"
PRIVATE_DETAIL = "private-provider-detail"
ERROR_FORMATS = ["legacy", "current", "legacy-http-code"]


def valid_payload() -> dict[str, object]:
    return {
        "token_type": "bearer",
        "access_token": ACCESS_TOKEN,
        "refresh_token": "synthetic-refresh-token",
        "user": {
            "id": USER_ID,
            "is_anonymous": False,
            "email": "owner@example.test",
        },
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
    with pytest.raises(AccountRecoveryVerificationUnavailable) as caught:
        interpret_recovery_verification_response(status_code, payload)

    assert str(caught.value) == "Recovery verification is unavailable."
    assert PRIVATE_DETAIL not in repr(caught.value)
    assert ACCESS_TOKEN not in repr(caught.value)


def test_returns_only_internal_credentials_with_masked_token() -> None:
    result = interpret_recovery_verification_response(200, valid_payload())

    assert result.user_id == UUID(USER_ID)
    assert result.access_token.get_secret_value() == ACCESS_TOKEN
    assert ACCESS_TOKEN not in repr(result)
    assert "synthetic-refresh-token" not in repr(result)
    assert "owner@example.test" not in repr(result)
    assert not hasattr(result, "refresh_token")


def test_accepts_case_insensitive_bearer_type() -> None:
    payload = valid_payload()
    payload["token_type"] = "Bearer"

    result = interpret_recovery_verification_response(200, payload)

    assert result.user_id == UUID(USER_ID)


def test_accepts_token_at_structural_length_limit() -> None:
    payload = valid_payload()
    payload["access_token"] = "x" * 8192

    result = interpret_recovery_verification_response(200, payload)

    assert len(result.access_token.get_secret_value()) == 8192


@pytest.mark.parametrize("payload", [None, [], PRIVATE_DETAIL, 123, True])
def test_rejects_non_object_payloads(payload: object) -> None:
    assert_unavailable(200, payload)


@pytest.mark.parametrize("missing", ["token_type", "access_token", "user"])
def test_requires_success_fields(missing: str) -> None:
    payload = valid_payload()
    del payload[missing]

    assert_unavailable(200, payload)


@pytest.mark.parametrize(
    "value",
    [
        None,
        123,
        True,
        "",
        "x" * 8193,
        "has space",
        "line\nbreak",
        "é",
        "\x00",
        "abc\x7f",
    ],
)
def test_rejects_invalid_access_tokens(value: object) -> None:
    payload = valid_payload()
    payload["access_token"] = value

    assert_unavailable(200, payload)


@pytest.mark.parametrize("value", [None, 123, "", "basic", " bearer "])
def test_rejects_invalid_token_types(value: object) -> None:
    payload = valid_payload()
    payload["token_type"] = value

    assert_unavailable(200, payload)


@pytest.mark.parametrize("value", [None, [], PRIVATE_DETAIL, 123])
def test_requires_a_user_object(value: object) -> None:
    payload = valid_payload()
    payload["user"] = value

    assert_unavailable(200, payload)


@pytest.mark.parametrize("value", [None, 123, True, "", "invalid", "x" * 65])
def test_rejects_invalid_user_ids(value: object) -> None:
    payload = valid_payload()
    payload["user"] = {"id": value, "is_anonymous": False}

    assert_unavailable(200, payload)


@pytest.mark.parametrize(
    "user",
    [
        {"id": USER_ID},
        {"id": USER_ID, "is_anonymous": None},
        {"id": USER_ID, "is_anonymous": True},
        {"id": USER_ID, "is_anonymous": 0},
        {"id": USER_ID, "is_anonymous": "false"},
    ],
)
def test_requires_explicit_non_anonymous_user(user: dict[str, object]) -> None:
    payload = valid_payload()
    payload["user"] = user

    assert_unavailable(200, payload)


@pytest.mark.parametrize(
    ("status_code", "code"),
    [
        (400, "otp_expired"),
        (401, "otp_expired"),
        (404, "user_not_found"),
        (403, "user_banned"),
        (422, "validation_failed"),
    ],
)
@pytest.mark.parametrize("source", ERROR_FORMATS)
def test_recognized_rejections_have_generic_errors(
    status_code: int,
    code: str,
    source: str,
) -> None:
    with pytest.raises(AccountRecoveryVerificationRejected) as caught:
        interpret_recovery_verification_response(
            status_code,
            provider_error(code, source, status_code),
        )

    assert str(caught.value) == "Recovery verification was rejected."
    assert PRIVATE_DETAIL not in repr(caught.value)


@pytest.mark.parametrize("source", ERROR_FORMATS)
def test_recognized_rate_limit_remains_distinct(source: str) -> None:
    with pytest.raises(AccountRecoveryVerificationRateLimited) as caught:
        interpret_recovery_verification_response(
            429,
            provider_error("over_request_rate_limit", source, 429),
        )

    assert str(caught.value) == ("Recovery verification is temporarily rate limited.")
    assert PRIVATE_DETAIL not in repr(caught.value)


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"msg": PRIVATE_DETAIL},
        {"code": "unknown-provider-code"},
        {"code": "otp_disabled"},
        {"code": 422},
        {"error_code": 123, "code": "otp_expired"},
        {"error_code": "otp_expired", "code": "user_banned"},
    ],
)
def test_unknown_or_conflicting_errors_are_unavailable(payload: object) -> None:
    assert_unavailable(422, payload)


@pytest.mark.parametrize("status_code", [201, 202, 204, 301, 302, 500, 503])
def test_unexpected_status_cannot_return_credentials(status_code: int) -> None:
    assert_unavailable(status_code, valid_payload())


@pytest.mark.parametrize(
    "payload",
    [
        {"code": "otp_expired"},
        {"code": "over_email_send_rate_limit"},
        {
            "error_code": "over_request_rate_limit",
            "code": "otp_expired",
        },
    ],
)
def test_unknown_or_conflicting_rate_limits_are_unavailable(
    payload: object,
) -> None:
    assert_unavailable(429, payload)
