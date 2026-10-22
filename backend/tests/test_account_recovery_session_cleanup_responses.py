"""Recovery-session cleanup classification using synthetic provider replies."""

from copy import deepcopy

import pytest

from app.account_recovery_session_cleanup import (
    AccountRecoverySessionCleanupUnavailable,
    interpret_recovery_session_cleanup_response,
)

PRIVATE_DETAIL = "private-provider-detail"
ACCESS_TOKEN = "synthetic-recovery-access-token"
EMAIL = "owner@example.test"


def assert_unavailable(status_code: int, payload: object) -> None:
    with pytest.raises(AccountRecoverySessionCleanupUnavailable) as caught:
        interpret_recovery_session_cleanup_response(status_code, payload)

    assert str(caught.value) == "Recovery session cleanup is unavailable."
    for private_value in (PRIVATE_DETAIL, ACCESS_TOKEN, EMAIL):
        assert private_value not in repr(caught.value)


def test_accepts_no_content_logout_response() -> None:
    interpret_recovery_session_cleanup_response(204, None)


@pytest.mark.parametrize(
    "payload",
    [
        {"code": "session_not_found"},
        {"error_code": "session_not_found"},
        {"error_code": "session_not_found", "code": 403},
        {"error_code": "session_not_found", "code": "session_not_found"},
        {"error_code": None, "code": "session_not_found"},
    ],
)
def test_accepts_explicit_absent_session_in_supported_error_formats(
    payload: dict[str, object],
) -> None:
    original = deepcopy(payload)

    interpret_recovery_session_cleanup_response(403, payload)
    interpret_recovery_session_cleanup_response(403, payload)

    assert payload == original


@pytest.mark.parametrize(
    "payload",
    [
        {},
        [],
        "",
        False,
        0,
        PRIVATE_DETAIL,
        {"code": "session_not_found"},
    ],
)
def test_no_content_status_does_not_accept_unexpected_payload(payload: object) -> None:
    assert_unavailable(204, payload)


@pytest.mark.parametrize("payload", [None, [], PRIVATE_DETAIL, 123, True])
def test_absent_session_requires_an_object_reply(payload: object) -> None:
    assert_unavailable(403, payload)


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"msg": "session_not_found"},
        {"code": "bad_jwt"},
        {"code": "user_not_found"},
        {"code": "user_banned"},
        {"code": "no_authorization"},
        {"code": "over_request_rate_limit"},
        {"code": "unknown-provider-code"},
        {"code": 403},
        {"error_code": 123, "code": "session_not_found"},
        {"error_code": [], "code": "session_not_found"},
        {"error_code": "session_not_found", "code": "bad_jwt"},
        {"error_code": "bad_jwt", "code": "session_not_found"},
        {"error": {"code": "session_not_found"}},
    ],
)
def test_unknown_or_conflicting_errors_do_not_confirm_cleanup(payload: object) -> None:
    assert_unavailable(403, payload)


@pytest.mark.parametrize(
    "status_code", [200, 201, 202, 301, 302, 400, 401, 404, 422, 429, 500, 503]
)
def test_absent_session_code_requires_the_expected_status(status_code: int) -> None:
    assert_unavailable(
        status_code,
        {"code": "session_not_found", "msg": PRIVATE_DETAIL},
    )


@pytest.mark.parametrize("status_code", [200, 202, 401, 403, 429, 500, 503])
def test_empty_response_does_not_confirm_cleanup_without_no_content_status(
    status_code: int,
) -> None:
    assert_unavailable(status_code, None)


def test_provider_details_are_not_exposed_in_cleanup_errors() -> None:
    assert_unavailable(
        403,
        {
            "code": "bad_jwt",
            "msg": PRIVATE_DETAIL,
            "access_token": ACCESS_TOKEN,
            "email": EMAIL,
        },
    )
