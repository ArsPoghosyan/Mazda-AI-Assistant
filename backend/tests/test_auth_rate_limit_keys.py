"""Fingerprint contracts using synthetic secrets and in-memory requests."""

from collections.abc import Callable
from secrets import token_hex
from typing import cast

import pytest
from fastapi import Request
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict
from starlette.types import Message, Scope

from app.auth_rate_limit_keys import (
    AuthRateLimitKeyUnavailable,
    get_email_confirmation_ip_key,
    get_password_recovery_ip_key,
    get_password_reset_ip_key,
    get_sign_in_ip_key,
    get_sign_up_ip_key,
)
from app.client_ip import ClientIPUnavailable
from app.config import Settings


class IsolatedKeySettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


type IPKeyFunction = Callable[[Request, Settings], bytes]


@pytest.fixture(
    params=[
        get_password_recovery_ip_key,
        get_sign_in_ip_key,
        get_sign_up_ip_key,
        get_email_confirmation_ip_key,
        get_password_reset_ip_key,
    ],
    ids=["password-recovery", "sign-in", "sign-up", "email-confirmation", "password-reset"],
)
def key_function(request: pytest.FixtureRequest) -> IPKeyFunction:
    return cast(IPKeyFunction, request.param)


@pytest.fixture
def settings(monkeypatch: pytest.MonkeyPatch) -> Settings:
    monkeypatch.delenv("AUTH_RATE_LIMIT_HMAC_SECRET", raising=False)
    return IsolatedKeySettings(auth_rate_limit_hmac_secret=SecretStr(token_hex(32)))


def make_request(
    host: str | None = "192.0.2.12",
    headers: list[tuple[bytes, bytes]] | None = None,
    port: int = 12345,
) -> Request:
    scope: Scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/v1/account/password-recovery",
        "headers": headers or [],
        "client": (host, port) if host is not None else None,
    }

    async def reject_body_read() -> Message:
        raise AssertionError("Fingerprint generation must not read request bodies.")

    return Request(scope, receive=reject_body_read)


@pytest.mark.parametrize(
    ("function", "expected"),
    [
        (
            get_password_recovery_ip_key,
            "094526c4a66b7525a9084b8ace9d060169e9d9358bf345e006d8660e5496de74",
        ),
        (
            get_sign_in_ip_key,
            "7fbbd354fc2c094906e306f401d871671063854622d7350d1b95bcfd2859aef4",
        ),
        (get_sign_up_ip_key, "4463cd425efc8e868de301d289792479886b7a88ec8c00e49044ded7875e89ff"),
        (
            get_email_confirmation_ip_key,
            "72b9edefd6197d30e7718c372e72c74cba639422b62b9cecc52d37a361c1c7d2",
        ),
        (
            get_password_reset_ip_key,
            "2da4b382ad0b950ff6b56764c722a2f2f8a430f65cb3cc3ee55cb0e83554787e",
        ),
    ],
    ids=["password-recovery", "sign-in", "sign-up", "email-confirmation", "password-reset"],
)
def test_versioned_fingerprint_matches_fixed_hmac_reference(
    function: IPKeyFunction, expected: str
) -> None:
    # Public synthetic key, never a deployment credential. This reference fixes
    # the decoded-key format, canonical address and each operation's domain.
    settings = Settings.model_construct(
        auth_rate_limit_hmac_secret=SecretStr(bytes(range(32)).hex())
    )
    result = function(make_request(), settings)
    assert result.hex() == expected


def test_same_identity_has_a_stable_binary_database_key(
    settings: Settings, key_function: IPKeyFunction
) -> None:
    first = key_function(make_request(), settings)
    second = key_function(make_request(), settings)
    assert isinstance(first, bytes)
    assert len(first) == 32
    assert first == second


@pytest.mark.parametrize(
    ("first", "second"),
    [
        ("192.0.2.12", "::ffff:192.0.2.12"),
        ("192.0.2.12", "0:0:0:0:0:FFFF:C000:020C"),
        ("2001:db8::1", "2001:0DB8:0000:0000:0000:0000:0000:0001"),
        ("::1", "0:0:0:0:0:0:0:1"),
    ],
)
def test_equivalent_addresses_cannot_split_limiter_identity(
    settings: Settings, key_function: IPKeyFunction, first: str, second: str
) -> None:
    assert key_function(make_request(first), settings) == (
        key_function(make_request(second), settings)
    )


@pytest.mark.parametrize("other", ["192.0.2.13", "2001:db8::1", "::192.0.2.12"])
def test_distinct_addresses_have_distinct_keys(
    settings: Settings, key_function: IPKeyFunction, other: str
) -> None:
    assert key_function(make_request(), settings) != (key_function(make_request(other), settings))


def test_changing_secret_changes_the_fingerprint(
    settings: Settings, key_function: IPKeyFunction
) -> None:
    other = settings.model_copy(update={"auth_rate_limit_hmac_secret": SecretStr(token_hex(32))})
    assert key_function(make_request(), settings) != (key_function(make_request(), other))


def test_hex_letter_case_does_not_change_the_decoded_key(
    settings: Settings, key_function: IPKeyFunction
) -> None:
    lower = settings.model_copy(update={"auth_rate_limit_hmac_secret": SecretStr("ab" * 32)})
    upper = settings.model_copy(update={"auth_rate_limit_hmac_secret": SecretStr("AB" * 32)})
    assert key_function(make_request(), lower) == (key_function(make_request(), upper))


def test_source_port_is_not_part_of_limiter_identity(
    settings: Settings, key_function: IPKeyFunction
) -> None:
    assert key_function(make_request(port=12345), settings) == (
        key_function(make_request(port=54321), settings)
    )


@pytest.mark.parametrize(
    "headers",
    [
        [(b"x-forwarded-for", b"198.51.100.20")],
        [(b"x-forwarded-for", b"198.51.100.20, 203.0.113.30")],
        [(b"x-forwarded-for", b"invalid-address")],
        [(b"x-forwarded-for", b"198.51.100.20"), (b"x-forwarded-for", b"203.0.113.30")],
        [(b"forwarded", b"for=198.51.100.20")],
        [(b"cf-connecting-ip", b"198.51.100.20")],
        [(b"true-client-ip", b"198.51.100.20")],
        [(b"x-real-ip", b"198.51.100.20")],
    ],
)
def test_spoofed_headers_cannot_change_the_asgi_peer_fingerprint(
    settings: Settings, key_function: IPKeyFunction, headers: list[tuple[bytes, bytes]]
) -> None:
    assert key_function(make_request(headers=headers), settings) == (
        key_function(make_request(), settings)
    )


@pytest.mark.parametrize("include_client", [True, False])
def test_missing_peer_has_no_header_fallback(
    settings: Settings, key_function: IPKeyFunction, include_client: bool
) -> None:
    request = make_request(None, [(b"x-forwarded-for", b"192.0.2.12")])
    if not include_client:
        request.scope.pop("client")
    with pytest.raises(ClientIPUnavailable, match="^Client address is unavailable\\.$"):
        key_function(request, settings)


@pytest.mark.parametrize("host", ["localhost", "", "192.0.2.12:1234", "fe80::1%eth0", "a" * 46])
def test_invalid_peer_is_rejected_without_exposing_input(
    settings: Settings, key_function: IPKeyFunction, host: str
) -> None:
    with pytest.raises(ClientIPUnavailable) as caught:
        key_function(make_request(host, [(b"x-forwarded-for", b"192.0.2.12")]), settings)
    assert str(caught.value) == "Client address is unavailable."
    assert caught.value.__cause__ is None


@pytest.mark.parametrize(
    "secret", [None, "", "a" * 63, "a" * 65, "g" * 64, "Ａ" * 64, "a" * 31 + " " + "a" * 32]
)
def test_missing_or_bypassed_invalid_configuration_fails_closed(
    key_function: IPKeyFunction, secret: str | None
) -> None:
    # Exercise the helper's guard even when normal Settings validation is bypassed.
    settings = Settings.model_construct(
        auth_rate_limit_hmac_secret=SecretStr(secret) if secret is not None else None
    )
    with pytest.raises(AuthRateLimitKeyUnavailable) as caught:
        key_function(make_request(), settings)
    assert str(caught.value) == "Authentication rate-limit key is unavailable."
    assert caught.value.__cause__ is None


def test_helper_leaves_request_and_settings_unchanged_and_emits_nothing(
    settings: Settings,
    key_function: IPKeyFunction,
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    request = make_request(headers=[(b"x-forwarded-for", b"198.51.100.20")])
    original_scope = dict(request.scope)
    original_settings = settings.model_dump()
    key_function(request, settings)
    assert request.scope == original_scope
    assert settings.model_dump() == original_settings
    assert not caplog.records
    output = capsys.readouterr()
    assert output.out == output.err == ""


def test_same_peer_and_secret_have_separate_operation_fingerprints(settings: Settings) -> None:
    request = make_request()

    assert get_sign_in_ip_key(request, settings) != get_password_recovery_ip_key(request, settings)


def test_request_path_cannot_choose_fingerprint_namespace(
    settings: Settings, key_function: IPKeyFunction
) -> None:
    recovery_request = make_request()
    sign_in_request = make_request()
    sign_in_request.scope["path"] = "/api/v1/account/sign-in"

    assert key_function(recovery_request, settings) == key_function(sign_in_request, settings)


def test_all_auth_operations_have_independent_fingerprints(settings: Settings) -> None:
    request = make_request()
    keys = {
        function(request, settings)
        for function in (
            get_password_recovery_ip_key,
            get_sign_in_ip_key,
            get_sign_up_ip_key,
            get_email_confirmation_ip_key,
            get_password_reset_ip_key,
        )
    }
    assert len(keys) == 5
