"""Fingerprint contracts using synthetic secrets and in-memory requests."""

from secrets import token_hex

import pytest
from fastapi import Request
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict
from starlette.types import Message, Scope

from app.auth_rate_limit_keys import AuthRateLimitKeyUnavailable, get_password_recovery_ip_key
from app.client_ip import ClientIPUnavailable
from app.config import Settings


class IsolatedKeySettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


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


def test_versioned_fingerprint_matches_fixed_hmac_reference() -> None:
    # Public synthetic key, never a deployment credential. This reference fixes
    # the decoded-key format, canonical address and password-recovery domain.
    settings = Settings.model_construct(
        auth_rate_limit_hmac_secret=SecretStr(bytes(range(32)).hex())
    )
    result = get_password_recovery_ip_key(make_request(), settings)
    assert result.hex() == "094526c4a66b7525a9084b8ace9d060169e9d9358bf345e006d8660e5496de74"


def test_same_identity_has_a_stable_binary_database_key(settings: Settings) -> None:
    first = get_password_recovery_ip_key(make_request(), settings)
    second = get_password_recovery_ip_key(make_request(), settings)
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
    settings: Settings, first: str, second: str
) -> None:
    assert get_password_recovery_ip_key(make_request(first), settings) == (
        get_password_recovery_ip_key(make_request(second), settings)
    )


@pytest.mark.parametrize("other", ["192.0.2.13", "2001:db8::1", "::192.0.2.12"])
def test_distinct_addresses_have_distinct_keys(settings: Settings, other: str) -> None:
    assert get_password_recovery_ip_key(make_request(), settings) != (
        get_password_recovery_ip_key(make_request(other), settings)
    )


def test_changing_secret_changes_the_fingerprint(settings: Settings) -> None:
    other = settings.model_copy(update={"auth_rate_limit_hmac_secret": SecretStr(token_hex(32))})
    assert get_password_recovery_ip_key(make_request(), settings) != (
        get_password_recovery_ip_key(make_request(), other)
    )


def test_hex_letter_case_does_not_change_the_decoded_key(settings: Settings) -> None:
    lower = settings.model_copy(update={"auth_rate_limit_hmac_secret": SecretStr("ab" * 32)})
    upper = settings.model_copy(update={"auth_rate_limit_hmac_secret": SecretStr("AB" * 32)})
    assert get_password_recovery_ip_key(make_request(), lower) == (
        get_password_recovery_ip_key(make_request(), upper)
    )


def test_source_port_is_not_part_of_limiter_identity(settings: Settings) -> None:
    assert get_password_recovery_ip_key(make_request(port=12345), settings) == (
        get_password_recovery_ip_key(make_request(port=54321), settings)
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
    settings: Settings, headers: list[tuple[bytes, bytes]]
) -> None:
    assert get_password_recovery_ip_key(make_request(headers=headers), settings) == (
        get_password_recovery_ip_key(make_request(), settings)
    )


@pytest.mark.parametrize("include_client", [True, False])
def test_missing_peer_has_no_header_fallback(settings: Settings, include_client: bool) -> None:
    request = make_request(None, [(b"x-forwarded-for", b"192.0.2.12")])
    if not include_client:
        request.scope.pop("client")
    with pytest.raises(ClientIPUnavailable, match="^Client address is unavailable\\.$"):
        get_password_recovery_ip_key(request, settings)


@pytest.mark.parametrize("host", ["localhost", "", "192.0.2.12:1234", "fe80::1%eth0", "a" * 46])
def test_invalid_peer_is_rejected_without_exposing_input(settings: Settings, host: str) -> None:
    with pytest.raises(ClientIPUnavailable) as caught:
        get_password_recovery_ip_key(
            make_request(host, [(b"x-forwarded-for", b"192.0.2.12")]), settings
        )
    assert str(caught.value) == "Client address is unavailable."
    assert caught.value.__cause__ is None


@pytest.mark.parametrize(
    "secret", [None, "", "a" * 63, "a" * 65, "g" * 64, "Ａ" * 64, "a" * 31 + " " + "a" * 32]
)
def test_missing_or_bypassed_invalid_configuration_fails_closed(secret: str | None) -> None:
    # Exercise the helper's guard even when normal Settings validation is bypassed.
    settings = Settings.model_construct(
        auth_rate_limit_hmac_secret=SecretStr(secret) if secret is not None else None
    )
    with pytest.raises(AuthRateLimitKeyUnavailable) as caught:
        get_password_recovery_ip_key(make_request(), settings)
    assert str(caught.value) == "Authentication rate-limit key is unavailable."
    assert caught.value.__cause__ is None


def test_helper_leaves_request_and_settings_unchanged_and_emits_nothing(
    settings: Settings, caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    request = make_request(headers=[(b"x-forwarded-for", b"198.51.100.20")])
    original_scope = dict(request.scope)
    original_settings = settings.model_dump()
    get_password_recovery_ip_key(request, settings)
    assert request.scope == original_scope
    assert settings.model_dump() == original_settings
    assert not caplog.records
    output = capsys.readouterr()
    assert output.out == output.err == ""
