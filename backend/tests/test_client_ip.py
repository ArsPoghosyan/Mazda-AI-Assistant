"""Client-address normalization without network calls or proxy-header trust."""

import pytest
from fastapi import Request
from pydantic import SecretStr, ValidationError
from pydantic_settings import SettingsConfigDict
from starlette.types import Scope

from app.client_ip import ClientIPUnavailable, get_client_ip
from app.config import Settings


def make_request(
    host: str | None,
    headers: list[tuple[bytes, bytes]] | None = None,
    port: int = 12345,
) -> Request:
    scope: Scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/v1/account/password-recovery",
        "headers": headers if headers is not None else [],
        "client": (host, port) if host is not None else None,
    }
    return Request(scope)


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("192.0.2.12", "192.0.2.12"),
        ("127.0.0.1", "127.0.0.1"),
        ("10.0.0.25", "10.0.0.25"),
        ("::1", "::1"),
        ("2001:0DB8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
        ("2001:db8::1", "2001:db8::1"),
        ("::ffff:192.0.2.12", "192.0.2.12"),
        ("0:0:0:0:0:FFFF:C000:020C", "192.0.2.12"),
        ("::192.0.2.12", "::c000:20c"),
        (
            "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        ),
    ],
)
def test_valid_client_addresses_have_a_canonical_identity(host: str, expected: str) -> None:
    assert get_client_ip(make_request(host)) == expected


def test_source_ports_do_not_split_the_same_ip_identity() -> None:
    first = make_request("192.0.2.12", port=12345)
    second = make_request("192.0.2.12", port=54321)

    assert get_client_ip(first) == get_client_ip(second)


@pytest.mark.parametrize(
    "headers",
    [
        [(b"x-forwarded-for", b"198.51.100.20")],
        [(b"x-forwarded-for", b"198.51.100.20, 203.0.113.30")],
        [
            (b"x-forwarded-for", b"198.51.100.20"),
            (b"x-forwarded-for", b"203.0.113.30"),
        ],
        [(b"forwarded", b'for="[2001:db8::99]";proto=https')],
        [(b"cf-connecting-ip", b"198.51.100.20")],
        [(b"true-client-ip", b"198.51.100.20")],
        [(b"x-real-ip", b"198.51.100.20")],
        [(b"x-forwarded-for", b"invalid-address")],
    ],
)
def test_forwarding_headers_cannot_replace_the_asgi_client_address(
    headers: list[tuple[bytes, bytes]],
) -> None:
    request = make_request("192.0.2.12", headers)

    assert get_client_ip(request) == "192.0.2.12"


@pytest.mark.parametrize("include_client", [False, True])
def test_missing_client_has_no_forwarded_header_fallback(include_client: bool) -> None:
    request = make_request(
        None,
        [
            (b"x-forwarded-for", b"198.51.100.20"),
            (b"forwarded", b"for=198.51.100.20"),
            (b"cf-connecting-ip", b"198.51.100.20"),
        ],
    )
    if not include_client:
        request.scope.pop("client")

    with pytest.raises(ClientIPUnavailable, match=r"^Client address is unavailable\.$"):
        get_client_ip(request)


@pytest.mark.parametrize(
    "host",
    [
        "",
        "localhost",
        "unknown",
        "192.0.2.12:12345",
        "[2001:db8::1]",
        "[2001:db8::1]:12345",
        " 192.0.2.12",
        "192.0.2.12 ",
        "192.0.2.12\n",
        "192.0.2.012",
        "999.0.2.12",
        "https://192.0.2.12",
        "2001:db8::g",
        "fe80::1%eth0",
        "fe80::1%1",
        "::ffff:192.0.2.12%eth0",
        "\x00192.0.2.12",
        "x" * 46,
    ],
)
def test_invalid_client_addresses_are_unavailable_without_exposing_input(host: str) -> None:
    request = make_request(host, [(b"x-forwarded-for", b"198.51.100.20")])

    with pytest.raises(ClientIPUnavailable) as caught:
        get_client_ip(request)

    assert str(caught.value) == "Client address is unavailable."
    assert caught.value.__cause__ is None


PROXY_SECRET = "ab" * 32  # Public synthetic fixture, never a deployment key.


@pytest.fixture
def proxy_settings() -> Settings:
    return Settings.model_construct(
        auth_proxy_trust_enabled=True,
        auth_proxy_shared_secret=SecretStr(PROXY_SECRET),
    )


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        ("198.51.100.20", "198.51.100.20"),
        ("::ffff:198.51.100.20", "198.51.100.20"),
        ("2001:0DB8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
    ],
)
def test_authenticated_proxy_assertion_replaces_peer_without_reading_other_headers(
    proxy_settings: Settings, address: str, expected: str
) -> None:
    request = make_request(
        None,
        [
            (b"x-askm6-proxy-secret", PROXY_SECRET.upper().encode()),
            (b"x-askm6-client-ip", address.encode()),
            (b"x-forwarded-for", b"203.0.113.99"),
            (b"cf-connecting-ip", b"203.0.113.98"),
        ],
    )
    assert get_client_ip(request, settings=proxy_settings) == expected


@pytest.mark.parametrize(
    "headers",
    [
        [],
        [(b"cf-connecting-ip", b"198.51.100.20")],
        [(b"x-askm6-client-ip", b"198.51.100.20")],
        [(b"x-askm6-proxy-secret", PROXY_SECRET.encode())],
        [(b"x-askm6-proxy-secret", b"00" * 32), (b"x-askm6-client-ip", b"198.51.100.20")],
        [(b"x-askm6-proxy-secret", b"a" * 65), (b"x-askm6-client-ip", b"198.51.100.20")],
        [(b"x-askm6-proxy-secret", b"\xff" * 64), (b"x-askm6-client-ip", b"198.51.100.20")],
        [
            (b"x-askm6-proxy-secret", PROXY_SECRET.encode()),
            (b"x-askm6-proxy-secret", PROXY_SECRET.encode()),
            (b"x-askm6-client-ip", b"198.51.100.20"),
        ],
        [
            (b"x-askm6-proxy-secret", PROXY_SECRET.encode()),
            (b"x-askm6-client-ip", b"198.51.100.20"),
            (b"x-askm6-client-ip", b"198.51.100.20"),
        ],
        *(
            [(b"x-askm6-proxy-secret", PROXY_SECRET.encode()), (b"x-askm6-client-ip", address)]
            for address in [
                b"",
                b"198.51.100.20, 203.0.113.30",
                b"198.51.100.20:1234",
                b"[2001:db8::1]",
                b"fe80::1%eth0",
                b" 198.51.100.20",
                b"999.1.1.1",
                b"x" * 46,
                b"\xff",
            ]
        ),
    ],
)
def test_proxy_mode_never_falls_back_to_peer_or_standard_headers(
    proxy_settings: Settings, headers: list[tuple[bytes, bytes]]
) -> None:
    request = make_request("192.0.2.12", headers)
    with pytest.raises(ClientIPUnavailable) as caught:
        get_client_ip(request, settings=proxy_settings)
    assert str(caught.value) == "Client address is unavailable."
    assert PROXY_SECRET not in str(caught.value)


@pytest.mark.parametrize("secret", [None, "bad", "a" * 65, "\u00e9" * 64])
def test_missing_or_mutated_proxy_config_fails_closed(secret: str | None) -> None:
    settings = Settings.model_construct(
        auth_proxy_trust_enabled=True,
        auth_proxy_shared_secret=None if secret is None else SecretStr(secret),
    )
    with pytest.raises(ClientIPUnavailable):
        get_client_ip(
            make_request(
                "192.0.2.12",
                [
                    (b"x-askm6-proxy-secret", PROXY_SECRET.encode()),
                    (b"x-askm6-client-ip", b"198.51.100.20"),
                ],
            ),
            settings=settings,
        )


def test_disabled_proxy_mode_ignores_even_authenticated_assertions(
    proxy_settings: Settings,
) -> None:
    proxy_settings.auth_proxy_trust_enabled = False
    request = make_request(
        "192.0.2.12",
        [
            (b"x-askm6-proxy-secret", PROXY_SECRET.encode()),
            (b"x-askm6-client-ip", b"198.51.100.20"),
        ],
    )
    assert get_client_ip(request, settings=proxy_settings) == "192.0.2.12"
    assert get_client_ip(request) == "192.0.2.12"


class IsolatedProxySettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


def test_proxy_settings_default_off_and_secret_is_redacted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AUTH_PROXY_TRUST_ENABLED", raising=False)
    monkeypatch.delenv("AUTH_PROXY_SHARED_SECRET", raising=False)
    settings = IsolatedProxySettings(auth_proxy_shared_secret=SecretStr(PROXY_SECRET))
    assert settings.auth_proxy_trust_enabled is False
    assert PROXY_SECRET not in repr(settings)


@pytest.mark.parametrize(
    "secret", ["short", "a" * 63, "a" * 65, "g" * 64, "\u00e9" * 64, "ab " * 32]
)
def test_proxy_settings_reject_invalid_secrets_without_echoing_input(secret: str) -> None:
    with pytest.raises(ValidationError) as caught:
        IsolatedProxySettings(auth_proxy_shared_secret=SecretStr(secret))
    assert secret not in str(caught.value)
