"""Validated client addresses for application-side abuse controls."""

from hmac import compare_digest
from ipaddress import IPv6Address, ip_address

from fastapi import Request

from app.config import Settings


class ClientIPUnavailable(RuntimeError):
    """The request has no usable server-provided client address."""


def _normalize(host: str) -> str:
    # Reject scoped IPv6 addresses and oversized or malformed input.
    if len(host) > 45 or "%" in host:
        raise ClientIPUnavailable("Client address is unavailable.")

    try:
        address = ip_address(host)
    except ValueError:
        raise ClientIPUnavailable("Client address is unavailable.") from None

    # Give IPv4 and its IPv6-mapped spelling the same limiter identity.
    if isinstance(address, IPv6Address) and address.ipv4_mapped is not None:
        return str(address.ipv4_mapped)

    return str(address)


def _proxy_ip(request: Request, settings: Settings) -> str:
    secret = settings.auth_proxy_shared_secret
    supplied = request.headers.getlist("x-askm6-proxy-secret")
    addresses = request.headers.getlist("x-askm6-client-ip")
    if secret is None or len(supplied) != 1 or len(addresses) != 1:
        raise ClientIPUnavailable("Client address is unavailable.")

    expected = secret.get_secret_value()
    actual = supplied[0]
    if any(
        len(value) != 64 or any(character not in "0123456789abcdefABCDEF" for character in value)
        for value in (expected, actual)
    ):
        raise ClientIPUnavailable("Client address is unavailable.")
    if not compare_digest(bytes.fromhex(expected), bytes.fromhex(actual)):
        raise ClientIPUnavailable("Client address is unavailable.")
    return _normalize(addresses[0])


def get_client_ip(request: Request, *, settings: Settings | None = None) -> str:
    """Use the peer locally, or require an authenticated proxy assertion when enabled."""
    if settings is not None and settings.auth_proxy_trust_enabled:
        return _proxy_ip(request, settings)
    client = request.client
    if client is None:
        raise ClientIPUnavailable("Client address is unavailable.")
    return _normalize(client.host)
