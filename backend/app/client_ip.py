"""Validated client addresses for application-side abuse controls."""

from ipaddress import IPv6Address, ip_address

from fastapi import Request


class ClientIPUnavailable(RuntimeError):
    """The request has no usable server-provided client address."""


def get_client_ip(request: Request) -> str:
    """Normalize the ASGI client address without reading forwarding headers."""
    client = request.client

    if client is None:
        raise ClientIPUnavailable("Client address is unavailable.")

    host = client.host

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
