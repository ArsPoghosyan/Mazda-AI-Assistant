"""Protected client-IP keys for authentication abuse controls."""

from hmac import digest

from fastapi import Request

from app.client_ip import get_client_ip
from app.config import Settings

_PASSWORD_RECOVERY_IP_CONTEXT = b"askm6:auth-rate-limit:v1:password_recovery:ip:"


class AuthRateLimitKeyUnavailable(RuntimeError):
    """The backend cannot safely produce a rate-limit key."""


def get_password_recovery_ip_key(
    request: Request,
    settings: Settings,
) -> bytes:
    """Return a 32-byte fingerprint without storing the client address."""
    secret = settings.auth_rate_limit_hmac_secret

    if secret is None:
        raise AuthRateLimitKeyUnavailable("Authentication rate-limit key is unavailable.")

    raw_secret = secret.get_secret_value()
    if len(raw_secret) != 64 or any(
        character not in "0123456789abcdefABCDEF" for character in raw_secret
    ):
        raise AuthRateLimitKeyUnavailable("Authentication rate-limit key is unavailable.")

    key = bytes.fromhex(raw_secret)
    client_ip = get_client_ip(request)
    message = _PASSWORD_RECOVERY_IP_CONTEXT + client_ip.encode("ascii")

    return digest(key, message, "sha256")
