"""Protected client-IP keys for authentication abuse controls."""

from hmac import digest

from fastapi import Request

from app.client_ip import get_client_ip
from app.config import Settings

_PASSWORD_RECOVERY_IP_CONTEXT = b"askm6:auth-rate-limit:v1:password_recovery:ip:"
_SIGN_IN_IP_CONTEXT = b"askm6:auth-rate-limit:v1:sign_in:ip:"
_SIGN_UP_IP_CONTEXT = b"askm6:auth-rate-limit:v1:sign_up:ip:"
_EMAIL_CONFIRMATION_IP_CONTEXT = b"askm6:auth-rate-limit:v1:email_confirmation:ip:"
_PASSWORD_RESET_IP_CONTEXT = b"askm6:auth-rate-limit:v1:password_reset:ip:"


class AuthRateLimitKeyUnavailable(RuntimeError):
    """The backend cannot safely produce a rate-limit key."""


def _get_ip_key(
    request: Request,
    settings: Settings,
    *,
    context: bytes,
) -> bytes:
    """Validate the secret and hash a canonical peer address in a fixed namespace."""
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
    message = context + client_ip.encode("ascii")

    return digest(key, message, "sha256")


def get_password_recovery_ip_key(
    request: Request,
    settings: Settings,
) -> bytes:
    """Return the recovery fingerprint without storing the client address."""
    return _get_ip_key(request, settings, context=_PASSWORD_RECOVERY_IP_CONTEXT)


def get_sign_in_ip_key(
    request: Request,
    settings: Settings,
) -> bytes:
    """Return a sign-in fingerprint distinct from the recovery namespace."""
    return _get_ip_key(request, settings, context=_SIGN_IN_IP_CONTEXT)


def get_sign_up_ip_key(request: Request, settings: Settings) -> bytes:
    """Return a registration fingerprint distinct from sign-in and recovery."""
    return _get_ip_key(request, settings, context=_SIGN_UP_IP_CONTEXT)


def get_email_confirmation_ip_key(request: Request, settings: Settings) -> bytes:
    """Return a confirmation fingerprint independent of other auth operations."""
    return _get_ip_key(request, settings, context=_EMAIL_CONFIRMATION_IP_CONTEXT)


def get_password_reset_ip_key(request: Request, settings: Settings) -> bytes:
    """Return a password-reset fingerprint independent of email recovery requests."""
    return _get_ip_key(request, settings, context=_PASSWORD_RESET_IP_CONTEXT)
