"""Short-lived browser binding for pending Google login attempts."""

import re
from datetime import UTC, datetime

from fastapi import Request, Response
from pydantic import SecretStr

from app.account_oauth_material import InvalidOAuthLoginMaterial
from app.config import Settings

_BROWSER_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}", re.ASCII)


def oauth_cookie_name(settings: Settings) -> str:
    if settings.account_cookie_secure:
        return "__Host-askm6_oauth"
    return "askm6_oauth"


def read_oauth_cookie(request: Request, settings: Settings) -> SecretStr | None:
    """Reject malformed or duplicate bindings instead of treating them as absent."""
    name = oauth_cookie_name(settings)
    values = []
    for header in request.headers.getlist("cookie"):
        for part in header.split(";"):
            key, separator, value = part.lstrip(" \t").partition("=")
            if key == name:
                if not separator:
                    raise InvalidOAuthLoginMaterial("Invalid OAuth login material.")
                values.append(value)

    if not values:
        return None
    if len(values) != 1 or _BROWSER_TOKEN.fullmatch(values[0]) is None:
        raise InvalidOAuthLoginMaterial("Invalid OAuth login material.")
    return SecretStr(values[0])


def set_oauth_cookie(
    response: Response,
    token: SecretStr,
    expires_at: datetime,
    settings: Settings,
) -> None:
    """Issue binding only after the pending-attempt transaction commits."""
    raw_token = token.get_secret_value()
    if _BROWSER_TOKEN.fullmatch(raw_token) is None:
        raise ValueError("Invalid OAuth cookie token.")
    if expires_at.utcoffset() is None:
        raise ValueError("OAuth cookie expiry must include a timezone.")

    response.set_cookie(
        key=oauth_cookie_name(settings),
        value=raw_token,
        expires=expires_at.astimezone(UTC),
        path="/",
        secure=settings.account_cookie_secure,
        httponly=True,
        samesite="lax",
    )
    response.headers["Cache-Control"] = "no-store"


def clear_oauth_cookie(response: Response, settings: Settings) -> None:
    """Clear only the transient binding, preserving account and guest cookies."""
    response.delete_cookie(
        key=oauth_cookie_name(settings),
        path="/",
        secure=settings.account_cookie_secure,
        httponly=True,
        samesite="lax",
    )
    response.headers["Cache-Control"] = "no-store"
