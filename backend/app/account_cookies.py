"""Cookie policy for opaque account-session browser credentials."""

import re
from datetime import UTC, datetime

from fastapi import Request, Response
from pydantic import SecretStr

from app.config import Settings

_ACCOUNT_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}", re.ASCII)


def account_cookie_name(settings: Settings) -> str:
    """Select the HTTPS-protected name or the local development name."""
    if settings.account_cookie_secure:
        return "__Host-askm6_account"
    return "askm6_account"


def read_account_cookie(
    request: Request,
    settings: Settings,
) -> SecretStr | None:
    """Read a correctly shaped token; database authentication is still required."""
    raw_token = request.cookies.get(account_cookie_name(settings))

    if raw_token is None or _ACCOUNT_TOKEN.fullmatch(raw_token) is None:
        return None

    return SecretStr(raw_token)


def set_account_cookie(
    response: Response,
    token: SecretStr,
    expires_at: datetime,
    settings: Settings,
) -> None:
    """Issue a browser token only after its database transaction commits."""
    raw_token = token.get_secret_value()

    if _ACCOUNT_TOKEN.fullmatch(raw_token) is None:
        raise ValueError("Invalid account cookie token.")

    if expires_at.utcoffset() is None:
        raise ValueError("Account cookie expiry must include a timezone.")

    response.set_cookie(
        key=account_cookie_name(settings),
        value=raw_token,
        expires=expires_at.astimezone(UTC),
        path="/",
        secure=settings.account_cookie_secure,
        httponly=True,
        samesite="lax",
    )
    response.headers["Cache-Control"] = "no-store"


def clear_account_cookie(
    response: Response,
    settings: Settings,
) -> None:
    """Expire the cookie using the same name and scope as issuance."""
    response.delete_cookie(
        key=account_cookie_name(settings),
        path="/",
        secure=settings.account_cookie_secure,
        httponly=True,
        samesite="lax",
    )
    response.headers["Cache-Control"] = "no-store"
