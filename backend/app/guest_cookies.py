"""Guest cookie policy shared by session endpoints."""

from datetime import UTC, datetime

from fastapi import Response
from pydantic import SecretStr

from app.config import Settings


def guest_cookie_name(settings: Settings) -> str:
    """Use the protected cookie prefix when HTTPS cookies are enabled."""
    if settings.guest_cookie_secure:
        return "__Host-askm6_guest"
    return "askm6_guest"


def set_guest_cookie(
    response: Response,
    token: SecretStr,
    expires_at: datetime,
    settings: Settings,
) -> None:
    """Set a persistent cookie using the database session's expiry."""
    if expires_at.utcoffset() is None:
        raise ValueError("Guest cookie expiry must include a timezone.")

    response.set_cookie(
        key=guest_cookie_name(settings),
        value=token.get_secret_value(),
        expires=expires_at.astimezone(UTC),
        path="/",
        secure=settings.guest_cookie_secure,
        httponly=True,
        samesite="lax",
    )
    response.headers["Cache-Control"] = "no-store"


def clear_guest_cookie(
    response: Response,
    settings: Settings,
) -> None:
    """Expire the cookie using the same name and scope."""
    response.delete_cookie(
        key=guest_cookie_name(settings),
        path="/",
        secure=settings.guest_cookie_secure,
        httponly=True,
        samesite="lax",
    )
    response.headers["Cache-Control"] = "no-store"
