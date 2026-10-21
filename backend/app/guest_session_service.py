"""Establish committed guest sessions with verification before new creation."""

from dataclasses import dataclass
from datetime import datetime

import httpx2
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncEngine

from app.config import Settings
from app.guest_sessions import create_guest_session, refresh_guest_session
from app.turnstile import (
    TurnstileRejected,
    TurnstileUnavailable,
    verify_turnstile_token,
)


@dataclass(frozen=True, slots=True)
class EstablishedGuestSession:
    """Internal cookie material returned only after database commit."""

    token: SecretStr
    expires_at: datetime


async def establish_guest_session(
    engine: AsyncEngine,
    *,
    browser_token: SecretStr | None,
    challenge_token: SecretStr | None,
    settings: Settings,
    client: httpx2.AsyncClient | None,
) -> EstablishedGuestSession:
    """Refresh an active session or verify a challenge before new creation.

    Verification runs without an open database transaction. The caller must
    bound the complete operation with a deadline and handle failures.
    Does not issue cookies, map HTTP errors, or retry.
    """
    if browser_token is not None:
        async with engine.begin() as connection:
            active = await refresh_guest_session(
                connection,
                browser_token.get_secret_value(),
                settings,
            )

        if active is not None:
            return EstablishedGuestSession(
                token=browser_token,
                expires_at=active.expires_at,
            )

    if client is None:
        raise TurnstileUnavailable("Human verification is unavailable.")

    if challenge_token is None:
        raise TurnstileRejected("Human verification is required.")

    await verify_turnstile_token(
        challenge_token,
        expected_action="guest_start",
        settings=settings,
        client=client,
    )

    async with engine.begin() as connection:
        created = await create_guest_session(connection, settings)

    return EstablishedGuestSession(
        token=created.token,
        expires_at=created.expires_at,
    )
