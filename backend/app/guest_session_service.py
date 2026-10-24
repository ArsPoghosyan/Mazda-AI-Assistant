"""Establish committed guest sessions with verification before new creation."""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

import httpx2
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncEngine

from app.auth_rate_limits import commit_guest_creation_attempt
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


class GuestCreationRateLimited(RuntimeError):
    """New guest creation was capped after committed accounting."""

    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__("Guest session creation is temporarily rate limited.")
        self.retry_after_seconds = retry_after_seconds


async def establish_guest_session(
    engine: AsyncEngine,
    *,
    browser_token: SecretStr | None,
    challenge_token: SecretStr | None,
    settings: Settings,
    client: httpx2.AsyncClient | None,
    creation_ip_key: Callable[[], bytes],
) -> EstablishedGuestSession:
    """Refresh an active session or verify a challenge before new creation.

    The peer key is resolved only after active-session reuse is ruled out.
    New attempts are committed before verification, even without a challenge;
    malformed request bodies have already been rejected by the HTTP boundary.
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

    if (
        client is None
        or settings.turnstile_secret_key is None
        or not settings.turnstile_allowed_hostnames
    ):
        raise TurnstileUnavailable("Human verification is unavailable.")

    decision = await commit_guest_creation_attempt(
        engine,
        creation_ip_key(),
        max_requests=settings.guest_creation_ip_max_requests,
        window_seconds=settings.guest_creation_ip_window_seconds,
    )
    if not decision.allowed:
        raise GuestCreationRateLimited(decision.retry_after_seconds)

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
