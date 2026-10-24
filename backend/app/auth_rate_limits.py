"""Atomic rolling-window accounting for recovery and sign-in attempts."""

from dataclasses import dataclass
from datetime import datetime, timedelta
from math import ceil
from typing import Literal

from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from app.models import AuthRateLimit


class AuthRateLimitUnavailable(RuntimeError):
    """The backend cannot safely decide whether an attempt is allowed."""


@dataclass(frozen=True, slots=True)
class AuthRateLimitDecision:
    """Internal decision, usable only after its transaction commits."""

    allowed: bool
    checked_at: datetime
    retry_after_seconds: int
    retry_at: datetime | None


async def _database_now(connection: AsyncConnection) -> datetime:
    now = await connection.scalar(select(func.clock_timestamp()))
    if not isinstance(now, datetime) or now.utcoffset() is None:
        raise AuthRateLimitUnavailable("Authentication rate limit is unavailable.")
    return now


async def _count_attempt(
    connection: AsyncConnection,
    key_hash: bytes,
    *,
    purpose: Literal["password_recovery", "sign_in"],
    max_requests: int,
    window_seconds: int,
) -> AuthRateLimitDecision:
    """Count under a row lock; the caller owns commit/rollback and its deadline.

    Allowed attempts remain counted regardless of later provider outcomes.
    Blocked attempts leave stored state unchanged. Exceptions must end the
    transaction; a provisional decision must never escape a failed commit.
    """
    if (
        not isinstance(key_hash, bytes)
        or len(key_hash) != 32
        or type(max_requests) is not int
        or not 1 <= max_requests <= 1000
        or type(window_seconds) is not int
        or not 60 <= window_seconds <= 86400
    ):
        raise ValueError("Invalid authentication rate-limit parameters.")
    if not connection.in_transaction():
        raise RuntimeError("Authentication rate limiting requires an active transaction.")

    window = timedelta(seconds=window_seconds)
    await connection.execute(
        insert(AuthRateLimit)
        .values(
            purpose=purpose,
            key_hash=key_hash,
            request_times=[],
            expires_at=func.clock_timestamp() + window,
        )
        .on_conflict_do_nothing(index_elements=[AuthRateLimit.purpose, AuthRateLimit.key_hash])
    )
    identity = (
        AuthRateLimit.purpose == purpose,
        AuthRateLimit.key_hash == key_hash,
    )
    row = (
        await connection.execute(select(AuthRateLimit).where(*identity).with_for_update())
    ).one_or_none()
    if row is None:
        # A concurrent cleanup may have removed the row before SELECT locked it.
        raise AuthRateLimitUnavailable("Authentication rate limit is unavailable.")

    # Transaction/statement start time can predate a lock wait. Read time only
    # after the row lock is held so an expired attempt cannot extend a block.
    now = await _database_now(connection)
    cutoff = now - window
    times: list[datetime] = sorted(stamp for stamp in row.request_times if stamp > cutoff)

    if len(times) >= max_requests:
        # If a configured cap was lowered, enough attempts must expire to get
        # below the new cap, rather than merely waiting for the oldest one.
        retry_at = times[len(times) - max_requests] + window
        return AuthRateLimitDecision(
            allowed=False,
            checked_at=now,
            retry_after_seconds=max(1, ceil((retry_at - now).total_seconds())),
            retry_at=retry_at,
        )

    times = sorted([*times, now])
    await connection.execute(
        update(AuthRateLimit)
        .where(*identity)
        .values(request_times=times, expires_at=times[-1] + window)
    )
    return AuthRateLimitDecision(allowed=True, checked_at=now, retry_after_seconds=0, retry_at=None)


async def count_password_recovery_attempt(
    connection: AsyncConnection,
    key_hash: bytes,
    *,
    max_requests: int,
    window_seconds: int,
) -> AuthRateLimitDecision:
    """Count recovery under its row lock; the caller owns commit and deadline."""
    return await _count_attempt(
        connection,
        key_hash,
        purpose="password_recovery",
        max_requests=max_requests,
        window_seconds=window_seconds,
    )


async def count_sign_in_attempt(
    connection: AsyncConnection,
    key_hash: bytes,
    *,
    max_requests: int,
    window_seconds: int,
) -> AuthRateLimitDecision:
    """Count sign-in under its row lock; the caller owns commit and deadline."""
    return await _count_attempt(
        connection,
        key_hash,
        purpose="sign_in",
        max_requests=max_requests,
        window_seconds=window_seconds,
    )


async def commit_password_recovery_attempt(
    engine: AsyncEngine,
    key_hash: bytes,
    *,
    max_requests: int,
    window_seconds: int,
) -> AuthRateLimitDecision:
    """Release the transaction successfully before returning a decision.

    No provider work or automatic retries run here. Database errors and
    cancellation propagate; the HTTP boundary must fail closed on failure.
    """
    async with engine.begin() as connection:
        decision = await count_password_recovery_attempt(
            connection,
            key_hash,
            max_requests=max_requests,
            window_seconds=window_seconds,
        )
    return decision


async def commit_sign_in_attempt(
    engine: AsyncEngine,
    key_hash: bytes,
    *,
    max_requests: int,
    window_seconds: int,
) -> AuthRateLimitDecision:
    """Return the sign-in decision only after commit and connection release.

    No provider calls or retries run here. Errors and cancellation propagate;
    callers must supply a deadline and fail closed when accounting fails.
    """
    async with engine.begin() as connection:
        decision = await count_sign_in_attempt(
            connection,
            key_hash,
            max_requests=max_requests,
            window_seconds=window_seconds,
        )
    return decision
