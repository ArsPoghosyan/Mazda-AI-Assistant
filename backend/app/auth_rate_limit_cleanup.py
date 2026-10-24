"""Bounded cleanup of expired authentication rate-limit records."""

import asyncio
from typing import Literal

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from app.models import AuthRateLimit


async def _delete_expired_limits(
    connection: AsyncConnection,
    *,
    batch_size: int,
    purposes: tuple[
        Literal[
            "password_recovery",
            "sign_in",
            "sign_up",
            "email_confirmation",
            "password_reset",
            "guest_creation",
            "google_start",
        ],
        ...,
    ],
) -> int:
    """Delete one batch; the caller owns commit, rollback and its deadline.

    The returned count is provisional until the transaction commits.
    Locked records are skipped so active accounting can finish.
    """
    if type(batch_size) is not int or not 1 <= batch_size <= 1000:
        raise ValueError("Cleanup batch size must be between 1 and 1000.")

    if not connection.in_transaction():
        raise RuntimeError("Rate-limit cleanup requires an active transaction.")

    # Stable for this statement, unlike transaction-start time, which may be old.
    cutoff = func.statement_timestamp()

    expired = (
        select(AuthRateLimit.purpose, AuthRateLimit.key_hash)
        .where(
            AuthRateLimit.purpose.in_(purposes),
            AuthRateLimit.expires_at <= cutoff,
        )
        .order_by(AuthRateLimit.expires_at, AuthRateLimit.key_hash, AuthRateLimit.purpose)
        .limit(batch_size)
        .with_for_update(skip_locked=True)
        .cte("expired_auth_rate_limits")
    )

    result = await connection.execute(
        delete(AuthRateLimit)
        .where(
            AuthRateLimit.purpose == expired.c.purpose,
            AuthRateLimit.key_hash == expired.c.key_hash,
            AuthRateLimit.expires_at <= cutoff,
        )
        .returning(AuthRateLimit.key_hash)
    )
    return len(result.all())


async def delete_expired_password_recovery_limits(
    connection: AsyncConnection,
    *,
    batch_size: int = 100,
) -> int:
    """Delete only expired recovery rows; the caller owns commit and deadline."""
    return await _delete_expired_limits(
        connection, batch_size=batch_size, purposes=("password_recovery",)
    )


async def delete_expired_auth_rate_limits(
    connection: AsyncConnection,
    *,
    batch_size: int = 100,
) -> int:
    """Delete one shared batch of expired authentication limiter records."""
    return await _delete_expired_limits(
        connection,
        batch_size=batch_size,
        purposes=(
            "password_recovery",
            "sign_in",
            "sign_up",
            "email_confirmation",
            "password_reset",
            "guest_creation",
            "google_start",
        ),
    )


async def _commit_cleanup(
    engine: AsyncEngine,
    *,
    timeout_seconds: float,
    batch_size: int,
    shared: bool,
) -> int:
    """Run one batch and return its count only after successful commit.

    Errors and cancellation propagate without retries. A timeout during
    commit does not prove that the database changes were rolled back.
    """
    if type(batch_size) is not int or not 1 <= batch_size <= 1000:
        raise ValueError("Cleanup batch size must be between 1 and 1000.")

    if type(timeout_seconds) not in (int, float) or not 0 < timeout_seconds <= 30:
        raise ValueError("Cleanup timeout must be greater than 0 and at most 30 seconds.")

    async with asyncio.timeout(timeout_seconds):
        async with engine.begin() as connection:
            delete_batch = (
                delete_expired_auth_rate_limits
                if shared
                else delete_expired_password_recovery_limits
            )
            deleted = await delete_batch(
                connection,
                batch_size=batch_size,
            )

    return deleted


async def commit_expired_password_recovery_cleanup(
    engine: AsyncEngine,
    *,
    timeout_seconds: float,
    batch_size: int = 100,
) -> int:
    """Commit one recovery-only batch under the caller-supplied deadline."""
    return await _commit_cleanup(
        engine, timeout_seconds=timeout_seconds, batch_size=batch_size, shared=False
    )


async def commit_expired_auth_rate_limit_cleanup(
    engine: AsyncEngine,
    *,
    timeout_seconds: float,
    batch_size: int = 100,
) -> int:
    """Commit one shared authentication limiter batch under the supplied deadline."""
    return await _commit_cleanup(
        engine, timeout_seconds=timeout_seconds, batch_size=batch_size, shared=True
    )
