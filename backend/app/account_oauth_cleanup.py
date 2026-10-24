"""Bounded cleanup of expired pending Google login attempts."""

import asyncio

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from app.models import OAuthLoginAttempt


async def delete_expired_oauth_login_attempts(
    connection: AsyncConnection, *, batch_size: int = 100
) -> int:
    """Delete one expired batch; its count is provisional until the caller commits."""
    if type(batch_size) is not int or not 1 <= batch_size <= 1000:
        raise ValueError("OAuth cleanup batch size must be between 1 and 1000.")
    if not connection.in_transaction():
        raise RuntimeError("OAuth cleanup requires an active transaction.")

    # Statement time stays fresh even if the caller began its transaction earlier.
    cutoff = func.statement_timestamp()
    eligible = (
        OAuthLoginAttempt.provider == "google",
        OAuthLoginAttempt.purpose == "sign_in",
        OAuthLoginAttempt.expires_at <= cutoff,
    )
    expired = (
        select(OAuthLoginAttempt.id)
        .where(*eligible)
        .order_by(OAuthLoginAttempt.expires_at, OAuthLoginAttempt.id)
        .limit(batch_size)
        .cte("expired_oauth_login_attempts")
    )
    # SELECT locking clauses require UPDATE privilege. Pending attempts are
    # intentionally immutable to the runtime role, so rely on DELETE's own row
    # locks and require the caller's deadline to bound any contention.
    result = await connection.execute(
        delete(OAuthLoginAttempt)
        .where(OAuthLoginAttempt.id == expired.c.id, *eligible)
        .returning(OAuthLoginAttempt.id)
    )
    return len(result.all())


async def commit_expired_oauth_login_attempt_cleanup(
    engine: AsyncEngine, *, timeout_seconds: float, batch_size: int = 100
) -> int:
    """Commit one batch under a deadline; propagate errors/cancellation without retries.

    No credentials are decrypted or sent to a provider. Cancellation during
    commit cannot establish whether a database change already took effect.
    """
    if type(batch_size) is not int or not 1 <= batch_size <= 1000:
        raise ValueError("OAuth cleanup batch size must be between 1 and 1000.")
    if type(timeout_seconds) not in (int, float) or not 0 < timeout_seconds <= 30:
        raise ValueError("OAuth cleanup timeout must be greater than 0 and at most 30 seconds.")

    async with asyncio.timeout(timeout_seconds):
        async with engine.begin() as connection:
            deleted = await delete_expired_oauth_login_attempts(connection, batch_size=batch_size)
    return deleted
