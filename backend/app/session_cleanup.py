"""Bounded local session cleanup; no provider revocation or history deletion."""

import asyncio

from sqlalchemy import delete, func, or_, select
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from app.models import AccountSession, GuestSession


def _validate_batch_size(batch_size: int) -> None:
    if type(batch_size) is not int or not 1 <= batch_size <= 1000:
        raise ValueError("Session cleanup batch size must be between 1 and 1000.")


async def delete_expired_guest_sessions(
    connection: AsyncConnection, *, batch_size: int = 100
) -> int:
    """Delete one expired guest batch; caller owns transaction and deadline.

    The count is provisional until commit. Skip locked rows so activity can finish.
    Revisit retention before introducing records owned by guest sessions.
    """
    _validate_batch_size(batch_size)
    if not connection.in_transaction():
        raise RuntimeError("Session cleanup requires an active transaction.")

    cutoff = func.statement_timestamp()
    expired = (
        select(GuestSession.id)
        .where(GuestSession.expires_at <= cutoff)
        .order_by(GuestSession.expires_at, GuestSession.id)
        .limit(batch_size)
        .with_for_update(skip_locked=True)
        .cte("expired_guest_sessions")
    )
    result = await connection.execute(
        delete(GuestSession)
        .where(GuestSession.id == expired.c.id, GuestSession.expires_at <= cutoff)
        .returning(GuestSession.id)
    )
    return len(result.all())


async def delete_expired_account_sessions(
    connection: AsyncConnection, *, batch_size: int = 100
) -> int:
    """Delete one expired application-session batch, preserving account profiles.

    Access-token expiry alone is insufficient: the session may still refresh.
    Caller owns transaction/deadline; the count is provisional until commit.
    """
    _validate_batch_size(batch_size)
    if not connection.in_transaction():
        raise RuntimeError("Session cleanup requires an active transaction.")

    cutoff = func.statement_timestamp()
    eligible = or_(
        AccountSession.idle_expires_at <= cutoff,
        AccountSession.absolute_expires_at <= cutoff,
    )
    expired = (
        select(AccountSession.id)
        .where(eligible)
        # Schema caps idle expiry at absolute expiry, so this orders the earliest
        # effective deadline in the same order as the existing idle-expiry index.
        .order_by(AccountSession.idle_expires_at, AccountSession.id)
        .limit(batch_size)
        .with_for_update(skip_locked=True)
        .cte("expired_account_sessions")
    )
    result = await connection.execute(
        delete(AccountSession)
        .where(AccountSession.id == expired.c.id, eligible)
        .returning(AccountSession.id)
    )
    return len(result.all())


async def _commit_cleanup(
    engine: AsyncEngine, *, timeout_seconds: float, batch_size: int, guest: bool
) -> int:
    _validate_batch_size(batch_size)
    if type(timeout_seconds) not in (int, float) or not 0 < timeout_seconds <= 30:
        raise ValueError("Session cleanup timeout must be greater than 0 and at most 30 seconds.")

    async with asyncio.timeout(timeout_seconds):
        async with engine.begin() as connection:
            delete_batch = (
                delete_expired_guest_sessions if guest else delete_expired_account_sessions
            )
            deleted = await delete_batch(connection, batch_size=batch_size)
    return deleted


async def commit_expired_guest_session_cleanup(
    engine: AsyncEngine, *, timeout_seconds: float, batch_size: int = 100
) -> int:
    """Commit one guest batch under a deadline, including acquisition and release.

    No retries; errors/cancellation propagate. Interrupted commit may have taken
    effect, so a timeout does not establish whether deletion was rolled back.
    """
    return await _commit_cleanup(
        engine, timeout_seconds=timeout_seconds, batch_size=batch_size, guest=True
    )


async def commit_expired_account_session_cleanup(
    engine: AsyncEngine, *, timeout_seconds: float, batch_size: int = 100
) -> int:
    """Commit one local account-session batch; never decrypt or revoke credentials.

    The deadline includes acquisition/commit/release. Errors/cancellation propagate
    without retries; an interrupted commit may already have taken effect.
    """
    return await _commit_cleanup(
        engine, timeout_seconds=timeout_seconds, batch_size=batch_size, guest=False
    )
