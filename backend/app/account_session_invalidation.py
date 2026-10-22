"""Invalidate account-owned application sessions in a caller-owned transaction."""

from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncConnection

from app.account_tokens import VerifiedAccount
from app.models import AccountSession


async def invalidate_account_sessions(
    connection: AsyncConnection,
    account: VerifiedAccount,
) -> int:
    """Delete sessions for a backend-verified account and return their count.

    The caller must establish recovery authorization before calling this helper.
    The caller owns commit/rollback; the result is provisional until commit.

    This deletes only application-session rows. It does not delete the account,
    guest sessions, or revoke provider credentials. Concurrent session creation
    must be coordinated by the reset service.
    """
    if not connection.in_transaction():
        raise RuntimeError("Account-session invalidation requires an active transaction.")

    result = await connection.execute(
        delete(AccountSession)
        .where(AccountSession.user_id == account.user_id)
        .returning(AccountSession.id)
    )

    return len(result.scalars().all())
