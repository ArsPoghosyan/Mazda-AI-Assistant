"""Commit OAuth attempt changes before exposing results to the caller."""

from sqlalchemy.ext.asyncio import AsyncEngine

from app.account_oauth_attempts import (
    ConsumedOAuthLoginAttempt,
    CreatedOAuthLoginAttempt,
    consume_oauth_login_attempt,
    create_oauth_login_attempt,
    replace_oauth_login_attempt,
)
from app.config import Settings


async def create_oauth_login_attempt_transaction(
    engine: AsyncEngine,
    settings: Settings,
) -> CreatedOAuthLoginAttempt:
    """Return pending cookie material only after successful commit and release."""
    async with engine.begin() as connection:
        created = await create_oauth_login_attempt(connection, settings)

    return created


async def replace_oauth_login_attempt_transaction(
    engine: AsyncEngine,
    settings: Settings,
    previous_token: str | None,
) -> CreatedOAuthLoginAttempt:
    """Commit replacement before returning new cookie material; never retry."""
    async with engine.begin() as connection:
        created = await replace_oauth_login_attempt(connection, settings, previous_token)

    return created


async def consume_oauth_login_attempt_transaction(
    engine: AsyncEngine,
    token: str | None,
) -> ConsumedOAuthLoginAttempt:
    """Commit deletion before returning verifier ciphertext; never retry.

    This does not decrypt, exchange a code or authenticate an account. Database
    errors and cancellation propagate without returning a result. An uncertain
    commit can already have taken effect: a caller must not replay the operation
    or contact the provider based on a failed/uncertain completion.
    """
    async with engine.begin() as connection:
        consumed = await consume_oauth_login_attempt(connection, token)

    return consumed
