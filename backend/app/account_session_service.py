"""Coordinate account-session authentication within caller-owned transactions."""

from datetime import timedelta

import httpx2
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncConnection

from app.account_auth import AccountAuthenticationUnavailable
from app.account_key_cache import AccountKeyCache
from app.account_session_auth import (
    AuthenticatedAccountSession,
    authenticate_stored_account_session,
    load_locked_account_session,
)
from app.account_session_refresh import (
    refresh_locked_account_tokens,
    store_verified_account_refresh,
)
from app.config import Settings


async def authenticate_account_session(
    connection: AsyncConnection,
    token: SecretStr | None,
    *,
    settings: Settings,
    client: httpx2.AsyncClient,
    key_cache: AccountKeyCache | None,
) -> AuthenticatedAccountSession | None:
    """Authenticate using current credentials or one provider refresh attempt.

    The caller must supply an active transaction and retain it throughout this
    operation. Commit successfully before using the result outside that
    transaction.

    Provider rejection, unavailability, cancellation, and database errors
    propagate. No automatic retries or fallback after verification failure
    are performed.
    """
    session = await load_locked_account_session(connection, token)
    if session is None:
        return None

    # Detect this known configuration failure before a provider exchange
    # could rotate credentials.
    try:
        timedelta(days=settings.account_session_inactivity_days)
    except OverflowError:
        raise AccountAuthenticationUnavailable("Account authentication is unavailable.") from None

    if session.access_token_expires_at > session.checked_at:
        return await authenticate_stored_account_session(
            connection,
            token,
            settings=settings,
            key_cache=key_cache,
        )

    refreshed = await refresh_locked_account_tokens(
        session,
        settings=settings,
        client=client,
        key_cache=key_cache,
    )

    return await store_verified_account_refresh(
        connection,
        session,
        refreshed,
        settings=settings,
    )
