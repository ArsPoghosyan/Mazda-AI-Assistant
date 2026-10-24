"""Create a committed application session from backend-exchanged credentials."""

import asyncio
import logging

import httpx2
from sqlalchemy.ext.asyncio import AsyncEngine

from app.account_auth import authenticate_active_account_token
from app.account_google_exchange import (
    ExchangedGoogleTokens,
    GoogleCodeExchangeUnavailable,
)
from app.account_key_cache import AccountKeyCache
from app.account_sessions import CreatedAccountSession, create_account_session
from app.config import Settings

_logger = logging.getLogger(__name__)


async def create_google_account_session(
    engine: AsyncEngine,
    tokens: ExchangedGoogleTokens,
    *,
    settings: Settings,
    client: httpx2.AsyncClient,
    key_cache: AccountKeyCache | None,
) -> CreatedAccountSession:
    """Return browser credentials only after verification and database commit.

    The caller must obtain these tokens through the attempt-bound backend
    exchange, never from browser-supplied token fields. The caller owns the
    complete operation deadline and prior attempt-consumption sequencing.

    This service verifies Supabase identity and live-session status. It does
    not independently establish the upstream Google authentication method,
    issue cookies, transfer guest data or retry failed operations.
    """
    if (
        settings.supabase_auth_issuer is None
        or settings.supabase_auth_publishable_key is None
        or settings.account_session_encryption_key is None
        or key_cache is None
    ):
        raise GoogleCodeExchangeUnavailable("Google sign-in is unavailable.")

    stage = "verify_provider_session"
    try:
        await authenticate_active_account_token(
            tokens.access_token,
            settings=settings,
            key_cache=key_cache,
            client=client,
        )

        stage = "open_local_transaction"
        async with engine.begin() as connection:
            stage = "persist_local_session"
            created = await create_account_session(
                connection,
                settings,
                access_token=tokens.access_token,
                refresh_token=tokens.refresh_token,
                key_cache=key_cache,
            )
            stage = "commit_or_release"
    except (Exception, asyncio.CancelledError):
        # No credential or exception text enters diagnostics. In particular,
        # cancellation and lost commit acknowledgements remain failures.
        _logger.warning("Google sign-in incomplete after provider response: stage=%s", stage)
        raise

    return created
