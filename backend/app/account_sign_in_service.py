"""Connect provider sign-in to committed application-session creation."""

import asyncio
import logging

import httpx2
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncEngine

from app.account_auth import authenticate_active_account_token
from app.account_key_cache import AccountKeyCache
from app.account_sessions import CreatedAccountSession, create_account_session
from app.account_sign_in import AccountSignInUnavailable, sign_in_with_password
from app.config import Settings

_logger = logging.getLogger(__name__)


async def sign_in_account(
    engine: AsyncEngine,
    email: SecretStr,
    password: SecretStr,
    *,
    settings: Settings,
    client: httpx2.AsyncClient,
    key_cache: AccountKeyCache | None,
    captcha_token: SecretStr | None = None,
) -> CreatedAccountSession:
    """Return a browser credential only after successful database commit.

    Provider sign-in and live session verification occur before opening the
    database transaction. Session creation retains its own JWT verification.
    Verification, persistence, and commit failures propagate without retries.
    This service does not issue cookies or expose an HTTP endpoint.
    """
    if (
        settings.supabase_auth_issuer is None
        or settings.supabase_auth_publishable_key is None
        or settings.account_session_encryption_key is None
        or key_cache is None
    ):
        raise AccountSignInUnavailable("Account sign-in is not configured.")

    tokens = await sign_in_with_password(
        email,
        password,
        settings=settings,
        client=client,
        captcha_token=captcha_token,
    )

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
        # A failed/uncertain commit must not expose a credential or trigger blind
        # revocation of a provider session which may already have a local binding.
        _logger.warning("Account sign-in incomplete after provider response: stage=%s", stage)
        raise

    return created
