"""Connect provider sign-in to committed application-session creation."""

import httpx2
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncEngine

from app.account_key_cache import AccountKeyCache
from app.account_sessions import CreatedAccountSession, create_account_session
from app.account_sign_in import AccountSignInUnavailable, sign_in_with_password
from app.config import Settings


async def sign_in_account(
    engine: AsyncEngine,
    email: SecretStr,
    password: SecretStr,
    *,
    settings: Settings,
    client: httpx2.AsyncClient,
    key_cache: AccountKeyCache | None,
) -> CreatedAccountSession:
    """Return a browser credential only after successful database commit.

    Provider sign-in occurs before opening the database transaction.
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
    )

    async with engine.begin() as connection:
        created = await create_account_session(
            connection,
            settings,
            access_token=tokens.access_token,
            refresh_token=tokens.refresh_token,
            key_cache=key_cache,
        )

    return created
