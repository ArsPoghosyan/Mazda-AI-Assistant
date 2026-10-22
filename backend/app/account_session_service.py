"""Coordinate account-session authentication within caller-owned transactions."""

from datetime import timedelta

import httpx2
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncConnection

from app.account_auth import AccountAuthenticationUnavailable, authenticate_account_token
from app.account_key_cache import AccountKeyCache
from app.account_provider_session import (
    AccountProviderSessionRejected,
    AccountProviderSessionUnavailable,
    check_provider_session,
)
from app.account_refresh import AccountRefreshRejected
from app.account_session_auth import (
    AuthenticatedAccountSession,
    LockedAccountSession,
    authenticate_stored_account_session,
    load_locked_account_session,
)
from app.account_session_refresh import (
    refresh_locked_account_tokens,
    store_verified_account_refresh,
)
from app.account_token_encryption import AccountTokenCipher
from app.account_tokens import InvalidAccountToken, VerifiedAccount
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

    Live provider verification precedes activity or credential writes in both
    branches. Provider rejection, unavailability, cancellation, and database errors
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
        encryption_key = settings.account_session_encryption_key
        if encryption_key is None:
            raise AccountAuthenticationUnavailable("Account authentication is unavailable.")

        try:
            access_token = AccountTokenCipher(encryption_key).decrypt(
                session.access_token_ciphertext
            )
        except ValueError:
            raise AccountAuthenticationUnavailable(
                "Account authentication is unavailable."
            ) from None

        await verify_active_account_session_token(
            access_token,
            session,
            settings=settings,
            client=client,
            key_cache=key_cache,
        )

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

    await verify_active_account_session_token(
        refreshed.tokens.access_token,
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


async def verify_active_account_session_token(
    token: SecretStr,
    session: LockedAccountSession,
    *,
    settings: Settings,
    client: httpx2.AsyncClient,
    key_cache: AccountKeyCache | None,
) -> VerifiedAccount:
    """Verify credentials against a locked application session and provider.

    The caller must retain the row lock and enforce fresh database deadlines
    before writing activity or replacement credentials.
    """
    try:
        account = await authenticate_account_token(
            token,
            settings=settings,
            key_cache=key_cache,
        )
    except InvalidAccountToken:
        raise AccountAuthenticationUnavailable("Account authentication is unavailable.") from None

    if (
        account.user_id != session.user_id
        or account.session_id != session.provider_session_id
        or account.session_id.int == 0
    ):
        raise AccountAuthenticationUnavailable("Account authentication is unavailable.")

    try:
        await check_provider_session(
            token,
            verified_account=account,
            settings=settings,
            client=client,
        )
    except AccountProviderSessionRejected:
        raise AccountRefreshRejected("Account credentials were rejected.") from None
    except AccountProviderSessionUnavailable:
        raise AccountAuthenticationUnavailable("Account authentication is unavailable.") from None

    return account
