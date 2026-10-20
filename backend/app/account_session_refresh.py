"""Refresh and verify credentials from an internally locked session."""

from datetime import timedelta

import httpx2
from sqlalchemy import func, literal, update
from sqlalchemy.ext.asyncio import AsyncConnection

from app.account_key_cache import AccountKeyCache
from app.account_refresh import (
    AccountRefreshUnavailable,
    refresh_account_tokens,
)
from app.account_refresh_verification import (
    VerifiedAccountRefresh,
    verify_refreshed_account_tokens,
)
from app.account_session_auth import (
    AuthenticatedAccountSession,
    LockedAccountSession,
)
from app.account_token_encryption import AccountTokenCipher
from app.config import Settings
from app.models import AccountSession


async def refresh_locked_account_tokens(
    session: LockedAccountSession,
    *,
    settings: Settings,
    client: httpx2.AsyncClient,
    key_cache: AccountKeyCache | None,
) -> VerifiedAccountRefresh:
    """Exchange stored refresh credentials once and verify returned identity.

    The caller must retain the session row lock, decide whether refresh is
    needed, and recheck application-session deadlines before and after this
    operation. This helper does not write credentials, update activity, commit,
    or establish completed application-session authentication.
    """
    encryption_key = settings.account_session_encryption_key

    # Check known configuration failures before potentially rotating tokens.
    if (
        encryption_key is None
        or settings.supabase_auth_issuer is None
        or settings.supabase_auth_publishable_key is None
        or key_cache is None
    ):
        raise AccountRefreshUnavailable("Account refresh is unavailable.")

    try:
        refresh_token = AccountTokenCipher(encryption_key).decrypt(session.refresh_token_ciphertext)
    except ValueError:
        raise AccountRefreshUnavailable("Account refresh is unavailable.") from None

    # Malformed stored credentials are a storage/configuration failure,
    # rather than evidence that the provider rejected the user's session.
    if any(
        ord(character) < 33 or ord(character) > 126
        for character in refresh_token.get_secret_value()
    ):
        raise AccountRefreshUnavailable("Account refresh is unavailable.")

    tokens = await refresh_account_tokens(
        refresh_token,
        settings=settings,
        client=client,
    )

    return await verify_refreshed_account_tokens(
        tokens,
        expected_user_id=session.user_id,
        expected_provider_session_id=session.provider_session_id,
        settings=settings,
        key_cache=key_cache,
    )


async def store_verified_account_refresh(
    connection: AsyncConnection,
    session: LockedAccountSession,
    refreshed: VerifiedAccountRefresh,
    *,
    settings: Settings,
) -> AuthenticatedAccountSession | None:
    """Store verified replacement credentials in the caller's transaction.

    The caller must retain the row lock for this session. Refreshed credentials
    must come from the verified trusted provider exchange, not browser input.
    The caller owns commit and rollback.
    """
    if not connection.in_transaction():
        raise RuntimeError("Account refresh storage requires an active transaction.")

    account = refreshed.account
    if account.user_id != session.user_id or account.session_id != session.provider_session_id:
        raise AccountRefreshUnavailable("Account refresh is unavailable.")

    encryption_key = settings.account_session_encryption_key
    if encryption_key is None:
        raise AccountRefreshUnavailable("Account refresh is unavailable.")

    try:
        cipher = AccountTokenCipher(encryption_key)
        access_ciphertext = cipher.encrypt(refreshed.tokens.access_token)
        refresh_ciphertext = cipher.encrypt(refreshed.tokens.refresh_token)
        inactivity_period = timedelta(days=settings.account_session_inactivity_days)
    except (ValueError, OverflowError):
        raise AccountRefreshUnavailable("Account refresh is unavailable.") from None

    # This statement starts after the provider exchange and JWT verification.
    checked_at = func.statement_timestamp()
    activity_at = func.greatest(AccountSession.last_seen_at, checked_at)

    result = await connection.execute(
        update(AccountSession)
        .where(
            AccountSession.id == session.session_id,
            AccountSession.user_id == account.user_id,
            AccountSession.provider_session_id == account.session_id,
            # Refuse to overwrite credentials from an outdated snapshot.
            AccountSession.access_token_ciphertext == session.access_token_ciphertext,
            AccountSession.refresh_token_ciphertext == session.refresh_token_ciphertext,
            AccountSession.access_token_expires_at == session.access_token_expires_at,
            # Both application deadlines and the new JWT must remain valid.
            AccountSession.idle_expires_at > checked_at,
            AccountSession.absolute_expires_at > checked_at,
            literal(account.access_token_expires_at) > checked_at,
        )
        .values(
            access_token_ciphertext=access_ciphertext,
            refresh_token_ciphertext=refresh_ciphertext,
            access_token_expires_at=account.access_token_expires_at,
            last_seen_at=activity_at,
            idle_expires_at=func.least(
                AccountSession.absolute_expires_at,
                activity_at + inactivity_period,
            ),
        )
        .returning(
            AccountSession.id,
            AccountSession.idle_expires_at,
            AccountSession.absolute_expires_at,
        )
    )

    row = result.one_or_none()
    if row is None:
        return None

    return AuthenticatedAccountSession(
        session_id=row.id,
        account=account,
        idle_expires_at=row.idle_expires_at,
        absolute_expires_at=row.absolute_expires_at,
    )
