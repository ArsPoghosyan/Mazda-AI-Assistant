"""Load locked account sessions for subsequent provider authentication."""

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from uuid import UUID

from pydantic import SecretStr
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncConnection

from app.account_auth import (
    AccountAuthenticationUnavailable,
    authenticate_account_token,
)
from app.account_key_cache import AccountKeyCache
from app.account_token_encryption import AccountTokenCipher
from app.account_tokens import InvalidAccountToken, VerifiedAccount
from app.config import Settings
from app.models import AccountSession


@dataclass(frozen=True, slots=True)
class LockedAccountSession:
    """Internal snapshot, not a completed authentication result."""

    session_id: UUID
    user_id: UUID
    provider_session_id: UUID
    access_token_ciphertext: bytes = field(repr=False)
    refresh_token_ciphertext: bytes = field(repr=False)
    access_token_expires_at: datetime
    last_seen_at: datetime
    idle_expires_at: datetime
    absolute_expires_at: datetime
    checked_at: datetime


async def load_locked_account_session(
    connection: AsyncConnection,
    token: SecretStr | None,
) -> LockedAccountSession | None:
    """Load an unexpired session without updating activity or credentials.

    The caller owns the transaction. The row lock lasts until that transaction
    ends; the returned snapshot must not be treated as proof of a continuing lock.
    Provider credentials still require decryption and verification.
    """
    if token is None:
        return None

    raw_token = token.get_secret_value()
    if re.fullmatch(r"[A-Za-z0-9_-]{43}", raw_token) is None:
        return None

    if not connection.in_transaction():
        raise RuntimeError("Account-session loading requires an active transaction.")

    token_hash = sha256(raw_token.encode("ascii")).digest()

    result = await connection.execute(
        select(
            AccountSession.id,
            AccountSession.user_id,
            AccountSession.provider_session_id,
            AccountSession.access_token_ciphertext,
            AccountSession.refresh_token_ciphertext,
            AccountSession.access_token_expires_at,
            AccountSession.last_seen_at,
            AccountSession.idle_expires_at,
            AccountSession.absolute_expires_at,
        )
        .where(AccountSession.token_hash == token_hash)
        .with_for_update()
    )
    row = result.one_or_none()
    if row is None:
        return None

    # A separate statement starts after any wait for the row lock.
    checked_at = await connection.scalar(select(func.statement_timestamp()))
    if not isinstance(checked_at, datetime) or checked_at.tzinfo is None:
        raise AccountAuthenticationUnavailable("Account authentication is unavailable.")

    checked_at = checked_at.astimezone(UTC)
    if row.idle_expires_at <= checked_at or row.absolute_expires_at <= checked_at:
        return None

    return LockedAccountSession(
        session_id=row.id,
        user_id=row.user_id,
        provider_session_id=row.provider_session_id,
        access_token_ciphertext=row.access_token_ciphertext,
        refresh_token_ciphertext=row.refresh_token_ciphertext,
        access_token_expires_at=row.access_token_expires_at,
        last_seen_at=row.last_seen_at,
        idle_expires_at=row.idle_expires_at,
        absolute_expires_at=row.absolute_expires_at,
        checked_at=checked_at,
    )


async def verify_locked_account_access(
    session: LockedAccountSession,
    *,
    settings: Settings,
    key_cache: AccountKeyCache | None,
) -> VerifiedAccount:
    """Decrypt and verify stored access credentials against session metadata.

    The caller must retain the session lock and recheck application-session
    deadlines using fresh database time before authorizing or updating activity.
    This helper does not decrypt refresh credentials or perform database writes.
    """
    key = settings.account_session_encryption_key
    if key is None:
        raise AccountAuthenticationUnavailable("Account authentication is unavailable.")

    try:
        access_token = AccountTokenCipher(key).decrypt(session.access_token_ciphertext)
    except ValueError:
        raise AccountAuthenticationUnavailable("Account authentication is unavailable.") from None

    try:
        account = await authenticate_account_token(
            access_token,
            settings=settings,
            key_cache=key_cache,
        )
    except InvalidAccountToken:
        raise AccountAuthenticationUnavailable("Account authentication is unavailable.") from None

    if (
        account.user_id != session.user_id
        or account.session_id != session.provider_session_id
        or account.access_token_expires_at != session.access_token_expires_at
        or account.access_token_expires_at <= session.checked_at
    ):
        raise AccountAuthenticationUnavailable("Account authentication is unavailable.")

    return account


@dataclass(frozen=True, slots=True)
class AuthenticatedAccountSession:
    """Verified account identity and current application-session deadlines."""

    session_id: UUID
    account: VerifiedAccount
    idle_expires_at: datetime
    absolute_expires_at: datetime


async def authenticate_stored_account_session(
    connection: AsyncConnection,
    token: SecretStr | None,
    *,
    settings: Settings,
    key_cache: AccountKeyCache | None,
) -> AuthenticatedAccountSession | None:
    """Authenticate using stored access credentials in the caller's transaction.

    This path requires a valid stored access token; it does not refresh tokens.
    The caller must commit successfully before using the result outside the
    transaction.
    """
    session = await load_locked_account_session(connection, token)
    if session is None:
        return None

    account = await verify_locked_account_access(
        session,
        settings=settings,
        key_cache=key_cache,
    )

    try:
        inactivity_period = timedelta(
            days=settings.account_session_inactivity_days,
        )
    except OverflowError:
        raise AccountAuthenticationUnavailable("Account authentication is unavailable.") from None

    # This statement starts after verification, including any signing-key fetch.
    # Keep the row lock held so other requests cannot change this session first.
    checked_at = func.statement_timestamp()
    activity_at = func.greatest(AccountSession.last_seen_at, checked_at)

    result = await connection.execute(
        update(AccountSession)
        .where(
            AccountSession.id == session.session_id,
            AccountSession.user_id == account.user_id,
            AccountSession.provider_session_id == account.session_id,
            AccountSession.access_token_expires_at == account.access_token_expires_at,
            AccountSession.access_token_expires_at > checked_at,
            AccountSession.idle_expires_at > checked_at,
            AccountSession.absolute_expires_at > checked_at,
        )
        .values(
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
