"""Account-session creation within a caller-owned transaction."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from secrets import token_urlsafe
from uuid import UUID

from pydantic import SecretStr
from sqlalchemy import func, insert, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncConnection

from app.account_auth import authenticate_account_token
from app.account_key_cache import AccountKeyCache
from app.account_token_encryption import AccountTokenCipher
from app.account_tokens import InvalidAccountToken
from app.config import Settings
from app.models import AccountSession, UserProfile


class AccountSessionUnavailable(RuntimeError):
    """Account-session creation is not currently available."""


@dataclass(frozen=True, slots=True)
class CreatedAccountSession:
    """Internal result; issue its browser token only after the outer commit."""

    session_id: UUID
    user_id: UUID
    token: SecretStr
    idle_expires_at: datetime
    absolute_expires_at: datetime


async def create_account_session(
    connection: AsyncConnection,
    settings: Settings,
    *,
    access_token: SecretStr,
    refresh_token: SecretStr,
    key_cache: AccountKeyCache | None,
) -> CreatedAccountSession:
    """Create a session from a token pair received directly from the provider.

    Access-token verification establishes identity. The caller must obtain the
    refresh token from the same trusted provider response, not a browser field.
    This operation does not independently verify refresh-token ownership.
    """
    encryption_key = settings.account_session_encryption_key
    if encryption_key is None:
        raise AccountSessionUnavailable("Account sessions are unavailable.")

    if not connection.in_transaction():
        raise RuntimeError("Account-session creation requires an active transaction.")

    account = await authenticate_account_token(
        access_token,
        settings=settings,
        key_cache=key_cache,
    )

    cipher = AccountTokenCipher(encryption_key)
    try:
        access_ciphertext = cipher.encrypt(access_token)
        refresh_ciphertext = cipher.encrypt(refresh_token)
    except ValueError:
        raise InvalidAccountToken("Invalid account token.") from None

    browser_token = token_urlsafe(32)
    token_hash = sha256(browser_token.encode("ascii")).digest()

    async with connection.begin_nested():
        await connection.execute(
            pg_insert(UserProfile)
            .values(id=account.user_id)
            .on_conflict_do_nothing(index_elements=[UserProfile.id])
        )

        # Obtain fresh database time after any wait on profile creation.
        created_at = await connection.scalar(select(func.statement_timestamp()))
        if not isinstance(created_at, datetime) or created_at.tzinfo is None:
            raise AccountSessionUnavailable("Account sessions are unavailable.")

        created_at = created_at.astimezone(UTC)
        if account.access_token_expires_at <= created_at:
            raise InvalidAccountToken("Invalid account token.")

        try:
            absolute_expires_at = created_at + timedelta(
                days=settings.account_session_absolute_lifetime_days
            )
            idle_expires_at = min(
                created_at + timedelta(days=settings.account_session_inactivity_days),
                absolute_expires_at,
            )
        except OverflowError:
            raise AccountSessionUnavailable("Account sessions are unavailable.") from None

        session_id = await connection.scalar(
            insert(AccountSession)
            .values(
                user_id=account.user_id,
                token_hash=token_hash,
                provider_session_id=account.session_id,
                access_token_ciphertext=access_ciphertext,
                refresh_token_ciphertext=refresh_ciphertext,
                access_token_expires_at=account.access_token_expires_at,
                created_at=created_at,
                last_seen_at=created_at,
                idle_expires_at=idle_expires_at,
                absolute_expires_at=absolute_expires_at,
            )
            .returning(AccountSession.id)
        )
        assert isinstance(session_id, UUID)

    return CreatedAccountSession(
        session_id=session_id,
        user_id=account.user_id,
        token=SecretStr(browser_token),
        idle_expires_at=idle_expires_at,
        absolute_expires_at=absolute_expires_at,
    )
