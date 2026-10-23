"""Pending OAuth attempt lifecycle within caller-owned transactions."""

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from uuid import UUID

from pydantic import SecretStr
from sqlalchemy import delete, func, insert, select
from sqlalchemy.ext.asyncio import AsyncConnection

from app.account_oauth_material import (
    InvalidOAuthLoginMaterial,
    create_oauth_login_material,
    hash_oauth_browser_token,
)
from app.account_token_encryption import AccountTokenCipher
from app.config import Settings
from app.models import OAuthLoginAttempt


class OAuthLoginAttemptUnavailable(RuntimeError):
    """Pending OAuth attempt operations are unavailable."""


@dataclass(frozen=True, slots=True)
class CreatedOAuthLoginAttempt:
    """Internal result; issue its browser cookie only after commit."""

    attempt_id: UUID
    browser_token: SecretStr
    code_challenge: str
    expires_at: datetime


async def create_oauth_login_attempt(
    connection: AsyncConnection,
    settings: Settings,
) -> CreatedOAuthLoginAttempt:
    """Insert a pending attempt without committing or contacting a provider."""
    if not connection.in_transaction():
        raise RuntimeError("OAuth attempt creation requires an active transaction.")

    encryption_key = settings.account_session_encryption_key
    if encryption_key is None:
        raise OAuthLoginAttemptUnavailable("OAuth login is unavailable.")

    material = create_oauth_login_material(AccountTokenCipher(encryption_key))

    created_at = await connection.scalar(select(func.statement_timestamp()))
    if not isinstance(created_at, datetime) or created_at.utcoffset() is None:
        raise OAuthLoginAttemptUnavailable("OAuth login is unavailable.")

    created_at = created_at.astimezone(UTC)
    expires_at = created_at + timedelta(
        seconds=settings.account_google_oauth_attempt_lifetime_seconds
    )

    attempt_id = await connection.scalar(
        insert(OAuthLoginAttempt)
        .values(
            browser_token_hash=material.browser_token_hash,
            pkce_verifier_ciphertext=material.pkce_verifier_ciphertext,
            provider="google",
            purpose="sign_in",
            created_at=created_at,
            expires_at=expires_at,
        )
        .returning(OAuthLoginAttempt.id)
    )
    if not isinstance(attempt_id, UUID):
        raise OAuthLoginAttemptUnavailable("OAuth login is unavailable.")

    return CreatedOAuthLoginAttempt(
        attempt_id=attempt_id,
        browser_token=material.browser_token,
        code_challenge=material.code_challenge,
        expires_at=expires_at,
    )


async def replace_oauth_login_attempt(
    connection: AsyncConnection,
    settings: Settings,
    previous_token: str | None,
) -> CreatedOAuthLoginAttempt:
    """Replace the proven previous attempt; commit before issuing the new cookie.

    A missing/consumed previous record requires a controlled restart. The savepoint
    restores the old record if creation fails, even if the caller catches errors.
    It does not commit the surrounding transaction.
    """
    if not connection.in_transaction():
        raise RuntimeError("OAuth attempt replacement requires an active transaction.")
    previous_hash = hash_oauth_browser_token(previous_token)

    async with connection.begin_nested():
        previous_id = await connection.scalar(
            delete(OAuthLoginAttempt)
            .where(
                OAuthLoginAttempt.browser_token_hash == previous_hash,
                OAuthLoginAttempt.provider == "google",
                OAuthLoginAttempt.purpose == "sign_in",
            )
            .returning(OAuthLoginAttempt.id)
        )
        if previous_id is None:
            raise InvalidOAuthLoginMaterial("Invalid OAuth login material.")
        return await create_oauth_login_attempt(connection, settings)


@dataclass(frozen=True, slots=True)
class ConsumedOAuthLoginAttempt:
    """Internal result; commit consumption before decrypting or exchanging a code."""

    attempt_id: UUID
    pkce_verifier_ciphertext: bytes = field(repr=False)
    expires_at: datetime


async def consume_oauth_login_attempt(
    connection: AsyncConnection,
    token: str | None,
) -> ConsumedOAuthLoginAttempt:
    """Delete once, then check expiry using fresh time after any row-lock wait.

    Rejected expired records may be deleted in this transaction. On any error the
    caller must end it deliberately; rolling back restores deletions. A returned
    result is provisional until commit and is never an authentication result.
    """
    if not connection.in_transaction():
        raise RuntimeError("OAuth attempt consumption requires an active transaction.")
    token_hash = hash_oauth_browser_token(token)
    result = await connection.execute(
        delete(OAuthLoginAttempt)
        .where(
            OAuthLoginAttempt.browser_token_hash == token_hash,
            OAuthLoginAttempt.provider == "google",
            OAuthLoginAttempt.purpose == "sign_in",
        )
        .returning(
            OAuthLoginAttempt.id,
            OAuthLoginAttempt.pkce_verifier_ciphertext,
            OAuthLoginAttempt.expires_at,
        )
    )
    row = result.one_or_none()
    if row is None:
        raise InvalidOAuthLoginMaterial("Invalid OAuth login material.")

    # The DELETE has acquired the row lock. Statement/transaction start time from
    # before that wait could wrongly accept an attempt whose deadline has passed.
    checked_at = await connection.scalar(select(func.clock_timestamp()))
    if not isinstance(checked_at, datetime) or checked_at.utcoffset() is None:
        raise OAuthLoginAttemptUnavailable("OAuth login is unavailable.")
    if row.expires_at <= checked_at:
        raise InvalidOAuthLoginMaterial("Invalid OAuth login material.")

    return ConsumedOAuthLoginAttempt(
        attempt_id=row.id,
        pkce_verifier_ciphertext=row.pkce_verifier_ciphertext,
        expires_at=row.expires_at,
    )
