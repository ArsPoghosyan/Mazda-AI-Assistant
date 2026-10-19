"""Guest-session creation and persistence."""

from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID

from pydantic import SecretStr
from sqlalchemy import func, insert, select, update
from sqlalchemy.ext.asyncio import AsyncConnection

from app.config import Settings
from app.guest_tokens import generate_guest_token, hash_guest_token
from app.models import GuestSession


@dataclass(frozen=True)
class CreatedGuestSession:
    """Internal result used when setting the guest cookie."""

    session_id: UUID
    token: SecretStr
    expires_at: datetime


async def create_guest_session(
    connection: AsyncConnection,
    settings: Settings,
) -> CreatedGuestSession:
    """Create a guest session within the caller's transaction."""
    token = generate_guest_token()

    result = await connection.execute(
        insert(GuestSession)
        .values(
            token_hash=hash_guest_token(token),
            expires_at=func.now() + timedelta(days=settings.guest_session_inactivity_days),
        )
        .returning(GuestSession.id, GuestSession.expires_at)
    )

    session_id, expires_at = result.one()

    return CreatedGuestSession(
        session_id=session_id,
        token=SecretStr(token),
        expires_at=expires_at,
    )


@dataclass(frozen=True)
class ActiveGuestSession:
    """Verified guest identity without its bearer token."""

    session_id: UUID
    expires_at: datetime


async def refresh_guest_session(
    connection: AsyncConnection,
    token: str | None,
    settings: Settings,
) -> ActiveGuestSession | None:
    """Refresh an unexpired session within the caller's transaction."""
    if token is None:
        return None

    try:
        token_hash = hash_guest_token(token)
    except ValueError:
        return None

    session_id = await connection.scalar(
        select(GuestSession.id).where(GuestSession.token_hash == token_hash).with_for_update()
    )
    if session_id is None:
        return None

    checked_at = func.statement_timestamp()
    activity_at = func.greatest(GuestSession.last_seen_at, checked_at)

    result = await connection.execute(
        update(GuestSession)
        .where(
            GuestSession.id == session_id,
            GuestSession.expires_at > checked_at,
        )
        .values(
            last_seen_at=activity_at,
            expires_at=activity_at + timedelta(days=settings.guest_session_inactivity_days),
        )
        .returning(GuestSession.id, GuestSession.expires_at)
    )

    row = result.one_or_none()
    if row is None:
        return None

    return ActiveGuestSession(
        session_id=row[0],
        expires_at=row[1],
    )
