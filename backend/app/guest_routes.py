"""HTTP endpoints for browser guest sessions."""

from datetime import datetime
from typing import Literal, cast

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, SecretStr
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine

from app.config import Settings
from app.csrf import require_trusted_origin
from app.guest_cookies import guest_cookie_name, set_guest_cookie
from app.guest_sessions import create_guest_session, refresh_guest_session

router = APIRouter(prefix="/api/v1/guest", tags=["guest"])


class GuestSessionResponse(BaseModel):
    status: Literal["ok"] = "ok"
    expires_at: datetime


def session_unavailable() -> HTTPException:
    """Return a generic failure without exposing database details."""
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Guest sessions are temporarily unavailable.",
        headers={"Cache-Control": "no-store"},
    )


@router.post(
    "/session",
    response_model=GuestSessionResponse,
    dependencies=[Depends(require_trusted_origin)],
)
async def ensure_guest_session(
    request: Request,
    response: Response,
) -> GuestSessionResponse:
    """Create or refresh a session, then set its cookie after commit."""
    settings = cast(Settings, request.app.state.settings)
    engine = cast(
        AsyncEngine | None,
        request.app.state.database_engine,
    )

    if not settings.guest_session_api_enabled or engine is None:
        raise session_unavailable()

    token = SecretStr(request.cookies.get(guest_cookie_name(settings), ""))

    try:
        async with engine.begin() as connection:
            active = await refresh_guest_session(
                connection,
                token.get_secret_value(),
                settings,
            )

            if active is None:
                created = await create_guest_session(connection, settings)
                token = created.token
                expires_at = created.expires_at
            else:
                expires_at = active.expires_at

    except SQLAlchemyError:
        raise session_unavailable() from None

    set_guest_cookie(response, token, expires_at, settings)

    return GuestSessionResponse(expires_at=expires_at)
