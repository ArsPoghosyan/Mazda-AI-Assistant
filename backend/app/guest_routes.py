"""HTTP endpoints for verified browser guest sessions."""

import asyncio
from datetime import datetime
from typing import Literal, cast

import httpx2
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, SecretStr
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine

from app.config import Settings
from app.csrf import require_trusted_origin
from app.guest_cookies import guest_cookie_name, set_guest_cookie
from app.guest_session_requests import read_guest_challenge
from app.guest_session_service import establish_guest_session
from app.turnstile import TurnstileRejected, TurnstileUnavailable

router = APIRouter(prefix="/api/v1/guest", tags=["guest"])


class GuestSessionResponse(BaseModel):
    status: Literal["ok"] = "ok"
    expires_at: datetime


def session_unavailable() -> HTTPException:
    """Return a generic failure without exposing provider or database details."""
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Guest sessions are temporarily unavailable.",
        headers={"Cache-Control": "no-store"},
    )


@router.post(
    "/session",
    response_model=GuestSessionResponse,
    dependencies=[Depends(require_trusted_origin)],
    responses={
        400: {"description": "Invalid guest-session request."},
        403: {"description": "Origin or human verification was rejected."},
        413: {"description": "Guest-session request is too large."},
        415: {"description": "Guest-session input requires JSON."},
        503: {"description": "Guest sessions are temporarily unavailable."},
    },
)
async def ensure_guest_session(
    request: Request,
    response: Response,
) -> GuestSessionResponse:
    """Refresh or create a session and issue its cookie after commit."""
    settings = cast(Settings, request.app.state.settings)

    if not settings.guest_session_api_enabled:
        raise session_unavailable()

    engine = cast(
        AsyncEngine | None,
        request.app.state.database_engine,
    )
    client = cast(
        httpx2.AsyncClient | None,
        request.app.state.turnstile_client,
    )

    if engine is None:
        raise session_unavailable()

    raw_cookie = request.cookies.get(guest_cookie_name(settings))
    browser_token = SecretStr(raw_cookie) if raw_cookie else None

    try:
        async with asyncio.timeout(settings.guest_session_timeout_seconds):
            challenge_token = await read_guest_challenge(request)

            established = await establish_guest_session(
                engine,
                browser_token=browser_token,
                challenge_token=challenge_token,
                settings=settings,
                client=client,
            )
    except TurnstileRejected:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Human verification is required or was rejected.",
            headers={
                "Cache-Control": "no-store",
                "X-Guest-Verification": "required",
            },
        ) from None
    except (TurnstileUnavailable, SQLAlchemyError, TimeoutError):
        raise session_unavailable() from None

    set_guest_cookie(
        response,
        established.token,
        established.expires_at,
        settings,
    )

    return GuestSessionResponse(expires_at=established.expires_at)
