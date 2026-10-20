"""HTTP authentication using an existing opaque account-session cookie."""

import asyncio
from datetime import datetime
from typing import cast
from uuid import UUID

import httpx2
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine

from app.account_auth import AccountAuthenticationUnavailable
from app.account_cookies import (
    clear_account_cookie,
    read_account_cookie,
    set_account_cookie,
)
from app.account_key_cache import AccountKeyCache
from app.account_refresh import AccountRefreshRejected, AccountRefreshUnavailable
from app.account_session_transactions import (
    authenticate_account_session_transaction,
)
from app.config import Settings
from app.csrf import require_trusted_origin

router = APIRouter(prefix="/api/v1/account", tags=["account"])


class AccountSessionResponse(BaseModel):
    user_id: UUID
    expires_at: datetime
    absolute_expires_at: datetime


def account_session_unavailable() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Account sessions are temporarily unavailable.",
        headers={"Cache-Control": "no-store"},
    )


def invalid_account_session(settings: Settings) -> HTTPException:
    cookie_response = Response()
    clear_account_cookie(cookie_response, settings)

    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired account session.",
        headers={
            "Cache-Control": "no-store",
            "Set-Cookie": cookie_response.headers["set-cookie"],
        },
    )


@router.post(
    "/session",
    response_model=AccountSessionResponse,
    dependencies=[Depends(require_trusted_origin)],
    responses={
        401: {"description": "Invalid or expired account session."},
        403: {"description": "Request origin is not allowed."},
        503: {"description": "Account sessions are temporarily unavailable."},
    },
)
async def check_account_session(
    request: Request,
    response: Response,
) -> AccountSessionResponse:
    """Authenticate an existing session and renew its cookie after commit."""
    settings = cast(Settings, request.app.state.settings)

    if not settings.account_session_api_enabled:
        raise account_session_unavailable()

    token = read_account_cookie(request, settings)
    if token is None:
        raise invalid_account_session(settings)

    engine = cast(
        AsyncEngine | None,
        request.app.state.database_engine,
    )
    client = cast(
        httpx2.AsyncClient | None,
        request.app.state.account_auth_client,
    )
    key_cache = cast(
        AccountKeyCache | None,
        request.app.state.account_key_cache,
    )

    if engine is None or client is None or key_cache is None:
        raise account_session_unavailable()

    try:
        async with asyncio.timeout(settings.account_session_auth_timeout_seconds):
            authenticated = await authenticate_account_session_transaction(
                engine,
                token,
                settings=settings,
                client=client,
                key_cache=key_cache,
            )
    except AccountRefreshRejected:
        raise invalid_account_session(settings) from None
    except (
        AccountAuthenticationUnavailable,
        AccountRefreshUnavailable,
        SQLAlchemyError,
        TimeoutError,
    ):
        raise account_session_unavailable() from None

    if authenticated is None:
        raise invalid_account_session(settings)

    set_account_cookie(
        response,
        token,
        authenticated.idle_expires_at,
        settings,
    )

    return AccountSessionResponse(
        user_id=authenticated.account.user_id,
        expires_at=authenticated.idle_expires_at,
        absolute_expires_at=authenticated.absolute_expires_at,
    )
