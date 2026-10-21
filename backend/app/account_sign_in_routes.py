"""Default-disabled HTTP sign-in with bounded credentials and secure cookies."""

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
from app.account_cookies import set_account_cookie
from app.account_key_cache import AccountKeyCache
from app.account_sessions import AccountSessionAlreadyExists, AccountSessionUnavailable
from app.account_sign_in import AccountSignInRejected, AccountSignInUnavailable
from app.account_sign_in_requests import read_sign_in_credentials
from app.account_sign_in_service import sign_in_account
from app.account_tokens import InvalidAccountToken
from app.config import Settings
from app.csrf import require_trusted_origin

router = APIRouter(prefix="/api/v1/account", tags=["account"])


class AccountSignInResponse(BaseModel):
    user_id: UUID
    expires_at: datetime
    absolute_expires_at: datetime


def account_sign_in_unavailable() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Account sign-in is temporarily unavailable.",
        headers={"Cache-Control": "no-store"},
    )


@router.post(
    "/sign-in",
    response_model=AccountSignInResponse,
    dependencies=[Depends(require_trusted_origin)],
    responses={
        400: {"description": "Invalid sign-in request."},
        401: {"description": "Sign-in was rejected."},
        403: {"description": "Request origin is not allowed."},
        413: {"description": "Sign-in request is too large."},
        415: {"description": "Sign-in requires a JSON request."},
        503: {"description": "Account sign-in is temporarily unavailable."},
    },
)
async def sign_in(
    request: Request,
    response: Response,
) -> AccountSignInResponse:
    """Create an account session and issue its cookie after successful commit."""
    settings = cast(Settings, request.app.state.settings)

    if not settings.account_sign_in_api_enabled:
        raise account_sign_in_unavailable()

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
        raise account_sign_in_unavailable()

    try:
        async with asyncio.timeout(settings.account_sign_in_timeout_seconds):
            credentials = await read_sign_in_credentials(request)

            created = await sign_in_account(
                engine,
                credentials.email,
                credentials.password,
                settings=settings,
                client=client,
                key_cache=key_cache,
            )
    except AccountSignInRejected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sign-in was rejected.",
            headers={"Cache-Control": "no-store"},
        ) from None
    except (
        AccountSignInUnavailable,
        AccountAuthenticationUnavailable,
        AccountSessionUnavailable,
        AccountSessionAlreadyExists,
        InvalidAccountToken,
        SQLAlchemyError,
        TimeoutError,
    ):
        raise account_sign_in_unavailable() from None

    set_account_cookie(
        response,
        created.token,
        created.idle_expires_at,
        settings,
    )

    return AccountSignInResponse(
        user_id=created.user_id,
        expires_at=created.idle_expires_at,
        absolute_expires_at=created.absolute_expires_at,
    )
