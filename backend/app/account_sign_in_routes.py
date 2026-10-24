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
from app.account_cookies import account_cookie_name, set_account_cookie
from app.account_key_cache import AccountKeyCache
from app.account_sessions import AccountSessionAlreadyExists, AccountSessionUnavailable
from app.account_sign_in import (
    AccountSignInCaptchaRejected,
    AccountSignInRejected,
    AccountSignInUnavailable,
)
from app.account_sign_in_requests import read_sign_in_credentials
from app.account_sign_in_service import sign_in_account
from app.account_tokens import InvalidAccountToken
from app.auth_rate_limit_keys import AuthRateLimitKeyUnavailable, get_sign_in_ip_key
from app.auth_rate_limits import AuthRateLimitUnavailable, commit_sign_in_attempt
from app.client_ip import ClientIPUnavailable
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
        403: {"description": "Request origin or human verification was rejected."},
        409: {"description": "Sign out before starting another account login."},
        413: {"description": "Sign-in request is too large."},
        415: {"description": "Sign-in requires a JSON request."},
        429: {"description": "Sign-in requests are temporarily rate limited."},
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

    if (
        engine is None
        or client is None
        or key_cache is None
        or settings.supabase_auth_issuer is None
        or settings.supabase_auth_publishable_key is None
        or settings.account_session_encryption_key is None
        or settings.auth_rate_limit_hmac_secret is None
    ):
        raise account_sign_in_unavailable()

    # Match the Google entry point: cookie presence requires explicit sign-out,
    # including stale/malformed cookies. Never silently replace an account.
    if account_cookie_name(settings) in request.cookies:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Sign out before starting another account login.",
            headers={"Cache-Control": "no-store"},
        )

    try:
        async with asyncio.timeout(settings.account_sign_in_timeout_seconds):
            key_hash = get_sign_in_ip_key(request, settings)
            decision = await commit_sign_in_attempt(
                engine,
                key_hash,
                max_requests=settings.account_sign_in_ip_max_requests,
                window_seconds=settings.account_sign_in_ip_window_seconds,
            )
            if not decision.allowed:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Sign-in is temporarily rate limited.",
                    headers={
                        "Cache-Control": "no-store",
                        "Retry-After": str(decision.retry_after_seconds),
                    },
                )

            credentials = await read_sign_in_credentials(request)
            if credentials.captcha_token is None:
                raise AccountSignInCaptchaRejected("Human verification is required.")

            created = await sign_in_account(
                engine,
                credentials.email,
                credentials.password,
                settings=settings,
                client=client,
                key_cache=key_cache,
                captcha_token=credentials.captcha_token,
            )
    except AccountSignInCaptchaRejected:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Human verification is required or was rejected.",
            headers={
                "Cache-Control": "no-store",
                "X-Account-Verification": "required",
            },
        ) from None
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
        AuthRateLimitKeyUnavailable,
        AuthRateLimitUnavailable,
        ClientIPUnavailable,
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
