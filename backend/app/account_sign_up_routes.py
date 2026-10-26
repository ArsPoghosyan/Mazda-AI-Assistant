"""Default-disabled registration without application-session creation."""

import asyncio
from typing import Literal, cast

import httpx2
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine

from app.account_sign_up import (
    AccountSignUpCaptchaRejected,
    AccountSignUpRejected,
    AccountSignUpUnavailable,
    sign_up_with_password,
)
from app.account_sign_up_requests import read_sign_up_credentials
from app.account_signup_terms import make_signup_terms_receipt, set_signup_terms_cookie
from app.auth_rate_limit_keys import AuthRateLimitKeyUnavailable, get_sign_up_ip_key
from app.auth_rate_limits import AuthRateLimitUnavailable, commit_sign_up_attempt
from app.client_ip import ClientIPUnavailable
from app.config import Settings
from app.csrf import require_trusted_origin

router = APIRouter(prefix="/api/v1/account", tags=["account"])


class AccountSignUpResponse(BaseModel):
    status: Literal["accepted"] = "accepted"
    message: Literal["If registration can proceed, check your email for a verification code."] = (
        "If registration can proceed, check your email for a verification code."
    )


def account_sign_up_unavailable() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Account registration is temporarily unavailable.",
        headers={"Cache-Control": "no-store"},
    )


@router.post(
    "/sign-up",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=AccountSignUpResponse,
    dependencies=[Depends(require_trusted_origin)],
    responses={
        400: {"description": "Invalid or rejected registration request."},
        403: {"description": "Request origin or human verification was rejected."},
        413: {"description": "Registration request is too large."},
        415: {"description": "Registration requires a JSON request."},
        429: {"description": "Registration requests are temporarily rate limited."},
        503: {"description": "Account registration is temporarily unavailable."},
    },
)
async def sign_up(
    request: Request,
    response: Response,
) -> AccountSignUpResponse:
    """Submit registration without returning provider identity or credentials."""
    settings = cast(Settings, request.app.state.settings)

    if not settings.account_sign_up_api_enabled:
        raise account_sign_up_unavailable()

    client = cast(
        httpx2.AsyncClient | None,
        request.app.state.account_auth_client,
    )
    engine = cast(AsyncEngine | None, request.app.state.database_engine)

    if (
        client is None
        or engine is None
        or settings.auth_rate_limit_hmac_secret is None
        or settings.supabase_auth_issuer is None
        or settings.supabase_auth_publishable_key is None
        or settings.account_session_encryption_key is None
        or not settings.account_terms_api_enabled
    ):
        raise account_sign_up_unavailable()

    try:
        async with asyncio.timeout(settings.account_sign_up_timeout_seconds):
            key_hash = get_sign_up_ip_key(request, settings)
            decision = await commit_sign_up_attempt(
                engine,
                key_hash,
                max_requests=settings.account_sign_up_ip_max_requests,
                window_seconds=settings.account_sign_up_ip_window_seconds,
            )
            if not decision.allowed:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Account registration is temporarily rate limited.",
                    headers={
                        "Cache-Control": "no-store",
                        "Retry-After": str(decision.retry_after_seconds),
                    },
                )

            credentials = await read_sign_up_credentials(request)
            receipt = make_signup_terms_receipt(credentials.email)

            await sign_up_with_password(
                credentials.email,
                credentials.password,
                credentials.captcha_token,
                settings=settings,
                client=client,
            )
    except AccountSignUpCaptchaRejected:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Human verification is required or was rejected.",
            headers={
                "Cache-Control": "no-store",
                "X-Account-Verification": "required",
            },
        ) from None
    except AccountSignUpRejected:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Registration was rejected.",
            headers={"Cache-Control": "no-store"},
        ) from None
    except (
        AccountSignUpUnavailable,
        AuthRateLimitKeyUnavailable,
        AuthRateLimitUnavailable,
        ClientIPUnavailable,
        SQLAlchemyError,
        TimeoutError,
    ):
        raise account_sign_up_unavailable() from None

    response.headers["Cache-Control"] = "no-store"
    set_signup_terms_cookie(response, receipt, settings)
    return AccountSignUpResponse()
