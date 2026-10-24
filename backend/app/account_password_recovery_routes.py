"""Default-disabled password-recovery requests without application login."""

import asyncio
from typing import Literal, cast

import httpx2
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine

from app.account_password_recovery import (
    AccountPasswordRecoveryCaptchaRejected,
    AccountPasswordRecoveryRateLimited,
    AccountPasswordRecoveryRejected,
    AccountPasswordRecoveryUnavailable,
    request_password_recovery,
)
from app.account_password_recovery_requests import (
    read_password_recovery_credentials,
)
from app.auth_rate_limit_keys import (
    AuthRateLimitKeyUnavailable,
    get_password_recovery_ip_key,
)
from app.auth_rate_limits import AuthRateLimitUnavailable, commit_password_recovery_attempt
from app.client_ip import ClientIPUnavailable
from app.config import Settings
from app.csrf import require_trusted_origin

router = APIRouter(prefix="/api/v1/account", tags=["account"])


class AccountPasswordRecoveryResponse(BaseModel):
    status: Literal["accepted"] = "accepted"
    message: Literal["If password recovery can proceed, check your email for the next steps."] = (
        "If password recovery can proceed, check your email for the next steps."
    )


def password_recovery_unavailable() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Password recovery is temporarily unavailable.",
        headers={"Cache-Control": "no-store"},
    )


@router.post(
    "/password-recovery",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=AccountPasswordRecoveryResponse,
    dependencies=[Depends(require_trusted_origin)],
    responses={
        400: {"description": "Invalid or rejected recovery request."},
        403: {"description": "Request origin or human verification was rejected."},
        413: {"description": "Recovery request is too large."},
        415: {"description": "Password recovery requires a JSON request."},
        429: {"description": "Recovery requests are temporarily rate limited."},
        503: {"description": "Password recovery is temporarily unavailable."},
    },
)
async def recover_password(
    request: Request,
    response: Response,
) -> AccountPasswordRecoveryResponse:
    """Request recovery without returning identity or provider credentials."""
    settings = cast(Settings, request.app.state.settings)

    if not settings.account_password_recovery_api_enabled:
        raise password_recovery_unavailable()

    engine = cast(
        AsyncEngine | None,
        getattr(request.app.state, "database_engine", None),
    )
    client = cast(
        httpx2.AsyncClient | None,
        request.app.state.account_auth_client,
    )

    if (
        engine is None
        or client is None
        or settings.supabase_auth_issuer is None
        or settings.supabase_auth_publishable_key is None
        or settings.auth_rate_limit_hmac_secret is None
    ):
        raise password_recovery_unavailable()

    try:
        async with asyncio.timeout(settings.account_password_recovery_timeout_seconds):
            key_hash = get_password_recovery_ip_key(request, settings)
            decision = await commit_password_recovery_attempt(
                engine,
                key_hash,
                max_requests=settings.account_password_recovery_ip_max_requests,
                window_seconds=settings.account_password_recovery_ip_window_seconds,
            )
            if not decision.allowed:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Password recovery is temporarily rate limited.",
                    headers={
                        "Cache-Control": "no-store",
                        "Retry-After": str(decision.retry_after_seconds),
                    },
                )

            credentials = await read_password_recovery_credentials(request)

            await request_password_recovery(
                credentials.email,
                credentials.captcha_token,
                settings=settings,
                client=client,
            )
    except AccountPasswordRecoveryCaptchaRejected:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Human verification is required or was rejected.",
            headers={
                "Cache-Control": "no-store",
                "X-Account-Verification": "required",
            },
        ) from None
    except AccountPasswordRecoveryRejected:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password recovery was rejected.",
            headers={"Cache-Control": "no-store"},
        ) from None
    except AccountPasswordRecoveryRateLimited:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Password recovery is temporarily rate limited.",
            headers={"Cache-Control": "no-store"},
        ) from None
    except (
        AccountPasswordRecoveryUnavailable,
        AuthRateLimitKeyUnavailable,
        AuthRateLimitUnavailable,
        ClientIPUnavailable,
        SQLAlchemyError,
        TimeoutError,
    ):
        raise password_recovery_unavailable() from None

    response.headers["Cache-Control"] = "no-store"
    return AccountPasswordRecoveryResponse()
