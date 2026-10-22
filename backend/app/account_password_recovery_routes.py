"""Default-disabled password-recovery requests without application login."""

import asyncio
from typing import Literal, cast

import httpx2
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel

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

    client = cast(
        httpx2.AsyncClient | None,
        request.app.state.account_auth_client,
    )

    if (
        client is None
        or settings.supabase_auth_issuer is None
        or settings.supabase_auth_publishable_key is None
    ):
        raise password_recovery_unavailable()

    try:
        async with asyncio.timeout(settings.account_password_recovery_timeout_seconds):
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
    except (AccountPasswordRecoveryUnavailable, TimeoutError):
        raise password_recovery_unavailable() from None

    response.headers["Cache-Control"] = "no-store"
    return AccountPasswordRecoveryResponse()
