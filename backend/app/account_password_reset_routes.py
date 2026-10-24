"""Default-disabled password reset without application login."""

import asyncio
from typing import Literal, cast

import httpx2
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine

from app.account_key_cache import AccountKeyCache
from app.account_password_reset_requests import read_password_reset_credentials
from app.account_password_reset_service import (
    AccountPasswordResetUnavailable,
    reset_account_password,
)
from app.account_password_update import (
    AccountPasswordUpdateRateLimited,
    AccountPasswordUpdateRejected,
    AccountPasswordUpdateUnavailable,
)
from app.account_recovery_session_cleanup import AccountRecoverySessionCleanupUnavailable
from app.account_recovery_verification import (
    AccountRecoveryVerificationRateLimited,
    AccountRecoveryVerificationRejected,
    AccountRecoveryVerificationUnavailable,
)
from app.auth_rate_limit_keys import AuthRateLimitKeyUnavailable, get_password_reset_ip_key
from app.auth_rate_limits import AuthRateLimitUnavailable, commit_password_reset_attempt
from app.client_ip import ClientIPUnavailable
from app.config import Settings
from app.csrf import require_trusted_origin

router = APIRouter(prefix="/api/v1/account", tags=["account"])


class AccountPasswordResetResponse(BaseModel):
    status: Literal["completed"] = "completed"
    message: Literal["Password reset completed. Sign in with your new password."] = (
        "Password reset completed. Sign in with your new password."
    )


def password_reset_unavailable() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Password reset is temporarily unavailable.",
        headers={"Cache-Control": "no-store"},
    )


@router.post(
    "/password-reset",
    response_model=AccountPasswordResetResponse,
    dependencies=[Depends(require_trusted_origin)],
    responses={
        400: {"description": "Invalid or rejected password reset."},
        403: {"description": "Request origin was rejected."},
        413: {"description": "Password reset request is too large."},
        415: {"description": "Password reset requires a JSON request."},
        429: {"description": "Password reset is temporarily rate limited."},
        503: {"description": "Password reset is temporarily unavailable."},
    },
)
async def reset_password(request: Request, response: Response) -> AccountPasswordResetResponse:
    """Return metadata only after provider cleanup and application-session commit."""
    settings = cast(Settings, request.app.state.settings)

    if not settings.account_password_reset_api_enabled:
        raise password_reset_unavailable()

    engine = cast(AsyncEngine | None, request.app.state.database_engine)
    client = cast(httpx2.AsyncClient | None, request.app.state.account_auth_client)
    key_cache = cast(AccountKeyCache | None, request.app.state.account_key_cache)

    if (
        engine is None
        or settings.auth_rate_limit_hmac_secret is None
        or client is None
        or key_cache is None
        or settings.supabase_auth_issuer is None
        or settings.supabase_auth_publishable_key is None
    ):
        raise password_reset_unavailable()

    try:
        async with asyncio.timeout(settings.account_password_reset_timeout_seconds):
            key_hash = get_password_reset_ip_key(request, settings)
            decision = await commit_password_reset_attempt(
                engine,
                key_hash,
                max_requests=settings.account_password_reset_ip_max_requests,
                window_seconds=settings.account_password_reset_ip_window_seconds,
            )
            if not decision.allowed:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Password reset is temporarily rate limited.",
                    headers={
                        "Cache-Control": "no-store",
                        "Retry-After": str(decision.retry_after_seconds),
                    },
                )

            credentials = await read_password_reset_credentials(request)
            await reset_account_password(
                engine,
                credentials.email,
                credentials.code,
                credentials.new_password,
                settings=settings,
                client=client,
                key_cache=key_cache,
            )
    except (AccountRecoveryVerificationRejected, AccountPasswordUpdateRejected):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password reset was rejected.",
            headers={"Cache-Control": "no-store"},
        ) from None
    except (AccountRecoveryVerificationRateLimited, AccountPasswordUpdateRateLimited):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Password reset is temporarily rate limited.",
            headers={"Cache-Control": "no-store"},
        ) from None
    except (
        AccountPasswordResetUnavailable,
        AccountRecoveryVerificationUnavailable,
        AccountPasswordUpdateUnavailable,
        AccountRecoverySessionCleanupUnavailable,
        AuthRateLimitKeyUnavailable,
        AuthRateLimitUnavailable,
        ClientIPUnavailable,
        SQLAlchemyError,
        TimeoutError,
    ):
        raise password_reset_unavailable() from None

    response.headers["Cache-Control"] = "no-store"
    return AccountPasswordResetResponse()
