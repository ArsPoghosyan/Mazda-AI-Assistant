"""Default-disabled email confirmation without application login."""

import asyncio
from typing import Literal, cast

import httpx2
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine

from app.account_email_confirmation import (
    AccountEmailConfirmationRejected,
    AccountEmailConfirmationUnavailable,
    confirm_email_code,
)
from app.account_email_confirmation_requests import (
    read_email_confirmation_credentials,
)
from app.account_signup_terms import (
    clear_signup_terms_cookie,
    decode_signup_terms_receipt,
    read_signup_terms_cookie,
    set_signup_terms_cookie,
    signup_terms_cookie_name,
)
from app.auth_rate_limit_keys import AuthRateLimitKeyUnavailable, get_email_confirmation_ip_key
from app.auth_rate_limits import AuthRateLimitUnavailable, commit_email_confirmation_attempt
from app.client_ip import ClientIPUnavailable
from app.config import Settings
from app.csrf import require_trusted_origin

router = APIRouter(prefix="/api/v1/account", tags=["account"])


class AccountEmailConfirmationResponse(BaseModel):
    status: Literal["confirmed"] = "confirmed"
    message: Literal["Email confirmed. You can now sign in."] = (
        "Email confirmed. You can now sign in."
    )


def email_confirmation_unavailable() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Email confirmation is temporarily unavailable.",
        headers={"Cache-Control": "no-store"},
    )


@router.post(
    "/confirm-email",
    response_model=AccountEmailConfirmationResponse,
    dependencies=[Depends(require_trusted_origin)],
    responses={
        400: {"description": "Invalid or rejected email confirmation."},
        403: {"description": "Request origin was rejected."},
        413: {"description": "Email confirmation request is too large."},
        415: {"description": "Email confirmation requires a JSON request."},
        429: {"description": "Email confirmation requests are temporarily rate limited."},
        503: {"description": "Email confirmation is temporarily unavailable."},
    },
)
async def confirm_email(
    request: Request,
    response: Response,
) -> AccountEmailConfirmationResponse:
    """Confirm the supplied email code without issuing a session cookie."""
    settings = cast(Settings, request.app.state.settings)

    if not settings.account_email_confirmation_api_enabled:
        raise email_confirmation_unavailable()

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
    ):
        raise email_confirmation_unavailable()

    try:
        async with asyncio.timeout(settings.account_email_confirmation_timeout_seconds):
            key_hash = get_email_confirmation_ip_key(request, settings)
            decision = await commit_email_confirmation_attempt(
                engine,
                key_hash,
                max_requests=settings.account_email_confirmation_ip_max_requests,
                window_seconds=settings.account_email_confirmation_ip_window_seconds,
            )
            if not decision.allowed:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Email confirmation is temporarily rate limited.",
                    headers={
                        "Cache-Control": "no-store",
                        "Retry-After": str(decision.retry_after_seconds),
                    },
                )

            credentials = await read_email_confirmation_credentials(request)

            confirmed_user_id = await confirm_email_code(
                credentials.email,
                credentials.code,
                settings=settings,
                client=client,
            )
    except AccountEmailConfirmationRejected:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email confirmation was rejected.",
            headers={"Cache-Control": "no-store"},
        ) from None
    except (
        AccountEmailConfirmationUnavailable,
        AuthRateLimitKeyUnavailable,
        AuthRateLimitUnavailable,
        ClientIPUnavailable,
        SQLAlchemyError,
        TimeoutError,
    ):
        raise email_confirmation_unavailable() from None

    response.headers["Cache-Control"] = "no-store"
    if signup_terms_cookie_name(settings) in request.cookies:
        receipt = decode_signup_terms_receipt(
            read_signup_terms_cookie(request, settings), credentials.email, settings
        )
        if (
            settings.account_terms_api_enabled
            and receipt is not None
            and receipt.confirmed_user_id in (None, confirmed_user_id)
        ):
            set_signup_terms_cookie(
                response,
                receipt.model_copy(update={"confirmed_user_id": confirmed_user_id}),
                settings,
            )
        else:
            clear_signup_terms_cookie(response, settings)
    return AccountEmailConfirmationResponse()
