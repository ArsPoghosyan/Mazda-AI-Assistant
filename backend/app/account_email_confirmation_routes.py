"""Default-disabled email confirmation without application login."""

import asyncio
from typing import Literal, cast

import httpx2
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel

from app.account_email_confirmation import (
    AccountEmailConfirmationRejected,
    AccountEmailConfirmationUnavailable,
    confirm_email_code,
)
from app.account_email_confirmation_requests import (
    read_email_confirmation_credentials,
)
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

    if (
        client is None
        or settings.supabase_auth_issuer is None
        or settings.supabase_auth_publishable_key is None
    ):
        raise email_confirmation_unavailable()

    try:
        async with asyncio.timeout(settings.account_email_confirmation_timeout_seconds):
            credentials = await read_email_confirmation_credentials(request)

            await confirm_email_code(
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
    except (AccountEmailConfirmationUnavailable, TimeoutError):
        raise email_confirmation_unavailable() from None

    response.headers["Cache-Control"] = "no-store"
    return AccountEmailConfirmationResponse()
