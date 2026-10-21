"""Sign out the current application session after committed deletion."""

import asyncio
from typing import cast

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine

from app.account_cookies import clear_account_cookie, read_account_cookie
from app.account_session_transactions import delete_account_session_transaction
from app.config import Settings
from app.csrf import require_trusted_origin

router = APIRouter(prefix="/api/v1/account", tags=["account"])


def account_sign_out_unavailable() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Account sign-out is temporarily unavailable.",
        headers={"Cache-Control": "no-store"},
    )


@router.post(
    "/sign-out",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    dependencies=[Depends(require_trusted_origin)],
    responses={
        403: {"description": "Request origin is not allowed."},
        503: {"description": "Account sign-out is temporarily unavailable."},
    },
)
async def sign_out(request: Request) -> Response:
    """Delete the matching application session before clearing its cookie."""
    settings = cast(Settings, request.app.state.settings)

    if not settings.account_sign_out_api_enabled:
        raise account_sign_out_unavailable()

    token = read_account_cookie(request, settings)

    if token is not None:
        engine = cast(
            AsyncEngine | None,
            request.app.state.database_engine,
        )
        if engine is None:
            raise account_sign_out_unavailable()

        try:
            async with asyncio.timeout(settings.account_sign_out_timeout_seconds):
                await delete_account_session_transaction(engine, token)
        except (SQLAlchemyError, TimeoutError):
            raise account_sign_out_unavailable() from None

    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    clear_account_cookie(response, settings)
    return response
