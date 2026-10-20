"""HTTP endpoints requiring verified managed-account credentials."""

from typing import Annotated, cast
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, SecretStr

from app.account_auth import (
    AccountAuthenticationUnavailable,
    authenticate_account_token,
)
from app.account_key_cache import AccountKeyCache
from app.account_tokens import InvalidAccountToken, VerifiedAccount
from app.config import Settings

router = APIRouter(prefix="/api/v1/account", tags=["account"])


class AccountIdentityResponse(BaseModel):
    user_id: UUID


def invalid_account_credentials() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing account credentials.",
        headers={
            "WWW-Authenticate": "Bearer",
            "Cache-Control": "no-store",
        },
    )


async def require_account(request: Request) -> VerifiedAccount:
    """Require exactly one Authorization header containing a Bearer token."""

    authorization = request.headers.getlist("authorization")

    if len(authorization) != 1:
        raise invalid_account_credentials()

    scheme, separator, credentials = authorization[0].partition(" ")
    credentials = credentials.lstrip(" ")

    if scheme.lower() != "bearer" or not separator or not credentials:
        raise invalid_account_credentials()

    settings = cast(Settings, request.app.state.settings)
    key_cache = cast(
        AccountKeyCache | None,
        request.app.state.account_key_cache,
    )

    try:
        return await authenticate_account_token(
            SecretStr(credentials),
            settings=settings,
            key_cache=key_cache,
        )
    except InvalidAccountToken:
        raise invalid_account_credentials() from None
    except AccountAuthenticationUnavailable:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Account authentication is unavailable.",
            headers={"Cache-Control": "no-store"},
        ) from None


@router.get(
    "/me",
    response_model=AccountIdentityResponse,
    responses={
        401: {"description": "Invalid or missing account credentials."},
        503: {"description": "Account verification is unavailable."},
    },
)
async def get_current_account(
    response: Response,
    account: Annotated[VerifiedAccount, Depends(require_account)],
) -> AccountIdentityResponse:
    response.headers["Cache-Control"] = "no-store"
    return AccountIdentityResponse(user_id=account.user_id)
