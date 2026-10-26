"""Default-disabled, cookie-authenticated explicit Terms acceptance."""

import asyncio
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, cast
from uuid import UUID

import httpx2
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, SecretStr
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine

from app.account_auth import AccountAuthenticationUnavailable
from app.account_cookies import clear_account_cookie, read_account_cookie, set_account_cookie
from app.account_key_cache import AccountKeyCache
from app.account_refresh import AccountRefreshRejected, AccountRefreshUnavailable
from app.account_terms import (
    AccountTermsRequired,
    AccountTermsSessionChanged,
    AccountTermsUnavailable,
    TermsAccountAccess,
    accept_account_terms_transaction,
    account_terms_status_transaction,
    terms_account_transaction,
)
from app.account_terms_requests import CURRENT_TERMS_VERSION, read_terms_acceptance
from app.config import Settings
from app.csrf import require_trusted_origin

router = APIRouter(prefix="/api/v1/account/terms", tags=["account"])


class AccountTermsAcceptanceResponse(BaseModel):
    terms_version: str
    accepted_at: datetime


class AccountTermsStatusResponse(BaseModel):
    terms_version: str
    accepted_at: datetime | None
    acceptance_required: bool


def _unavailable() -> HTTPException:
    return HTTPException(
        503, "Terms acceptance is temporarily unavailable.", headers={"Cache-Control": "no-store"}
    )


def _invalid_session(settings: Settings) -> HTTPException:
    response = Response()
    clear_account_cookie(response, settings)
    return HTTPException(
        401,
        "Invalid or expired account session.",
        headers={"Cache-Control": "no-store", "Set-Cookie": response.headers["set-cookie"]},
    )


@dataclass(frozen=True, slots=True)
class _TermsResources:
    settings: Settings
    token: SecretStr
    engine: AsyncEngine
    client: httpx2.AsyncClient
    key_cache: AccountKeyCache
    expected_user_id: UUID


def _resources(request: Request) -> _TermsResources:
    settings = cast(Settings, request.app.state.settings)
    if not settings.account_terms_api_enabled:
        raise _unavailable()
    token = read_account_cookie(request, settings)
    if token is None:
        raise _invalid_session(settings)
    subjects = request.headers.getlist("x-account-subject")
    try:
        if len(subjects) != 1 or len(subjects[0]) != 36:
            raise ValueError
        expected = UUID(subjects[0])
        if str(expected) != subjects[0].lower():
            raise ValueError
    except ValueError:
        raise HTTPException(
            400, "Invalid account setup request.", headers={"Cache-Control": "no-store"}
        ) from None
    engine = cast(AsyncEngine | None, request.app.state.database_engine)
    client = cast(httpx2.AsyncClient | None, request.app.state.account_auth_client)
    key_cache = cast(AccountKeyCache | None, request.app.state.account_key_cache)
    if engine is None or client is None or key_cache is None:
        raise _unavailable()
    return _TermsResources(settings, token, engine, client, key_cache, expected)


@router.post(
    "/accept",
    response_model=AccountTermsAcceptanceResponse,
    dependencies=[Depends(require_trusted_origin)],
    responses={
        400: {"description": "Explicit acceptance of the current Terms is required."},
        401: {"description": "Invalid or expired account session."},
        403: {"description": "Request origin is not allowed."},
        409: {"description": "The account changed; check the session again."},
        413: {"description": "Terms acceptance request is too large."},
        415: {"description": "Terms acceptance requires JSON."},
        503: {"description": "Terms acceptance is disabled or unavailable."},
    },
)
async def accept_terms(request: Request, response: Response) -> AccountTermsAcceptanceResponse:
    resources = _resources(request)
    settings = resources.settings

    try:
        async with asyncio.timeout(settings.account_session_auth_timeout_seconds):
            acceptance = await read_terms_acceptance(request)
            recorded = await accept_account_terms_transaction(
                resources.engine,
                resources.token,
                acceptance,
                settings=settings,
                client=resources.client,
                key_cache=resources.key_cache,
                expected_user_id=resources.expected_user_id,
            )
    except AccountTermsSessionChanged:
        raise HTTPException(
            409,
            "Account session changed. Please check it again.",
            headers={"Cache-Control": "no-store"},
        ) from None
    except AccountRefreshRejected:
        raise _invalid_session(settings) from None
    except (
        AccountAuthenticationUnavailable,
        AccountRefreshUnavailable,
        AccountTermsUnavailable,
        SQLAlchemyError,
        TimeoutError,
    ):
        raise _unavailable() from None

    if recorded is None:
        raise _invalid_session(settings)
    set_account_cookie(response, resources.token, recorded.session.idle_expires_at, settings)
    return AccountTermsAcceptanceResponse(
        terms_version=CURRENT_TERMS_VERSION, accepted_at=recorded.accepted_at
    )


@router.post(
    "/status",
    response_model=AccountTermsStatusResponse,
    dependencies=[Depends(require_trusted_origin)],
    responses={
        400: {"description": "An empty request without query options is required."},
        401: {"description": "Invalid or expired account session."},
        403: {"description": "Request origin is not allowed."},
        409: {"description": "The account changed; check the session again."},
        503: {"description": "Account setup status is disabled or unavailable."},
    },
)
async def terms_status(request: Request, response: Response) -> AccountTermsStatusResponse:
    """Read setup status without modifying the existing session response contract."""
    resources = _resources(request)
    settings = resources.settings
    try:
        async with asyncio.timeout(settings.account_session_auth_timeout_seconds):
            if request.scope.get("query_string", b""):
                raise HTTPException(
                    400, "Invalid Terms status request.", headers={"Cache-Control": "no-store"}
                )
            async for chunk in request.stream():
                if chunk:
                    raise HTTPException(
                        400, "Invalid Terms status request.", headers={"Cache-Control": "no-store"}
                    )
            checked = await account_terms_status_transaction(
                resources.engine,
                resources.token,
                settings=settings,
                client=resources.client,
                key_cache=resources.key_cache,
                expected_user_id=resources.expected_user_id,
            )
    except AccountTermsSessionChanged:
        raise HTTPException(
            409,
            "Account session changed. Please check it again.",
            headers={"Cache-Control": "no-store"},
        ) from None
    except AccountRefreshRejected:
        raise _invalid_session(settings) from None
    except (
        AccountAuthenticationUnavailable,
        AccountRefreshUnavailable,
        AccountTermsUnavailable,
        SQLAlchemyError,
        TimeoutError,
    ):
        raise _unavailable() from None
    if checked is None:
        raise _invalid_session(settings)
    set_account_cookie(response, resources.token, checked.session.idle_expires_at, settings)
    return AccountTermsStatusResponse(
        terms_version=CURRENT_TERMS_VERSION,
        accepted_at=checked.accepted_at,
        acceptance_required=checked.accepted_at is None,
    )


async def require_terms_account(
    request: Request, response: Response
) -> AsyncIterator[TermsAccountAccess]:
    """Resource dependency; use TermsAccountDependency for function-scoped commit.

    Real account resources must still scope all queries to the verified account.
    Authentication/setup/sign-out endpoints deliberately do not use this gate.
    """
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        await require_trusted_origin(request)
    resources = _resources(request)
    response.headers["Cache-Control"] = "no-store"
    try:
        async with asyncio.timeout(resources.settings.account_session_auth_timeout_seconds):
            async with terms_account_transaction(
                resources.engine,
                resources.token,
                settings=resources.settings,
                client=resources.client,
                key_cache=resources.key_cache,
                expected_user_id=resources.expected_user_id,
            ) as access:
                yield access
    except AccountTermsRequired:
        raise HTTPException(
            428,
            "Terms acceptance is required.",
            headers={"Cache-Control": "no-store", "X-Account-Setup": "terms-required"},
        ) from None
    except AccountTermsSessionChanged:
        raise HTTPException(
            409,
            "Account session changed. Please check it again.",
            headers={"Cache-Control": "no-store"},
        ) from None
    except AccountRefreshRejected:
        raise _invalid_session(resources.settings) from None
    except (
        AccountAuthenticationUnavailable,
        AccountRefreshUnavailable,
        AccountTermsUnavailable,
        SQLAlchemyError,
        TimeoutError,
    ):
        raise _unavailable() from None


# Function scope guarantees commit failures are handled before an HTTP success is sent.
TermsAccountDependency = Annotated[
    TermsAccountAccess, Depends(require_terms_account, scope="function")
]
