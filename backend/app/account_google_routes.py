"""Default-disabled Google initiation and browser-bound callback handling."""

import asyncio
from datetime import datetime
from typing import Literal, cast
from urllib.parse import urlsplit, urlunsplit

import httpx2
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine

from app.account_auth import AccountAuthenticationUnavailable
from app.account_cookies import account_cookie_name, set_account_cookie
from app.account_google_authorization import (
    GoogleAuthorizationUnavailable,
    build_google_authorization_url,
)
from app.account_google_callback import complete_google_callback
from app.account_google_exchange import GoogleCodeExchangeRejected, GoogleCodeExchangeUnavailable
from app.account_google_requests import read_google_callback_code
from app.account_key_cache import AccountKeyCache
from app.account_oauth_attempts import OAuthLoginAttemptUnavailable
from app.account_oauth_cookies import clear_oauth_cookie, read_oauth_cookie, set_oauth_cookie
from app.account_oauth_material import InvalidOAuthLoginMaterial
from app.account_oauth_transactions import (
    create_oauth_login_attempt_transaction,
    replace_oauth_login_attempt_transaction,
)
from app.account_sessions import AccountSessionAlreadyExists, AccountSessionUnavailable
from app.account_signup_terms import (
    clear_signup_terms_cookie,
    read_signup_terms_cookie,
    signup_terms_cookie_name,
)
from app.account_terms import AccountTermsUnavailable
from app.account_tokens import InvalidAccountToken
from app.auth_rate_limit_keys import AuthRateLimitKeyUnavailable, get_google_start_ip_key
from app.auth_rate_limits import AuthRateLimitUnavailable, commit_google_start_attempt
from app.client_ip import ClientIPUnavailable
from app.config import Settings
from app.csrf import require_trusted_origin

router = APIRouter(prefix="/api/v1/account/google", tags=["account"])
_HEADERS = {"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"}


class GoogleLoginStartResponse(BaseModel):
    authorization_url: str
    expires_at: datetime


def google_login_unavailable() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Google sign-in is temporarily unavailable.",
        headers=dict(_HEADERS),
    )


@router.post(
    "/start",
    response_model=GoogleLoginStartResponse,
    dependencies=[Depends(require_trusted_origin)],
    responses={
        400: {"description": "Invalid request or a fresh login start is required."},
        403: {"description": "Request origin is not allowed."},
        409: {"description": "Sign out before starting another account login."},
        429: {"description": "Too many Google sign-in attempts; retry later."},
        503: {"description": "Google sign-in is temporarily unavailable."},
    },
)
async def start_google_login(request: Request, response: Response) -> GoogleLoginStartResponse:
    """Accept an empty POST; never accept provider or redirect options from a browser."""
    settings = cast(Settings, request.app.state.settings)
    if not settings.account_google_oauth_api_enabled:
        raise google_login_unavailable()

    engine = cast(AsyncEngine | None, request.app.state.database_engine)
    client = cast(httpx2.AsyncClient | None, request.app.state.account_auth_client)
    key_cache = cast(AccountKeyCache | None, request.app.state.account_key_cache)
    if (
        engine is None
        or client is None
        or key_cache is None
        or settings.supabase_auth_issuer is None
        or settings.supabase_auth_publishable_key is None
        or settings.account_session_encryption_key is None
        or settings.account_google_oauth_callback_url is None
    ):
        raise google_login_unavailable()

    if account_cookie_name(settings) in request.cookies:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Sign out before starting another account login.",
            headers=dict(_HEADERS),
        )

    try:
        async with asyncio.timeout(settings.account_google_oauth_timeout_seconds):
            if request.scope.get("query_string", b""):
                raise HTTPException(400, "Invalid Google sign-in request.", headers=dict(_HEADERS))
            async for chunk in request.stream():
                if chunk:
                    raise HTTPException(
                        400, "Invalid Google sign-in request.", headers=dict(_HEADERS)
                    )

            decision = await commit_google_start_attempt(
                engine,
                get_google_start_ip_key(request, settings),
                max_requests=settings.account_google_oauth_ip_max_requests,
                window_seconds=settings.account_google_oauth_ip_window_seconds,
            )
            if not decision.allowed:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Google sign-in is temporarily rate limited.",
                    headers={**_HEADERS, "Retry-After": str(decision.retry_after_seconds)},
                )

            previous = read_oauth_cookie(request, settings)
            if previous is None:
                created = await create_oauth_login_attempt_transaction(engine, settings)
            else:
                created = await replace_oauth_login_attempt_transaction(
                    engine, settings, previous.get_secret_value()
                )
            authorization_url = build_google_authorization_url(settings, created.code_challenge)
    except InvalidOAuthLoginMaterial:
        cleared = Response()
        clear_oauth_cookie(cleared, settings)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google sign-in must be started again.",
            headers={**_HEADERS, "Set-Cookie": cleared.headers["set-cookie"]},
        ) from None
    except (
        GoogleAuthorizationUnavailable,
        OAuthLoginAttemptUnavailable,
        SQLAlchemyError,
        TimeoutError,
        AuthRateLimitKeyUnavailable,
        AuthRateLimitUnavailable,
        ClientIPUnavailable,
    ):
        raise google_login_unavailable() from None

    set_oauth_cookie(response, created.browser_token, created.expires_at, settings)
    response.headers["Referrer-Policy"] = "no-referrer"
    return GoogleLoginStartResponse(
        authorization_url=authorization_url,
        expires_at=created.expires_at,
    )


def _callback_return(
    settings: Settings,
    outcome: Literal["success", "rejected", "unavailable", "sign-out-required"],
) -> Response:
    """Return to the configured public callback origin, never a request destination."""
    callback = settings.account_google_oauth_callback_url
    response: Response
    if not settings.account_google_oauth_api_enabled or callback is None:
        response = JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"detail": "Google sign-in is temporarily unavailable."},
            headers=dict(_HEADERS),
        )
    else:
        parsed = urlsplit(str(callback))
        destination = urlunsplit(
            (parsed.scheme, parsed.netloc, "/", "", f"google-sign-in={outcome}")
        )
        response = RedirectResponse(
            destination, status_code=status.HTTP_303_SEE_OTHER, headers=dict(_HEADERS)
        )
    clear_oauth_cookie(response, settings)
    return response


@router.get(
    "/callback/{remainder:path}",
    response_class=Response,
    include_in_schema=False,
)
@router.get(
    "/callback",
    response_class=Response,
    status_code=status.HTTP_303_SEE_OTHER,
    responses={
        303: {"description": "Return to the fixed website destination with a generic outcome."},
        503: {"description": "Google sign-in is disabled or its callback is not configured."},
    },
)
async def finish_google_login(request: Request) -> Response:
    """Accept a top-level callback using browser binding and PKCE, without an Origin gate."""
    settings = cast(Settings, request.app.state.settings)
    if (
        not settings.account_google_oauth_api_enabled
        or settings.account_google_oauth_callback_url is None
    ):
        return _callback_return(settings, "unavailable")

    if request.scope["path"] != "/api/v1/account/google/callback":
        return _callback_return(settings, "rejected")

    engine = cast(AsyncEngine | None, request.app.state.database_engine)
    client = cast(httpx2.AsyncClient | None, request.app.state.account_auth_client)
    key_cache = cast(AccountKeyCache | None, request.app.state.account_key_cache)
    if (
        engine is None
        or client is None
        or key_cache is None
        or settings.supabase_auth_issuer is None
        or settings.supabase_auth_publishable_key is None
        or settings.account_session_encryption_key is None
    ):
        return _callback_return(settings, "unavailable")

    if account_cookie_name(settings) in request.cookies:
        return _callback_return(settings, "sign-out-required")

    try:
        code = read_google_callback_code(request)
    except HTTPException:
        return _callback_return(settings, "rejected")

    try:
        binding = read_oauth_cookie(request, settings)
        if binding is None:
            raise InvalidOAuthLoginMaterial("Invalid OAuth login material.")
        created = await complete_google_callback(
            engine,
            code,
            binding.get_secret_value(),
            settings=settings,
            client=client,
            key_cache=key_cache,
            signup_terms_receipt=read_signup_terms_cookie(request, settings),
        )
    except (InvalidOAuthLoginMaterial, GoogleCodeExchangeRejected, InvalidAccountToken):
        return _callback_return(settings, "rejected")
    except (
        OAuthLoginAttemptUnavailable,
        GoogleCodeExchangeUnavailable,
        AccountAuthenticationUnavailable,
        AccountSessionAlreadyExists,
        AccountSessionUnavailable,
        AccountTermsUnavailable,
        SQLAlchemyError,
        TimeoutError,
    ):
        return _callback_return(settings, "unavailable")

    response = _callback_return(settings, "success")
    set_account_cookie(response, created.token, created.idle_expires_at, settings)
    if signup_terms_cookie_name(settings) in request.cookies:
        clear_signup_terms_cookie(response, settings)
    return response
