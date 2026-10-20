"""Bounded provider-token refresh without database or browser integration."""

import asyncio
import json
from dataclasses import dataclass

import httpx2
from pydantic import SecretStr

from app.config import Settings

_REFRESH_TIMEOUT_SECONDS = 5.0
_MAX_RESPONSE_BYTES = 64 * 1024
_MAX_TOKEN_CHARACTERS = 8192

_REJECTED_CODES = frozenset(
    {
        "refresh_token_not_found",
        "refresh_token_already_used",
        "session_not_found",
        "session_expired",
        "user_not_found",
        "user_banned",
    }
)


class AccountRefreshRejected(ValueError):
    """Provider credentials cannot continue the account session."""


class AccountRefreshUnavailable(RuntimeError):
    """Refresh could not safely produce a usable provider response."""


@dataclass(frozen=True, slots=True)
class RefreshedAccountTokens:
    """Provider token pair; identity still requires JWT verification."""

    access_token: SecretStr
    refresh_token: SecretStr


def _valid_token(value: str) -> bool:
    return 1 <= len(value) <= _MAX_TOKEN_CHARACTERS and all(
        33 <= ord(character) <= 126 for character in value
    )


def _response_token(value: object) -> SecretStr:
    if not isinstance(value, str) or not _valid_token(value):
        raise AccountRefreshUnavailable("Account refresh is unavailable.")

    return SecretStr(value)


async def refresh_account_tokens(
    refresh_token: SecretStr,
    *,
    settings: Settings,
    client: httpx2.AsyncClient,
) -> RefreshedAccountTokens:
    """Exchange credentials once using a caller-owned HTTP client.

    Does not retry, persist tokens, verify JWT identity, or extend application
    session deadlines. The caller must coordinate concurrent refresh attempts.
    """
    issuer = settings.supabase_auth_issuer
    publishable_key = settings.supabase_auth_publishable_key

    if issuer is None or publishable_key is None:
        raise AccountRefreshUnavailable("Account refresh is not configured.")

    raw_refresh_token = refresh_token.get_secret_value()
    if not _valid_token(raw_refresh_token):
        raise AccountRefreshRejected("Account credentials were rejected.")

    url = f"{issuer}/token?grant_type=refresh_token"
    body = bytearray()

    try:
        async with asyncio.timeout(_REFRESH_TIMEOUT_SECONDS):
            async with client.stream(
                "POST",
                url,
                headers={
                    "apikey": publishable_key.get_secret_value(),
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                },
                json={"refresh_token": raw_refresh_token},
                auth=None,
                follow_redirects=False,
                timeout=_REFRESH_TIMEOUT_SECONDS,
            ) as response:
                status_code = response.status_code

                if status_code not in (200, 400, 401, 403, 422):
                    raise AccountRefreshUnavailable("Account refresh is unavailable.")

                content_type = (
                    response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                )
                if content_type != "application/json":
                    raise AccountRefreshUnavailable("Account refresh is unavailable.")

                content_encoding = (
                    response.headers.get("content-encoding", "identity").strip().lower()
                )
                if content_encoding not in ("", "identity"):
                    raise AccountRefreshUnavailable("Account refresh is unavailable.")

                async for chunk in response.aiter_raw():
                    if len(body) + len(chunk) > _MAX_RESPONSE_BYTES:
                        raise AccountRefreshUnavailable("Account refresh is unavailable.")
                    body.extend(chunk)

    except (httpx2.HTTPError, TimeoutError):
        raise AccountRefreshUnavailable("Account refresh is unavailable.") from None

    try:
        payload: object = json.loads(body)
    except (ValueError, UnicodeError, RecursionError):
        raise AccountRefreshUnavailable("Account refresh is unavailable.") from None

    if not isinstance(payload, dict):
        raise AccountRefreshUnavailable("Account refresh is unavailable.")

    if status_code != 200:
        error_code = payload.get("error_code")
        if isinstance(error_code, str) and error_code in _REJECTED_CODES:
            raise AccountRefreshRejected("Account credentials were rejected.")

        raise AccountRefreshUnavailable("Account refresh is unavailable.")

    token_type = payload.get("token_type")
    if not isinstance(token_type, str) or token_type.lower() != "bearer":
        raise AccountRefreshUnavailable("Account refresh is unavailable.")

    return RefreshedAccountTokens(
        access_token=_response_token(payload.get("access_token")),
        refresh_token=_response_token(payload.get("refresh_token")),
    )
