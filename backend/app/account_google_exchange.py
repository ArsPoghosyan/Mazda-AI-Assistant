"""Bounded Supabase PKCE exchange without application authentication."""

import asyncio
import json
import re
from dataclasses import dataclass

import httpx2
from pydantic import SecretStr

from app.config import Settings

_EXCHANGE_TIMEOUT_SECONDS = 5.0
_MAX_RESPONSE_BYTES = 64 * 1024


class GoogleCodeExchangeRejected(ValueError):
    """The provider rejected the authorization code or verifier."""


class GoogleCodeExchangeUnavailable(RuntimeError):
    """The exchange could not safely produce usable credentials."""


@dataclass(frozen=True, slots=True)
class ExchangedGoogleTokens:
    """Supabase credentials; JWT and provider identity remain unverified."""

    access_token: SecretStr
    refresh_token: SecretStr


def _error_code(payload: dict[str, object]) -> str | None:
    legacy = payload.get("error_code")
    current = payload.get("code")

    if isinstance(legacy, str):
        if isinstance(current, str) and current != legacy:
            return None
        return legacy

    if legacy is None and isinstance(current, str):
        return current

    return None


def _response_token(value: object) -> SecretStr:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 8192
        or any(ord(character) < 33 or ord(character) > 126 for character in value)
    ):
        raise GoogleCodeExchangeUnavailable("Google sign-in is unavailable.")

    return SecretStr(value)


def interpret_google_code_exchange_response(
    status_code: int,
    payload: object,
) -> ExchangedGoogleTokens:
    """Accept only a bounded response obtained from the trusted provider."""
    if not isinstance(payload, dict):
        raise GoogleCodeExchangeUnavailable("Google sign-in is unavailable.")

    if status_code != 200:
        if status_code in (400, 401, 403, 404, 422) and _error_code(payload) in {
            "flow_state_not_found",
            "flow_state_expired",
            "bad_code_verifier",
        }:
            raise GoogleCodeExchangeRejected("Google sign-in was rejected.")

        raise GoogleCodeExchangeUnavailable("Google sign-in is unavailable.")

    if any(name in payload for name in ("error", "error_code", "code")):
        raise GoogleCodeExchangeUnavailable("Google sign-in is unavailable.")

    token_type = payload.get("token_type")
    if not isinstance(token_type, str) or token_type.lower() != "bearer":
        raise GoogleCodeExchangeUnavailable("Google sign-in is unavailable.")

    # Discard Google API credentials, user metadata and all unrelated fields.
    return ExchangedGoogleTokens(
        access_token=_response_token(payload.get("access_token")),
        refresh_token=_response_token(payload.get("refresh_token")),
    )


async def exchange_google_authorization_code(
    code: SecretStr,
    verifier: SecretStr,
    *,
    settings: Settings,
    client: httpx2.AsyncClient,
) -> ExchangedGoogleTokens:
    """Exchange once after pending-attempt consumption has committed successfully.

    The caller supplies the recovered verifier and owns the HTTP client's
    lifecycle. This adapter cannot prove prior consumption/commit. It performs
    no retry, cookie issuance, persistence, JWT or Google-identity verification.
    A failed/uncertain exchange requires a fresh flow, not a replay.
    """
    issuer = settings.supabase_auth_issuer
    publishable_key = settings.supabase_auth_publishable_key
    if issuer is None or publishable_key is None:
        raise GoogleCodeExchangeUnavailable("Google sign-in is unavailable.")

    raw_code = code.get_secret_value()
    raw_verifier = verifier.get_secret_value()
    if (
        not 1 <= len(raw_code) <= 1024
        or any(ord(character) < 33 or ord(character) > 126 for character in raw_code)
        or len(raw_verifier) != 43
        or re.fullmatch(r"[A-Za-z0-9_-]{43}", raw_verifier) is None
    ):
        raise GoogleCodeExchangeRejected("Google sign-in was rejected.")

    # An explicit Request avoids merging the shared client's cookies, default
    # Authorization header or query parameters into this credential exchange.
    request = httpx2.Request(
        "POST",
        f"{issuer}/token?grant_type=pkce",
        headers={
            "apikey": publishable_key.get_secret_value(),
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "Cache-Control": "no-store",
        },
        json={"auth_code": raw_code, "code_verifier": raw_verifier},
        extensions={"timeout": httpx2.Timeout(_EXCHANGE_TIMEOUT_SECONDS).as_dict()},
    )
    body = bytearray()
    try:
        async with asyncio.timeout(_EXCHANGE_TIMEOUT_SECONDS):
            response = await client.send(request, stream=True, auth=None, follow_redirects=False)
            try:
                status_code = response.status_code
                if status_code not in (200, 400, 401, 403, 404, 422):
                    raise GoogleCodeExchangeUnavailable("Google sign-in is unavailable.")
                content_type = (
                    response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                )
                content_encoding = (
                    response.headers.get("content-encoding", "identity").strip().lower()
                )
                if content_type != "application/json" or content_encoding not in ("", "identity"):
                    raise GoogleCodeExchangeUnavailable("Google sign-in is unavailable.")

                async for chunk in response.aiter_raw():
                    if len(body) + len(chunk) > _MAX_RESPONSE_BYTES:
                        raise GoogleCodeExchangeUnavailable("Google sign-in is unavailable.")
                    body.extend(chunk)
            finally:
                await response.aclose()
    except (httpx2.HTTPError, TimeoutError):
        raise GoogleCodeExchangeUnavailable("Google sign-in is unavailable.") from None

    try:
        payload: object = json.loads(body)
    except (ValueError, UnicodeError, RecursionError):
        raise GoogleCodeExchangeUnavailable("Google sign-in is unavailable.") from None

    return interpret_google_code_exchange_response(status_code, payload)
