"""Bounded email/password sign-in without database or browser integration."""

import asyncio
import json
from dataclasses import dataclass

import httpx2
from pydantic import SecretStr

from app.config import Settings

_SIGN_IN_TIMEOUT_SECONDS = 5.0
_MAX_RESPONSE_BYTES = 64 * 1024
_MAX_TOKEN_CHARACTERS = 8192
_MAX_EMAIL_CHARACTERS = 320
_MAX_PASSWORD_CHARACTERS = 1024

_REJECTED_CODES = frozenset(
    {
        "invalid_credentials",
        "email_not_confirmed",
        "user_banned",
        "validation_failed",
    }
)


class AccountSignInRejected(ValueError):
    """Credentials could not establish a provider session."""


class AccountSignInUnavailable(RuntimeError):
    """Sign-in could not safely obtain a usable provider response."""


@dataclass(frozen=True, slots=True)
class SignedInAccountTokens:
    """Masked provider credentials; JWT identity still requires verification."""

    access_token: SecretStr
    refresh_token: SecretStr


def _input_value(value: SecretStr, max_characters: int) -> str:
    raw_value = value.get_secret_value()

    if not 1 <= len(raw_value) <= max_characters:
        raise AccountSignInRejected("Sign-in was rejected.")

    try:
        raw_value.encode("utf-8")
    except UnicodeError:
        raise AccountSignInRejected("Sign-in was rejected.") from None

    return raw_value


def _response_token(value: object) -> SecretStr:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= _MAX_TOKEN_CHARACTERS
        or any(ord(character) < 33 or ord(character) > 126 for character in value)
    ):
        raise AccountSignInUnavailable("Account sign-in is unavailable.")

    return SecretStr(value)


async def sign_in_with_password(
    email: SecretStr,
    password: SecretStr,
    *,
    settings: Settings,
    client: httpx2.AsyncClient,
) -> SignedInAccountTokens:
    """Exchange credentials once using a caller-owned HTTP client.

    Does not retry, persist passwords or tokens, verify JWT identity, create
    an application session, or issue browser cookies.
    """
    issuer = settings.supabase_auth_issuer
    publishable_key = settings.supabase_auth_publishable_key

    if issuer is None or publishable_key is None:
        raise AccountSignInUnavailable("Account sign-in is not configured.")

    raw_email = _input_value(email, _MAX_EMAIL_CHARACTERS)
    raw_password = _input_value(password, _MAX_PASSWORD_CHARACTERS)
    body = bytearray()

    try:
        async with asyncio.timeout(_SIGN_IN_TIMEOUT_SECONDS):
            async with client.stream(
                "POST",
                f"{issuer}/token?grant_type=password",
                headers={
                    "apikey": publishable_key.get_secret_value(),
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                },
                json={
                    "email": raw_email,
                    "password": raw_password,
                },
                auth=None,
                follow_redirects=False,
                timeout=_SIGN_IN_TIMEOUT_SECONDS,
            ) as response:
                status_code = response.status_code

                if status_code not in (200, 400, 401, 403, 422):
                    raise AccountSignInUnavailable("Account sign-in is unavailable.")

                content_type = (
                    response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                )
                if content_type != "application/json":
                    raise AccountSignInUnavailable("Account sign-in is unavailable.")

                content_encoding = (
                    response.headers.get("content-encoding", "identity").strip().lower()
                )
                if content_encoding not in ("", "identity"):
                    raise AccountSignInUnavailable("Account sign-in is unavailable.")

                async for chunk in response.aiter_raw():
                    if len(body) + len(chunk) > _MAX_RESPONSE_BYTES:
                        raise AccountSignInUnavailable("Account sign-in is unavailable.")
                    body.extend(chunk)

    except (httpx2.HTTPError, TimeoutError):
        raise AccountSignInUnavailable("Account sign-in is unavailable.") from None

    try:
        payload: object = json.loads(body)
    except (ValueError, UnicodeError, RecursionError):
        raise AccountSignInUnavailable("Account sign-in is unavailable.") from None

    if not isinstance(payload, dict):
        raise AccountSignInUnavailable("Account sign-in is unavailable.")

    if status_code != 200:
        error_code = payload.get("error_code")
        if isinstance(error_code, str) and error_code in _REJECTED_CODES:
            raise AccountSignInRejected("Sign-in was rejected.")

        raise AccountSignInUnavailable("Account sign-in is unavailable.")

    token_type = payload.get("token_type")
    if not isinstance(token_type, str) or token_type.lower() != "bearer":
        raise AccountSignInUnavailable("Account sign-in is unavailable.")

    return SignedInAccountTokens(
        access_token=_response_token(payload.get("access_token")),
        refresh_token=_response_token(payload.get("refresh_token")),
    )
