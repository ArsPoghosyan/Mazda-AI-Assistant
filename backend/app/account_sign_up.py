"""Bounded provider registration without application-session creation."""

import asyncio
import json
from uuid import UUID

import httpx2
from pydantic import SecretStr

from app.config import Settings

_SIGN_UP_TIMEOUT_SECONDS = 5.0
_MAX_RESPONSE_BYTES = 64 * 1024


class AccountSignUpRejected(ValueError):
    """Registration input was rejected."""


class AccountSignUpCaptchaRejected(AccountSignUpRejected):
    """The provider rejected human verification."""


class AccountSignUpUnavailable(RuntimeError):
    """Registration could not safely process the provider response."""


def _error_code(payload: dict[str, object]) -> str | None:
    legacy_code = payload.get("error_code")
    current_code = payload.get("code")

    if isinstance(legacy_code, str):
        if isinstance(current_code, str) and current_code != legacy_code:
            return None

        return legacy_code

    if legacy_code is None and isinstance(current_code, str):
        return current_code

    return None


def interpret_sign_up_response(status_code: int, payload: object) -> None:
    """Accept a generic registration outcome or raise a controlled error.

    Returning normally does not prove that an account was newly created
    or that an email was delivered. No provider identity or tokens escape.
    """
    if not isinstance(payload, dict):
        raise AccountSignUpUnavailable("Account registration is unavailable.")

    if status_code == 200:
        # Registration must not establish a session before email confirmation.
        if any(field in payload for field in ("access_token", "refresh_token", "session")):
            raise AccountSignUpUnavailable("Account registration is unavailable.")

        user_id = payload.get("id")

        if not isinstance(user_id, str) or len(user_id) > 64:
            raise AccountSignUpUnavailable("Account registration is unavailable.")

        try:
            UUID(user_id)
        except ValueError:
            raise AccountSignUpUnavailable("Account registration is unavailable.") from None

        # Validate the response shape, then discard all provider user details.
        return

    if status_code not in (400, 401, 403, 422):
        raise AccountSignUpUnavailable("Account registration is unavailable.")

    error_code = _error_code(payload)

    if error_code in {"user_already_exists", "email_exists"}:
        # Keep the public outcome independent of account existence.
        return

    if error_code == "captcha_failed":
        raise AccountSignUpCaptchaRejected("Human verification was rejected.")

    if error_code in {
        "validation_failed",
        "email_address_invalid",
        "weak_password",
    }:
        raise AccountSignUpRejected("Registration was rejected.")

    raise AccountSignUpUnavailable("Account registration is unavailable.")


def _input_value(value: SecretStr, max_characters: int) -> str:
    raw_value = value.get_secret_value()

    if not 1 <= len(raw_value) <= max_characters:
        raise AccountSignUpRejected("Registration was rejected.")

    try:
        raw_value.encode("utf-8")
    except UnicodeError:
        raise AccountSignUpRejected("Registration was rejected.") from None

    return raw_value


async def sign_up_with_password(
    email: SecretStr,
    password: SecretStr,
    captcha_token: SecretStr,
    *,
    settings: Settings,
    client: httpx2.AsyncClient,
) -> None:
    """Submit registration once using a caller-owned HTTP client.

    Returns no identity or credentials. Does not retry, create an application
    session, write to the application database, or issue browser cookies.
    """
    issuer = settings.supabase_auth_issuer
    publishable_key = settings.supabase_auth_publishable_key

    if issuer is None or publishable_key is None:
        raise AccountSignUpUnavailable("Account registration is not configured.")

    raw_email = _input_value(email, 320)
    raw_password = _input_value(password, 1024)
    raw_captcha = _input_value(captcha_token, 2048)

    if any(ord(character) < 33 or ord(character) > 126 for character in raw_captcha):
        raise AccountSignUpCaptchaRejected("Human verification was rejected.")

    request_payload: dict[str, object] = {
        "email": raw_email,
        "password": raw_password,
        "gotrue_meta_security": {
            "captcha_token": raw_captcha,
        },
    }
    body = bytearray()

    try:
        async with asyncio.timeout(_SIGN_UP_TIMEOUT_SECONDS):
            async with client.stream(
                "POST",
                f"{issuer}/signup",
                headers={
                    "apikey": publishable_key.get_secret_value(),
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                },
                json=request_payload,
                auth=None,
                follow_redirects=False,
                timeout=_SIGN_UP_TIMEOUT_SECONDS,
            ) as response:
                status_code = response.status_code

                if status_code not in (200, 400, 401, 403, 422):
                    raise AccountSignUpUnavailable("Account registration is unavailable.")

                content_type = (
                    response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                )
                if content_type != "application/json":
                    raise AccountSignUpUnavailable("Account registration is unavailable.")

                content_encoding = (
                    response.headers.get("content-encoding", "identity").strip().lower()
                )
                if content_encoding not in ("", "identity"):
                    raise AccountSignUpUnavailable("Account registration is unavailable.")

                async for chunk in response.aiter_raw():
                    if len(body) + len(chunk) > _MAX_RESPONSE_BYTES:
                        raise AccountSignUpUnavailable("Account registration is unavailable.")

                    body.extend(chunk)

    except (httpx2.HTTPError, TimeoutError):
        raise AccountSignUpUnavailable("Account registration is unavailable.") from None

    try:
        payload: object = json.loads(body)
    except (ValueError, UnicodeError, RecursionError):
        raise AccountSignUpUnavailable("Account registration is unavailable.") from None

    interpret_sign_up_response(status_code, payload)
