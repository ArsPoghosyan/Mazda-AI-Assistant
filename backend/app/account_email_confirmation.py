"""Provider email-confirmation responses without application login."""

import asyncio
import json
from datetime import datetime
from uuid import UUID

import httpx2
from pydantic import SecretStr

from app.config import Settings

_CONFIRMATION_TIMEOUT_SECONDS = 5.0
_MAX_RESPONSE_BYTES = 64 * 1024


class AccountEmailConfirmationRejected(ValueError):
    """The provider rejected the confirmation attempt."""


class AccountEmailConfirmationUnavailable(RuntimeError):
    """Confirmation could not safely process the provider response."""


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


def interpret_email_confirmation_response(
    status_code: int,
    payload: object,
) -> None:
    """Validate a confirmation outcome without returning identity or tokens.

    The caller must supply a bounded response from the trusted provider.
    This does not verify a JWT or authenticate an application session.
    """
    if not isinstance(payload, dict):
        raise AccountEmailConfirmationUnavailable("Email confirmation is unavailable.")

    if status_code == 200:
        user = payload.get("user")

        if not isinstance(user, dict):
            raise AccountEmailConfirmationUnavailable("Email confirmation is unavailable.")

        user_id = user.get("id")
        confirmed_at = user.get("email_confirmed_at")

        if (
            not isinstance(user_id, str)
            or len(user_id) > 64
            or not isinstance(confirmed_at, str)
            or len(confirmed_at) > 64
        ):
            raise AccountEmailConfirmationUnavailable("Email confirmation is unavailable.")

        try:
            UUID(user_id)
            confirmation_time = datetime.fromisoformat(confirmed_at)
        except ValueError:
            raise AccountEmailConfirmationUnavailable(
                "Email confirmation is unavailable."
            ) from None

        if confirmation_time.utcoffset() is None:
            raise AccountEmailConfirmationUnavailable("Email confirmation is unavailable.")

        # Discard provider identity and any returned session credentials.
        return

    if status_code not in (400, 401, 403, 404, 422):
        raise AccountEmailConfirmationUnavailable("Email confirmation is unavailable.")

    if _error_code(payload) in {
        "otp_expired",
        "validation_failed",
        "email_address_invalid",
        "user_banned",
    }:
        raise AccountEmailConfirmationRejected("Email confirmation was rejected.")

    raise AccountEmailConfirmationUnavailable("Email confirmation is unavailable.")


async def confirm_email_code(
    email: SecretStr,
    code: SecretStr,
    *,
    settings: Settings,
    client: httpx2.AsyncClient,
) -> None:
    """Submit a signup confirmation once using a caller-owned HTTP client.

    Does not create an application session, issue browser cookies, persist
    provider credentials, or retry. Provider session credentials are discarded.
    """
    issuer = settings.supabase_auth_issuer
    publishable_key = settings.supabase_auth_publishable_key

    if issuer is None or publishable_key is None:
        raise AccountEmailConfirmationUnavailable("Email confirmation is not configured.")

    raw_email = email.get_secret_value()
    raw_code = code.get_secret_value()

    if (
        not 1 <= len(raw_email) <= 320
        or not 6 <= len(raw_code) <= 10
        or any(character not in "0123456789" for character in raw_code)
    ):
        raise AccountEmailConfirmationRejected("Email confirmation was rejected.")

    try:
        raw_email.encode("utf-8")
    except UnicodeError:
        raise AccountEmailConfirmationRejected("Email confirmation was rejected.") from None

    body = bytearray()

    try:
        async with asyncio.timeout(_CONFIRMATION_TIMEOUT_SECONDS):
            async with client.stream(
                "POST",
                f"{issuer}/verify",
                headers={
                    "apikey": publishable_key.get_secret_value(),
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                },
                json={
                    "email": raw_email,
                    "token": raw_code,
                    "type": "signup",
                },
                auth=None,
                follow_redirects=False,
                timeout=_CONFIRMATION_TIMEOUT_SECONDS,
            ) as response:
                status_code = response.status_code

                if status_code not in (200, 400, 401, 403, 404, 422):
                    raise AccountEmailConfirmationUnavailable("Email confirmation is unavailable.")

                content_type = (
                    response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                )
                if content_type != "application/json":
                    raise AccountEmailConfirmationUnavailable("Email confirmation is unavailable.")

                content_encoding = (
                    response.headers.get("content-encoding", "identity").strip().lower()
                )
                if content_encoding not in ("", "identity"):
                    raise AccountEmailConfirmationUnavailable("Email confirmation is unavailable.")

                async for chunk in response.aiter_raw():
                    if len(body) + len(chunk) > _MAX_RESPONSE_BYTES:
                        raise AccountEmailConfirmationUnavailable(
                            "Email confirmation is unavailable."
                        )

                    body.extend(chunk)

    except (httpx2.HTTPError, TimeoutError):
        raise AccountEmailConfirmationUnavailable("Email confirmation is unavailable.") from None

    try:
        payload: object = json.loads(body)
    except (ValueError, UnicodeError, RecursionError):
        raise AccountEmailConfirmationUnavailable("Email confirmation is unavailable.") from None

    interpret_email_confirmation_response(status_code, payload)
