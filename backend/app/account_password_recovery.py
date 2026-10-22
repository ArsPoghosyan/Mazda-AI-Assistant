"""Bounded provider password recovery with controlled response interpretation."""

import asyncio
import json

import httpx2
from pydantic import SecretStr

from app.config import Settings

_PASSWORD_RECOVERY_TIMEOUT_SECONDS = 5.0
_MAX_RESPONSE_BYTES = 64 * 1024


class AccountPasswordRecoveryRejected(ValueError):
    """The provider rejected the recovery input."""


class AccountPasswordRecoveryCaptchaRejected(AccountPasswordRecoveryRejected):
    """The provider rejected human verification."""


class AccountPasswordRecoveryRateLimited(RuntimeError):
    """The provider limited requests from this client."""


class AccountPasswordRecoveryUnavailable(RuntimeError):
    """The provider response could not be processed safely."""


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


def interpret_password_recovery_response(
    status_code: int,
    payload: object,
) -> None:
    """Accept a generic outcome or raise a controlled error.

    Returning normally does not prove account existence or email delivery.
    Provider messages, identities, and credentials are never returned.
    """
    if not isinstance(payload, dict):
        raise AccountPasswordRecoveryUnavailable("Password recovery is unavailable.")

    if status_code == 200:
        # The recovery endpoint's documented implementation returns {}.
        if payload:
            raise AccountPasswordRecoveryUnavailable("Password recovery is unavailable.")

        return

    error_code = _error_code(payload)

    if status_code == 429:
        if error_code == "over_email_send_rate_limit":
            # An address-specific cooldown must not disclose account existence.
            # This acknowledgement does not retry or bypass the provider limit.
            return

        if error_code == "over_request_rate_limit":
            raise AccountPasswordRecoveryRateLimited(
                "Password recovery is temporarily rate limited."
            )

        raise AccountPasswordRecoveryUnavailable("Password recovery is unavailable.")

    if status_code not in (400, 403, 404, 422):
        raise AccountPasswordRecoveryUnavailable("Password recovery is unavailable.")

    if error_code in {
        "email_address_invalid",
        "user_not_found",
        "user_banned",
        "email_not_confirmed",
    }:
        # Keep known account-dependent outcomes on the generic acknowledgement path.
        return

    if error_code == "captcha_failed":
        raise AccountPasswordRecoveryCaptchaRejected("Human verification was rejected.")

    if error_code == "validation_failed":
        raise AccountPasswordRecoveryRejected("Password recovery was rejected.")

    raise AccountPasswordRecoveryUnavailable("Password recovery is unavailable.")


def _input_value(value: SecretStr, max_characters: int) -> str:
    raw_value = value.get_secret_value()

    if not 1 <= len(raw_value) <= max_characters:
        raise AccountPasswordRecoveryRejected("Password recovery was rejected.")

    try:
        raw_value.encode("utf-8")
    except UnicodeError:
        raise AccountPasswordRecoveryRejected("Password recovery was rejected.") from None

    return raw_value


async def request_password_recovery(
    email: SecretStr,
    captcha_token: SecretStr,
    *,
    settings: Settings,
    client: httpx2.AsyncClient,
) -> None:
    """Submit recovery once using a caller-owned HTTP client.

    Returns no identity or credentials. A normal return does not prove email
    delivery. The HTTP route must enforce its feature flag and total deadline.
    """
    issuer = settings.supabase_auth_issuer
    publishable_key = settings.supabase_auth_publishable_key

    if issuer is None or publishable_key is None:
        raise AccountPasswordRecoveryUnavailable("Password recovery is not configured.")

    raw_email = _input_value(email, 320)
    raw_captcha = _input_value(captcha_token, 2048)

    if any(ord(character) < 33 or ord(character) > 126 for character in raw_captcha):
        raise AccountPasswordRecoveryCaptchaRejected("Human verification was rejected.")

    request_payload: dict[str, object] = {
        "email": raw_email,
        "gotrue_meta_security": {
            "captcha_token": raw_captcha,
        },
    }
    body = bytearray()

    try:
        async with asyncio.timeout(_PASSWORD_RECOVERY_TIMEOUT_SECONDS):
            async with client.stream(
                "POST",
                f"{issuer}/recover",
                headers={
                    "apikey": publishable_key.get_secret_value(),
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                },
                json=request_payload,
                auth=None,
                follow_redirects=False,
                timeout=_PASSWORD_RECOVERY_TIMEOUT_SECONDS,
            ) as response:
                status_code = response.status_code

                if status_code not in (200, 400, 403, 404, 422, 429):
                    raise AccountPasswordRecoveryUnavailable("Password recovery is unavailable.")

                content_type = (
                    response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                )
                if content_type != "application/json":
                    raise AccountPasswordRecoveryUnavailable("Password recovery is unavailable.")

                content_encoding = (
                    response.headers.get("content-encoding", "identity").strip().lower()
                )
                if content_encoding not in ("", "identity"):
                    raise AccountPasswordRecoveryUnavailable("Password recovery is unavailable.")

                async for chunk in response.aiter_raw():
                    if len(body) + len(chunk) > _MAX_RESPONSE_BYTES:
                        raise AccountPasswordRecoveryUnavailable(
                            "Password recovery is unavailable."
                        )

                    body.extend(chunk)

    except (httpx2.HTTPError, TimeoutError):
        raise AccountPasswordRecoveryUnavailable("Password recovery is unavailable.") from None

    try:
        payload: object = json.loads(body)
    except (ValueError, UnicodeError, RecursionError):
        raise AccountPasswordRecoveryUnavailable("Password recovery is unavailable.") from None

    interpret_password_recovery_response(status_code, payload)
