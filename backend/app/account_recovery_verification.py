"""Controlled recovery-verification responses without application login."""

import asyncio
import json
from dataclasses import dataclass
from uuid import UUID

import httpx2
from pydantic import SecretStr

from app.config import Settings

_MAX_TOKEN_CHARACTERS = 8192
_VERIFICATION_TIMEOUT_SECONDS = 5.0
_MAX_RESPONSE_BYTES = 64 * 1024


class AccountRecoveryVerificationRejected(ValueError):
    """The provider rejected the recovery proof."""


class AccountRecoveryVerificationRateLimited(RuntimeError):
    """The provider temporarily limited verification requests."""


class AccountRecoveryVerificationUnavailable(RuntimeError):
    """Recovery verification could not safely process the provider response."""


@dataclass(frozen=True, slots=True)
class RecoveryVerificationCredentials:
    """Internal provider credentials; JWT identity still needs verification.

    Never return this object through an HTTP response or create a login from it.
    """

    user_id: UUID
    access_token: SecretStr


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


def _response_token(value: object) -> SecretStr:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= _MAX_TOKEN_CHARACTERS
        or any(ord(character) < 33 or ord(character) > 126 for character in value)
    ):
        raise AccountRecoveryVerificationUnavailable("Recovery verification is unavailable.")

    return SecretStr(value)


def interpret_recovery_verification_response(
    status_code: int,
    payload: object,
) -> RecoveryVerificationCredentials:
    """Validate response structure without verifying JWT identity.

    The caller must provide a bounded response from the trusted provider.
    Refresh tokens and other provider fields are discarded.
    """
    if not isinstance(payload, dict):
        raise AccountRecoveryVerificationUnavailable("Recovery verification is unavailable.")

    if status_code != 200:
        error_code = _error_code(payload)

        if status_code == 429 and error_code == "over_request_rate_limit":
            raise AccountRecoveryVerificationRateLimited(
                "Recovery verification is temporarily rate limited."
            )

        if status_code in (400, 401, 403, 404, 422) and error_code in {
            "otp_expired",
            "user_not_found",
            "user_banned",
            "validation_failed",
        }:
            raise AccountRecoveryVerificationRejected("Recovery verification was rejected.")

        raise AccountRecoveryVerificationUnavailable("Recovery verification is unavailable.")

    token_type = payload.get("token_type")
    user = payload.get("user")

    if (
        not isinstance(token_type, str)
        or token_type.lower() != "bearer"
        or not isinstance(user, dict)
        or user.get("is_anonymous") is not False
    ):
        raise AccountRecoveryVerificationUnavailable("Recovery verification is unavailable.")

    raw_user_id = user.get("id")

    if not isinstance(raw_user_id, str) or not 1 <= len(raw_user_id) <= 64:
        raise AccountRecoveryVerificationUnavailable("Recovery verification is unavailable.")

    try:
        user_id = UUID(raw_user_id)
    except ValueError:
        raise AccountRecoveryVerificationUnavailable(
            "Recovery verification is unavailable."
        ) from None

    return RecoveryVerificationCredentials(
        user_id=user_id,
        access_token=_response_token(payload.get("access_token")),
    )


async def verify_recovery_code(
    email: SecretStr,
    code: SecretStr,
    *,
    settings: Settings,
    client: httpx2.AsyncClient,
) -> RecoveryVerificationCredentials:
    """Exchange a recovery code once using a caller-owned HTTP client.

    Does not verify JWT identity, change passwords, create application sessions,
    issue cookies, or retry. The caller owns the complete reset deadline.
    """
    issuer = settings.supabase_auth_issuer
    publishable_key = settings.supabase_auth_publishable_key

    if issuer is None or publishable_key is None:
        raise AccountRecoveryVerificationUnavailable("Recovery verification is not configured.")

    raw_email = email.get_secret_value()
    raw_code = code.get_secret_value()

    if (
        not 1 <= len(raw_email) <= 320
        or not 6 <= len(raw_code) <= 10
        or any(character not in "0123456789" for character in raw_code)
    ):
        raise AccountRecoveryVerificationRejected("Recovery verification was rejected.")

    try:
        raw_email.encode("utf-8")
    except UnicodeError:
        raise AccountRecoveryVerificationRejected("Recovery verification was rejected.") from None

    body = bytearray()

    try:
        async with asyncio.timeout(_VERIFICATION_TIMEOUT_SECONDS):
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
                    "type": "recovery",
                },
                auth=None,
                follow_redirects=False,
                timeout=_VERIFICATION_TIMEOUT_SECONDS,
            ) as response:
                status_code = response.status_code

                if status_code not in (200, 400, 401, 403, 404, 422, 429):
                    raise AccountRecoveryVerificationUnavailable(
                        "Recovery verification is unavailable."
                    )

                content_type = (
                    response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                )
                if content_type != "application/json":
                    raise AccountRecoveryVerificationUnavailable(
                        "Recovery verification is unavailable."
                    )

                content_encoding = (
                    response.headers.get("content-encoding", "identity").strip().lower()
                )
                if content_encoding not in ("", "identity"):
                    raise AccountRecoveryVerificationUnavailable(
                        "Recovery verification is unavailable."
                    )

                async for chunk in response.aiter_raw():
                    if len(body) + len(chunk) > _MAX_RESPONSE_BYTES:
                        raise AccountRecoveryVerificationUnavailable(
                            "Recovery verification is unavailable."
                        )

                    body.extend(chunk)

    except (httpx2.HTTPError, TimeoutError):
        raise AccountRecoveryVerificationUnavailable(
            "Recovery verification is unavailable."
        ) from None

    try:
        payload: object = json.loads(body)
    except (ValueError, UnicodeError, RecursionError):
        raise AccountRecoveryVerificationUnavailable(
            "Recovery verification is unavailable."
        ) from None

    return interpret_recovery_verification_response(status_code, payload)
