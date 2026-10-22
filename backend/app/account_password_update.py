"""Controlled provider password-update responses."""

import asyncio
import json
from uuid import UUID

import httpx2
from pydantic import SecretStr

from app.account_recovery_verification import RecoveryVerificationCredentials
from app.account_tokens import VerifiedAccount
from app.config import Settings

_UPDATE_TIMEOUT_SECONDS = 5.0
_MAX_RESPONSE_BYTES = 64 * 1024


class AccountPasswordUpdateRejected(ValueError):
    """The provider rejected the password update."""


class AccountPasswordUpdateRateLimited(RuntimeError):
    """The provider temporarily limited password updates."""


class AccountPasswordUpdateUnavailable(RuntimeError):
    """The password-update response could not be processed safely."""


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


def interpret_password_update_response(
    status_code: int,
    payload: object,
    *,
    expected_user_id: UUID,
) -> None:
    """Validate an update reply without returning identity or credentials.

    The caller must supply a bounded response from the trusted provider.
    The expected identity must come from verified recovery credentials.
    A normal return does not complete application-session invalidation.
    """
    if not isinstance(payload, dict):
        raise AccountPasswordUpdateUnavailable("Password update is unavailable.")

    if status_code != 200:
        error_code = _error_code(payload)

        if status_code == 429 and error_code == "over_request_rate_limit":
            raise AccountPasswordUpdateRateLimited("Password update is temporarily rate limited.")

        if status_code in (400, 401, 403, 404, 422) and error_code in {
            "weak_password",
            "same_password",
            "validation_failed",
            "reauthentication_needed",
            "reauthentication_not_valid",
            "insufficient_aal",
            "current_password_required",
            "current_password_mismatch",
        }:
            raise AccountPasswordUpdateRejected("Password update was rejected.")

        raise AccountPasswordUpdateUnavailable("Password update is unavailable.")

    if payload.get("is_anonymous") is not False or any(
        field in payload for field in ("access_token", "refresh_token", "session")
    ):
        raise AccountPasswordUpdateUnavailable("Password update is unavailable.")

    raw_user_id = payload.get("id")

    if not isinstance(raw_user_id, str) or not 1 <= len(raw_user_id) <= 64:
        raise AccountPasswordUpdateUnavailable("Password update is unavailable.")

    try:
        user_id = UUID(raw_user_id)
    except ValueError:
        raise AccountPasswordUpdateUnavailable("Password update is unavailable.") from None

    if user_id != expected_user_id:
        raise AccountPasswordUpdateUnavailable("Password update is unavailable.")


async def update_recovered_password(
    credentials: RecoveryVerificationCredentials,
    new_password: SecretStr,
    *,
    verified_account: VerifiedAccount,
    settings: Settings,
    client: httpx2.AsyncClient,
) -> None:
    """Submit a password update once after recovery identity verification.

    The caller must verify these exact credentials before calling this function.
    This does not invalidate application sessions, issue cookies, or retry.
    The caller owns the complete password-reset deadline.
    """
    issuer = settings.supabase_auth_issuer
    publishable_key = settings.supabase_auth_publishable_key

    if issuer is None or publishable_key is None:
        raise AccountPasswordUpdateUnavailable("Password update is not configured.")

    if credentials.user_id != verified_account.user_id:
        raise AccountPasswordUpdateUnavailable("Password update is unavailable.")

    raw_token = credentials.access_token.get_secret_value()
    raw_password = new_password.get_secret_value()

    if not 1 <= len(raw_token) <= 8192 or any(
        ord(character) < 33 or ord(character) > 126 for character in raw_token
    ):
        raise AccountPasswordUpdateUnavailable("Password update is unavailable.")

    if not 1 <= len(raw_password) <= 1024:
        raise AccountPasswordUpdateRejected("Password update was rejected.")

    try:
        raw_password.encode("utf-8")
    except UnicodeError:
        raise AccountPasswordUpdateRejected("Password update was rejected.") from None

    body = bytearray()

    try:
        async with asyncio.timeout(_UPDATE_TIMEOUT_SECONDS):
            async with client.stream(
                "PUT",
                f"{issuer}/user",
                headers={
                    "apikey": publishable_key.get_secret_value(),
                    "Authorization": f"Bearer {raw_token}",
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                },
                json={"password": raw_password},
                auth=None,
                follow_redirects=False,
                timeout=_UPDATE_TIMEOUT_SECONDS,
            ) as response:
                status_code = response.status_code

                if status_code not in (200, 400, 401, 403, 404, 422, 429):
                    raise AccountPasswordUpdateUnavailable("Password update is unavailable.")

                content_type = (
                    response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                )
                if content_type != "application/json":
                    raise AccountPasswordUpdateUnavailable("Password update is unavailable.")

                content_encoding = (
                    response.headers.get("content-encoding", "identity").strip().lower()
                )
                if content_encoding not in ("", "identity"):
                    raise AccountPasswordUpdateUnavailable("Password update is unavailable.")

                async for chunk in response.aiter_raw():
                    if len(body) + len(chunk) > _MAX_RESPONSE_BYTES:
                        raise AccountPasswordUpdateUnavailable("Password update is unavailable.")

                    body.extend(chunk)

    except (httpx2.HTTPError, TimeoutError):
        raise AccountPasswordUpdateUnavailable("Password update is unavailable.") from None

    try:
        payload: object = json.loads(body)
    except (ValueError, UnicodeError, RecursionError):
        raise AccountPasswordUpdateUnavailable("Password update is unavailable.") from None

    interpret_password_update_response(
        status_code,
        payload,
        expected_user_id=verified_account.user_id,
    )
