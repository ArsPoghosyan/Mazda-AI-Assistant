"""Validate replies from the provider's authenticated user endpoint."""

import asyncio
import json
from uuid import UUID

import httpx2
from pydantic import SecretStr

from app.account_tokens import VerifiedAccount
from app.config import Settings

_SESSION_CHECK_TIMEOUT_SECONDS = 5.0
_MAX_RESPONSE_BYTES = 64 * 1024


class AccountProviderSessionRejected(ValueError):
    """The provider rejected the account session."""


class AccountProviderSessionUnavailable(RuntimeError):
    """The provider session could not be checked safely."""


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


def interpret_provider_session_response(
    status_code: int,
    payload: object,
    *,
    expected_user_id: UUID,
) -> None:
    """Validate a bounded reply from the trusted provider's user endpoint.

    The expected identity must come from backend-verified credentials.
    This function does not verify a JWT or make a provider request.
    """
    if not isinstance(payload, dict):
        raise AccountProviderSessionUnavailable("Account session verification is unavailable.")

    if status_code != 200:
        error_code = _error_code(payload)

        if status_code in (401, 403) and error_code in {
            "session_not_found",
            "user_not_found",
            "user_banned",
            "bad_jwt",
            "no_authorization",
        }:
            raise AccountProviderSessionRejected("Account session was rejected.")

        raise AccountProviderSessionUnavailable("Account session verification is unavailable.")

    if payload.get("is_anonymous") is not False or any(
        field in payload for field in ("access_token", "refresh_token", "session")
    ):
        raise AccountProviderSessionUnavailable("Account session verification is unavailable.")

    raw_user_id = payload.get("id")

    if not isinstance(raw_user_id, str) or not 1 <= len(raw_user_id) <= 64:
        raise AccountProviderSessionUnavailable("Account session verification is unavailable.")

    try:
        user_id = UUID(raw_user_id)
    except ValueError:
        raise AccountProviderSessionUnavailable(
            "Account session verification is unavailable."
        ) from None

    if user_id != expected_user_id:
        raise AccountProviderSessionUnavailable("Account session verification is unavailable.")


async def check_provider_session(
    access_token: SecretStr,
    *,
    verified_account: VerifiedAccount,
    settings: Settings,
    client: httpx2.AsyncClient,
) -> None:
    """Check previously verified credentials against the live provider.

    The caller must verify this exact token before calling this function.
    This check does not refresh credentials, create sessions, or retry.
    The caller owns the complete authentication deadline.
    """
    issuer = settings.supabase_auth_issuer
    publishable_key = settings.supabase_auth_publishable_key

    if issuer is None or publishable_key is None:
        raise AccountProviderSessionUnavailable("Account session verification is not configured.")

    raw_token = access_token.get_secret_value()

    if not 1 <= len(raw_token) <= 8192 or any(
        ord(character) < 33 or ord(character) > 126 for character in raw_token
    ):
        raise AccountProviderSessionUnavailable("Account session verification is unavailable.")

    body = bytearray()

    try:
        async with asyncio.timeout(_SESSION_CHECK_TIMEOUT_SECONDS):
            async with client.stream(
                "GET",
                f"{issuer}/user",
                headers={
                    "apikey": publishable_key.get_secret_value(),
                    "Authorization": f"Bearer {raw_token}",
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                },
                auth=None,
                follow_redirects=False,
                timeout=_SESSION_CHECK_TIMEOUT_SECONDS,
            ) as response:
                status_code = response.status_code

                if status_code not in (200, 401, 403):
                    raise AccountProviderSessionUnavailable(
                        "Account session verification is unavailable."
                    )

                content_type = (
                    response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                )
                if content_type != "application/json":
                    raise AccountProviderSessionUnavailable(
                        "Account session verification is unavailable."
                    )

                content_encoding = (
                    response.headers.get("content-encoding", "identity").strip().lower()
                )
                if content_encoding not in ("", "identity"):
                    raise AccountProviderSessionUnavailable(
                        "Account session verification is unavailable."
                    )

                async for chunk in response.aiter_raw():
                    if len(body) + len(chunk) > _MAX_RESPONSE_BYTES:
                        raise AccountProviderSessionUnavailable(
                            "Account session verification is unavailable."
                        )

                    body.extend(chunk)

    except (httpx2.HTTPError, TimeoutError):
        raise AccountProviderSessionUnavailable(
            "Account session verification is unavailable."
        ) from None

    try:
        payload: object = json.loads(body)
    except (ValueError, UnicodeError, RecursionError):
        raise AccountProviderSessionUnavailable(
            "Account session verification is unavailable."
        ) from None

    interpret_provider_session_response(
        status_code,
        payload,
        expected_user_id=verified_account.user_id,
    )
