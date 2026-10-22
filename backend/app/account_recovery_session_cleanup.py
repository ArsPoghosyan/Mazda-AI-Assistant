"""Bounded cleanup of a temporary recovery provider session."""

import asyncio
import json

import httpx2

from app.account_recovery_verification import RecoveryVerificationCredentials
from app.account_tokens import VerifiedAccount
from app.config import Settings

_CLEANUP_TIMEOUT_SECONDS = 5.0
_MAX_RESPONSE_BYTES = 64 * 1024


class AccountRecoverySessionCleanupUnavailable(RuntimeError):
    """The temporary provider session could not be confirmed absent."""


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


def interpret_recovery_session_cleanup_response(
    status_code: int,
    payload: object,
) -> None:
    """Accept confirmed logout or an explicitly absent provider session.

    The caller must supply a bounded reply from the configured provider's
    local-scope logout endpoint using backend-verified recovery credentials.
    This function does not make requests or invalidate application sessions.
    """
    if status_code == 204 and payload is None:
        return

    if (
        status_code == 403
        and isinstance(payload, dict)
        and _error_code(payload) == "session_not_found"
    ):
        return

    raise AccountRecoverySessionCleanupUnavailable("Recovery session cleanup is unavailable.")


async def cleanup_recovery_session(
    credentials: RecoveryVerificationCredentials,
    *,
    verified_account: VerifiedAccount,
    settings: Settings,
    client: httpx2.AsyncClient,
) -> None:
    """End the temporary provider session using verified recovery credentials.

    The caller must verify these exact credentials before calling this helper.
    This does not invalidate application sessions, issue cookies, or retry.
    The caller owns the complete password-reset deadline.
    """
    issuer = settings.supabase_auth_issuer
    publishable_key = settings.supabase_auth_publishable_key

    if issuer is None or publishable_key is None:
        raise AccountRecoverySessionCleanupUnavailable(
            "Recovery session cleanup is not configured."
        )

    if credentials.user_id != verified_account.user_id or verified_account.session_id.int == 0:
        raise AccountRecoverySessionCleanupUnavailable("Recovery session cleanup is unavailable.")

    raw_token = credentials.access_token.get_secret_value()

    if not 1 <= len(raw_token) <= 8192 or any(
        ord(character) < 33 or ord(character) > 126 for character in raw_token
    ):
        raise AccountRecoverySessionCleanupUnavailable("Recovery session cleanup is unavailable.")

    body = bytearray()

    try:
        async with asyncio.timeout(_CLEANUP_TIMEOUT_SECONDS):
            async with client.stream(
                "POST",
                f"{issuer}/logout?scope=local",
                headers={
                    "apikey": publishable_key.get_secret_value(),
                    "Authorization": f"Bearer {raw_token}",
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                },
                auth=None,
                follow_redirects=False,
                timeout=_CLEANUP_TIMEOUT_SECONDS,
            ) as response:
                status_code = response.status_code

                if status_code not in (204, 403):
                    raise AccountRecoverySessionCleanupUnavailable(
                        "Recovery session cleanup is unavailable."
                    )

                content_encoding = (
                    response.headers.get("content-encoding", "identity").strip().lower()
                )
                if content_encoding not in ("", "identity"):
                    raise AccountRecoverySessionCleanupUnavailable(
                        "Recovery session cleanup is unavailable."
                    )

                if status_code == 403:
                    content_type = (
                        response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                    )
                    if content_type != "application/json":
                        raise AccountRecoverySessionCleanupUnavailable(
                            "Recovery session cleanup is unavailable."
                        )

                async for chunk in response.aiter_raw():
                    if (status_code == 204 and chunk) or len(body) + len(
                        chunk
                    ) > _MAX_RESPONSE_BYTES:
                        raise AccountRecoverySessionCleanupUnavailable(
                            "Recovery session cleanup is unavailable."
                        )

                    body.extend(chunk)

    except (httpx2.HTTPError, TimeoutError):
        raise AccountRecoverySessionCleanupUnavailable(
            "Recovery session cleanup is unavailable."
        ) from None

    if status_code == 204:
        interpret_recovery_session_cleanup_response(204, None)
        return

    try:
        payload: object = json.loads(body)
    except (ValueError, UnicodeError, RecursionError):
        raise AccountRecoverySessionCleanupUnavailable(
            "Recovery session cleanup is unavailable."
        ) from None

    interpret_recovery_session_cleanup_response(status_code, payload)
