"""Bounded server-side Turnstile verification without route integration."""

import asyncio
import json
import re

import httpx2
from pydantic import SecretStr

from app.config import Settings

_SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
_MAX_RESPONSE_BYTES = 64 * 1024

_REJECTED_CODES = frozenset(
    {
        "missing-input-response",
        "invalid-input-response",
        "timeout-or-duplicate",
    }
)


class TurnstileRejected(ValueError):
    """The challenge cannot authorize the attempted action."""


class TurnstileUnavailable(RuntimeError):
    """Verification could not safely establish a result."""


async def verify_turnstile_token(
    token: SecretStr,
    *,
    expected_action: str,
    settings: Settings,
    client: httpx2.AsyncClient,
) -> None:
    """Verify one challenge using a caller-owned HTTP client.

    Successful completion authorizes only the caller's intended operation.
    Does not create sessions, issue cookies, retry, or establish user identity.
    """
    secret = settings.turnstile_secret_key
    hostnames = settings.turnstile_allowed_hostnames

    if secret is None or not hostnames:
        raise TurnstileUnavailable("Human verification is not configured.")

    raw_secret = secret.get_secret_value()
    if (
        not 1 <= len(raw_secret) <= 512
        or any(ord(character) < 33 or ord(character) > 126 for character in raw_secret)
        or re.fullmatch(r"[A-Za-z0-9_-]{1,32}", expected_action) is None
    ):
        raise TurnstileUnavailable("Human verification is not configured.")

    raw_token = token.get_secret_value()
    if not 1 <= len(raw_token) <= 2048 or any(
        ord(character) < 33 or ord(character) > 126 for character in raw_token
    ):
        raise TurnstileRejected("Human verification was rejected.")

    body = bytearray()

    try:
        async with asyncio.timeout(settings.turnstile_timeout_seconds):
            async with client.stream(
                "POST",
                _SITEVERIFY_URL,
                headers={
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                },
                json={
                    "secret": raw_secret,
                    "response": raw_token,
                },
                auth=None,
                follow_redirects=False,
                timeout=settings.turnstile_timeout_seconds,
            ) as response:
                if response.status_code != 200:
                    raise TurnstileUnavailable("Human verification is unavailable.")

                content_type = (
                    response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                )
                if content_type != "application/json":
                    raise TurnstileUnavailable("Human verification is unavailable.")

                content_encoding = (
                    response.headers.get("content-encoding", "identity").strip().lower()
                )
                if content_encoding not in ("", "identity"):
                    raise TurnstileUnavailable("Human verification is unavailable.")

                async for chunk in response.aiter_raw():
                    if len(body) + len(chunk) > _MAX_RESPONSE_BYTES:
                        raise TurnstileUnavailable("Human verification is unavailable.")
                    body.extend(chunk)

    except (httpx2.HTTPError, TimeoutError):
        raise TurnstileUnavailable("Human verification is unavailable.") from None

    try:
        payload: object = json.loads(body)
    except (ValueError, UnicodeError, RecursionError):
        raise TurnstileUnavailable("Human verification is unavailable.") from None

    if not isinstance(payload, dict):
        raise TurnstileUnavailable("Human verification is unavailable.")

    success = payload.get("success")
    error_codes = payload.get("error-codes", [])

    if not isinstance(error_codes, list) or any(not isinstance(code, str) for code in error_codes):
        raise TurnstileUnavailable("Human verification is unavailable.")

    if success is False:
        if error_codes and all(code in _REJECTED_CODES for code in error_codes):
            raise TurnstileRejected("Human verification was rejected.")

        raise TurnstileUnavailable("Human verification is unavailable.")

    if success is not True or error_codes:
        raise TurnstileUnavailable("Human verification is unavailable.")

    hostname = payload.get("hostname")
    action = payload.get("action")

    if (
        not isinstance(hostname, str)
        or not 1 <= len(hostname) <= 253
        or not isinstance(action, str)
        or re.fullmatch(r"[A-Za-z0-9_-]{1,32}", action) is None
    ):
        raise TurnstileUnavailable("Human verification is unavailable.")

    if hostname not in hostnames or action != expected_action:
        raise TurnstileRejected("Human verification was rejected.")
