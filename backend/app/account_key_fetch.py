"""Fetch public account-signing keys from the configured auth provider."""

import asyncio
import json

import httpx2

from app.config import Settings

_FETCH_TIMEOUT_SECONDS = 5.0
_MAX_RESPONSE_BYTES = 64 * 1024


class AccountKeyFetchError(RuntimeError):
    """Public signing keys could not be retrieved safely."""


async def fetch_account_key_set(
    settings: Settings,
    *,
    client: httpx2.AsyncClient,
) -> dict[str, object]:
    """Download bounded JWKS JSON using a caller-owned HTTP client."""

    issuer = settings.supabase_auth_issuer

    if issuer is None:
        raise AccountKeyFetchError("Account authentication is not configured.")

    url = f"{issuer}/.well-known/jwks.json"
    body = bytearray()

    try:
        async with asyncio.timeout(_FETCH_TIMEOUT_SECONDS):
            async with client.stream(
                "GET",
                url,
                headers={
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                },
                auth=None,
                follow_redirects=False,
                timeout=_FETCH_TIMEOUT_SECONDS,
            ) as response:
                if response.status_code != 200:
                    raise AccountKeyFetchError("Account signing keys are unavailable.")

                content_type = (
                    response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                )

                if content_type not in (
                    "application/json",
                    "application/jwk-set+json",
                ):
                    raise AccountKeyFetchError("Invalid account signing key response.")

                content_encoding = (
                    response.headers.get("content-encoding", "identity").strip().lower()
                )

                if content_encoding not in ("", "identity"):
                    raise AccountKeyFetchError("Unsupported account signing key response encoding.")

                async for chunk in response.aiter_raw():
                    if len(body) + len(chunk) > _MAX_RESPONSE_BYTES:
                        raise AccountKeyFetchError("Account signing key response is too large.")

                    body.extend(chunk)

    except (httpx2.HTTPError, TimeoutError):
        raise AccountKeyFetchError("Account signing keys are unavailable.") from None

    try:
        payload: object = json.loads(body)
    except (ValueError, UnicodeError, RecursionError):
        raise AccountKeyFetchError("Invalid account signing key response.") from None

    if not isinstance(payload, dict) or not isinstance(payload.get("keys"), list):
        raise AccountKeyFetchError("Invalid account signing key response.")

    return payload
