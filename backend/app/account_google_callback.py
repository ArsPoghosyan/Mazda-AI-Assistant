"""Complete a browser-bound Google callback without issuing cookies."""

import asyncio

import httpx2
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncEngine

from app.account_google_exchange import (
    GoogleCodeExchangeRejected,
    GoogleCodeExchangeUnavailable,
    exchange_google_authorization_code,
)
from app.account_google_session import create_google_account_session
from app.account_key_cache import AccountKeyCache
from app.account_oauth_material import recover_oauth_pkce_verifier
from app.account_oauth_transactions import consume_oauth_login_attempt_transaction
from app.account_sessions import CreatedAccountSession
from app.account_token_encryption import AccountTokenCipher
from app.config import Settings


async def complete_google_callback(
    engine: AsyncEngine,
    code: SecretStr,
    browser_token: str | None,
    *,
    settings: Settings,
    client: httpx2.AsyncClient,
    key_cache: AccountKeyCache | None,
) -> CreatedAccountSession:
    """Consume once, exchange once, and return only a committed session.

    The HTTP caller must validate callback parameters and enforce the feature
    flag. Failed or uncertain completion requires a fresh login attempt.
    Cancellation propagates; this service never retries or issues cookies.
    """
    encryption_key = settings.account_session_encryption_key
    if (
        settings.supabase_auth_issuer is None
        or settings.supabase_auth_publishable_key is None
        or encryption_key is None
        or key_cache is None
    ):
        raise GoogleCodeExchangeUnavailable("Google sign-in is unavailable.")

    raw_code = code.get_secret_value()
    if not 1 <= len(raw_code) <= 1024 or any(
        ord(character) < 33 or ord(character) > 126 for character in raw_code
    ):
        raise GoogleCodeExchangeRejected("Google sign-in was rejected.")

    cipher = AccountTokenCipher(encryption_key)

    try:
        async with asyncio.timeout(settings.account_google_oauth_timeout_seconds):
            consumed = await consume_oauth_login_attempt_transaction(
                engine,
                browser_token,
            )

            verifier = recover_oauth_pkce_verifier(
                consumed.pkce_verifier_ciphertext,
                cipher=cipher,
            )

            tokens = await exchange_google_authorization_code(
                code,
                verifier,
                settings=settings,
                client=client,
            )

            created = await create_google_account_session(
                engine,
                tokens,
                settings=settings,
                client=client,
                key_cache=key_cache,
            )

        return created
    except TimeoutError:
        raise GoogleCodeExchangeUnavailable("Google sign-in is unavailable.") from None
