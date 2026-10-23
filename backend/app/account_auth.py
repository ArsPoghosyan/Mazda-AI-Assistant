"""Authenticate account tokens using configured, cached signing keys."""

import httpx2
from pydantic import SecretStr

from app.account_key_cache import AccountKeyCache
from app.account_key_fetch import AccountKeyFetchError
from app.account_keys import AccountKeyNotFound
from app.account_provider_session import (
    AccountProviderSessionRejected,
    AccountProviderSessionUnavailable,
    check_provider_session,
)
from app.account_tokens import (
    InvalidAccountToken,
    VerifiedAccount,
    get_account_token_key_id,
    verify_account_token,
)
from app.config import Settings


class AccountAuthenticationUnavailable(RuntimeError):
    """Account authentication cannot currently verify credentials."""


async def authenticate_account_token(
    token: SecretStr,
    *,
    settings: Settings,
    key_cache: AccountKeyCache | None,
) -> VerifiedAccount:
    """Validate a token header, resolve its trusted key, and verify identity."""

    issuer = settings.supabase_auth_issuer

    if issuer is None or key_cache is None:
        raise AccountAuthenticationUnavailable("Account authentication is unavailable.")

    key_id = get_account_token_key_id(token)

    try:
        public_key = await key_cache.get_public_key(key_id)
    except AccountKeyNotFound:
        raise InvalidAccountToken("Invalid account token.") from None
    except AccountKeyFetchError:
        raise AccountAuthenticationUnavailable("Account authentication is unavailable.") from None

    return verify_account_token(
        token,
        public_key=public_key,
        issuer=str(issuer),
        audience=settings.supabase_auth_audience,
        issued_at_leeway_seconds=settings.supabase_auth_iat_clock_skew_seconds,
    )


async def authenticate_active_account_token(
    token: SecretStr,
    *,
    settings: Settings,
    key_cache: AccountKeyCache | None,
    client: httpx2.AsyncClient,
) -> VerifiedAccount:
    """Verify JWT identity, then require an active provider session.

    The caller owns the complete authentication deadline.
    Provider unavailability never falls back to JWT-only acceptance.
    """
    account = await authenticate_account_token(
        token,
        settings=settings,
        key_cache=key_cache,
    )

    if account.session_id.int == 0:
        raise InvalidAccountToken("Invalid account token.")

    try:
        await check_provider_session(
            token,
            verified_account=account,
            settings=settings,
            client=client,
        )
    except AccountProviderSessionRejected:
        raise InvalidAccountToken("Invalid account token.") from None
    except AccountProviderSessionUnavailable:
        raise AccountAuthenticationUnavailable("Account authentication is unavailable.") from None

    return account
