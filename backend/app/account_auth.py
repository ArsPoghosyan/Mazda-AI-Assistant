"""Authenticate account tokens using configured, cached signing keys."""

from pydantic import SecretStr

from app.account_key_cache import AccountKeyCache
from app.account_key_fetch import AccountKeyFetchError
from app.account_keys import AccountKeyNotFound
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
    )
