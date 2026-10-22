"""Bind recovery-provider credentials to a verified account identity."""

from app.account_auth import (
    AccountAuthenticationUnavailable,
    authenticate_account_token,
)
from app.account_key_cache import AccountKeyCache
from app.account_recovery_verification import (
    AccountRecoveryVerificationUnavailable,
    RecoveryVerificationCredentials,
)
from app.account_tokens import InvalidAccountToken, VerifiedAccount
from app.config import Settings


async def verify_recovery_identity(
    credentials: RecoveryVerificationCredentials,
    *,
    settings: Settings,
    key_cache: AccountKeyCache | None,
) -> VerifiedAccount:
    """Verify the JWT and match its subject to the provider account.

    Credentials must come from the server's recovery-code exchange, never
    directly from browser input. JWT validity alone does not prove recovery
    purpose. This helper creates no session and changes no password.
    """
    try:
        account = await authenticate_account_token(
            credentials.access_token,
            settings=settings,
            key_cache=key_cache,
        )
    except (InvalidAccountToken, AccountAuthenticationUnavailable):
        raise AccountRecoveryVerificationUnavailable(
            "Recovery verification is unavailable."
        ) from None

    if account.user_id != credentials.user_id:
        raise AccountRecoveryVerificationUnavailable("Recovery verification is unavailable.")

    return account
