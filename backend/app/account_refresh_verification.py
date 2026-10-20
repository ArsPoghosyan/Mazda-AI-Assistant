"""Verify refreshed credentials against an existing account-session identity."""

from dataclasses import dataclass
from uuid import UUID

from app.account_auth import (
    AccountAuthenticationUnavailable,
    authenticate_account_token,
)
from app.account_key_cache import AccountKeyCache
from app.account_refresh import (
    AccountRefreshUnavailable,
    RefreshedAccountTokens,
)
from app.account_tokens import InvalidAccountToken, VerifiedAccount
from app.config import Settings


@dataclass(frozen=True, slots=True)
class VerifiedAccountRefresh:
    """Verified access-token identity paired with masked provider credentials."""

    account: VerifiedAccount
    tokens: RefreshedAccountTokens


async def verify_refreshed_account_tokens(
    tokens: RefreshedAccountTokens,
    *,
    expected_user_id: UUID,
    expected_provider_session_id: UUID,
    settings: Settings,
    key_cache: AccountKeyCache | None,
) -> VerifiedAccountRefresh:
    """Verify a token pair received directly from the refresh adapter.

    Expected identities must come from the server's stored session, never
    browser-supplied owner IDs. Refresh-token ownership is not independently
    verified; the pair must originate from the same trusted provider response.
    """
    try:
        account = await authenticate_account_token(
            tokens.access_token,
            settings=settings,
            key_cache=key_cache,
        )
    except (InvalidAccountToken, AccountAuthenticationUnavailable):
        raise AccountRefreshUnavailable("Account refresh is unavailable.") from None

    if account.user_id != expected_user_id or account.session_id != expected_provider_session_id:
        raise AccountRefreshUnavailable("Account refresh is unavailable.")

    return VerifiedAccountRefresh(
        account=account,
        tokens=tokens,
    )
