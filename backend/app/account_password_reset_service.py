"""Coordinate password recovery without creating an application login."""

import httpx2
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncEngine

from app.account_key_cache import AccountKeyCache
from app.account_password_update import (
    AccountPasswordUpdateRateLimited,
    AccountPasswordUpdateRejected,
    AccountPasswordUpdateUnavailable,
    update_recovered_password,
)
from app.account_recovery_identity import verify_recovery_identity
from app.account_recovery_session_cleanup import (
    AccountRecoverySessionCleanupUnavailable,
    cleanup_recovery_session,
)
from app.account_recovery_verification import verify_recovery_code
from app.account_session_invalidation import invalidate_account_sessions
from app.config import Settings


class AccountPasswordResetUnavailable(RuntimeError):
    """The password reset cannot currently be completed."""


async def reset_account_password(
    engine: AsyncEngine,
    email: SecretStr,
    code: SecretStr,
    new_password: SecretStr,
    *,
    settings: Settings,
    client: httpx2.AsyncClient,
    key_cache: AccountKeyCache | None,
) -> None:
    """Complete the reset sequence without returning credentials.

    Provider operations precede the database transaction.
    The caller owns the complete reset deadline.

    Known password-update failures trigger one cleanup attempt before propagating.
    Cleanup failure makes the reset unavailable. Cancellation propagates without
    starting additional cleanup work or automatic retries.
    A failure may occur after the password has already changed;
    database rollback cannot undo a provider-side operation.
    """
    if (
        settings.supabase_auth_issuer is None
        or settings.supabase_auth_publishable_key is None
        or key_cache is None
    ):
        raise AccountPasswordResetUnavailable("Password reset is not configured.")

    credentials = await verify_recovery_code(
        email,
        code,
        settings=settings,
        client=client,
    )

    account = await verify_recovery_identity(
        credentials,
        settings=settings,
        key_cache=key_cache,
    )

    if account.session_id.int == 0:
        raise AccountPasswordResetUnavailable("Password reset is unavailable.")

    try:
        await update_recovered_password(
            credentials,
            new_password,
            verified_account=account,
            settings=settings,
            client=client,
        )
    except (
        AccountPasswordUpdateRejected,
        AccountPasswordUpdateRateLimited,
        AccountPasswordUpdateUnavailable,
    ):
        try:
            await cleanup_recovery_session(
                credentials,
                verified_account=account,
                settings=settings,
                client=client,
            )
        except AccountRecoverySessionCleanupUnavailable:
            raise AccountPasswordResetUnavailable("Password reset is unavailable.") from None

        raise

    await cleanup_recovery_session(
        credentials,
        verified_account=account,
        settings=settings,
        client=client,
    )

    async with engine.begin() as connection:
        await invalidate_account_sessions(connection, account)
