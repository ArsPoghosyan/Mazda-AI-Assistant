"""Complete account authentication within a short database transaction."""

import httpx2
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncEngine

from app.account_key_cache import AccountKeyCache
from app.account_session_auth import AuthenticatedAccountSession
from app.account_session_service import authenticate_account_session
from app.config import Settings


async def authenticate_account_session_transaction(
    engine: AsyncEngine,
    token: SecretStr | None,
    *,
    settings: Settings,
    client: httpx2.AsyncClient,
    key_cache: AccountKeyCache | None,
) -> AuthenticatedAccountSession | None:
    """Return authentication only after the transaction commits successfully.

    Authentication failures, cancellation, and database errors propagate.
    No automatic retry is performed.
    """
    async with engine.begin() as connection:
        authenticated = await authenticate_account_session(
            connection,
            token,
            settings=settings,
            client=client,
            key_cache=key_cache,
        )

    return authenticated
