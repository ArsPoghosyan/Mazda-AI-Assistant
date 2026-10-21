"""Delete an application session within a caller-owned transaction."""

import re
from hashlib import sha256

from pydantic import SecretStr
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncConnection

from app.models import AccountSession


async def delete_account_session(
    connection: AsyncConnection,
    token: SecretStr | None,
) -> bool:
    """Delete only the session matching the supplied browser credential.

    Missing, malformed, and unknown credentials return False.
    The caller owns commit/rollback; True is provisional until commit succeeds.
    This does not delete the account or revoke a provider session.
    """
    if token is None:
        return False

    raw_token = token.get_secret_value()
    if re.fullmatch(r"[A-Za-z0-9_-]{43}", raw_token) is None:
        return False

    if not connection.in_transaction():
        raise RuntimeError("Account-session deletion requires an active transaction.")

    token_hash = sha256(raw_token.encode("ascii")).digest()

    deleted_id = await connection.scalar(
        delete(AccountSession)
        .where(AccountSession.token_hash == token_hash)
        .returning(AccountSession.id)
    )

    return deleted_id is not None
