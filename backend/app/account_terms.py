"""Versioned Terms records using an authenticated session and database time."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

import httpx2
from pydantic import SecretStr
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from app.account_key_cache import AccountKeyCache
from app.account_refresh import AccountRefreshRejected
from app.account_session_auth import AuthenticatedAccountSession, load_locked_account_session
from app.account_session_service import authenticate_account_session
from app.account_sessions import CreatedAccountSession
from app.account_signup_terms import SignupTermsReceipt
from app.account_terms_requests import CURRENT_TERMS_VERSION, TermsAcceptanceRequest
from app.config import Settings
from app.models import AccountTermsAcceptance


class AccountTermsUnavailable(RuntimeError):
    """A verified acceptance result could not be obtained safely."""


class AccountTermsRequired(ValueError):
    """The verified account has no acceptance of the current Terms revision."""


class AccountTermsSessionChanged(ValueError):
    """The verified cookie no longer matches the caller's account snapshot."""


def _require_expected_account(
    session: AuthenticatedAccountSession, expected_user_id: UUID | None
) -> None:
    if expected_user_id is not None and session.account.user_id != expected_user_id:
        raise AccountTermsSessionChanged("Account session changed.")


async def _check_expected_session(
    connection: AsyncConnection,
    token: SecretStr,
    expected_user_id: UUID | None,
) -> bool:
    if expected_user_id is None:
        return True
    # Reject an account switch before a provider refresh could rotate credentials.
    # Keep this lock through live verification and the caller's transaction.
    snapshot = await load_locked_account_session(connection, token)
    if snapshot is None:
        return False
    if snapshot.user_id != expected_user_id:
        raise AccountTermsSessionChanged("Account session changed.")
    return True


async def current_terms_accepted_at(connection: AsyncConnection, user_id: UUID) -> datetime | None:
    """Look up the current revision for a backend-verified account identity."""
    accepted_at = await connection.scalar(
        select(AccountTermsAcceptance.accepted_at).where(
            AccountTermsAcceptance.user_id == user_id,
            AccountTermsAcceptance.terms_version == CURRENT_TERMS_VERSION,
        )
    )
    if accepted_at is not None and (
        not isinstance(accepted_at, datetime) or accepted_at.utcoffset() is None
    ):
        raise AccountTermsUnavailable("Terms acceptance is unavailable.")
    return accepted_at


async def record_terms_acceptance(
    connection: AsyncConnection,
    account: AuthenticatedAccountSession,
    acceptance: TermsAcceptanceRequest,
) -> datetime:
    """Write once in the caller's transaction; preserve the first acceptance time.

    The account must come from server-side session verification, never request
    identity fields. The insert waits for conflicting concurrent inserts; the
    subsequent READ COMMITTED statement can then see the committed original.
    """
    # Revalidate even if a caller used Pydantic's unchecked construction helpers.
    TermsAcceptanceRequest.model_validate(acceptance.model_dump())
    if not connection.in_transaction():
        raise RuntimeError("Terms acceptance requires an active transaction.")

    return await _persist_acceptance(connection, account.account.user_id)


async def _persist_acceptance(
    connection: AsyncConnection,
    user_id: UUID,
    accepted_at: datetime | None = None,
) -> datetime:
    if not connection.in_transaction():
        raise RuntimeError("Terms acceptance requires an active transaction.")
    values: dict[str, object] = {"user_id": user_id, "terms_version": CURRENT_TERMS_VERSION}
    if accepted_at is not None:
        values["accepted_at"] = accepted_at
    await connection.execute(
        pg_insert(AccountTermsAcceptance)
        .values(**values)
        .on_conflict_do_nothing(
            index_elements=[AccountTermsAcceptance.user_id, AccountTermsAcceptance.terms_version]
        )
    )
    accepted_at = await current_terms_accepted_at(connection, user_id)
    if not isinstance(accepted_at, datetime) or accepted_at.utcoffset() is None:
        raise AccountTermsUnavailable("Terms acceptance is unavailable.")
    return accepted_at


async def record_signup_terms_acceptance(
    connection: AsyncConnection,
    created: CreatedAccountSession,
    receipt: SignupTermsReceipt,
) -> None:
    """Consume confirmed registration evidence only for the verified login subject."""
    if (
        receipt.confirmed_user_id != created.user_id
        or receipt.terms_version != CURRENT_TERMS_VERSION
    ):
        return
    await _persist_acceptance(connection, created.user_id, receipt.accepted_at)


@dataclass(frozen=True, slots=True)
class RecordedTermsAcceptance:
    session: AuthenticatedAccountSession
    accepted_at: datetime


async def accept_account_terms_transaction(
    engine: AsyncEngine,
    token: SecretStr,
    acceptance: TermsAcceptanceRequest,
    *,
    settings: Settings,
    client: httpx2.AsyncClient,
    key_cache: AccountKeyCache | None,
    expected_user_id: UUID | None = None,
) -> RecordedTermsAcceptance | None:
    """Verify live credentials and commit acceptance before reporting success.

    Does not create a profile, trust provider user metadata, issue cookies, retry,
    or treat sign-in itself as agreement. The caller owns the total deadline.
    """
    TermsAcceptanceRequest.model_validate(acceptance.model_dump())
    async with engine.begin() as connection:
        if not await _check_expected_session(connection, token, expected_user_id):
            return None
        session = await authenticate_account_session(
            connection, token, settings=settings, client=client, key_cache=key_cache
        )
        if session is None:
            return None
        _require_expected_account(session, expected_user_id)
        accepted_at = await record_terms_acceptance(connection, session, acceptance)

    return RecordedTermsAcceptance(session=session, accepted_at=accepted_at)


@dataclass(frozen=True, slots=True)
class AccountTermsStatus:
    session: AuthenticatedAccountSession
    accepted_at: datetime | None


async def account_terms_status_transaction(
    engine: AsyncEngine,
    token: SecretStr,
    *,
    settings: Settings,
    client: httpx2.AsyncClient,
    key_cache: AccountKeyCache | None,
    expected_user_id: UUID | None = None,
) -> AccountTermsStatus | None:
    """Read status for the verified subject, returning only after commit.

    Does not create an acceptance record or require one to read setup status.
    Authentication and lookup share a transaction and the session row lock.
    """
    async with engine.begin() as connection:
        if not await _check_expected_session(connection, token, expected_user_id):
            return None
        session = await authenticate_account_session(
            connection, token, settings=settings, client=client, key_cache=key_cache
        )
        if session is None:
            return None
        _require_expected_account(session, expected_user_id)
        accepted_at = await current_terms_accepted_at(connection, session.account.user_id)

    return AccountTermsStatus(session=session, accepted_at=accepted_at)


@dataclass(frozen=True, slots=True)
class TermsAccountAccess:
    """Verified resource access bound to the still-open caller transaction."""

    connection: AsyncConnection
    session: AuthenticatedAccountSession


@asynccontextmanager
async def terms_account_transaction(
    engine: AsyncEngine,
    token: SecretStr,
    *,
    settings: Settings,
    client: httpx2.AsyncClient,
    key_cache: AccountKeyCache | None,
    expected_user_id: UUID | None = None,
) -> AsyncIterator[TermsAccountAccess]:
    """Gate account resources and keep their operations in the same transaction.

    The consumer must use the yielded connection and verified subject for its
    ownership-scoped queries. Terms acceptance never replaces ownership checks.
    Failure, cancellation or missing acceptance rolls the transaction back.
    Setup status, acceptance and sign-out must not use this prerequisite.
    Complete resource work before leaving this context; do not pass the yielded
    connection to a streaming response or background task.
    """
    if not settings.account_terms_api_enabled:
        raise AccountTermsUnavailable("Account setup is unavailable.")
    async with engine.begin() as connection:
        if not await _check_expected_session(connection, token, expected_user_id):
            raise AccountRefreshRejected("Account credentials were rejected.")
        session = await authenticate_account_session(
            connection, token, settings=settings, client=client, key_cache=key_cache
        )
        if session is None:
            raise AccountRefreshRejected("Account credentials were rejected.")
        _require_expected_account(session, expected_user_id)
        if await current_terms_accepted_at(connection, session.account.user_id) is None:
            raise AccountTermsRequired("Terms acceptance is required.")
        yield TermsAccountAccess(connection=connection, session=session)
